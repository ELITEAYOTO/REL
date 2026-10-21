//! Experimental EX-02: limited, deterministic differences between PE v1 manifests.
mod output;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::File;
use std::io::Read;
use std::process::ExitCode;

const MAX_INPUT: u64 = 16 * 1024 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    schema_version: String,
    binary_sha256: String,
    size_bytes: u64,
    format: String,
    #[serde(deserialize_with = "required_nullable")]
    arch: Option<String>,
    sections: Vec<Section>,
    imports: Vec<String>,
    exports: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Section {
    name: String,
    offset: u64,
    size: u64,
    #[serde(deserialize_with = "required_nullable")]
    virtual_address: Option<u64>,
}

#[derive(Serialize, Debug, PartialEq, Eq)]
struct Delta {
    added: Vec<String>,
    removed: Vec<String>,
}

#[derive(Serialize)]
struct SectionDelta {
    status: &'static str,
    reason: &'static str,
    added: Vec<String>,
    removed: Vec<String>,
    changed: Vec<String>,
}

#[derive(Serialize)]
struct Report {
    schema_version: &'static str,
    left_sha256: String,
    right_sha256: String,
    size_changed: bool,
    arch_changed: bool,
    imports: Delta,
    import_dll_case_only: bool,
    exports: Delta,
    sections: SectionDelta,
    limitations: Vec<&'static str>,
}

#[derive(Serialize)]
struct PartialCoverage {
    // v1 has no typed coverage completeness contract; no warnings is UNKNOWN.
    status: &'static str,
    left_warnings: Vec<String>,
    right_warnings: Vec<String>,
    negative_behavior_conclusions: bool,
}

#[derive(Serialize)]
struct PartialReport {
    schema_version: &'static str,
    coverage: PartialCoverage,
    // The historical 0.1 schema remains nested and unchanged.
    observed: Report,
}

// JSON Schema requires these keys even when their values are null.
// Serde's default Option behavior would otherwise accept an omitted key.
fn required_nullable<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::<T>::deserialize(deserializer)
}

// Nonblocking Unix open prevents a FIFO or device substituted at the leaf
// from stalling *before* the opened-handle regular-file check can reject it.
// O_NOFOLLOW protects the leaf only, not ancestor components or filesystem races.
fn open_manifest(path: &str) -> Result<File, String> {
    #[cfg(unix)]
    let opened = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW)
            .open(path)
    };
    #[cfg(windows)]
    let opened = {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        // Open the final component itself rather than following a reparse
        // point. Keep ordinary writers out while the descriptor is live.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        const FILE_SHARE_READ: u32 = 0x0000_0001;

        std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .and_then(|file| {
                if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "input final-component reparse points are unsupported",
                    ))
                } else {
                    Ok(file)
                }
            })
    };
    #[cfg(not(any(unix, windows)))]
    let opened = File::open(path);
    opened.map_err(|e| format!("{path}: {e}"))
}

fn load(path: &str, allow_warnings: bool) -> Result<Manifest, String> {
    let file = open_manifest(path)?;
    let metadata = file.metadata().map_err(|e| format!("{path}: {e}"))?;
    if !metadata.is_file() {
        return Err(format!("{path}: input must be a regular file"));
    }
    if metadata.len() > MAX_INPUT {
        return Err(format!("{path}: input exceeds 16 MiB"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_INPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{path}: {e}"))?;
    if bytes.len() as u64 > MAX_INPUT {
        return Err(format!("{path}: input exceeds 16 MiB"));
    }
    let manifest: Manifest = serde_json::from_slice(&bytes).map_err(|e| format!("{path}: {e}"))?;
    if manifest.schema_version != "1.0.0" || manifest.format != "PE" {
        return Err(format!(
            "{path}: only PE binary-manifest v1.0.0 is supported"
        ));
    }
    if manifest.binary_sha256.len() != 64
        || !manifest
            .binary_sha256
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(format!("{path}: invalid SHA-256"));
    }
    if has_duplicates(&manifest.imports) || has_duplicates(&manifest.exports) {
        return Err(format!("{path}: duplicate import or export observations"));
    }
    if !allow_warnings && !manifest.warnings.is_empty() {
        return Err(format!(
            "{path}: extraction warnings require explicit coverage handling"
        ));
    }
    Ok(manifest)
}

fn has_duplicates(items: &[String]) -> bool {
    let unique: BTreeSet<_> = items.iter().collect();
    unique.len() != items.len()
}

fn delta(left: &[String], right: &[String]) -> Delta {
    // Membership comparisons borrow the input observations; only report
    // differences need owned strings. Avoid copying every input string.
    let a: BTreeSet<_> = left.iter().collect();
    let b: BTreeSet<_> = right.iter().collect();
    Delta {
        added: b.difference(&a).map(|entry| (**entry).clone()).collect(),
        removed: a.difference(&b).map(|entry| (**entry).clone()).collect(),
    }
}

// Only the DLL prefix before '!' is ASCII case-insensitive. Keep raw evidence in Delta.
fn normalized_import(item: &str) -> String {
    match item.split_once('!') {
        Some((dll, symbol)) if !dll.is_empty() && !symbol.is_empty() => {
            format!("{}!{symbol}", dll.to_ascii_lowercase())
        }
        _ => item.to_owned(),
    }
}

fn dll_case_only(left: &[String], right: &[String]) -> bool {
    let raw_left: BTreeSet<_> = left.iter().collect();
    let raw_right: BTreeSet<_> = right.iter().collect();
    if raw_left == raw_right {
        return false;
    }
    let normalized = |items: &[String]| -> BTreeSet<String> {
        items.iter().map(|item| normalized_import(item)).collect()
    };
    let lhs = normalized(left);
    let rhs = normalized(right);
    // Collisions mean we cannot establish a one-to-one observation mapping.
    lhs.len() == left.len() && rhs.len() == right.len() && lhs == rhs
}

fn section_status(a: &[Section], b: &[Section]) -> SectionDelta {
    let left_names: Vec<String> = a.iter().map(|s| s.name.clone()).collect();
    let right_names: Vec<String> = b.iter().map(|s| s.name.clone()).collect();
    if has_duplicates(&left_names) || has_duplicates(&right_names) {
        return SectionDelta {
            status: "ambiguous",
            reason: "Repeated section names prevent unique name-based matching.",
            added: Vec::new(),
            removed: Vec::new(),
            changed: Vec::new(),
        };
    }
    let left: BTreeMap<_, _> = a.iter().map(|s| (s.name.as_str(), s)).collect();
    let right: BTreeMap<_, _> = b.iter().map(|s| (s.name.as_str(), s)).collect();
    let added: Vec<String> = right
        .keys()
        .filter(|name| !left.contains_key(**name))
        .map(|name| (*name).to_owned())
        .collect();
    let removed: Vec<String> = left
        .keys()
        .filter(|name| !right.contains_key(**name))
        .map(|name| (*name).to_owned())
        .collect();
    let changed: Vec<String> = left
        .iter()
        .filter(|(name, section)| {
            right.get(**name).is_some_and(|other| {
                section.name != other.name
                    || section.offset != other.offset
                    || section.size != other.size
                    || section.virtual_address != other.virtual_address
            })
        })
        .map(|(name, _)| (*name).to_owned())
        .collect();
    let status = if added.is_empty() && removed.is_empty() && changed.is_empty() {
        "unchanged"
    } else {
        "changed"
    };
    SectionDelta {
        status,
        reason: "Sections matched only by unique exact name; metadata, not behavior.",
        added,
        removed,
        changed,
    }
}

fn compare(a: Manifest, b: Manifest) -> Report {
    Report {
        schema_version: "0.1.0-experimental",
        left_sha256: a.binary_sha256,
        right_sha256: b.binary_sha256,
        size_changed: a.size_bytes != b.size_bytes,
        arch_changed: a.arch != b.arch,
        import_dll_case_only: dll_case_only(&a.imports, &b.imports),
        imports: delta(&a.imports, &b.imports),
        exports: delta(&a.exports, &b.exports),
        sections: section_status(&a.sections, &b.sections),
        limitations: vec![
            "Sections compared by unique exact name only; duplicate names cause abstention.",
            "Imports and exports are observed strings, not runtime capabilities.",
            "Original import strings are retained; only a collision-safe DLL-case-only hint is emitted.",
            "Unknown extraction coverage; no negative behavioral conclusions.",
        ],
    }
}

fn compare_partial(mut left: Manifest, mut right: Manifest) -> PartialReport {
    let mut left_warnings = std::mem::take(&mut left.warnings);
    let mut right_warnings = std::mem::take(&mut right.warnings);
    // Retain every warning, even unknown or repeated ones. Canonicalize
    // their order for byte-identical results from permuted observations.
    left_warnings.sort();
    right_warnings.sort();
    let status = if left_warnings.is_empty() && right_warnings.is_empty() {
        "unknown"
    } else {
        "partial"
    };
    PartialReport {
        schema_version: "0.2.0-experimental",
        coverage: PartialCoverage {
            status,
            left_warnings,
            right_warnings,
            negative_behavior_conclusions: false,
        },
        observed: compare(left, right),
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    let (partial, left_path, right_path) = match args.as_slice() {
        [_, left, right] => (false, left.as_str(), right.as_str()),
        [_, flag, left, right] if flag == "--partial" => (true, left.as_str(), right.as_str()),
        _ => return Err("usage: rel-diff [--partial] LEFT.json RIGHT.json".to_owned()),
    };
    let left = load(left_path, partial)?;
    let right = load(right_path, partial)?;
    let bytes = if partial {
        output::serialize_report(&compare_partial(left, right))?
    } else {
        output::serialize_report(&compare(left, right))?
    };
    use std::io::Write;
    std::io::stdout()
        .write_all(&bytes)
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("rel-diff: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
