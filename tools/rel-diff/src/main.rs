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
    #[cfg(not(unix))]
    let opened = File::open(path);
    opened.map_err(|e| format!("{path}: {e}"))
}

fn load(path: &str) -> Result<Manifest, String> {
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
    if !manifest.warnings.is_empty() {
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
    let a: BTreeSet<_> = left.iter().cloned().collect();
    let b: BTreeSet<_> = right.iter().cloned().collect();
    Delta {
        added: b.difference(&a).cloned().collect(),
        removed: a.difference(&b).cloned().collect(),
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

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        return Err("usage: rel-diff LEFT.json RIGHT.json".to_owned());
    }
    let report = compare(load(&args[1])?, load(&args[2])?);
    let bytes = output::serialize_report(&report)?;
    use std::io::Write;
    std::io::stdout().write_all(&bytes).map_err(|e| e.to_string())?;
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
mod tests {
    use super::*;

    #[test]
    fn invalid_manifest_shapes_fail_deserialization() {
        let valid = format!(
            r#"{{"schema_version":"1.0.0","binary_sha256":"{}","size_bytes":1,"format":"PE","arch":null,"sections":[],"imports":[],"exports":[],"warnings":[]}}"#,
            "a".repeat(64)
        );
        assert!(serde_json::from_str::<Manifest>(&valid).is_ok());
        assert!(serde_json::from_str::<Manifest>(&valid.replace(r#","warnings":[]"#, "")).is_err());
        assert!(serde_json::from_str::<Manifest>(&valid.replace(r#","arch":null"#, "")).is_err());
        assert!(serde_json::from_str::<Manifest>(
            &valid.replace(r#""warnings":[]}"#, r#""warnings":[],"unknown":1}"#)
        )
        .is_err());
        assert!(serde_json::from_str::<Manifest>(
            &valid.replace(r#""size_bytes":1"#, r#""size_bytes":-1"#)
        )
        .is_err());
    }

    #[test]
    fn dll_case_hint_preserves_exact_import_evidence() {
        let left = vec!["KERNEL32.DLL!ReadFile".to_owned()];
        let right = vec!["kernel32.dll!ReadFile".to_owned()];
        assert!(dll_case_only(&left, &right));
        assert_eq!(delta(&left, &right).removed, left);
        assert!(!dll_case_only(
            &[
                "KERNEL32.DLL!ReadFile".into(),
                "kernel32.dll!ReadFile".into()
            ],
            &["kernel32.dll!ReadFile".into()]
        ));
        assert!(!dll_case_only(
            &["KERNEL32.DLL!ReadFile".into()],
            &["kernel32.dll!readfile".into()]
        ));
    }

    #[test]
    fn golden_manifest_comparison_reports_observed_changes() {
        let parse = |sha: char, size: u64, imports: &str| {
            let raw = format!(
                r#"{{"schema_version":"1.0.0","binary_sha256":"{}","size_bytes":{},"format":"PE","arch":"x86_64","sections":[{{"name":".text","offset":512,"size":100,"virtual_address":4096}}],"imports":[{}],"exports":[],"warnings":[]}}"#,
                sha.to_string().repeat(64),
                size,
                imports
            );
            serde_json::from_str::<Manifest>(&raw).expect("controlled valid manifest")
        };
        let left = parse('a', 1000, r#""KERNEL32.dll!ReadFile""#);
        let right = parse('b', 1200, r#""KERNEL32.dll!WriteFile""#);
        let result = compare(left, right);
        assert!(result.size_changed);
        assert!(!result.arch_changed);
        assert_eq!(result.sections.status, "unchanged");
        assert_eq!(result.imports.added, vec!["KERNEL32.dll!WriteFile"]);
        assert_eq!(result.imports.removed, vec!["KERNEL32.dll!ReadFile"]);
        let json = serde_json::to_value(&result).expect("serializable report");
        assert_eq!(json["schema_version"], "0.1.0-experimental");
        assert_eq!(json["sections"]["status"], "unchanged");
    }

    #[test]
    fn section_order_does_not_change_delta() {
        let section = |name: &str, size| Section {
            name: name.into(),
            offset: 0,
            size,
            virtual_address: Some(4096),
        };
        let a = vec![section(".text", 10), section(".data", 20)];
        let b = vec![section(".data", 20), section(".text", 10)];
        let result = section_status(&a, &b);
        assert_eq!(result.status, "unchanged");
        assert!(result.added.is_empty());
        assert!(result.removed.is_empty());
        assert!(result.changed.is_empty());
    }

    #[test]
    fn ambiguous_sections_do_not_emit_misleading_partial_deltas() {
        let section = |name: &str| Section {
            name: name.into(),
            offset: 0,
            size: 10,
            virtual_address: None,
        };
        let result = section_status(&[section(".text"), section(".text")], &[section(".new")]);
        assert_eq!(result.status, "ambiguous");
        assert!(result.added.is_empty());
        assert!(result.removed.is_empty());
        assert!(result.changed.is_empty());
    }

    #[test]
    fn repeated_sections_are_not_silently_matched() {
        let section = |name: &str| Section {
            name: name.into(),
            offset: 0,
            size: 10,
            virtual_address: Some(4096),
        };
        let result = section_status(&[section(".text"), section(".text")], &[]);
        assert_eq!(result.status, "ambiguous");
        let result = section_status(&[section(".text")], &[section(".text")]);
        assert_eq!(result.status, "unchanged");
    }

    #[test]
    fn unique_sections_have_deterministic_metadata_deltas() {
        let section = |name: &str, size| Section {
            name: name.into(),
            offset: 0,
            size,
            virtual_address: Some(4096),
        };
        let a = vec![section(".text", 10), section(".old", 1)];
        let b = vec![section(".new", 3), section(".text", 20)];
        let result = section_status(&a, &b);
        assert_eq!(result.status, "changed");
        assert_eq!(result.added, vec![".new"]);
        assert_eq!(result.removed, vec![".old"]);
        assert_eq!(result.changed, vec![".text"]);
        let reversed = section_status(&b, &a);
        assert_eq!(reversed.added, result.removed);
        assert_eq!(reversed.removed, result.added);
        assert_eq!(reversed.changed, result.changed);
    }

    #[test]
    fn repeated_observations_are_detected() {
        assert!(has_duplicates(&["x".into(), "x".into()]));
        assert!(!has_duplicates(&["x".into(), "y".into()]));
    }

    #[test]
    fn sets_are_order_independent_and_inverse() {
        let a = vec!["B".into(), "A".into()];
        let b = vec!["C".into(), "B".into()];
        assert_eq!(
            delta(&a, &a),
            Delta {
                added: vec![],
                removed: vec![]
            }
        );
        assert_eq!(
            delta(&a, &b),
            Delta {
                added: vec!["C".into()],
                removed: vec!["A".into()]
            }
        );
        assert_eq!(
            delta(&b, &a),
            Delta {
                added: vec!["A".into()],
                removed: vec!["C".into()]
            }
        );
    }
}
