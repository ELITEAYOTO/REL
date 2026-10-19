//! Experimental EX-02: limited, deterministic differences between PE v1 manifests.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::env;
use std::fs::{self, File};
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
    arch: Option<String>,
    sections: Vec<Section>,
    imports: Vec<String>,
    exports: Vec<String>,
    warnings: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Section {
    name: String,
    offset: u64,
    size: u64,
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
}

#[derive(Serialize)]
struct Report {
    schema_version: &'static str,
    left_sha256: String,
    right_sha256: String,
    size_changed: bool,
    arch_changed: bool,
    imports: Delta,
    exports: Delta,
    sections: SectionDelta,
    limitations: Vec<&'static str>,
}

fn load(path: &str) -> Result<Manifest, String> {
    let size = fs::metadata(path)
        .map_err(|e| format!("{path}: {e}"))?
        .len();
    if size > MAX_INPUT {
        return Err(format!("{path}: input exceeds 16 MiB"));
    }
    let file = File::open(path).map_err(|e| format!("{path}: {e}"))?;
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

fn section_status(a: &[Section], b: &[Section]) -> SectionDelta {
    let left_names: Vec<String> = a.iter().map(|s| s.name.clone()).collect();
    let right_names: Vec<String> = b.iter().map(|s| s.name.clone()).collect();
    if has_duplicates(&left_names) || has_duplicates(&right_names) {
        return SectionDelta {
            status: "ambiguous",
            reason: "Repeated section names prevent unique name-based matching.",
        };
    }
    SectionDelta {
        status: "incomparable",
        reason: "Section matching is not implemented in this pilot.",
    }
}

fn compare(a: Manifest, b: Manifest) -> Report {
    Report {
        schema_version: "0.1.0-experimental",
        left_sha256: a.binary_sha256,
        right_sha256: b.binary_sha256,
        size_changed: a.size_bytes != b.size_bytes,
        arch_changed: a.arch != b.arch,
        imports: delta(&a.imports, &b.imports),
        exports: delta(&a.exports, &b.exports),
        sections: section_status(&a.sections, &b.sections),
        limitations: vec![
            "Section status is ambiguous or incomparable; no section deltas are claimed.",
            "Imports and exports are observed strings, not runtime capabilities.",
            "Duplicates and import DLL casing are not normalized in this pilot.",
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
    let output = serde_json::to_string_pretty(&report).map_err(|e| e.to_string())?;
    println!("{output}");
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
        assert_eq!(result.status, "incomparable");
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
