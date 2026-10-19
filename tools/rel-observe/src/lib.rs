//! Narrow EX-01 controlled-input producer. This is not a PE parser or sandbox.
//! The subject and evidence come from the same bounded byte buffer.
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    path::Path,
};

pub const MAX_INPUT_BYTES: usize = 2 * 1024 * 1024;
pub const CONFIG: &str = "rel-observe:dos-magic:v1;limit=2097152;require-mz-and-pe-signatures";
const DOMAIN: &str = "pe.dos_magic";
const VERSION: &str = env!("CARGO_PKG_VERSION");

fn hash(data: &[u8]) -> String {
    format!("{:x}", Sha256::digest(data))
}

/// Analyze only a controlled, size-bounded PE-like file.
/// Does not validate imports, execute code, or establish PE parser correctness.
pub fn observe_bytes(bytes: &[u8]) -> Result<Value, String> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err("EX-01 input exceeds 2 MiB prototype limit".to_owned());
    }
    if bytes.get(..2) != Some(b"MZ".as_slice()) {
        return Err("EX-01 requires a DOS MZ prefix".to_owned());
    }
    let offset_bytes = bytes
        .get(0x3c..0x40)
        .ok_or("EX-01 requires a complete DOS e_lfanew field")?;
    let nt_offset = u32::from_le_bytes(
        offset_bytes
            .try_into()
            .map_err(|_| "invalid e_lfanew bytes")?,
    ) as usize;
    let nt_end = nt_offset
        .checked_add(4)
        .ok_or("NT signature offset overflow")?;
    if bytes.get(nt_offset..nt_end) != Some(b"PE\0\0".as_slice()) {
        return Err("EX-01 requires a minimal PE signature".to_owned());
    }

    let digest = Sha256::digest(bytes);
    let config_digest = Sha256::digest(CONFIG.as_bytes());
    let mut run = Sha256::new();
    run.update(b"REL-EX01-RUN-v1\0");
    run.update(digest);
    run.update(config_digest);
    run.update(b"pe.dos_magic\0");
    run.update(VERSION.as_bytes());

    let subject_hash = hash(bytes);
    let report = json!({
        "schema_version": "0.1.0-experimental",
        "subject": {
            "sha256": &subject_hash,
            "size_bytes": bytes.len(),
            "format": "PE"
        },
        "producer": {
            "component": "rel-observe",
            "version": VERSION,
            "backend": "rust-static-byte-reader",
            "backend_version": VERSION,
            "config_sha256": hash(CONFIG.as_bytes()),
            "run_id": format!("{:x}", run.finalize())
        },
        "scope": {
            "domain": DOMAIN,
            "status": "complete",
            "procedure": "Compare exactly the two bytes at file offsets [0,2) to MZ and NE after minimal PE signature checks.",
            "limitations": [
                "Only DOS magic comparisons are covered; no full PE validation, import analysis or behavior inference.",
                "Input acquisition is controlled-only; concurrent writers and hostile filesystems are not isolated."
            ]
        },
        "observations": [
            {
                "id": "dos-mz-present",
                "predicate": "equals.MZ",
                "status": "present",
                "raw_value": "MZ",
                "normalized_value": "MZ",
                "evidence_ids": ["dos-prefix"]
            },
            {
                "id": "dos-ne-absent",
                "predicate": "equals.NE",
                "status": "absent_in_scope",
                "raw_value": null,
                "normalized_value": null,
                "evidence_ids": ["dos-prefix"]
            }
        ],
        "evidence": [{
            "id": "dos-prefix",
            "subject_sha256": &subject_hash,
            "location": {"kind": "file_offset", "start": 0, "length": 2},
            "method": "exact-two-byte-comparison",
            "extractor_version": VERSION
        }],
        "diagnostics": []
    });
    Ok(report)
}

/// Read an ordinary, currently non-symlinked controlled input. Not an
/// atomic snapshot or race-free path resolver; do not feed hostile files.
pub fn observe_file(path: &Path) -> Result<Value, String> {
    let before = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !before.file_type().is_file() {
        return Err("EX-01 requires an ordinary file (no leaf symlink)".to_owned());
    }
    if before.len() > MAX_INPUT_BYTES as u64 {
        return Err("EX-01 input exceeds 2 MiB prototype limit".to_owned());
    }
    let file = File::open(path).map_err(|e| e.to_string())?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    if !opened.is_file() || opened.len() > MAX_INPUT_BYTES as u64 {
        return Err("EX-01 input is not a bounded regular file".to_owned());
    }
    let mut bytes = Vec::new();
    file.take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > MAX_INPUT_BYTES || bytes.len() as u64 != opened.len() {
        return Err("EX-01 input changed size during read or exceeded limit".to_owned());
    }
    observe_bytes(&bytes)
}
