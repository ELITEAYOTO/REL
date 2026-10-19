//! Narrow EX-01 controlled-input producer. This is not a PE parser or sandbox.
//! The subject and evidence come from the same bounded byte buffer.
mod coff;
pub use coff::{observe_coff_machine_bytes, observe_coff_machine_file};

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

/// Verify only the minimal DOS + NT signature framing for controlled samples.
/// This deliberately does not validate a complete PE or its COFF header.
pub(crate) fn pe_nt_offset(bytes: &[u8]) -> Result<usize, String> {
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
    Ok(nt_offset)
}

/// Shared byte-bound provenance envelope for independently scoped EX-01 domains.
pub(crate) fn envelope(
    bytes: &[u8],
    domain: &str,
    config: &str,
    scope: Value,
    observations: Value,
    evidence: Value,
    diagnostics: Value,
) -> Value {
    let digest = Sha256::digest(bytes);
    let config_digest = Sha256::digest(config.as_bytes());
    let mut run = Sha256::new();
    run.update(b"REL-EX01-RUN-v1\0");
    run.update(digest);
    run.update(config_digest);
    run.update(domain.as_bytes());
    run.update(b"\0");
    run.update(VERSION.as_bytes());
    json!({
        "schema_version": "0.1.0-experimental",
        "subject": {
            "sha256": hash(bytes),
            "size_bytes": bytes.len(),
            "format": "PE"
        },
        "producer": {
            "component": "rel-observe",
            "version": VERSION,
            "backend": "rust-static-byte-reader",
            "backend_version": VERSION,
            "config_sha256": hash(config.as_bytes()),
            "run_id": format!("{:x}", run.finalize())
        },
        "scope": scope,
        "observations": observations,
        "evidence": evidence,
        "diagnostics": diagnostics
    })
}

/// Observe two DOS signature predicates only, on a controlled PE-like input.
/// This preserves the original EX-01 `dos-magic` domain and stable run ID.
pub fn observe_bytes(bytes: &[u8]) -> Result<Value, String> {
    pe_nt_offset(bytes)?;
    let subject_hash = hash(bytes);
    Ok(envelope(
        bytes,
        DOMAIN,
        CONFIG,
        json!({
            "domain": DOMAIN,
            "status": "complete",
            "procedure": "Compare exactly the two bytes at file offsets [0,2) to MZ and NE after minimal PE signature checks.",
            "limitations": [
                "Only DOS magic comparisons are covered; no full PE validation, import analysis or behavior inference.",
                "Input acquisition is controlled-only; concurrent writers and hostile filesystems are not isolated."
            ]
        }),
        json!([
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
        ]),
        json!([{
            "id": "dos-prefix",
            "subject_sha256": &subject_hash,
            "location": {"kind": "file_offset", "start": 0, "length": 2},
            "method": "exact-two-byte-comparison",
            "extractor_version": VERSION
        }]),
        json!([])
    ))
}

/// Read an ordinary, currently non-symlinked controlled input. Not an
/// atomic snapshot or race-free path resolver; do not feed hostile files.
pub(crate) fn load_controlled_file(path: &Path) -> Result<Vec<u8>, String> {
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
    Ok(bytes)
}

pub fn observe_file(path: &Path) -> Result<Value, String> {
    observe_bytes(&load_controlled_file(path)?)
}
