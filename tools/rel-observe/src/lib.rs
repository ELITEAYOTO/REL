//! Narrow EX-01 controlled-input producer. This is not a PE parser or sandbox.
//! The subject and evidence come from the same bounded byte buffer.
mod coff;
mod sections;
pub use coff::{observe_coff_machine_bytes, observe_coff_machine_file};
pub use sections::{observe_section_headers_bytes, observe_section_headers_file};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, Metadata},
    io::{Read, Seek, SeekFrom},
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
        json!([]),
    ))
}

/// Re-read on the SAME already-open handle, comparing to the initial buffer.
/// This detects observed in-place mutations without allocating a second
/// whole-file copy; it is not a filesystem snapshot or concurrency lock.
fn verify_second_pass<R: Read>(reader: &mut R, expected: &[u8]) -> Result<(), String> {
    let mut scratch = [0_u8; 64 * 1024];
    for chunk in expected.chunks(scratch.len()) {
        reader
            .read_exact(&mut scratch[..chunk.len()])
            .map_err(|_| "EX-01 input shortened or unreadable during verification")?;
        if scratch[..chunk.len()] != *chunk {
            return Err("EX-01 input bytes changed during verification".to_owned());
        }
    }
    let mut extra = [0_u8; 1];
    if reader.read(&mut extra).map_err(|e| e.to_string())? != 0 {
        return Err("EX-01 input grew during verification".to_owned());
    }
    Ok(())
}

/// Refuse final-component symlinks/reparse points even if inserted after preflight.
/// This does not protect ancestor paths or create an atomic input snapshot.
fn open_controlled_leaf(path: &Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
        const FILE_SHARE_READ: u32 = 0x0000_0001;
        let file = fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_READ)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "EX-01 final-component reparse points are unsupported",
            ));
        }
        Ok(file)
    }
    #[cfg(not(any(unix, windows)))]
    {
        File::open(path)
    }
}

/// Read a bounded controlled file with a second, same-descriptor byte check.
/// Neither the parent path nor this check provides an atomic snapshot.
pub(crate) fn load_controlled_file(path: &Path) -> Result<Vec<u8>, String> {
    let before = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !before.file_type().is_file() {
        return Err("EX-01 requires an ordinary file (no leaf symlink)".to_owned());
    }
    if before.len() > MAX_INPUT_BYTES as u64 {
        return Err("EX-01 input exceeds 2 MiB prototype limit".to_owned());
    }
    load_after_preflight(path, &before)
}

/// Validate and read the handle after the preflight. Tests can simulate a
/// deterministic path swap between the two independently observable steps.
fn load_after_preflight(path: &Path, before: &Metadata) -> Result<Vec<u8>, String> {
    let mut file = open_controlled_leaf(path).map_err(|e| e.to_string())?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err("EX-01 input identity changed before opening".to_owned());
        }
    }
    if !opened.is_file() || opened.len() > MAX_INPUT_BYTES as u64 {
        return Err("EX-01 input is not a bounded regular file".to_owned());
    }
    if opened.len() != before.len() {
        return Err("EX-01 input size changed before opening".to_owned());
    }
    let mut bytes = Vec::new();
    (&mut file)
        .take((MAX_INPUT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > MAX_INPUT_BYTES || bytes.len() as u64 != opened.len() {
        return Err("EX-01 input changed size during read or exceeded limit".to_owned());
    }
    file.seek(SeekFrom::Start(0)).map_err(|e| e.to_string())?;
    verify_second_pass(&mut file, &bytes)?;
    let after = file.metadata().map_err(|e| e.to_string())?;
    if !after.is_file() || after.len() != opened.len() {
        return Err("EX-01 input metadata changed during verification".to_owned());
    }
    if let (Ok(initial), Ok(final_stamp)) = (opened.modified(), after.modified()) {
        if initial != final_stamp {
            return Err("EX-01 input timestamp changed during verification".to_owned());
        }
    }
    Ok(bytes)
}

pub fn observe_file(path: &Path) -> Result<Value, String> {
    observe_bytes(&load_controlled_file(path)?)
}

#[cfg(test)]
mod controlled_input_tests;

#[cfg(test)]
mod second_pass_tests {
    use super::verify_second_pass;
    use std::io::Cursor;

    #[test]
    fn unchanged_bytes_and_multichunk_buffer_succeed() {
        let bytes = vec![0x5a; 128 * 1024 + 7];
        assert!(verify_second_pass(&mut Cursor::new(&bytes), &bytes).is_ok());
        assert!(verify_second_pass(&mut Cursor::new(&[]), &[]).is_ok());
    }

    #[test]
    fn in_place_same_size_mutation_is_rejected() {
        let bytes = vec![0x5a; 128 * 1024 + 7];
        for offset in [0, 64 * 1024, bytes.len() - 1] {
            let mut mutated = bytes.clone();
            mutated[offset] ^= 0xff;
            assert!(verify_second_pass(&mut Cursor::new(mutated), &bytes)
                .unwrap_err()
                .contains("bytes changed"));
        }
    }

    #[test]
    fn truncated_or_extended_second_read_is_rejected() {
        let bytes = vec![7; 65537];
        let short = &bytes[..bytes.len() - 1];
        assert!(verify_second_pass(&mut Cursor::new(short), &bytes).is_err());
        let mut long = bytes.clone();
        long.push(8);
        assert!(verify_second_pass(&mut Cursor::new(long), &bytes)
            .unwrap_err()
            .contains("grew"));
    }
}
