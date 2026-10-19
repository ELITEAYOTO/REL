//! Experimental COFF Machine field observation from real bounded PE bytes.
//! Only this exact two-byte field is covered, not full architecture validation.
use crate::{envelope, hash, load_controlled_file, pe_nt_offset, VERSION};
use serde_json::{json, Value};
use std::path::Path;

const DOMAIN: &str = "pe.coff_machine";
const CONFIG: &str = "rel-observe:coff-machine:v1;limit=2097152;require-mz-and-pe-signatures";

pub fn observe_coff_machine_bytes(bytes: &[u8]) -> Result<Value, String> {
    let nt_offset = pe_nt_offset(bytes)?;
    let machine_offset = nt_offset
        .checked_add(4)
        .ok_or("COFF Machine offset overflow")?;
    let machine_end = machine_offset
        .checked_add(2)
        .ok_or("COFF Machine range overflow")?;

    let (status, observations, evidence, diagnostics) =
        if let Some(raw_bytes) = bytes.get(machine_offset..machine_end) {
            let machine = u16::from_le_bytes(
                raw_bytes
                    .try_into()
                    .map_err(|_| "invalid COFF Machine bytes")?,
            );
            let raw = format!("0x{machine:04x}");
            let normalized = match machine {
                0x014c => "x86".to_owned(),
                0x8664 => "x86_64".to_owned(),
                _ => raw.clone(),
            };
            (
                "complete",
                json!([{
                    "id": "coff-machine-value",
                    "predicate": "pe.coff_machine.value",
                    "status": "present",
                    "raw_value": raw,
                    "normalized_value": normalized,
                    "evidence_ids": ["coff-machine-field"]
                }]),
                json!([{
                    "id": "coff-machine-field",
                    "subject_sha256": hash(bytes),
                    "location": {
                        "kind": "file_offset",
                        "start": machine_offset,
                        "length": 2
                    },
                    "method": "exact-le-u16-field-extraction",
                    "extractor_version": VERSION
                }]),
                json!([]),
            )
        } else {
            // Valid minimal PE signature, but the following two bytes are not
            // fully present. Never fill missing bytes with zero or claim x86/x64.
            (
                "partial",
                json!([{
                    "id": "coff-machine-value",
                    "predicate": "pe.coff_machine.value",
                    "status": "indeterminate",
                    "raw_value": null,
                    "normalized_value": null,
                    "evidence_ids": []
                }]),
                json!([]),
                json!([{
                    "code": "COFF_MACHINE_TRUNCATED",
                    "severity": "warning",
                    "stage": "coff_machine",
                    "message": "The two-byte COFF Machine field is not completely present."
                }]),
            )
        };

    Ok(envelope(
        bytes,
        DOMAIN,
        CONFIG,
        json!({
            "domain": DOMAIN,
            "status": status,
            "procedure": "Read the two-byte little-endian COFF Machine field at e_lfanew + 4 after validating minimal MZ and PE signatures.",
            "limitations": [
                "Only the COFF Machine field is covered; no full PE header or architecture execution validation.",
                "Unrecognized machine values remain literal hex rather than assumed architectures.",
                "Controlled inputs only; concurrent file writes and hostile filesystems are not isolated."
            ]
        }),
        observations,
        evidence,
        diagnostics,
    ))
}

pub fn observe_coff_machine_file(path: &Path) -> Result<Value, String> {
    observe_coff_machine_bytes(&load_controlled_file(path)?)
}
