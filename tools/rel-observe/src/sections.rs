//! Experimental section header records from bounded PE bytes.
//! Only the declared 40-byte COFF section header records are observed;
//! raw section contents and mapped memory ranges are NOT validated.
use crate::{envelope, hash, load_controlled_file, pe_nt_offset, VERSION};
use serde_json::{json, Value};
use std::path::Path;

const DOMAIN: &str = "pe.section_headers";
const CONFIG: &str = "rel-observe:section-headers:v1;limit=2097152;max=32;record=40";
const COFF_SIZE: usize = 20;
const RECORD_SIZE: usize = 40;
const MAX_SECTIONS: usize = 32;

fn report(
    bytes: &[u8],
    state: &str,
    observations: Vec<Value>,
    evidence: Vec<Value>,
    diagnostics: Vec<Value>,
) -> Value {
    envelope(
        bytes,
        DOMAIN,
        CONFIG,
        json!({
            "domain": DOMAIN,
            "status": state,
            "procedure": "Read the COFF NumberOfSections and SizeOfOptionalHeader, then inspect the complete declared 40-byte section-header array at e_lfanew + 24 + SizeOfOptionalHeader.",
            "limitations": [
                "Only declared header bytes are covered, not mapped section payloads, executable behavior, or general PE validity.",
                "At most 32 headers are supported; exceeding the limit yields unsupported with no fabricated entries.",
                "Controlled inputs only; concurrent writes and hostile filesystem races are not isolated."
            ]
        }),
        json!(observations),
        json!(evidence),
        json!(diagnostics),
    )
}

fn abstain(bytes: &[u8], state: &str, code: &str, message: &str) -> Value {
    report(
        bytes,
        state,
        vec![json!({
            "id": "section-headers-undetermined",
            "predicate": "pe.section_headers.records",
            "status": "indeterminate",
            "raw_value": null,
            "normalized_value": null,
            "evidence_ids": []
        })],
        vec![],
        vec![json!({
            "code": code,
            "severity": "warning",
            "stage": "section_headers",
            "message": message
        })],
    )
}

fn little_u32(record: &[u8], offset: usize) -> u32 {
    let part = &record[offset..offset + 4];
    u32::from_le_bytes([part[0], part[1], part[2], part[3]])
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Inspect section header records only, from a single owned, bounded buffer.
/// A complete state means all declared header records were read, NOT that
/// their RVA/raw ranges resolve or that the binary is otherwise valid.
pub fn observe_section_headers_bytes(bytes: &[u8]) -> Result<Value, String> {
    let nt = pe_nt_offset(bytes)?;
    let coff_start = nt.checked_add(4).ok_or("COFF offset overflow")?;
    let coff_end = coff_start.checked_add(COFF_SIZE).ok_or("COFF end overflow")?;
    let Some(coff) = bytes.get(coff_start..coff_end) else {
        return Ok(abstain(
            bytes, "partial", "SECTION_COFF_TRUNCATED",
            "Complete 20-byte COFF header unavailable; section count cannot be established.",
        ));
    };
    let count = u16::from_le_bytes([coff[2], coff[3]]) as usize;
    let optional_size = u16::from_le_bytes([coff[16], coff[17]]) as usize;
    if count > MAX_SECTIONS {
        return Ok(abstain(
            bytes, "unsupported", "SECTION_COUNT_LIMIT",
            "Declared section count exceeds this experimental 32-record limit.",
        ));
    }
    let start = coff_end
        .checked_add(optional_size)
        .ok_or("section table start overflow")?;
    let span = count
        .checked_mul(RECORD_SIZE)
        .ok_or("section table length overflow")?;
    let end = start.checked_add(span).ok_or("section table end overflow")?;
    if bytes.get(coff_end..start).is_none() || bytes.get(start..end).is_none() {
        return Ok(abstain(
            bytes, "partial", "SECTION_TABLE_TRUNCATED",
            "Declared optional-header or complete section-header table bytes are unavailable.",
        ));
    }

    let subject_sha = hash(bytes);
    if count == 0 {
        return Ok(report(
            bytes, "complete",
            vec![json!({
                "id": "section-headers-empty",
                "predicate": "pe.section_headers.records",
                "status": "absent_in_scope",
                "raw_value": null,
                "normalized_value": null,
                "evidence_ids": ["coff-section-count"]
            })],
            vec![json!({
                "id": "coff-section-count",
                "subject_sha256": subject_sha,
                "location": {"kind": "file_offset", "start": coff_start + 2, "length": 2},
                "method": "exact-le-u16-section-count",
                "extractor_version": VERSION
            })],
            vec![],
        ));
    }

    let mut observations = Vec::with_capacity(count);
    let mut evidence = Vec::with_capacity(count);
    for index in 0..count {
        // Bounds were checked above for the entire record array.
        let offset = start + index * RECORD_SIZE;
        let record = &bytes[offset..offset + RECORD_SIZE];
        let id = format!("section-{index:03}");
        let proof = format!("{id}-header");
        let name_hex = hex(&record[..8]);
        let normalized = format!(
            "name_hex={name_hex};virtual_size=0x{:08x};rva=0x{:08x};raw_size=0x{:08x};raw_pointer=0x{:08x};characteristics=0x{:08x}",
            little_u32(record, 8),
            little_u32(record, 12),
            little_u32(record, 16),
            little_u32(record, 20),
            little_u32(record, 36),
        );
        observations.push(json!({
            "id": id,
            "predicate": "pe.section_headers.record",
            "status": "present",
            "raw_value": hex(record),
            "normalized_value": normalized,
            "evidence_ids": [proof]
        }));
        evidence.push(json!({
            "id": proof,
            "subject_sha256": &subject_sha,
            "location": {"kind": "file_offset", "start": offset, "length": RECORD_SIZE},
            "method": "exact-40-byte-coff-section-record",
            "extractor_version": VERSION
        }));
    }
    Ok(report(bytes, "complete", observations, evidence, vec![]))
}

pub fn observe_section_headers_file(path: &Path) -> Result<Value, String> {
    observe_section_headers_bytes(&load_controlled_file(path)?)
}
