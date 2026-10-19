//! Controlled reference fixtures and explicit rejection of unsupported data.
use rel_observe::{observe_bytes, MAX_INPUT_BYTES};
use serde_json::Value;

const PE32: &[u8] = include_bytes!("../../../fixtures/pe32-basic.exe");
const PE64: &[u8] = include_bytes!("../../../fixtures/pe64-basic.exe");

fn evidence(report: &Value) {
    assert_eq!(report["scope"]["status"], "complete");
    assert_eq!(report["scope"]["domain"], "pe.dos_magic");
    assert_eq!(report["observations"][0]["status"], "present");
    assert_eq!(report["observations"][1]["status"], "absent_in_scope");
    assert_eq!(report["evidence"][0]["location"]["start"], 0);
    assert_eq!(report["evidence"][0]["location"]["length"], 2);
}

#[test]
fn controlled_reference_pe32_and_pe64_produce_real_evidence() {
    let pe32 = observe_bytes(PE32).unwrap();
    let pe64 = observe_bytes(PE64).unwrap();
    evidence(&pe32);
    evidence(&pe64);
    assert_eq!(pe32, observe_bytes(PE32).unwrap());
    assert_ne!(pe32["subject"]["sha256"], pe64["subject"]["sha256"]);
    assert_ne!(pe32["producer"]["run_id"], pe64["producer"]["run_id"]);
}

#[test]
fn refuses_empty_truncated_non_pe_or_too_large_inputs() {
    assert!(observe_bytes(&[]).is_err());
    assert!(observe_bytes(b"MZ").is_err());
    assert!(observe_bytes(b"not a PE").is_err());
    let mut invalid = PE32.to_vec();
    invalid[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(observe_bytes(&invalid).is_err());
    let mut broken = PE32.to_vec();
    broken[0] = b'N';
    assert!(observe_bytes(&broken).is_err());
    assert!(observe_bytes(&vec![0; MAX_INPUT_BYTES + 1]).is_err());
}

// The COFF field is located immediately after the 4-byte PE signature.
fn coff_offset(bytes: &[u8]) -> usize {
    let nt = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    assert_eq!(&bytes[nt..nt + 4], b"PE\0\0");
    nt + 4
}

#[test]
fn coff_machine_is_bounded_and_reproducible_on_both_reference_formats() {
    for (source, expected) in [(PE32, "x86"), (PE64, "x86_64")] {
        let report = rel_observe::observe_coff_machine_bytes(source).unwrap();
        assert_eq!(report["schema_version"], "0.1.0-experimental");
        assert_eq!(report["scope"]["domain"], "pe.coff_machine");
        assert_eq!(report["scope"]["status"], "complete");
        assert_eq!(report["observations"][0]["status"], "present");
        assert_eq!(report["observations"][0]["normalized_value"], expected);
        assert_eq!(
            report["evidence"][0]["location"]["start"],
            coff_offset(source)
        );
        assert_eq!(report["evidence"][0]["location"]["length"], 2);
        assert_eq!(report["diagnostics"].as_array().unwrap().len(), 0);
        assert_eq!(
            report,
            rel_observe::observe_coff_machine_bytes(source).unwrap()
        );
        assert_ne!(
            report["producer"]["run_id"],
            rel_observe::observe_bytes(source).unwrap()["producer"]["run_id"]
        );
    }
}

#[test]
fn truncated_coff_machine_is_explicitly_partial_without_invented_bytes() {
    let at = coff_offset(PE32);
    for end in [at, at + 1] {
        let report = rel_observe::observe_coff_machine_bytes(&PE32[..end]).unwrap();
        assert_eq!(report["scope"]["status"], "partial");
        assert_eq!(report["observations"][0]["status"], "indeterminate");
        assert!(report["observations"][0]["raw_value"].is_null());
        assert!(report["observations"][0]["evidence_ids"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(report["evidence"].as_array().unwrap().is_empty());
        assert_eq!(report["diagnostics"][0]["code"], "COFF_MACHINE_TRUNCATED");
    }
}

#[test]
fn unknown_machine_is_reported_as_raw_hex_not_made_up_architecture() {
    let mut bytes = PE32.to_vec();
    let at = coff_offset(&bytes);
    bytes[at..at + 2].copy_from_slice(&0x9999_u16.to_le_bytes());
    let report = rel_observe::observe_coff_machine_bytes(&bytes).unwrap();
    assert_eq!(report["observations"][0]["raw_value"], "0x9999");
    assert_eq!(report["observations"][0]["normalized_value"], "0x9999");
    assert_eq!(report["scope"]["status"], "complete");
    assert!(rel_observe::observe_coff_machine_bytes(&[]).is_err());
}


fn section_fields(bytes: &[u8]) -> (usize, usize) {
    let coff_start = coff_offset(bytes);
    let coff = &bytes[coff_start..coff_start + 20];
    let count = u16::from_le_bytes([coff[2], coff[3]]) as usize;
    let optional_size = u16::from_le_bytes([coff[16], coff[17]]) as usize;
    (count, coff_start + 20 + optional_size)
}

#[test]
fn section_records_match_exact_fixture_bytes_without_inferring_payload_validity() {
    for source in [PE32, PE64] {
        let (count, start) = section_fields(source);
        assert!(count > 0 && count <= 32);
        let report = rel_observe::observe_section_headers_bytes(source).unwrap();
        assert_eq!(report["scope"]["domain"], "pe.section_headers");
        assert_eq!(report["scope"]["status"], "complete");
        assert_eq!(report["observations"].as_array().unwrap().len(), count);
        for index in 0..count {
            let offset = start + index * 40;
            assert_eq!(report["observations"][index]["status"], "present");
            assert_eq!(report["evidence"][index]["location"]["start"], offset);
            assert_eq!(report["evidence"][index]["location"]["length"], 40);
            assert_eq!(
                report["observations"][index]["raw_value"].as_str().unwrap().len(),
                80
            );
        }
        assert_eq!(
            report,
            rel_observe::observe_section_headers_bytes(source).unwrap()
        );
    }
}

#[test]
fn section_truncations_abstain_with_diagnostics() {
    let (count, table) = section_fields(PE32);
    assert!(count > 0);
    let coff = coff_offset(PE32);
    for end in [coff + 19, table.saturating_sub(1), table, table + count * 40 - 1] {
        let report = rel_observe::observe_section_headers_bytes(&PE32[..end]).unwrap();
        assert_eq!(report["scope"]["status"], "partial");
        assert_eq!(report["observations"][0]["status"], "indeterminate");
        assert!(report["observations"][0]["raw_value"].is_null());
        assert!(report["evidence"].as_array().unwrap().is_empty());
        assert_eq!(report["diagnostics"][0]["severity"], "warning");
    }
}

#[test]
fn section_count_limit_and_empty_declaration_never_invent_entries() {
    let mut bytes = PE32.to_vec();
    let coff = coff_offset(&bytes);
    bytes[coff + 2..coff + 4].copy_from_slice(&33_u16.to_le_bytes());
    let unsupported = rel_observe::observe_section_headers_bytes(&bytes).unwrap();
    assert_eq!(unsupported["scope"]["status"], "unsupported");
    assert_eq!(unsupported["observations"][0]["status"], "indeterminate");
    assert!(unsupported["evidence"].as_array().unwrap().is_empty());

    bytes[coff + 2..coff + 4].copy_from_slice(&0_u16.to_le_bytes());
    let empty = rel_observe::observe_section_headers_bytes(&bytes).unwrap();
    assert_eq!(empty["scope"]["status"], "complete");
    assert_eq!(empty["observations"][0]["status"], "absent_in_scope");
    assert_eq!(empty["evidence"][0]["location"]["start"], coff + 2);
    assert_eq!(empty["evidence"][0]["location"]["length"], 2);
    assert!(rel_observe::observe_section_headers_bytes(b"invalid").is_err());
}
