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
