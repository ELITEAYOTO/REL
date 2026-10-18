//! Synthetic public-domain reference files; no production executable is bundled.
use rel_pe::inspect;

const PE32: &[u8] = include_bytes!("../../../fixtures/pe32-basic.exe");
const PE64: &[u8] = include_bytes!("../../../fixtures/pe64-basic.exe");

#[test]
fn reports_pe32_sections_import_and_export() {
    let output = inspect(PE32).expect("PE32 fixture must parse");
    assert_eq!(output.arch, "x86");
    assert_eq!(
        output
            .sections
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>(),
        [".text", ".rdata"]
    );
    assert_eq!(output.imports, ["KERNEL32.dll!GetTickCount"]);
    assert_eq!(output.exports, ["SampleExport"]);
}

#[test]
fn reports_pe64_sections_import_and_export() {
    let output = inspect(PE64).expect("PE32+ fixture must parse");
    assert_eq!(output.arch, "x86_64");
    assert_eq!(
        output
            .sections
            .iter()
            .map(|s| s.name.as_str())
            .collect::<Vec<_>>(),
        [".text", ".rdata"]
    );
    assert_eq!(output.imports, ["KERNEL32.dll!GetTickCount64"]);
    assert_eq!(output.exports, ["SampleExport"]);
}

#[test]
fn rejects_corrupt_and_truncated_inputs() {
    assert!(inspect(b"not an executable").is_err());
    assert!(inspect(b"MZ").is_err());
    for length in [3, 64, 140, 320, 512] {
        assert!(inspect(&PE64[..length]).is_err());
    }
}

#[test]
fn rejects_invalid_nt_header_pointer() {
    let mut bytes = PE32.to_vec();
    bytes[0x3c..0x40].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(inspect(&bytes).is_err());
}
