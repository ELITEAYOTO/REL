//! Synthetic public-domain reference files; no production executable is bundled.
use rel_pe::{inspect, PeError};

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

#[test]
fn rejects_excessive_section_count_at_public_api() {
    let mut bytes = PE32.to_vec();
    let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    bytes[pe + 6..pe + 8].copy_from_slice(&97_u16.to_le_bytes());
    let failure = inspect(&bytes)
        .err()
        .expect("structural cap must reject input");
    assert!(matches!(
        failure,
        PeError::Parse(ref message) if message.contains("section count outside alpha policy")
    ));
}

#[test]
fn rejects_optional_header_larger_than_alpha_cap_at_public_api() {
    let mut bytes = PE64.to_vec();
    let pe = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
    bytes[pe + 20..pe + 22].copy_from_slice(&4097_u16.to_le_bytes());
    let failure = inspect(&bytes)
        .err()
        .expect("structural cap must reject input");
    assert!(matches!(
        failure,
        PeError::Parse(ref message) if message.contains("optional header size outside alpha policy")
    ));
}

#[test]
fn rejects_oversized_export_count_via_public_inspect_api() {
    let mut bytes = PE32.to_vec();
    // Known golden fixture: export directory RVA 0x2100 in .rdata,
    // mapped through section raw start 0x400 and virtual address 0x2000.
    let export_header = 0x400 + (0x2100 - 0x2000);
    bytes[export_header + 20..export_header + 24].copy_from_slice(&65_537_u32.to_le_bytes());
    let failure = inspect(&bytes)
        .err()
        .expect("export count must be rejected");
    assert!(matches!(
        failure,
        PeError::Parse(ref message) if message.contains("export count exceeds alpha symbol limit")
    ));
}

#[test]
fn rejects_out_of_file_raw_section_via_public_inspect_api() {
    for fixture in [PE32, PE64] {
        let mut bytes = fixture.to_vec();
        let nt = u32::from_le_bytes(bytes[0x3c..0x40].try_into().unwrap()) as usize;
        let coff = nt + 4;
        let optional_size =
            u16::from_le_bytes(bytes[coff + 16..coff + 18].try_into().unwrap()) as usize;
        let section = coff + 20 + optional_size;
        let end = bytes.len() as u32;
        bytes[section + 20..section + 24].copy_from_slice(&end.to_le_bytes());
        bytes[section + 16..section + 20].copy_from_slice(&1_u32.to_le_bytes());

        let failure = inspect(&bytes)
            .err()
            .expect("raw section outside the input must fail before the backend");
        assert!(matches!(
            failure,
            PeError::Parse(ref message) if message.contains("section raw data extends beyond input")
        ));
    }
}
