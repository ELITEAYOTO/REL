//! Conservative, allocation-free bounds checks before invoking a PE backend.
//! These checks cover header layout only, not the entire PE grammar.
const DOS_NT_POINTER_OFFSET: usize = 0x3c;
const COFF_HEADER_SIZE: usize = 20;
const SECTION_HEADER_SIZE: usize = 40;

/// Alpha-policy limits, not PE format universals or an OS security boundary.
pub(crate) const MAX_NT_HEADER_OFFSET: usize = 1024 * 1024;
pub(crate) const MAX_OPTIONAL_HEADER_SIZE: usize = 4096;
pub(crate) const MAX_SECTIONS: usize = 96;

fn region(data: &[u8], offset: usize, length: usize) -> Option<&[u8]> {
    data.get(offset..offset.checked_add(length)?)
}

fn le_u16(data: &[u8], offset: usize) -> Option<u16> {
    let bytes: [u8; 2] = region(data, offset, 2)?.try_into().ok()?;
    Some(u16::from_le_bytes(bytes))
}

fn le_u32(data: &[u8], offset: usize) -> Option<u32> {
    let bytes: [u8; 4] = region(data, offset, 4)?.try_into().ok()?;
    Some(u32::from_le_bytes(bytes))
}

/// Reject implausibly expensive or out-of-bounds PE header layouts before
/// goblin allocates structures. No section contents or imports are inspected.
pub(crate) fn validate(data: &[u8]) -> Result<(), &'static str> {
    let nt_offset = le_u32(data, DOS_NT_POINTER_OFFSET)
        .ok_or("DOS header missing NT pointer")? as usize;
    if nt_offset > MAX_NT_HEADER_OFFSET {
        return Err("PE header offset exceeds alpha limit");
    }
    if region(data, nt_offset, 4) != Some(&b"PE\0\0"[..]) {
        return Err("invalid or truncated PE signature");
    }

    let coff = nt_offset.checked_add(4).ok_or("PE header overflow")?;
    region(data, coff, COFF_HEADER_SIZE).ok_or("truncated COFF header")?;

    let count = le_u16(data, coff + 2).ok_or("missing section count")? as usize;
    if count == 0 || count > MAX_SECTIONS {
        return Err("section count outside alpha policy");
    }
    let optional_size =
        le_u16(data, coff + 16).ok_or("missing optional header size")? as usize;
    if !(2..=MAX_OPTIONAL_HEADER_SIZE).contains(&optional_size) {
        return Err("optional header size outside alpha policy");
    }

    let optional_start = coff
        .checked_add(COFF_HEADER_SIZE)
        .ok_or("optional header offset overflow")?;
    region(data, optional_start, optional_size).ok_or("truncated optional header")?;

    match le_u16(data, optional_start) {
        Some(0x10b | 0x20b) => {}
        _ => return Err("unsupported PE optional header magic"),
    }

    let sections_start = optional_start
        .checked_add(optional_size)
        .ok_or("section table offset overflow")?;
    let table_size = count
        .checked_mul(SECTION_HEADER_SIZE)
        .ok_or("section table size overflow")?;
    region(data, sections_start, table_size).ok_or("section table extends beyond input")?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PE32: &[u8] = include_bytes!("../../../fixtures/pe32-basic.exe");
    const PE64: &[u8] = include_bytes!("../../../fixtures/pe64-basic.exe");

    fn coff_offset(data: &[u8]) -> usize {
        le_u32(data, DOS_NT_POINTER_OFFSET).unwrap() as usize + 4
    }

    fn with_u16(data: &[u8], offset: usize, value: u16) -> Vec<u8> {
        let mut copy = data.to_vec();
        copy[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        copy
    }

    #[test]
    fn accepts_both_golden_pe_formats() {
        assert_eq!(validate(PE32), Ok(()));
        assert_eq!(validate(PE64), Ok(()));
    }

    #[test]
    fn rejects_missing_dos_pointer_and_signature() {
        assert!(validate(b"MZ").is_err());
        let mut bad = PE32.to_vec();
        let nt = coff_offset(&bad) - 4;
        bad[nt] = b'X';
        assert_eq!(validate(&bad), Err("invalid or truncated PE signature"));
    }

    #[test]
    fn rejects_header_pointer_outside_alpha_limit() {
        let mut bad = PE32.to_vec();
        bad[DOS_NT_POINTER_OFFSET..DOS_NT_POINTER_OFFSET + 4]
            .copy_from_slice(&((MAX_NT_HEADER_OFFSET + 1) as u32).to_le_bytes());
        assert_eq!(validate(&bad), Err("PE header offset exceeds alpha limit"));
    }

    #[test]
    fn rejects_truncated_coff_header() {
        let mut bad = PE32.to_vec();
        bad.truncate(coff_offset(&bad) + COFF_HEADER_SIZE - 1);
        assert_eq!(validate(&bad), Err("truncated COFF header"));
    }

    #[test]
    fn rejects_zero_or_excessive_section_count() {
        let coff = coff_offset(PE32);
        assert_eq!(
            validate(&with_u16(PE32, coff + 2, 0)),
            Err("section count outside alpha policy")
        );
        assert_eq!(
            validate(&with_u16(PE32, coff + 2, (MAX_SECTIONS + 1) as u16)),
            Err("section count outside alpha policy")
        );
    }

    #[test]
    fn permits_policy_maximum_when_table_fits() {
        let coff = coff_offset(PE32);
        let mut padded = with_u16(PE32, coff + 2, MAX_SECTIONS as u16);
        padded.resize(16 * 1024, 0);
        assert_eq!(validate(&padded), Ok(()));
    }

    #[test]
    fn rejects_missing_or_oversized_optional_header() {
        let coff = coff_offset(PE32);
        assert_eq!(
            validate(&with_u16(PE32, coff + 16, 1)),
            Err("optional header size outside alpha policy")
        );
        assert_eq!(
            validate(&with_u16(
                PE32,
                coff + 16,
                (MAX_OPTIONAL_HEADER_SIZE + 1) as u16
            )),
            Err("optional header size outside alpha policy")
        );
    }

    #[test]
    fn rejects_truncated_optional_header() {
        let coff = coff_offset(PE32);
        let bad = with_u16(PE32, coff + 16, 2048);
        assert_eq!(validate(&bad), Err("truncated optional header"));
    }

    #[test]
    fn rejects_unrecognized_optional_magic() {
        let coff = coff_offset(PE32);
        assert_eq!(
            validate(&with_u16(PE32, coff + COFF_HEADER_SIZE, 0x107)),
            Err("unsupported PE optional header magic")
        );
    }

    #[test]
    fn rejects_truncated_section_table() {
        let coff = coff_offset(PE32);
        let bad = with_u16(PE32, coff + 2, 64);
        assert_eq!(
            validate(&bad),
            Err("section table extends beyond input")
        );
    }
}
