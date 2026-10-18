//! Conservative, allocation-free bounds checks before invoking a PE backend.
//! These checks cover declared header/directory budgets, not the whole PE grammar.
mod directories;
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

/// Validate declared raw file ranges without reading or copying section contents.
/// The section table itself has already been checked for complete containment.
fn validate_section_raw_ranges(
    data: &[u8],
    sections_start: usize,
    count: usize,
) -> Result<(), &'static str> {
    for index in 0..count {
        let section = sections_start + index * SECTION_HEADER_SIZE;
        let size = le_u32(data, section + 16).ok_or("truncated section raw size")? as usize;
        if size == 0 {
            // A virtual-only or uninitialized section may have no raw bytes.
            continue;
        }
        let offset = le_u32(data, section + 20).ok_or("truncated section raw offset")? as usize;
        region(data, offset, size).ok_or("section raw data extends beyond input")?;
    }
    Ok(())
}

/// Reject implausibly expensive or out-of-bounds PE header layouts before
/// goblin allocates structures. No section contents or imports are inspected.
pub(crate) fn validate(data: &[u8]) -> Result<(), &'static str> {
    let nt_offset =
        le_u32(data, DOS_NT_POINTER_OFFSET).ok_or("DOS header missing NT pointer")? as usize;
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
    let optional_size = le_u16(data, coff + 16).ok_or("missing optional header size")? as usize;
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
    validate_section_raw_ranges(data, sections_start, count)?;
    directories::validate(data, optional_start, optional_size, sections_start, count)?;

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
        assert_eq!(validate(&bad), Err("section table extends beyond input"));
    }

    fn first_section(data: &[u8]) -> usize {
        let coff = coff_offset(data);
        coff + COFF_HEADER_SIZE + le_u16(data, coff + 16).unwrap() as usize
    }

    #[test]
    fn rejects_raw_section_range_past_file_on_pe32_and_pe64() {
        for fixture in [PE32, PE64] {
            let mut bad = fixture.to_vec();
            let section = first_section(&bad);
            let eof = bad.len() as u32;
            bad[section + 20..section + 24].copy_from_slice(&eof.to_le_bytes());
            bad[section + 16..section + 20].copy_from_slice(&1_u32.to_le_bytes());
            assert_eq!(validate(&bad), Err("section raw data extends beyond input"));

            bad[section + 20..section + 24].copy_from_slice(&u32::MAX.to_le_bytes());
            bad[section + 16..section + 20].copy_from_slice(&u32::MAX.to_le_bytes());
            assert_eq!(validate(&bad), Err("section raw data extends beyond input"));
        }
    }

    #[test]
    fn accepts_raw_section_ending_at_file_boundary() {
        let mut data = PE32.to_vec();
        let section = first_section(&data);
        let last_byte = (data.len() - 1) as u32;
        data[section + 20..section + 24].copy_from_slice(&last_byte.to_le_bytes());
        data[section + 16..section + 20].copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(validate(&data), Ok(()));
    }

    #[test]
    fn allows_zero_raw_size_for_virtual_only_section() {
        let mut data = PE64.to_vec();
        let section = first_section(&data);
        data[section + 20..section + 24].copy_from_slice(&u32::MAX.to_le_bytes());
        data[section + 16..section + 20].copy_from_slice(&0_u32.to_le_bytes());
        assert_eq!(validate(&data), Ok(()));
    }
}
