//! Bounded declarations for PE data directories; no allocations or imports executed.
//! The checks are intentionally narrow and do not validate complete PE semantics.
use super::{le_u16, le_u32, region, SECTION_HEADER_SIZE};

/// Provisional alpha policy, not limits imposed by the PE format.
pub(super) const MAX_DIRECTORY_BYTES: u32 = 1024 * 1024;
pub(super) const MAX_EXPORT_SYMBOLS: u32 = 65_536;

const IMPORT_DESCRIPTOR_BYTES: usize = 20;
const EXPORT_HEADER_BYTES: usize = 40;
const PE32_DIRECTORY_START: usize = 96;
const PE64_DIRECTORY_START: usize = 112;
const DATA_DIRECTORY_BYTES: usize = 8;

fn raw_offset_for_rva(
    data: &[u8],
    sections_start: usize,
    section_count: usize,
    rva: u32,
    required: usize,
) -> Result<usize, &'static str> {
    let target = u64::from(rva);
    for index in 0..section_count {
        let header = sections_start
            .checked_add(index * SECTION_HEADER_SIZE)
            .ok_or("section table arithmetic overflow")?;
        let va = u64::from(le_u32(data, header + 12).ok_or("truncated section header")?);
        let raw_size = u64::from(le_u32(data, header + 16).ok_or("truncated section header")?);
        let raw_start = u64::from(le_u32(data, header + 20).ok_or("truncated section header")?);
        if target < va || target - va >= raw_size {
            continue;
        }
        let delta = target - va;
        if delta + required as u64 > raw_size {
            return Err("export directory header exceeds section raw data");
        }
        let raw = raw_start
            .checked_add(delta)
            .ok_or("export directory file offset overflow")?;
        let raw = usize::try_from(raw).map_err(|_| "export directory offset too large")?;
        region(data, raw, required).ok_or("export directory header exceeds file")?;
        return Ok(raw);
    }
    Err("export directory cannot be mapped to raw section data")
}

/// Inspect only import descriptor records within the advertised byte span.
/// Size is a declared PE field, not a trustworthy guarantee of completeness.
/// A missing RVA mapping is still delegated to the backend for compatibility.
fn validate_declared_import_descriptors(
    data: &[u8],
    sections_start: usize,
    section_count: usize,
    imports_rva: u32,
    imports_size: u32,
) -> Result<(), &'static str> {
    // imports_size is already limited to MAX_DIRECTORY_BYTES. Preserve the
    // previous first-record check even if the declared size is under 20 bytes.
    let records = (imports_size as usize / IMPORT_DESCRIPTOR_BYTES).max(1);
    for index in 0..records {
        let offset = (index * IMPORT_DESCRIPTOR_BYTES) as u32;
        let record_rva = imports_rva
            .checked_add(offset)
            .ok_or("import descriptor RVA overflow")?;
        let Ok(raw) = raw_offset_for_rva(
            data,
            sections_start,
            section_count,
            record_rva,
            IMPORT_DESCRIPTOR_BYTES,
        ) else {
            break;
        };
        let descriptor =
            region(data, raw, IMPORT_DESCRIPTOR_BYTES).ok_or("truncated import descriptor")?;
        if descriptor.iter().all(|byte| *byte == 0) {
            break;
        }
        let name = le_u32(data, raw + 12).ok_or("truncated import Name RVA")?;
        let thunk = le_u32(data, raw + 16).ok_or("truncated import FirstThunk RVA")?;
        if name == 0 || thunk == 0 {
            return Err("non-null import descriptor missing Name or FirstThunk");
        }
    }
    Ok(())
}

/// Verify declared directories and export counts before the backend allocates.
/// The first two data directory entries, export header and advertised import
/// descriptors are inspected; this does not validate import thunks or every PE layout.
pub(super) fn validate(
    data: &[u8],
    optional_start: usize,
    optional_size: usize,
    sections_start: usize,
    section_count: usize,
) -> Result<(), &'static str> {
    let directory_start = match le_u16(data, optional_start) {
        Some(0x10b) => PE32_DIRECTORY_START,
        Some(0x20b) => PE64_DIRECTORY_START,
        _ => return Err("invalid optional header magic for data directories"),
    };
    // DataDirectory[] starts after NumberOfRvaAndSizes in PE32/PE32+.
    if optional_size < directory_start {
        // Minimal optional headers are handled by goblin; nothing to budget here.
        return Ok(());
    }
    let count_pos = optional_start
        .checked_add(directory_start - 4)
        .ok_or("data directory count offset overflow")?;
    let count = le_u32(data, count_pos).ok_or("truncated data directory count")?;
    if count == 0 {
        return Ok(());
    }

    let dir_start = optional_start
        .checked_add(directory_start)
        .ok_or("data directory offset overflow")?;
    let visible = (optional_size - directory_start) / DATA_DIRECTORY_BYTES;
    // All advertised 8-byte records must physically fit in the optional
    // header. Earlier policy checked only the first two entries even when
    // NumberOfRvaAndSizes claimed more, leaving inconsistent declarations.
    if (count as usize) > visible {
        return Err("declared PE data directories exceed optional header");
    }
    let export_rva = le_u32(data, dir_start).ok_or("truncated export directory")?;
    let export_size = le_u32(data, dir_start + 4).ok_or("truncated export directory")?;
    if export_size > MAX_DIRECTORY_BYTES {
        return Err("export directory declaration exceeds alpha size limit");
    }
    if count >= 2 {
        let imports_rva =
            le_u32(data, dir_start + DATA_DIRECTORY_BYTES).ok_or("truncated import directory")?;
        let imports_size = le_u32(data, dir_start + DATA_DIRECTORY_BYTES + 4)
            .ok_or("truncated import directory")?;
        if imports_size > MAX_DIRECTORY_BYTES {
            return Err("import directory declaration exceeds alpha size limit");
        }
        // A nonempty declared directory at RVA 0 cannot identify an import
        // table. Reject this inconsistent declaration before asking Goblin
        // to extract a potentially empty v1 import list.
        if imports_rva == 0 && imports_size != 0 {
            return Err("nonempty import directory requires nonzero RVA");
        }
        // Goblin may stop on a non-null descriptor missing mandatory
        // fields and silently omit later imports. Inspect each advertised,
        // raw-mappable record, stopping on the all-zero terminator.
        if imports_rva != 0 && imports_size != 0 {
            validate_declared_import_descriptors(
                data,
                sections_start,
                section_count,
                imports_rva,
                imports_size,
            )?;
        }
    }
    if export_rva == 0 && export_size == 0 {
        return Ok(());
    }
    if export_rva == 0 || export_size < EXPORT_HEADER_BYTES as u32 {
        return Err("invalid export directory RVA or size");
    }
    let raw = raw_offset_for_rva(
        data,
        sections_start,
        section_count,
        export_rva,
        EXPORT_HEADER_BYTES,
    )?;
    let functions = le_u32(data, raw + 20).ok_or("truncated export function count")?;
    let names = le_u32(data, raw + 24).ok_or("truncated export name count")?;
    if functions > MAX_EXPORT_SYMBOLS || names > MAX_EXPORT_SYMBOLS {
        return Err("export count exceeds alpha symbol limit");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PE32: &[u8] = include_bytes!("../../../../fixtures/pe32-basic.exe");
    const PE64: &[u8] = include_bytes!("../../../../fixtures/pe64-basic.exe");

    fn fixture_fields(bytes: &[u8]) -> (usize, usize) {
        let nt = le_u32(bytes, 0x3c).unwrap() as usize;
        let coff = nt + 4;
        let opt = coff + 20;
        let optional_size = le_u16(bytes, coff + 16).unwrap() as usize;
        (opt, optional_size)
    }

    fn check(data: &[u8]) -> Result<(), &'static str> {
        let (opt, size) = fixture_fields(data);
        let coff = le_u32(data, 0x3c).unwrap() as usize + 4;
        let count = le_u16(data, coff + 2).unwrap() as usize;
        validate(data, opt, size, opt + size, count)
    }

    fn modify_u32(base: &[u8], offset: usize, value: u32) -> Vec<u8> {
        let mut copy = base.to_vec();
        copy[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
        copy
    }

    fn export_header_raw(data: &[u8]) -> usize {
        let (opt, size) = fixture_fields(data);
        let directory_offset = if le_u16(data, opt) == Some(0x10b) {
            PE32_DIRECTORY_START
        } else {
            PE64_DIRECTORY_START
        };
        let rva = le_u32(data, opt + directory_offset).unwrap();
        raw_offset_for_rva(data, opt + size, 2, rva, EXPORT_HEADER_BYTES).unwrap()
    }

    #[test]
    fn golden_images_are_accepted() {
        assert_eq!(check(PE32), Ok(()));
        assert_eq!(check(PE64), Ok(()));
    }

    #[test]
    fn rejects_declared_oversized_import_directory() {
        let (opt, _) = fixture_fields(PE32);
        let bad = modify_u32(
            PE32,
            opt + PE32_DIRECTORY_START + 12,
            MAX_DIRECTORY_BYTES + 1,
        );
        assert_eq!(
            check(&bad),
            Err("import directory declaration exceeds alpha size limit")
        );
    }

    #[test]
    fn rejects_nonempty_import_directory_with_zero_rva() {
        for fixture in [PE32, PE64] {
            let (opt, _) = fixture_fields(fixture);
            let start = if le_u16(fixture, opt) == Some(0x10b) {
                PE32_DIRECTORY_START
            } else {
                PE64_DIRECTORY_START
            };
            let at = opt + start + DATA_DIRECTORY_BYTES;
            assert_ne!(le_u32(fixture, at), Some(0));
            assert_ne!(le_u32(fixture, at + 4), Some(0));
            let bad = modify_u32(fixture, at, 0);
            assert_eq!(
                check(&bad),
                Err("nonempty import directory requires nonzero RVA")
            );

            // An explicitly absent import directory remains acceptable at
            // the preflight layer; this does not decode the raw bytes.
            let absent = modify_u32(&bad, at + 4, 0);
            assert_eq!(check(&absent), Ok(()));
        }
    }

    #[test]
    fn rejects_first_non_null_import_descriptor_with_missing_required_field() {
        for fixture in [PE32, PE64] {
            for field in [12_usize, 16] {
                let mut malformed = fixture.to_vec();
                assert_ne!(le_u32(fixture, 0x400 + field), Some(0));
                malformed[0x400 + field..0x400 + field + 4].fill(0);
                assert_eq!(
                    check(&malformed),
                    Err("non-null import descriptor missing Name or FirstThunk")
                );
            }
            let mut empty = fixture.to_vec();
            empty[0x400..0x400 + IMPORT_DESCRIPTOR_BYTES].fill(0);
            assert_eq!(check(&empty), Ok(()));
        }
    }

    #[test]
    fn rejects_later_non_null_import_descriptor_missing_required_field() {
        for fixture in [PE32, PE64] {
            let second = 0x400_usize + IMPORT_DESCRIPTOR_BYTES;
            assert_eq!(
                &fixture[second..second + IMPORT_DESCRIPTOR_BYTES],
                &[0; IMPORT_DESCRIPTOR_BYTES]
            );
            let mut with_two = fixture.to_vec();
            with_two[second..second + IMPORT_DESCRIPTOR_BYTES]
                .copy_from_slice(&fixture[0x400..0x400 + IMPORT_DESCRIPTOR_BYTES]);
            assert_eq!(check(&with_two), Ok(()));
            for field in [12_usize, 16] {
                let mut malformed = with_two.clone();
                malformed[second + field..second + field + 4].fill(0);
                assert_eq!(
                    check(&malformed),
                    Err("non-null import descriptor missing Name or FirstThunk")
                );
            }
        }
    }

    #[test]
    fn rejects_declared_oversized_export_directory() {
        let (opt, _) = fixture_fields(PE64);
        let bad = modify_u32(
            PE64,
            opt + PE64_DIRECTORY_START + 4,
            MAX_DIRECTORY_BYTES + 1,
        );
        assert_eq!(
            check(&bad),
            Err("export directory declaration exceeds alpha size limit")
        );
    }

    #[test]
    fn rejects_excessive_export_functions_and_names() {
        for fixture in [PE32, PE64] {
            let raw = export_header_raw(fixture);
            for field in [20, 24] {
                let bad = modify_u32(fixture, raw + field, MAX_EXPORT_SYMBOLS + 1);
                assert_eq!(check(&bad), Err("export count exceeds alpha symbol limit"));
            }
        }
    }

    #[test]
    fn rejects_unmapped_export_directory() {
        let (opt, _) = fixture_fields(PE32);
        let bad = modify_u32(PE32, opt + PE32_DIRECTORY_START, 0xfffffff0);
        assert_eq!(
            check(&bad),
            Err("export directory cannot be mapped to raw section data")
        );
    }

    #[test]
    fn exact_budget_values_do_not_fail_due_to_threshold_alone() {
        let (opt, _) = fixture_fields(PE32);
        let size = modify_u32(PE32, opt + PE32_DIRECTORY_START + 12, MAX_DIRECTORY_BYTES);
        assert_eq!(check(&size), Ok(()));
        let count = modify_u32(PE32, export_header_raw(PE32) + 20, MAX_EXPORT_SYMBOLS);
        assert_eq!(check(&count), Ok(()));
    }

    #[test]
    fn rejects_directory_counts_larger_than_optional_header_capacity() {
        for fixture in [PE32, PE64] {
            let (opt, optional_size) = fixture_fields(fixture);
            let start = if le_u16(fixture, opt) == Some(0x10b) {
                PE32_DIRECTORY_START
            } else {
                PE64_DIRECTORY_START
            };
            let capacity = (optional_size - start) / DATA_DIRECTORY_BYTES;
            assert!(
                capacity >= 2,
                "golden fixture must have two directory slots"
            );

            let too_many = modify_u32(fixture, opt + start - 4, capacity as u32 + 1);
            assert_eq!(
                check(&too_many),
                Err("declared PE data directories exceed optional header")
            );

            let exact = modify_u32(fixture, opt + start - 4, capacity as u32);
            assert_eq!(check(&exact), Ok(()));
        }
    }

    #[test]
    fn missing_optional_directory_records_fail_cleanly() {
        let (opt, _) = fixture_fields(PE32);
        let bad = modify_u32(PE32, opt + PE32_DIRECTORY_START - 4, 4);
        let mut short = bad;
        let nt = le_u32(&short, 0x3c).unwrap() as usize;
        short[nt + 4 + 16..nt + 4 + 18].copy_from_slice(&100_u16.to_le_bytes());
        assert_eq!(
            check(&short),
            Err("declared PE data directories exceed optional header")
        );
    }
}
