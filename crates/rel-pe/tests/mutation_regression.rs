//! Deterministic malformed-input regression tests. NOT coverage-guided fuzzing.
use rel_pe::{inspect, PeError};
use std::panic::{catch_unwind, AssertUnwindSafe};

const PE32: &[u8] = include_bytes!("../../../fixtures/pe32-basic.exe");
const PE64: &[u8] = include_bytes!("../../../fixtures/pe64-basic.exe");

fn next_random(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn assert_no_panic(input: &[u8], scenario: &str) {
    let result = catch_unwind(AssertUnwindSafe(|| inspect(input)));
    assert!(result.is_ok(), "PE parser panicked: {scenario}");
    assert!(
        !matches!(result, Ok(Err(PeError::DependencyPanic))),
        "PE dependency panic was caught and returned: {scenario}"
    );
}

fn exercise_mutations(fixture: &[u8], seed: u64) {
    // Exercise every truncation boundary at a fixed, reproducible interval.
    for end in (0..fixture.len()).step_by(17) {
        assert_no_panic(&fixture[..end], "truncated PE");
    }
    assert_no_panic(fixture, "intact PE");

    let mut rng = seed;
    for iteration in 0..512usize {
        let mut bytes = fixture.to_vec();
        let changes = 1 + (next_random(&mut rng) % 12) as usize;
        for _ in 0..changes {
            let location = match next_random(&mut rng) % 4 {
                0 => (next_random(&mut rng) as usize) % bytes.len(),
                1 => (next_random(&mut rng) as usize) % 0x200,
                2 => 0x3c + (next_random(&mut rng) as usize) % 0x80,
                _ => 0x400 + (next_random(&mut rng) as usize) % 0x200,
            };
            bytes[location] ^= ((next_random(&mut rng) >> 24) as u8) | 1;
        }
        if iteration % 7 == 0 {
            let new_length = (next_random(&mut rng) as usize) % bytes.len();
            bytes.truncate(new_length);
        }
        assert_no_panic(&bytes, "mutated PE");
    }
}

#[test]
fn pe32_parser_survives_deterministic_mutations() {
    exercise_mutations(PE32, 0x7265_6c31_5f70_6532);
}

#[test]
fn pe64_parser_survives_deterministic_mutations() {
    exercise_mutations(PE64, 0x7265_6c31_5f70_6536);
}
/// Deterministic directed fuzzing of all three declared directory families.
/// Each mutation changes exactly one header field in a verified golden seed.
/// Zero-size, exact limit, just-over-limit and high RVA values are deliberate;
/// acceptance of any particular mutated PE is NOT a required invariant.
fn exercise_directory_boundaries(fixture: &[u8], family: &str) {
    let nt = u32::from_le_bytes(fixture[0x3c..0x40].try_into().unwrap()) as usize;
    let optional = nt + 24;
    let magic = u16::from_le_bytes(fixture[optional..optional + 2].try_into().unwrap());
    let directories = match magic {
        0x10b => 96,
        0x20b => 112,
        other => panic!("unexpected golden PE optional header: {other:#x}"),
    };
    let count = u32::from_le_bytes(
        fixture[optional + directories - 4..optional + directories]
            .try_into()
            .unwrap(),
    );
    assert!(
        count >= 10,
        "{family}: golden fixture must declare TLS slot"
    );

    for (index, name) in [(0, "export"), (1, "import"), (9, "TLS")] {
        for (field_offset, field) in [(0, "RVA"), (4, "size")] {
            for value in [0_u32, 1, 39, 40, 0x2100, 0x100000, 0x100001, u32::MAX] {
                let mut bytes = fixture.to_vec();
                let at = optional + directories + index * 8 + field_offset;
                bytes[at..at + 4].copy_from_slice(&value.to_le_bytes());
                let scenario = format!("{family} {name} {field}={value:#x}");
                assert_no_panic(&bytes, &scenario);
            }
        }
    }
}

#[test]
fn pe32_and_pe64_directories_survive_targeted_boundary_mutations() {
    // 2 known-source PEs × 3 directories × 2 fields × 8 boundary values
    // = 96 controlled single-field mutations, without PE execution.
    exercise_directory_boundaries(PE32, "PE32");
    exercise_directory_boundaries(PE64, "PE32+");
}

// Targeted internal pointer mutations on known-source golden PE layouts.
// All changes exist only in memory; no sample is executed or loaded.
fn exercise_internal_table_rvas(fixture: &[u8], family: &str) {
    let read = |at: usize| u32::from_le_bytes(fixture[at..at + 4].try_into().unwrap());
    let nt = read(0x3c) as usize;
    let optional = nt + 24;
    let magic = u16::from_le_bytes(fixture[optional..optional + 2].try_into().unwrap());
    let directory_start = match magic {
        0x10b => 96,
        0x20b => 112,
        other => panic!("unexpected golden PE magic: {other:#x}"),
    };
    assert_eq!(
        read(optional + directory_start),
        0x2100,
        "{family}: export RVA drift"
    );
    assert_eq!(
        read(optional + directory_start + 8),
        0x2000,
        "{family}: import RVA drift"
    );
    assert_eq!(
        read(0x500 + 20),
        1,
        "{family}: expected one export function"
    );
    assert_eq!(read(0x500 + 24), 1, "{family}: expected one export name");
    assert_eq!(
        read(0x400 + 12),
        0x20a0,
        "{family}: import DLL name RVA drift"
    );

    // Three export table pointers and three import descriptor pointers.
    for (directory, base, fields) in [
        ("export", 0x500_usize, [28_usize, 32, 36]),
        ("import", 0x400_usize, [0_usize, 12, 16]),
    ] {
        for field in fields {
            for value in [
                0_u32,
                1,
                0x1fff,
                0x2000,
                0x23ff,
                0x2400,
                0xffff_fffc,
                u32::MAX,
            ] {
                let mut bytes = fixture.to_vec();
                bytes[base + field..base + field + 4].copy_from_slice(&value.to_le_bytes());
                let scenario = format!("{family} {directory} +{field} RVA={value:#x}");
                assert_no_panic(&bytes, &scenario);
            }
        }
    }

    // A required import descriptor name RVA is unmappable: no clean result.
    let mut invalid_dll_name = fixture.to_vec();
    invalid_dll_name[0x400 + 12..0x400 + 16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(
        matches!(inspect(&invalid_dll_name), Err(PeError::Parse(_))),
        "{family}: unmappable import DLL name was silently accepted"
    );
}

#[test]
fn pe32_and_pe64_internal_directory_table_pointers_fail_safely() {
    // 2 PE fixtures × 6 fields × 8 values = 96 bounded mutations.
    exercise_internal_table_rvas(PE32, "PE32");
    exercise_internal_table_rvas(PE64, "PE32+");
}
