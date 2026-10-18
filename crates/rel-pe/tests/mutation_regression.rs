//! Deterministic malformed-input regression tests. NOT coverage-guided fuzzing.
use rel_pe::inspect;
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
