//! Preserved finding F001: malformed TLS directory triggered goblin 0.9.3 panic.
use rel_pe::{inspect, PeError};

const MALFORMED_TLS: &[u8] =
    include_bytes!("../../../fixtures/regressions/goblin-0.9.3-tls-oob.bin");

#[test]
fn malformed_tls_directory_is_rejected_without_unwinding() {
    let attempt = std::panic::catch_unwind(|| inspect(MALFORMED_TLS));
    assert!(attempt.is_ok(), "REL exposed the dependency panic");
    let outcome = attempt.unwrap();
    assert!(outcome.is_err(), "invalid TLS directory was accepted");
    assert!(
        !matches!(outcome, Err(PeError::DependencyPanic)),
        "the historical TLS seed still panics inside the parser"
    );
}

#[test]
fn original_f001_truncations_and_single_byte_corruptions_do_not_unwind() {
    // Keep the historical bytes untouched; mutations use local copies only.
    // Exhaustively test each truncated length and one XOR mutation per byte.
    // Mutation may change validity, so the only invariant is no propagated panic.
    assert_eq!(MALFORMED_TLS.len(), 1104, "F001 fixture length changed");
    for length in 0..MALFORMED_TLS.len() {
        assert!(
            std::panic::catch_unwind(|| inspect(&MALFORMED_TLS[..length])).is_ok(),
            "F001 truncated to {length} bytes caused a panic"
        );
    }

    let mut changed = MALFORMED_TLS.to_vec();
    for offset in 0..MALFORMED_TLS.len() {
        changed[offset] ^= 0xff;
        assert!(
            std::panic::catch_unwind(|| inspect(&changed)).is_ok(),
            "F001 one-byte corruption at offset {offset} caused a panic"
        );
        changed[offset] ^= 0xff;
    }
}

#[test]
fn minimized_legacy_tls_panic_input_is_rejected_without_unwinding() {
    // A budgeted ddmin reduction of the unchanged, preserved original F001.
    // The legacy goblin 0.9.3 parser crashes at tls.rs:228 on these bytes.
    // Current REL must not accept this malformed source or propagate a panic.
    const MINIMIZED_TLS: &[u8] =
        include_bytes!("../../../fixtures/regressions/goblin-0.9.3-tls-oob-minimized.bin");
    assert_eq!(MINIMIZED_TLS.len(), 1048);
    let attempt = std::panic::catch_unwind(|| inspect(MINIMIZED_TLS));
    assert!(attempt.is_ok(), "REL exposed the legacy TLS panic");
    let outcome = attempt.unwrap();
    assert!(
        outcome.is_err(),
        "malformed minimized F001 input was accepted"
    );
    assert!(
        !matches!(outcome, Err(PeError::DependencyPanic)),
        "the minimized historical TLS seed still panics inside the parser"
    );
}
