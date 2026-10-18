//! Preserved finding F001: malformed TLS directory triggered goblin 0.9.3 panic.
use rel_pe::inspect;

const MALFORMED_TLS: &[u8] =
    include_bytes!("../../../fixtures/regressions/goblin-0.9.3-tls-oob.bin");

#[test]
fn malformed_tls_directory_is_rejected_without_unwinding() {
    let attempt = std::panic::catch_unwind(|| inspect(MALFORMED_TLS));
    assert!(attempt.is_ok(), "REL exposed the dependency panic");
    assert!(
        attempt.unwrap().is_err(),
        "invalid TLS directory was accepted"
    );
}
