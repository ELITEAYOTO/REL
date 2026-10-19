//! Strict CLI rejection checks against controlled manifest inputs.
use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

#[test]
fn cli_rejects_invalid_identity_and_schema_without_stdout() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir =
        std::env::temp_dir().join(format!("rel-diff-negative-{}-{nonce}", std::process::id()));
    fs::create_dir(&dir).expect("temporary directory");
    let left = dir.join("left.json");
    let right = dir.join("right.json");
    let base = format!(
        r#"{{"schema_version":"1.0.0","binary_sha256":"{}","size_bytes":10,"format":"PE","arch":null,"sections":[],"imports":[],"exports":[],"warnings":[]}}"#,
        "a".repeat(64)
    );
    fs::write(&left, &base).expect("write reference");
    let variants = [
        base.replace("1.0.0", "2.0.0"),
        base.replace(&"a".repeat(64), "not-a-digest"),
        base.replace(r#""format":"PE""#, r#""format":"ELF""#),
        base.replace(r#","warnings":[]"#, ""),
        base.replace(r#""size_bytes":10"#, r#""size_bytes":-2"#),
    ];
    for invalid in variants {
        fs::write(&right, invalid).expect("write invalid candidate");
        let result = Command::new(env!("CARGO_BIN_EXE_rel-diff"))
            .arg(&left)
            .arg(&right)
            .output()
            .expect("run CLI");
        assert!(!result.status.success(), "invalid input was accepted");
        assert!(result.stdout.is_empty(), "failure published stdout");
    }
    let directory_input = Command::new(env!("CARGO_BIN_EXE_rel-diff"))
        .arg(&left)
        .arg(&dir)
        .output()
        .expect("run CLI with directory");
    assert!(!directory_input.status.success());
    assert!(directory_input.stdout.is_empty());
    assert!(
        String::from_utf8_lossy(&directory_input.stderr).contains("input must be a regular file")
    );
    fs::remove_dir_all(dir).expect("cleanup");
}
