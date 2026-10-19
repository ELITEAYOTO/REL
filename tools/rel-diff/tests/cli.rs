//! Black-box CLI regressions for the experimental EX-02 boundary.
use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn manifest(imports: &str, warnings: &str) -> String {
    format!(
        r#"{{"schema_version":"1.0.0","binary_sha256":"{}","size_bytes":512,"format":"PE","arch":"x86","sections":[],"imports":[{}],"exports":[],"warnings":[{}]}}"#,
        "a".repeat(64),
        imports,
        warnings
    )
}

#[test]
fn cli_compares_two_reports_and_rejects_incomplete_inputs() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rel-diff-test-{}-{nonce}", std::process::id()));
    fs::create_dir(&dir).expect("create temp dir");
    let left = dir.join("left.json");
    let right = dir.join("right.json");
    fs::write(&left, manifest(r#""kernel32.dll!ReadFile""#, "")).expect("left");
    fs::write(&right, manifest(r#""kernel32.dll!WriteFile""#, "")).expect("right");

    let output = Command::new(env!("CARGO_BIN_EXE_rel-diff"))
        .arg(&left)
        .arg(&right)
        .output()
        .expect("run CLI");
    assert!(output.status.success(), "{:?}", output.stderr);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("report JSON");
    assert_eq!(report["schema_version"], "0.1.0-experimental");
    assert_eq!(report["imports"]["added"][0], "kernel32.dll!WriteFile");
    assert_eq!(report["imports"]["removed"][0], "kernel32.dll!ReadFile");

    fs::write(&right, manifest("", r#""extraction incomplete""#)).expect("invalid report");
    let rejected = Command::new(env!("CARGO_BIN_EXE_rel-diff"))
        .arg(&left)
        .arg(&right)
        .output()
        .expect("run CLI");
    assert!(!rejected.status.success());
    assert!(rejected.stdout.is_empty(), "invalid input must not publish report");
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("extraction warnings"));
    fs::remove_dir_all(dir).expect("cleanup");
}
