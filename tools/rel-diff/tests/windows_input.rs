#![cfg(windows)]
//! Windows-only black-box regressions for manifest handle-open policy.
use std::fs;
use std::io::ErrorKind;
use std::os::windows::fs::symlink_file;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

// Windows clocks can return the same timestamp to parallel tests. Directory
// creation is atomic: retry a distinct suffix on AlreadyExists instead of
// failing or deleting a directory belonging to another test.
fn create_test_directory(parent: &Path, stem: &str) -> PathBuf {
    for attempt in 0..256 {
        let dir = parent.join(format!("{stem}-{attempt}"));
        match fs::create_dir(&dir) {
            Ok(()) => return dir,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => panic!("create test directory {dir:?}: {error}"),
        }
    }
    panic!("cannot allocate unique test directory for {stem}");
}

fn fixture() -> (PathBuf, PathBuf) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let stem = format!("rel-diff-win-{}-{nonce}", std::process::id());
    let dir = create_test_directory(&std::env::temp_dir(), &stem);
    let source = dir.join("manifest.json");
    let content = format!(
        r#"{{"schema_version":"1.0.0","binary_sha256":"{}","size_bytes":5,"format":"PE","arch":null,"sections":[],"imports":[],"exports":[],"warnings":[]}}"#,
        "a".repeat(64)
    );
    fs::write(&source, content).expect("write controlled manifest");
    (dir, source)
}

#[test]
fn colliding_test_directory_names_are_allocated_without_overwrite() {
    let sandbox = std::env::temp_dir().join(format!(
        "rel-diff-collision-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    ));
    // This collision is intentional and reproducible, unlike the wall-clock
    // collision that caused the intermittent Windows CI failure.
    fs::create_dir(&sandbox).expect("create collision test parent");
    let first = create_test_directory(&sandbox, "fixed-name");
    let marker = first.join("preserve.txt");
    fs::write(&marker, b"original").expect("write first fixture marker");
    let second = create_test_directory(&sandbox, "fixed-name");
    assert_ne!(first, second, "collision must allocate a different folder");
    assert_eq!(
        fs::read(&marker).expect("first fixture marker intact"),
        b"original"
    );
    assert!(second.is_dir());
    fs::remove_dir_all(&sandbox).expect("cleanup collision fixtures");
}

#[test]
fn windows_cli_rejects_leaf_symlinks_without_stdout() {
    let (dir, source) = fixture();
    let link = dir.join("manifest-link.json");
    match symlink_file(&source, &link) {
        Ok(()) => {
            let result = Command::new(env!("CARGO_BIN_EXE_rel-diff"))
                .arg(&source)
                .arg(&link)
                .output()
                .expect("run rel-diff");
            assert!(!result.status.success(), "symlink was followed");
            assert!(
                result.stdout.is_empty(),
                "symlink rejection published a report"
            );
            assert!(!result.stderr.is_empty(), "missing rejection diagnostic");
            fs::remove_file(&link).expect("remove symlink");
        }
        Err(error) => {
            // The hosted CI exercises symlink creation; some local Windows
            // machines require Developer Mode or explicit privileges.
            if std::env::var_os("GITHUB_ACTIONS").is_some() {
                panic!("Windows CI must create this regression symlink: {error}");
            }
            eprintln!("SKIP: Windows symlink creation unavailable: {error}");
        }
    }
    fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn windows_cli_rejects_conflicting_writer_and_accepts_after_close() {
    let (dir, source) = fixture();
    let writer = fs::OpenOptions::new()
        .write(true)
        .open(&source)
        .expect("open an existing writer");
    let blocked = Command::new(env!("CARGO_BIN_EXE_rel-diff"))
        .arg(&source)
        .arg(&source)
        .output()
        .expect("run rel-diff with competing writer");
    assert!(!blocked.status.success(), "conflicting writer was accepted");
    assert!(
        blocked.stdout.is_empty(),
        "write-sharing failure emitted JSON"
    );
    drop(writer);

    let accepted = Command::new(env!("CARGO_BIN_EXE_rel-diff"))
        .arg(&source)
        .arg(&source)
        .output()
        .expect("run rel-diff after writer closes");
    assert!(accepted.status.success(), "{:?}", accepted.stderr);
    let report: serde_json::Value =
        serde_json::from_slice(&accepted.stdout).expect("valid report JSON");
    assert_eq!(report["schema_version"], "0.1.0-experimental");
    fs::remove_dir_all(dir).expect("cleanup");
}
