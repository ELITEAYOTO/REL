#![cfg(unix)]
//! Unix-only regression: special files must not stall before descriptor validation.
use std::fs;
use std::os::unix::fs::symlink;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[test]
fn rejects_fifo_and_leaf_symlink_without_blocking_or_stdout() {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("rel-diff-fifo-{}-{stamp}", std::process::id()));
    fs::create_dir(&dir).expect("create temp directory");
    let source = dir.join("valid.json");
    let fifo = dir.join("blocked.fifo");
    let link = dir.join("alias.json");
    let data = format!(
        r#"{{"schema_version":"1.0.0","binary_sha256":"{}","size_bytes":1,"format":"PE","arch":null,"sections":[],"imports":[],"exports":[],"warnings":[]}}"#,
        "a".repeat(64)
    );
    fs::write(&source, data).expect("write manifest");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("mkfifo utility")
            .success()
    );
    symlink(&source, &link).expect("create leaf symlink");

    for invalid in [&fifo, &link] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_rel-diff"))
            .arg(&source)
            .arg(invalid)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("run rel-diff");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(status) = child.try_wait().expect("poll child") {
                let output = child.wait_with_output().expect("collect output");
                assert!(!status.success(), "non-regular input was accepted");
                assert!(output.stdout.is_empty(), "failure emitted a JSON report");
                assert!(!output.stderr.is_empty(), "failure lacked diagnostic");
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("rel-diff blocked while opening non-regular input");
            }
            thread::sleep(Duration::from_millis(20));
        }
    }
    fs::remove_dir_all(dir).expect("cleanup");
}
