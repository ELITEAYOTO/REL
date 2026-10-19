//! OS-specific regression tests for preflight-to-leaf-open substitution.
use super::{load_after_preflight, load_controlled_file};
use std::{
    fs,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

fn test_root(label: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "rel-observe-leaf-{label}-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("temporary directory");
    root
}

#[test]
fn accepts_regular_controlled_file() {
    let root = test_root("regular");
    let input = root.join("input.exe");
    fs::write(&input, b"MZ stable controlled sample").unwrap();
    assert_eq!(
        load_controlled_file(&input).unwrap(),
        b"MZ stable controlled sample"
    );
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn unix_rejects_symlink_inserted_after_preflight() {
    use std::os::unix::fs::symlink;
    let root = test_root("unix-link");
    let path = root.join("input.exe");
    let target = root.join("target.exe");
    fs::write(&path, b"MZ original").unwrap();
    fs::write(&target, b"MZ replacement").unwrap();
    let before = fs::symlink_metadata(&path).unwrap();
    fs::remove_file(&path).unwrap();
    symlink(&target, &path).unwrap();
    assert!(load_after_preflight(&path, &before).is_err());
    fs::remove_dir_all(root).unwrap();
}

#[cfg(unix)]
#[test]
fn unix_rejects_same_size_inode_swap_after_preflight() {
    let root = test_root("unix-inode");
    let path = root.join("input.exe");
    let other = root.join("other.exe");
    fs::write(&path, b"MZ original").unwrap();
    fs::write(&other, b"MZ replaced").unwrap();
    let before = fs::symlink_metadata(&path).unwrap();
    fs::rename(&other, &path).unwrap();
    let error = load_after_preflight(&path, &before).unwrap_err();
    assert!(error.contains("identity changed"), "{error}");
    fs::remove_dir_all(root).unwrap();
}

#[cfg(windows)]
#[test]
fn windows_rejects_symlink_inserted_after_preflight() {
    use std::os::windows::fs::symlink_file;
    let root = test_root("win-link");
    let path = root.join("input.exe");
    let target = root.join("target.exe");
    fs::write(&path, b"MZ original").unwrap();
    fs::write(&target, b"MZ replacement").unwrap();
    let before = fs::symlink_metadata(&path).unwrap();
    fs::remove_file(&path).unwrap();
    match symlink_file(&target, &path) {
        Ok(()) => assert!(load_after_preflight(&path, &before).is_err()),
        Err(error) => {
            if std::env::var_os("GITHUB_ACTIONS").is_some() {
                panic!("Windows CI must create the symlink: {error}");
            }
            eprintln!("SKIP: Windows symlink privilege unavailable: {error}");
        }
    }
    fs::remove_dir_all(root).unwrap();
}

#[cfg(windows)]
#[test]
fn windows_rejects_conflicting_writer_then_accepts_after_close() {
    let root = test_root("win-share");
    let path = root.join("input.exe");
    fs::write(&path, b"MZ stable").unwrap();
    let writer = fs::OpenOptions::new().write(true).open(&path).unwrap();
    assert!(load_controlled_file(&path).is_err());
    drop(writer);
    assert_eq!(load_controlled_file(&path).unwrap(), b"MZ stable");
    fs::remove_dir_all(root).unwrap();
}
