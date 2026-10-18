//! Publish a complete JSON report without exposing partial destination files.
//! Requires same-directory hard links; this is not a path-race sandbox or
//! a power-loss durability guarantee.
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);
const TEMP_ATTEMPTS: usize = 32;

struct TemporaryReport {
    path: PathBuf,
}

impl Drop for TemporaryReport {
    fn drop(&mut self) {
        // Best effort on all error paths; Windows needs the file closed first.
        let _ = fs::remove_file(&self.path);
    }
}

fn create_temporary_report(target: &Path) -> io::Result<(TemporaryReport, File)> {
    if target.file_name().is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "output path must name a file",
        ));
    }

    let parent = target
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));

    for _ in 0..TEMP_ATTEMPTS {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let path = parent.join(format!(
            ".rel-inspect-{}-{nanos}-{id}.tmp",
            std::process::id()
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        match options.open(&path) {
            Ok(file) => return Ok((TemporaryReport { path }, file)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }

    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "unable to create a unique temporary report",
    ))
}

/// Publish bytes only after a complete, synced same-directory temporary write.
///
/// Hard-linking refuses an existing destination, including a symlink, unlike a
/// rename which may overwrite on Unix. Unsupported filesystems fail closed.
/// This is not atomic directory-path resolution or crash-durable metadata.
pub(crate) fn publish_new_report(target: &Path, serialized: &[u8]) -> io::Result<()> {
    let (temporary, mut file) = create_temporary_report(target)?;
    file.write_all(serialized)?;
    file.sync_all()?;
    drop(file);

    fs::hard_link(&temporary.path, target)?;
    // The destination now contains the complete report. A cleanup error can
    // leave a second name for it and is deliberately returned to the caller.
    fs::remove_file(&temporary.path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_directory(label: &str) -> PathBuf {
        let id = NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "rel-report-{label}-{}-{nanos}-{id}",
            std::process::id()
        ));
        fs::create_dir(&path).unwrap();
        path
    }

    fn check_no_temporary_reports(directory: &Path) {
        for entry in fs::read_dir(directory).unwrap() {
            let name = entry.unwrap().file_name();
            assert!(
                !name.to_string_lossy().starts_with(".rel-inspect-"),
                "temporary report leaked: {name:?}"
            );
        }
    }

    #[test]
    fn publishes_identical_bytes_and_cleans_temporary_name() {
        let directory = test_directory("publish");
        let target = directory.join("report.json");
        let payload = br#"{"schema_version":"1.0.0"}"#;
        publish_new_report(&target, payload).unwrap();
        assert_eq!(fs::read(&target).unwrap(), payload);
        check_no_temporary_reports(&directory);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn existing_output_is_preserved_and_temporary_name_removed() {
        let directory = test_directory("existing");
        let target = directory.join("report.json");
        fs::write(&target, b"existing content").unwrap();
        let failure = publish_new_report(&target, b"replacement").unwrap_err();
        assert_eq!(failure.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&target).unwrap(), b"existing content");
        check_no_temporary_reports(&directory);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn target_directory_does_not_leave_temporary_files() {
        let directory = test_directory("directory");
        let target = directory.join("occupied");
        fs::create_dir(&target).unwrap();
        assert!(publish_new_report(&target, b"json").is_err());
        check_no_temporary_reports(&directory);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn empty_output_path_fails_without_creating_files() {
        let error = publish_new_report(Path::new(""), b"json").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_destination_is_not_followed_or_replaced() {
        use std::os::unix::fs::symlink;
        let directory = test_directory("symlink");
        let original = directory.join("original.bin");
        let destination = directory.join("result.json");
        fs::write(&original, b"MZ protected").unwrap();
        symlink(&original, &destination).unwrap();

        assert!(publish_new_report(&destination, b"do not overwrite").is_err());
        assert_eq!(fs::read(&original).unwrap(), b"MZ protected");
        check_no_temporary_reports(&directory);
        fs::remove_dir_all(directory).unwrap();
    }
}
