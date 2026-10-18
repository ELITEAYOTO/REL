//! Bounded, static input acquisition. No parsing or execution belongs here.
use std::{
    fs::{self, File, Metadata},
    io::{self, Read},
    path::Path,
};

pub(crate) const MAX_SIZE: u64 = 512 * 1024 * 1024;

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Open the candidate descriptor with platform-specific safeguards.
/// On Unix, no-follow is checked by the kernel on the final path component
/// at open time, and nonblocking open avoids hanging on a swapped-in FIFO.
/// On Windows, open the final reparse point itself and reject the handle.
/// Ancestor symlinks, special devices and concurrent writes remain out of scope.
fn open_candidate(path: &Path) -> io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = fs::OpenOptions::new();
        options.read(true);
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        options.open(path)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

        // CreateFileW: FILE_FLAG_OPEN_REPARSE_POINT (0x0020_0000) returns
        // a handle to the final reparse point rather than following it.
        // Check attributes on THAT HANDLE, not through a fresh path lookup.
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

        let mut options = fs::OpenOptions::new();
        let file = options
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)?;
        if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(invalid("input reparse points are unsupported"));
        }
        Ok(file)
    }
    #[cfg(not(any(unix, windows)))]
    {
        File::open(path)
    }
}

/// Open a regular file only; symbolic links are rejected by alpha policy.
/// The pre-open path check is still racy; the last component is protected
/// at open time on Unix and Windows. This is not a security sandbox.
pub(crate) fn read_binary(path: &Path) -> io::Result<Vec<u8>> {
    let preflight = fs::symlink_metadata(path)?;
    if !preflight.file_type().is_file() {
        return Err(invalid(
            "input must be a regular file; symlinks are unsupported",
        ));
    }

    let mut file = open_candidate(path)?;
    let before = file.metadata()?;
    read_open_file(&mut file, &before, MAX_SIZE)
}

/// Enforce the *actual* bytes read, not only an earlier path-based stat.
/// The descriptor is opened once. Metadata catches detectable modifications,
/// but concurrent same-size writes can still produce an inconsistent snapshot.
fn read_open_file(file: &mut File, before: &Metadata, limit: u64) -> io::Result<Vec<u8>> {
    if !before.is_file() {
        return Err(invalid("input must be a regular file"));
    }
    if before.len() > limit {
        return Err(invalid("file exceeds configured input size limit"));
    }

    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(invalid("file grew beyond configured input size limit"));
    }

    let after = file.metadata()?;
    if after.len() != before.len() || after.len() != bytes.len() as u64 {
        return Err(invalid("input file changed size during analysis"));
    }

    if let (Ok(start), Ok(end)) = (before.modified(), after.modified()) {
        if start != end {
            return Err(invalid(
                "input file modification time changed during analysis",
            ));
        }
    }

    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Seek, SeekFrom, Write},
        time::{SystemTime, UNIX_EPOCH},
    };

    fn test_path(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("rel-input-{label}-{}-{nanos}", std::process::id()))
    }

    #[test]
    fn accepts_a_regular_file() {
        let path = test_path("regular");
        fs::write(&path, b"MZ test").unwrap();
        let result = read_binary(&path);
        fs::remove_file(&path).unwrap();
        assert_eq!(result.unwrap(), b"MZ test");
    }

    #[test]
    fn rejects_directory() {
        let path = test_path("directory");
        fs::create_dir(&path).unwrap();
        let result = read_binary(&path);
        fs::remove_dir(&path).unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn rejects_file_larger_than_limit_without_reading_it() {
        let path = test_path("oversize");
        let mut file = File::create(&path).unwrap();
        file.write_all(b"0123456789").unwrap();
        file.rewind().unwrap();
        let before = file.metadata().unwrap();
        let result = read_open_file(&mut file, &before, 8);
        drop(file);
        fs::remove_file(&path).unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn rejects_growth_after_the_size_snapshot() {
        let path = test_path("growth");
        fs::write(&path, b"abcd").unwrap();
        let mut reader = File::open(&path).unwrap();
        let before = reader.metadata().unwrap();

        let mut writer = fs::OpenOptions::new().append(true).open(&path).unwrap();
        writer.write_all(b"ef").unwrap();
        writer.flush().unwrap();
        reader.seek(SeekFrom::Start(0)).unwrap();

        let result = read_open_file(&mut reader, &before, 8);
        drop(reader);
        drop(writer);
        fs::remove_file(&path).unwrap();
        assert!(result.is_err());
    }

    #[test]
    fn rejects_truncation_after_the_size_snapshot() {
        let path = test_path("truncated");
        fs::write(&path, b"12345678").unwrap();
        let mut reader = File::open(&path).unwrap();
        let before = reader.metadata().unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(2)
            .unwrap();

        let result = read_open_file(&mut reader, &before, 8);
        drop(reader);
        fs::remove_file(&path).unwrap();
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlinks() {
        use std::os::unix::fs::symlink;
        let target = test_path("target");
        let link = test_path("link");
        fs::write(&target, b"MZ").unwrap();
        symlink(&target, &link).unwrap();
        let result = read_binary(&link);
        fs::remove_file(&link).unwrap();
        fs::remove_file(&target).unwrap();
        assert!(result.is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_final_component_replaced_with_symlink_before_open() {
        use std::os::unix::fs::symlink;
        let candidate = test_path("race-candidate");
        let replacement = test_path("race-target");
        fs::write(&candidate, b"MZ original").unwrap();
        fs::write(&replacement, b"MZ replacement").unwrap();

        // Deterministic model of a swap between symlink_metadata and open.
        assert!(fs::symlink_metadata(&candidate)
            .unwrap()
            .file_type()
            .is_file());
        fs::remove_file(&candidate).unwrap();
        symlink(&replacement, &candidate).unwrap();
        assert!(open_candidate(&candidate).is_err());

        fs::remove_file(&candidate).unwrap();
        fs::remove_file(&replacement).unwrap();
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn opens_fifo_nonblocking_but_refuses_it_as_input() {
        use std::process::Command;
        let fifo = test_path("fifo");
        let status = Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .expect("Linux test requires mkfifo");
        assert!(status.success());

        // No writer is attached: read-only open would block without O_NONBLOCK.
        let descriptor = open_candidate(&fifo).expect("nonblocking FIFO open");
        assert!(!descriptor.metadata().unwrap().is_file());
        drop(descriptor);
        assert!(read_binary(&fifo).is_err());
        fs::remove_file(&fifo).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn opens_regular_file_through_windows_candidate_policy() {
        let path = test_path("windows-regular");
        fs::write(&path, b"MZ regular").unwrap();
        let mut file = open_candidate(&path).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        assert_eq!(bytes, b"MZ regular");
        drop(file);
        fs::remove_file(&path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn refuses_final_component_symlink_after_preflight_swap() {
        use std::os::windows::fs::symlink_file;

        let candidate = test_path("windows-swap-candidate");
        let destination = test_path("windows-swap-target");
        fs::write(&candidate, b"MZ original").unwrap();
        fs::write(&destination, b"MZ target").unwrap();

        // Model the TOCTOU window deterministically, without a racing thread.
        assert!(fs::symlink_metadata(&candidate)
            .unwrap()
            .file_type()
            .is_file());
        fs::remove_file(&candidate).unwrap();

        match symlink_file(&destination, &candidate) {
            Ok(()) => {
                assert!(
                    open_candidate(&candidate).is_err(),
                    "a final-component reparse point must not be followed"
                );
                assert_eq!(fs::read(&destination).unwrap(), b"MZ target");
                fs::remove_file(&candidate).unwrap();
            }
            Err(error) => {
                // Developer Mode/SeCreateSymbolicLinkPrivilege may be unavailable.
                // Explicitly report the skipped setup, never claim this exercised
                // symlink rejection on an unprivileged runner.
                println!("SKIP Windows symlink swap scenario: {error}");
            }
        }
        fs::remove_file(&destination).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn refuses_replaced_directory_as_candidate() {
        let candidate = test_path("windows-swapped-directory");
        fs::write(&candidate, b"MZ original").unwrap();
        assert!(fs::symlink_metadata(&candidate).unwrap().is_file());
        fs::remove_file(&candidate).unwrap();
        fs::create_dir(&candidate).unwrap();

        if let Ok(file) = open_candidate(&candidate) {
            assert!(!file.metadata().unwrap().is_file());
            drop(file);
        }
        assert!(read_binary(&candidate).is_err());
        fs::remove_dir(&candidate).unwrap();
    }
}
