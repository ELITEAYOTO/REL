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

/// Open a regular file only; symbolic links are rejected by alpha policy.
/// The pre-open type check is NOT race-free or a security sandbox.
pub(crate) fn read_binary(path: &Path) -> io::Result<Vec<u8>> {
    let preflight = fs::symlink_metadata(path)?;
    if !preflight.file_type().is_file() {
        return Err(invalid("input must be a regular file; symlinks are unsupported"));
    }

    let mut file = File::open(path)?;
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
            return Err(invalid("input file modification time changed during analysis"));
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
        std::env::temp_dir().join(format!(
            "rel-input-{label}-{}-{nanos}",
            std::process::id()
        ))
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
}
