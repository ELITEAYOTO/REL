//! Descriptor-relative Unix path traversal for controlled PE input files.
//! Every ancestor is opened without following symlinks; this is not a sandbox.
use std::{
    ffi::{CString, OsStr},
    fs::File,
    io,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
    path::{Component, Path},
};

fn child(parent: &File, name: &OsStr, directory: bool) -> io::Result<File> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in input path"))?;
    let flags = libc::O_RDONLY
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW
        | libc::O_NONBLOCK
        | if directory { libc::O_DIRECTORY } else { 0 };

    // SAFETY: the parent File keeps its valid descriptor alive; the CString
    // provides a terminated path for the duration of openat. O_CREAT is absent,
    // so no variadic mode argument is needed. A successful openat returns a
    // newly owned descriptor, transferred exactly once into File.
    let descriptor = unsafe { libc::openat(parent.as_raw_fd(), name.as_ptr(), flags) };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat returned a fresh owned descriptor on success.
    Ok(unsafe { File::from_raw_fd(descriptor) })
}

/// Resolve each nontrivial input component relative to an already-open
/// directory descriptor, rejecting symbolic links in any ancestor or leaf.
/// No trusted root is imposed: '..' is deliberately permitted.
pub(super) fn open(path: &Path) -> io::Result<File> {
    let mut parent = File::open(if path.is_absolute() { "/" } else { "." })?;
    let mut parts = path
        .components()
        .filter(|part| !matches!(part, Component::RootDir | Component::CurDir))
        .peekable();
    let mut visited = false;
    while let Some(part) = parts.next() {
        let name = match part {
            Component::Normal(name) => name,
            Component::ParentDir => OsStr::new(".."),
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "unsupported input path prefix",
                ))
            }
        };
        let directory = parts.peek().is_some();
        parent = child(&parent, name, directory)?;
        visited = true;
    }
    if !visited {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "input must name a regular file",
        ));
    }
    Ok(parent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::symlink,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn test_root(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "rel-unix-components-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        root
    }

    #[test]
    fn accepts_regular_file_in_nested_directories() {
        let root = test_root("nested");
        let directory = root.join("one").join("two");
        fs::create_dir_all(&directory).unwrap();
        let input = directory.join("sample.exe");
        fs::write(&input, b"MZ nested").unwrap();
        assert_eq!(super::super::read_binary(&input).unwrap(), b"MZ nested");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_an_ancestor_directory_symlink() {
        let root = test_root("ancestor");
        fs::create_dir(root.join("real")).unwrap();
        fs::write(root.join("real").join("sample.exe"), b"MZ real").unwrap();
        symlink("real", root.join("linked")).unwrap();
        let candidate = root.join("linked").join("sample.exe");
        assert!(fs::symlink_metadata(&candidate).unwrap().is_file());
        assert!(open(&candidate).is_err());
        assert!(super::super::read_binary(&candidate).is_err());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_ancestor_symlink_swapped_after_preflight() {
        let root = test_root("parent-swap");
        let original = root.join("before");
        fs::create_dir(&original).unwrap();
        let candidate = original.join("sample.exe");
        fs::write(&candidate, b"MZ original").unwrap();
        assert!(fs::symlink_metadata(&candidate).unwrap().is_file());

        fs::rename(&original, root.join("moved")).unwrap();
        symlink("moved", &original).unwrap();
        assert!(open(&candidate).is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
