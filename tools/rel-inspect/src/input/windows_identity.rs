//! Windows-only, handle-based 128-bit file identity check.
//! A second ordinary guarded open is verified against the original handle.
//! This does not make path resolution atomic or prevent same-inode writes.
use std::{
    ffi::c_void,
    fs::File,
    io,
    mem::{size_of, MaybeUninit},
    os::windows::io::AsRawHandle,
    path::Path,
};

const FILE_ID_INFO_CLASS: i32 = 18; // FILE_INFO_BY_HANDLE_CLASS::FileIdInfo.

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdInfo {
    volume_serial_number: u64,
    file_id: [u8; 16],
}

#[link(name = "kernel32")]
unsafe extern "system" {
    #[link_name = "GetFileInformationByHandleEx"]
    fn get_file_information_by_handle_ex(
        handle: *mut c_void,
        info_class: i32,
        output: *mut c_void,
        output_bytes: u32,
    ) -> i32;
}

fn identity(file: &File) -> io::Result<FileIdInfo> {
    let mut output = MaybeUninit::<FileIdInfo>::uninit();
    // SAFETY: File owns a live handle; FileIdInfo matches Win32 FILE_ID_INFO
    // (u64 volume serial + 16-byte FILE_ID_128) and has a fixed 24-byte size.
    // The buffer is correctly aligned and exclusively writable. It is only
    // assumed initialized if GetFileInformationByHandleEx reports success.
    let status = unsafe {
        get_file_information_by_handle_ex(
            file.as_raw_handle(),
            FILE_ID_INFO_CLASS,
            output.as_mut_ptr().cast(),
            size_of::<FileIdInfo>() as u32,
        )
    };
    if status == 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: the preceding Win32 call succeeded and wrote the entire FILE_ID_INFO.
    let id = unsafe { output.assume_init() };
    if id.file_id == [0; 16] {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file system did not provide a usable 128-bit identity",
        ));
    }
    Ok(id)
}

fn require_same_file(first: &File, second: &File) -> io::Result<()> {
    if identity(first)? != identity(second)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "input file identity changed after opening",
        ));
    }
    Ok(())
}

/// Detect a *currently observable* change of the path target after the
/// guarded input handle was opened. Re-opening a path is not an atomic
/// ancestor check, file snapshot or guarantee against fast replacements.
pub(super) fn verify_against_reopened_path(path: &Path, opened: &File) -> io::Result<()> {
    let subsequent = super::open_candidate(path)?;
    require_same_file(opened, &subsequent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn test_path(label: &str) -> std::path::PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "rel-file-identity-{label}-{}-{nanos}",
            std::process::id()
        ))
    }

    #[test]
    fn accepts_two_handles_for_one_file_and_normal_reader() {
        let path = test_path("same");
        fs::write(&path, b"MZ identical").unwrap();
        let first = super::super::open_candidate(&path).unwrap();
        let second = super::super::open_candidate(&path).unwrap();
        require_same_file(&first, &second).unwrap();
        verify_against_reopened_path(&path, &first).unwrap();
        drop(first);
        drop(second);
        assert_eq!(super::super::read_binary(&path).unwrap(), b"MZ identical");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn rejects_two_distinct_regular_files_even_with_equal_size_and_mtime() {
        let first_path = test_path("first");
        let second_path = test_path("second");
        fs::write(&first_path, b"MZ alpha").unwrap();
        fs::write(&second_path, b"MZ omega").unwrap();
        let mtime = fs::metadata(&first_path).unwrap().modified().unwrap();
        fs::OpenOptions::new()
            .write(true)
            .open(&second_path)
            .unwrap()
            .set_times(fs::FileTimes::new().set_modified(mtime))
            .unwrap();
        assert_eq!(
            fs::metadata(&first_path).unwrap().modified().unwrap(),
            fs::metadata(&second_path).unwrap().modified().unwrap()
        );
        let first = super::super::open_candidate(&first_path).unwrap();
        let second = super::super::open_candidate(&second_path).unwrap();
        let error = require_same_file(&first, &second).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        drop(first);
        drop(second);
        fs::remove_file(&first_path).unwrap();
        fs::remove_file(&second_path).unwrap();
    }

    #[test]
    fn accepts_hard_link_alias_of_the_same_file() {
        let original = test_path("hard-link-source");
        let alias = test_path("hard-link-alias");
        fs::write(&original, b"MZ alias").unwrap();
        fs::hard_link(&original, &alias).unwrap();
        let first = super::super::open_candidate(&original).unwrap();
        let second = super::super::open_candidate(&alias).unwrap();
        require_same_file(&first, &second).unwrap();
        drop(first);
        drop(second);
        fs::remove_file(&alias).unwrap();
        fs::remove_file(&original).unwrap();
    }
}
