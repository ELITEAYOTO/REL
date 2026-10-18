//! Windows ancestor-path check for controlled-input alpha.
//! This is a double path inspection, NOT a descriptor-relative or atomic open.
use std::os::windows::fs::MetadataExt;
use std::{fs, io, path::Path};

const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

/// Fail closed if any observable parent component is a reparse point.
/// Called both before and immediately after the final input handle is opened.
/// This is not a race-free path walk: each metadata query resolves a path anew.
pub(super) fn reject_reparse_ancestors(input: &Path) -> io::Result<()> {
    let mut parent = input.parent();
    while let Some(directory) = parent {
        if directory.as_os_str().is_empty() {
            break;
        }
        let metadata = fs::symlink_metadata(directory)?;
        if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "input parent reparse points are unsupported",
            ));
        }
        if !metadata.is_dir() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "input parent must be a directory",
            ));
        }
        parent = directory.parent();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        path::PathBuf,
        process::Command,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn temp_root(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "rel-parent-reparse-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir(&root).unwrap();
        root
    }

    fn junction(link: &Path, target: &Path) {
        // mklink /J creates a real directory junction without needing the
        // symlink-creation privilege on ordinary Windows CI runners.
        let output = Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .output()
            .expect("cmd.exe must be available on Windows CI");
        assert!(
            output.status.success(),
            "mklink /J failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_ne!(
            fs::symlink_metadata(link).unwrap().file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT,
            0,
            "the test requires an actual reparse point"
        );
    }

    #[test]
    fn allows_ordinary_nested_file() {
        let root = temp_root("nested");
        let directory = root.join("one").join("two");
        fs::create_dir_all(&directory).unwrap();
        let file = directory.join("sample.exe");
        fs::write(&file, b"MZ nested").unwrap();

        assert_eq!(super::super::read_binary(&file).unwrap(), b"MZ nested");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_existing_parent_junction() {
        let root = temp_root("junction");
        let real = root.join("real");
        fs::create_dir(&real).unwrap();
        fs::write(real.join("sample.exe"), b"MZ real").unwrap();
        let link = root.join("linked");
        junction(&link, &real);
        let candidate = link.join("sample.exe");

        assert!(fs::symlink_metadata(&candidate).unwrap().is_file());
        let error = super::super::read_binary(&candidate).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("parent reparse"));
        println!("PASS Windows existing directory junction rejected");

        fs::remove_dir(&link).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn refuses_parent_junction_created_after_initial_file_stat() {
        let root = temp_root("swapped");
        let original = root.join("candidate");
        fs::create_dir(&original).unwrap();
        let file = original.join("sample.exe");
        fs::write(&file, b"MZ original").unwrap();
        assert!(fs::symlink_metadata(&file).unwrap().is_file());

        let moved = root.join("moved");
        fs::rename(&original, &moved).unwrap();
        junction(&original, &moved);

        // Deterministic model of replacement between leaf preflight and the
        // next parent-component check, not an atomic race guarantee.
        let error = reject_reparse_ancestors(&file).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(super::super::read_binary(&file).is_err());
        println!("PASS Windows swapped directory junction rejected");

        fs::remove_dir(&original).unwrap();
        fs::remove_dir_all(root).unwrap();
    }
}
