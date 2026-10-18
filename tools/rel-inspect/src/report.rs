//! Bounded JSON encoding for an already constructed manifest.
//! Does not claim a cap on parser allocations, CPU usage or the input file.
use rel_contracts::BinaryManifest;
use std::io::{self, Write};

pub(crate) const MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;

struct BoundedJsonWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedJsonWriter {
    fn write(&mut self, chunk: &[u8]) -> io::Result<usize> {
        if chunk.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other(
                "JSON report exceeds configured 16 MiB output limit",
            ));
        }
        self.bytes
            .try_reserve(chunk.len())
            .map_err(io::Error::other)?;
        self.bytes.extend_from_slice(chunk);
        Ok(chunk.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Build a complete report before any file/stdout write. This avoids partial
/// output when the cap is reached and preserves the existing JSON v1 schema.
pub(crate) fn serialize_manifest(
    manifest: &BinaryManifest,
    limit: usize,
) -> Result<Vec<u8>, serde_json::Error> {
    let mut writer = BoundedJsonWriter {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer_pretty(&mut writer, manifest)?;
    Ok(writer.bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_manifest() -> BinaryManifest {
        BinaryManifest {
            schema_version: "1.0.0".to_owned(),
            binary_sha256: "a".repeat(64),
            size_bytes: 2,
            format: "PE".to_owned(),
            arch: Some("x86".to_owned()),
            sections: vec![],
            imports: vec![],
            exports: vec![],
            warnings: vec![],
        }
    }

    #[test]
    fn matches_original_pretty_json_output() {
        let manifest = fixture_manifest();
        let expected = serde_json::to_vec_pretty(&manifest).unwrap();
        assert_eq!(
            serialize_manifest(&manifest, MAX_REPORT_BYTES).unwrap(),
            expected
        );
    }

    #[test]
    fn accepts_exact_output_limit() {
        let manifest = fixture_manifest();
        let expected = serde_json::to_vec_pretty(&manifest).unwrap();
        assert_eq!(
            serialize_manifest(&manifest, expected.len()).unwrap(),
            expected
        );
    }

    #[test]
    fn rejects_report_exceeding_limit() {
        let mut manifest = fixture_manifest();
        manifest.warnings.push("large diagnostic".repeat(20));
        let error = serialize_manifest(&manifest, 100).unwrap_err();
        assert!(error.to_string().contains("output limit"));
    }

    #[test]
    fn rejects_one_byte_below_full_json_length() {
        let manifest = fixture_manifest();
        let expected = serde_json::to_vec_pretty(&manifest).unwrap();
        let error = serialize_manifest(&manifest, expected.len() - 1).unwrap_err();
        assert!(error.to_string().contains("output limit"));
    }

    #[test]
    fn writer_rejects_additional_data_without_modifying_buffer() {
        let mut writer = BoundedJsonWriter {
            bytes: Vec::new(),
            limit: 4,
        };
        writer.write_all(b"abcd").unwrap();
        assert!(writer.write_all(b"e").is_err());
        assert_eq!(writer.bytes, b"abcd");
    }
}
