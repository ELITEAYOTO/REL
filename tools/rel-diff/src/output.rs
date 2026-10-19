//! Preflight the entire diff report before writing any stdout bytes.
//! This limits serialized bytes, not all transient allocations or CPU time.
use serde::Serialize;
use std::io::{self, Write};

pub(crate) const MAX_REPORT_BYTES: usize = 16 * 1024 * 1024;

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedWriter {
    fn write(&mut self, chunk: &[u8]) -> io::Result<usize> {
        if chunk.len() > self.limit.saturating_sub(self.bytes.len()) {
            return Err(io::Error::other("diff JSON exceeds 16 MiB output limit"));
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

fn bounded_serialize<T: Serialize>(report: &T, limit: usize) -> Result<Vec<u8>, String> {
    let mut writer = BoundedWriter {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer_pretty(&mut writer, report).map_err(|e| e.to_string())?;
    writer.write_all(b"\n").map_err(|e| e.to_string())?;
    Ok(writer.bytes)
}

pub(crate) fn serialize_report<T: Serialize>(report: &T) -> Result<Vec<u8>, String> {
    bounded_serialize(report, MAX_REPORT_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn serializes_exactly_with_terminal_newline() {
        let value = json!({"example": [1, 2]});
        let mut expected = serde_json::to_vec_pretty(&value).unwrap();
        expected.push(b'\n');
        assert_eq!(bounded_serialize(&value, expected.len()).unwrap(), expected);
    }

    #[test]
    fn rejects_a_report_one_byte_over_limit() {
        let value = json!({"example": "text"});
        let exact = bounded_serialize(&value, 1024).unwrap();
        let error = bounded_serialize(&value, exact.len() - 1).unwrap_err();
        assert!(error.contains("output limit"));
    }

    #[test]
    fn writer_rejects_overflow_without_appending_chunk() {
        let mut writer = BoundedWriter {
            bytes: Vec::new(),
            limit: 4,
        };
        writer.write_all(b"abcd").unwrap();
        assert!(writer.write_all(b"e").is_err());
        assert_eq!(writer.bytes, b"abcd");
    }
}
