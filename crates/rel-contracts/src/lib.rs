//! Shared analysis contracts. No parser-specific types cross this boundary.
use serde::Serialize;

pub const MANIFEST_SCHEMA: &str = "1.0.0";

#[derive(Debug, Serialize)]
pub struct BinarySection {
    pub name: String,
    pub offset: u64,
    pub size: u64,
    pub virtual_address: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct BinaryManifest {
    pub schema_version: String,
    pub binary_sha256: String,
    pub size_bytes: u64,
    pub format: String,
    pub arch: Option<String>,
    pub sections: Vec<BinarySection>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub warnings: Vec<String>,
}
