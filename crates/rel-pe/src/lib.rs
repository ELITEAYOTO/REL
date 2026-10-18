//! Static Portable Executable inspection. Input bytes are never executed.
use rel_contracts::BinarySection;

#[derive(Debug)]
pub enum PeError {
    Unsupported,
    Parse(String),
    DependencyPanic,
}

impl std::fmt::Display for PeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unsupported => write!(f, "unsupported format (PE only)"),
            Self::Parse(detail) => write!(f, "invalid PE: {detail}"),
            Self::DependencyPanic => write!(f, "PE parser dependency panicked while parsing"),
        }
    }
}

impl std::error::Error for PeError {}

pub struct PeInspection {
    pub arch: String,
    pub sections: Vec<BinarySection>,
    pub imports: Vec<String>,
    pub exports: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn inspect(data: &[u8]) -> Result<PeInspection, PeError> {
    if !data.starts_with(b"MZ") {
        return Err(PeError::Unsupported);
    }
    // goblin 0.9.3 may panic on malformed TLS directory offsets.
    // Contain unwinding panics at the untrusted third-party parser boundary.
    // This does not handle aborts, OOM or memory-unsafety and does not replace
    // upstream fixes or process isolation for hostile inputs.
    let pe = std::panic::catch_unwind(|| goblin::pe::PE::parse(data))
        .map_err(|_| PeError::DependencyPanic)?
        .map_err(|e| PeError::Parse(e.to_string()))?;
    let arch = match pe.header.coff_header.machine {
        0x8664 => "x86_64",
        0x014c => "x86",
        0xaa64 => "aarch64",
        _ => "unknown",
    }
    .to_string();

    let sections = pe
        .sections
        .iter()
        .map(|s| BinarySection {
            name: s
                .name()
                .unwrap_or("<invalid>")
                .trim_end_matches('\0')
                .to_string(),
            offset: u64::from(s.pointer_to_raw_data),
            size: u64::from(s.size_of_raw_data),
            virtual_address: Some(u64::from(s.virtual_address)),
        })
        .collect();

    let mut imports: Vec<_> = pe
        .imports
        .iter()
        .map(|i| format!("{}!{}", i.dll, i.name))
        .collect();
    imports.sort();
    imports.dedup();

    let mut exports: Vec<_> = pe
        .exports
        .iter()
        .filter_map(|e| e.name.map(str::to_owned))
        .collect();
    exports.sort();
    exports.dedup();

    Ok(PeInspection {
        arch,
        sections,
        imports,
        exports,
        warnings: Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_unknown_formats() {
        assert!(matches!(inspect(b"invalid"), Err(PeError::Unsupported)));
        assert!(matches!(inspect(b"\x7fELF"), Err(PeError::Unsupported)));
    }
    #[test]
    fn rejects_truncated_pe() {
        assert!(inspect(b"MZ").is_err());
    }
}
