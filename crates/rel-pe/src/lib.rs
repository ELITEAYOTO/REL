//! Static Portable Executable inspection. Input bytes are never executed.
mod preflight;
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
    // Reject oversized or truncated PE header structures before entering goblin.
    preflight::validate(data).map_err(|detail| PeError::Parse(detail.to_owned()))?;
    // Historical goblin 0.9.3 TLS parsing panic is retained as regression F001.
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
        .map(|s| {
            // The v1 manifest stores names as UTF-8 strings. Returning a
            // fabricated placeholder with no warning would falsely present
            // an incomplete observation as a successful extraction.
            let name = s
                .name()
                .map_err(|_| PeError::Parse("section name cannot be decoded as UTF-8".into()))?;
            Ok(BinarySection {
                name: name.trim_end_matches('\0').to_string(),
                offset: u64::from(s.pointer_to_raw_data),
                size: u64::from(s.size_of_raw_data),
                virtual_address: Some(u64::from(s.virtual_address)),
            })
        })
        .collect::<Result<Vec<_>, PeError>>()?;

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

    // The public v1 list contains names only. An export address table may
    // also have unnamed ordinal entries or unrepresented unused slots; do
    // not present the remaining name list as complete, warning-free evidence.
    let unrepresented_export_slots = pe.exports.iter().any(|entry| entry.name.is_none())
        || pe.export_data.as_ref().is_some_and(|data| {
            data.export_directory_table.address_table_entries
                > data.export_directory_table.number_of_name_pointers
        });
    // Goblin's synthesized "ORDINAL N" import name is indistinguishable
    // in the v1 string list from a real symbol literally named "ORDINAL N".
    // Use the parsed lookup-entry variant, not its display text or hint.
    let ordinal_imports = pe.import_data.as_ref().is_some_and(|data| {
        data.import_data.iter().any(|descriptor| {
            descriptor.import_lookup_table.as_ref().is_some_and(|entries| {
                entries.iter().any(|entry| {
                    matches!(
                        entry,
                        goblin::pe::import::SyntheticImportLookupTableEntry::OrdinalNumber(_)
                    )
                })
            })
        })
    });
    let mut warnings = Vec::new();
    if unrepresented_export_slots {
        warnings.push(
            "export address table has unnamed or unrepresented ordinal slots; only named exports are reported"
                .to_owned(),
        );
    }
    if ordinal_imports {
        warnings.push(
            "import lookup table contains ordinal references; v1 import strings cannot distinguish ordinals from literal symbol names"
                .to_owned(),
        );
    }

    Ok(PeInspection {
        arch,
        sections,
        imports,
        exports,
        warnings,
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
