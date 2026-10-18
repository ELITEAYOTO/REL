mod input;
mod report;

use rel_contracts::{BinaryManifest, MANIFEST_SCHEMA};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    io::{self, Write},
    path::Path,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("rel-inspect: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("--version") => {
            println!("rel-inspect {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some("analyze") => {
            let input = args.next().ok_or("missing input path")?;
            let mut output = None;
            while let Some(arg) = args.next() {
                match arg.as_str() {
                    "--output" => output = Some(args.next().ok_or("missing output path")?),
                    _ => return Err(format!("unknown argument: {arg}").into()),
                }
            }
            if let Some(ref target) = output {
                let same = fs::canonicalize(&input)
                    .ok()
                    .zip(fs::canonicalize(target).ok())
                    .is_some_and(|(a, b)| a == b);
                if same || input == *target {
                    return Err("output must not overwrite the analyzed binary".into());
                }
            }
            let bytes = input::read_binary(Path::new(&input))?;
            let inspection = rel_pe::inspect(&bytes)?;
            let manifest = BinaryManifest {
                schema_version: MANIFEST_SCHEMA.to_owned(),
                binary_sha256: format!("{:x}", Sha256::digest(&bytes)),
                size_bytes: bytes.len() as u64,
                format: "PE".into(),
                arch: Some(inspection.arch),
                sections: inspection.sections,
                imports: inspection.imports,
                exports: inspection.exports,
                warnings: inspection.warnings,
            };
            let serialized = report::serialize_manifest(&manifest, report::MAX_REPORT_BYTES)?;
            match output {
                Some(path) => {
                    // Refuse implicit overwrite.
                    let mut file = fs::OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .open(Path::new(&path))?;
                    file.write_all(&serialized)?;
                }
                None => {
                    io::stdout().write_all(&serialized)?;
                    println!();
                }
            }
            Ok(())
        }
        _ => {
            eprintln!("Usage: rel-inspect analyze <file.exe> [--output report.json]");
            eprintln!("       rel-inspect --version");
            Err("invalid command".into())
        }
    }
}
