//! Separate experimental CLI; rel-inspect's binary-manifest v1 is unchanged.
use std::{
    env,
    io::{self, Write},
    path::Path,
};

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let operation = args.next();
    if !matches!(
        operation.as_deref(),
        Some("dos-magic" | "coff-machine" | "section-headers")
    ) {
        return Err(
            "usage: rel-observe <dos-magic|coff-machine|section-headers> <controlled-file.exe>"
                .to_owned(),
        );
    }
    let input = args.next().ok_or("missing input path")?;
    if args.next().is_some() {
        return Err("unexpected extra arguments".to_owned());
    }
    let report = match operation.as_deref() {
        Some("dos-magic") => rel_observe::observe_file(Path::new(&input))?,
        Some("coff-machine") => rel_observe::observe_coff_machine_file(Path::new(&input))?,
        Some("section-headers") => rel_observe::observe_section_headers_file(Path::new(&input))?,
        _ => unreachable!("validated operation"),
    };
    let mut data = serde_json::to_vec_pretty(&report).map_err(|e| e.to_string())?;
    data.push(b'\n');
    io::stdout().write_all(&data).map_err(|e| e.to_string())
}

fn main() {
    if let Err(error) = run() {
        eprintln!("rel-observe: {error}");
        std::process::exit(1);
    }
}
