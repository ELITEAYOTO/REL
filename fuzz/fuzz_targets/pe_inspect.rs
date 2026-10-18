#![no_main]

// Only parse bytes; never load or execute the input image.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = rel_pe::inspect(data);
});
