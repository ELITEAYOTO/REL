#![no_main]

// Only parse bytes; never load or execute the input image.
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Ordinary malformed PE rejections are expected. rel-pe contains
    // third-party unwinds and exposes them as DependencyPanic; ignoring the
    // Result here would hide exactly the regressions libFuzzer should save.
    // Panic only inside this fuzz process so libFuzzer records a reproducer.
    if let Err(rel_pe::PeError::DependencyPanic) = rel_pe::inspect(data) {
        panic!("rel-pe dependency panic caught while fuzzing PE input");
    }
});
