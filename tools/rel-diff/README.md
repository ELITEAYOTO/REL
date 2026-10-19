# rel-diff — EX-02 experimental first slice

Compare two pre-generated **controlled PE** binary-manifest v1.0.0 JSON reports:

```sh
cargo run --locked -p rel-diff -- left.json right.json
```

Initial output is a separately versioned experimental JSON report. Size and architecture change flags, additions/removals of exact import/export strings, and metadata differences for uniquely named sections are compared. Section entries report added/removed/changed exact names with deterministic ordering. Output order is deterministic. Inputs are read with a hard 16 MiB + 1 byte ceiling each, decoded with known fields, and extraction warnings or duplicate import/export strings fail closed. This is a bounded read, not an overall memory/CPU sandbox. Section status reports `ambiguous` with no partial section deltas when either input repeats a section name. Otherwise comparison uses exact unique section names and flags changes to file offset, raw size or virtual address; a renamed section appears as removed plus added, not inferred as a rename. Unknown coverage is explicitly reported as a limitation; this is **not** a complete EX-02 implementation, exact JSON Schema validation, function diff, decompilation, security verdict or behavioral proof. Original manifest v1.0.0 stays unchanged.

Next gate: schema-complete validation; explicit DLL-case normalization and duplicate semantics; richer section pairing and ambiguity tests; golden end-to-end fixtures; Windows/Linux CI and benchmarks on authorized A/B builds. Do not promote EX-02 until those gates pass.
