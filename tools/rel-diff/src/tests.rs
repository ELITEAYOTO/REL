use super::*;

#[test]
fn invalid_manifest_shapes_fail_deserialization() {
    let valid = format!(
        r#"{{"schema_version":"1.0.0","binary_sha256":"{}","size_bytes":1,"format":"PE","arch":null,"sections":[],"imports":[],"exports":[],"warnings":[]}}"#,
        "a".repeat(64)
    );
    assert!(serde_json::from_str::<Manifest>(&valid).is_ok());
    assert!(serde_json::from_str::<Manifest>(&valid.replace(r#","warnings":[]"#, "")).is_err());
    assert!(serde_json::from_str::<Manifest>(&valid.replace(r#","arch":null"#, "")).is_err());
    assert!(serde_json::from_str::<Manifest>(
        &valid.replace(r#""warnings":[]}"#, r#""warnings":[],"unknown":1}"#)
    )
    .is_err());
    assert!(serde_json::from_str::<Manifest>(
        &valid.replace(r#""size_bytes":1"#, r#""size_bytes":-1"#)
    )
    .is_err());
}

#[test]
fn dll_case_hint_preserves_exact_import_evidence() {
    let left = vec!["KERNEL32.DLL!ReadFile".to_owned()];
    let right = vec!["kernel32.dll!ReadFile".to_owned()];
    assert!(dll_case_only(&left, &right));
    assert_eq!(delta(&left, &right).removed, left);
    assert!(!dll_case_only(
        &[
            "KERNEL32.DLL!ReadFile".into(),
            "kernel32.dll!ReadFile".into()
        ],
        &["kernel32.dll!ReadFile".into()]
    ));
    assert!(!dll_case_only(
        &["KERNEL32.DLL!ReadFile".into()],
        &["kernel32.dll!readfile".into()]
    ));
}

#[test]
fn golden_manifest_comparison_reports_observed_changes() {
    let parse = |sha: char, size: u64, imports: &str| {
        let raw = format!(
            r#"{{"schema_version":"1.0.0","binary_sha256":"{}","size_bytes":{},"format":"PE","arch":"x86_64","sections":[{{"name":".text","offset":512,"size":100,"virtual_address":4096}}],"imports":[{}],"exports":[],"warnings":[]}}"#,
            sha.to_string().repeat(64),
            size,
            imports
        );
        serde_json::from_str::<Manifest>(&raw).expect("controlled valid manifest")
    };
    let left = parse('a', 1000, r#""KERNEL32.dll!ReadFile""#);
    let right = parse('b', 1200, r#""KERNEL32.dll!WriteFile""#);
    let result = compare(left, right);
    assert!(result.size_changed);
    assert!(!result.arch_changed);
    assert_eq!(result.sections.status, "unchanged");
    assert_eq!(result.imports.added, vec!["KERNEL32.dll!WriteFile"]);
    assert_eq!(result.imports.removed, vec!["KERNEL32.dll!ReadFile"]);
    let json = serde_json::to_value(&result).expect("serializable report");
    assert_eq!(json["schema_version"], "0.1.0-experimental");
    assert_eq!(json["sections"]["status"], "unchanged");
}

#[test]
fn section_order_does_not_change_delta() {
    let section = |name: &str, size| Section {
        name: name.into(),
        offset: 0,
        size,
        virtual_address: Some(4096),
    };
    let a = vec![section(".text", 10), section(".data", 20)];
    let b = vec![section(".data", 20), section(".text", 10)];
    let result = section_status(&a, &b);
    assert_eq!(result.status, "unchanged");
    assert!(result.added.is_empty());
    assert!(result.removed.is_empty());
    assert!(result.changed.is_empty());
}

#[test]
fn ambiguous_sections_do_not_emit_misleading_partial_deltas() {
    let section = |name: &str| Section {
        name: name.into(),
        offset: 0,
        size: 10,
        virtual_address: None,
    };
    let result = section_status(&[section(".text"), section(".text")], &[section(".new")]);
    assert_eq!(result.status, "ambiguous");
    assert!(result.added.is_empty());
    assert!(result.removed.is_empty());
    assert!(result.changed.is_empty());
}

#[test]
fn repeated_sections_are_not_silently_matched() {
    let section = |name: &str| Section {
        name: name.into(),
        offset: 0,
        size: 10,
        virtual_address: Some(4096),
    };
    let result = section_status(&[section(".text"), section(".text")], &[]);
    assert_eq!(result.status, "ambiguous");
    let result = section_status(&[section(".text")], &[section(".text")]);
    assert_eq!(result.status, "unchanged");
}

#[test]
fn unique_sections_have_deterministic_metadata_deltas() {
    let section = |name: &str, size| Section {
        name: name.into(),
        offset: 0,
        size,
        virtual_address: Some(4096),
    };
    let a = vec![section(".text", 10), section(".old", 1)];
    let b = vec![section(".new", 3), section(".text", 20)];
    let result = section_status(&a, &b);
    assert_eq!(result.status, "changed");
    assert_eq!(result.added, vec![".new"]);
    assert_eq!(result.removed, vec![".old"]);
    assert_eq!(result.changed, vec![".text"]);
    let reversed = section_status(&b, &a);
    assert_eq!(reversed.added, result.removed);
    assert_eq!(reversed.removed, result.added);
    assert_eq!(reversed.changed, result.changed);
}

#[test]
fn repeated_observations_are_detected() {
    assert!(has_duplicates(&["x".into(), "x".into()]));
    assert!(!has_duplicates(&["x".into(), "y".into()]));
}

#[test]
fn sets_are_order_independent_and_inverse() {
    let a = vec!["B".into(), "A".into()];
    let b = vec!["C".into(), "B".into()];
    assert_eq!(
        delta(&a, &a),
        Delta {
            added: vec![],
            removed: vec![]
        }
    );
    assert_eq!(
        delta(&a, &b),
        Delta {
            added: vec!["C".into()],
            removed: vec!["A".into()]
        }
    );
    assert_eq!(
        delta(&b, &a),
        Delta {
            added: vec!["A".into()],
            removed: vec!["C".into()]
        }
    );
}
