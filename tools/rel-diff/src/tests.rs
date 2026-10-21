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

#[test]
fn borrowed_delta_sets_preserve_long_observations_and_sorted_inverse() {
    let padding = "X".repeat(950);
    let shared = format!("KERNEL32.dll!Shared{padding}");
    let removed = format!("KERNEL32.dll!Removed{padding}");
    let added = format!("KERNEL32.dll!Added{padding}");
    let left = vec![shared.clone(), removed.clone()];
    let right = vec![added.clone(), shared.clone()];
    let forward = delta(&left, &right);
    assert_eq!(forward.added, vec![added.clone()]);
    assert_eq!(forward.removed, vec![removed.clone()]);
    let reverse = delta(&right, &left);
    assert_eq!(reverse.added, forward.removed);
    assert_eq!(reverse.removed, forward.added);
    assert!(delta(&left, &left).added.is_empty());
    assert_eq!(left[1], removed);
    assert_eq!(right[0], added);
}

#[test]
fn partial_mode_preserves_warnings_and_never_claims_negative_behaviors() {
    let raw = format!(
        r#"{{"schema_version":"1.0.0","binary_sha256":"{}","size_bytes":5,"format":"PE","arch":null,"sections":[],"imports":["kernel32.dll!ORDINAL 42"],"exports":[],"warnings":[]}}"#,
        "a".repeat(64)
    );
    let mut left: Manifest = serde_json::from_str(&raw).expect("controlled manifest");
    left.warnings = vec!["future unknown diagnostic".into(), "ordinal import".into()];
    let right: Manifest = serde_json::from_str(&raw).expect("controlled manifest");
    let value = serde_json::to_value(compare_partial(left, right)).expect("partial JSON");
    assert_eq!(value["schema_version"], "0.2.0-experimental");
    assert_eq!(value["coverage"]["status"], "partial");
    assert_eq!(value["coverage"]["negative_behavior_conclusions"], false);
    assert_eq!(
        value["coverage"]["left_warnings"],
        serde_json::json!(["future unknown diagnostic", "ordinal import"])
    );
    assert_eq!(value["coverage"]["right_warnings"], serde_json::json!([]));
    assert_eq!(value["observed"]["schema_version"], "0.1.0-experimental");
    assert_eq!(
        value["observed"]["imports"]["removed"],
        serde_json::json!([])
    );
}

#[test]
fn warning_free_partial_mode_still_has_unknown_coverage() {
    let raw = format!(
        r#"{{"schema_version":"1.0.0","binary_sha256":"{}","size_bytes":5,"format":"PE","arch":null,"sections":[],"imports":[],"exports":[],"warnings":[]}}"#,
        "a".repeat(64)
    );
    let left: Manifest = serde_json::from_str(&raw).expect("controlled manifest");
    let right: Manifest = serde_json::from_str(&raw).expect("controlled manifest");
    let value = serde_json::to_value(compare_partial(left, right)).expect("partial JSON");
    assert_eq!(value["coverage"]["status"], "unknown");
    assert_eq!(value["coverage"]["negative_behavior_conclusions"], false);
}
