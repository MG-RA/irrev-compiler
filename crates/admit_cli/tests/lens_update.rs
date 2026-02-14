use std::path::{Path, PathBuf};
use std::process::Command;

fn find_admit_cli_bin() -> PathBuf {
    for key in ["CARGO_BIN_EXE_admit_cli", "CARGO_BIN_EXE_admit-cli"] {
        if let Ok(path) = std::env::var(key) {
            return PathBuf::from(path);
        }
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let target_debug = workspace_root.join("target").join("debug");
    let candidates = if cfg!(windows) {
        vec!["admit_cli.exe", "admit-cli.exe"]
    } else {
        vec!["admit_cli", "admit-cli"]
    };
    for candidate in candidates {
        let path = target_debug.join(candidate);
        if path.exists() {
            return path;
        }
    }
    panic!("admit_cli binary path not found");
}

fn write_registry(path: &Path) {
    let value = serde_json::json!({
        "schema_id": "meta-registry/1",
        "schema_version": 1,
        "registry_version": 1,
        "default_lens": {
            "lens_id": "lens:default@0",
            "lens_hash": "hash-default"
        },
        "lenses": [
            {
                "lens_id": "lens:default@0",
                "lens_hash": "hash-default"
            },
            {
                "lens_id": "lens:candidate@1",
                "lens_hash": "hash-candidate-mismatch"
            }
        ],
        "meta_change_kinds": [
            {
                "kind_id": "constraint_tuning",
                "may_change_transform_space": false,
                "may_change_constraints": true,
                "may_change_accounting_routes": false,
                "may_change_permissions": false,
                "requires_manual_approval": false
            },
            {
                "kind_id": "permission_policy_update",
                "may_change_transform_space": false,
                "may_change_constraints": false,
                "may_change_accounting_routes": false,
                "may_change_permissions": true,
                "requires_manual_approval": true
            }
        ],
        "meta_buckets": [
            { "bucket_id": "bucket:trust_debt", "unit": "risk_points" },
            { "bucket_id": "bucket:compatibility_debt", "unit": "risk_points" },
            { "bucket_id": "bucket:explanation_debt", "unit": "risk_points" }
        ],
        "stdlib": [
            { "module_id": "module:irrev_std@1" }
        ],
        "schemas": [
            { "id": "meta-registry/1", "schema_version": 1, "kind": "meta_registry", "canonical_encoding": "canonical-cbor" },
            { "id": "admissibility-witness/2", "schema_version": 2, "kind": "witness", "canonical_encoding": "canonical-cbor" },
            { "id": "lens-delta-witness/0", "schema_version": 0, "kind": "witness", "canonical_encoding": "canonical-cbor" }
        ],
        "scopes": [
            { "id": "scope:main", "version": 0 }
        ]
    });
    let text = serde_json::to_string_pretty(&value).expect("serialize registry");
    std::fs::write(path, text).expect("write registry");
}

fn run_lens_update(args: &[&str]) -> std::process::Output {
    Command::new(find_admit_cli_bin())
        .args(args)
        .output()
        .expect("run lens update")
}

#[test]
fn lens_update_emits_meta_change_checked_event() {
    let temp = tempfile::tempdir().expect("tempdir");
    let registry_path = temp.path().join("meta-registry.json");
    let ledger_path = temp.path().join("ledger.jsonl");
    write_registry(&registry_path);

    let output = run_lens_update(&[
        "lens",
        "update",
        "--from-lens",
        "lens:default@0",
        "--kind",
        "constraint_tuning",
        "--payload-ref",
        "payload:test@1",
        "--route",
        "bucket:trust_debt=1:risk_points",
        "--change-constraints",
        "--meta-registry",
        registry_path.to_str().expect("registry path"),
        "--ledger",
        ledger_path.to_str().expect("ledger path"),
        "--json",
    ]);

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );

    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("decode json");
    assert_eq!(
        value.get("command").and_then(|v| v.as_str()),
        Some("lens_update")
    );
    assert_eq!(
        value
            .get("meta_change_checked_event")
            .and_then(|v| v.get("event_type"))
            .and_then(|v| v.as_str()),
        Some("meta.change.checked")
    );

    let ledger = std::fs::read_to_string(&ledger_path).expect("read ledger");
    assert!(
        ledger.contains("\"event_type\":\"meta.change.checked\""),
        "ledger missing meta.change.checked event:\n{}",
        ledger
    );
}

#[test]
fn lens_update_rejects_unknown_kind() {
    let temp = tempfile::tempdir().expect("tempdir");
    let registry_path = temp.path().join("meta-registry.json");
    write_registry(&registry_path);

    let output = run_lens_update(&[
        "lens",
        "update",
        "--from-lens",
        "lens:default@0",
        "--kind",
        "unknown_kind",
        "--payload-ref",
        "payload:test@1",
        "--route",
        "bucket:trust_debt=1:risk_points",
        "--change-constraints",
        "--meta-registry",
        registry_path.to_str().expect("registry path"),
    ]);

    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(!output.status.success(), "expected command to fail");
    assert!(
        stderr.contains("unknown meta-change kind"),
        "stderr:\n{}",
        stderr
    );
}

#[test]
fn lens_update_rejects_unknown_route_bucket() {
    let temp = tempfile::tempdir().expect("tempdir");
    let registry_path = temp.path().join("meta-registry.json");
    write_registry(&registry_path);

    let output = run_lens_update(&[
        "lens",
        "update",
        "--from-lens",
        "lens:default@0",
        "--kind",
        "constraint_tuning",
        "--payload-ref",
        "payload:test@1",
        "--route",
        "bucket:unknown=1:risk_points",
        "--change-constraints",
        "--meta-registry",
        registry_path.to_str().expect("registry path"),
    ]);

    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(!output.status.success(), "expected command to fail");
    assert!(
        stderr.contains("unknown route bucket"),
        "stderr:\n{}",
        stderr
    );
}

#[test]
fn lens_update_rejects_missing_routes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let registry_path = temp.path().join("meta-registry.json");
    write_registry(&registry_path);

    let output = run_lens_update(&[
        "lens",
        "update",
        "--from-lens",
        "lens:default@0",
        "--kind",
        "constraint_tuning",
        "--payload-ref",
        "payload:test@1",
        "--change-constraints",
        "--meta-registry",
        registry_path.to_str().expect("registry path"),
    ]);

    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(!output.status.success(), "expected command to fail");
    assert!(
        stderr.contains("requires at least one --route"),
        "stderr:\n{}",
        stderr
    );
}

#[test]
fn lens_update_rejects_missing_explicit_capability_allow() {
    let temp = tempfile::tempdir().expect("tempdir");
    let registry_path = temp.path().join("meta-registry.json");
    write_registry(&registry_path);

    let output = run_lens_update(&[
        "lens",
        "update",
        "--from-lens",
        "lens:default@0",
        "--kind",
        "constraint_tuning",
        "--payload-ref",
        "payload:test@1",
        "--route",
        "bucket:trust_debt=1:risk_points",
        "--meta-registry",
        registry_path.to_str().expect("registry path"),
    ]);

    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(!output.status.success(), "expected command to fail");
    assert!(
        stderr.contains("requires explicit capability allow"),
        "stderr:\n{}",
        stderr
    );
}

#[test]
fn lens_update_rejects_kind_capability_mismatch() {
    let temp = tempfile::tempdir().expect("tempdir");
    let registry_path = temp.path().join("meta-registry.json");
    write_registry(&registry_path);

    let output = run_lens_update(&[
        "lens",
        "update",
        "--from-lens",
        "lens:default@0",
        "--kind",
        "constraint_tuning",
        "--payload-ref",
        "payload:test@1",
        "--route",
        "bucket:trust_debt=1:risk_points",
        "--change-permissions",
        "--meta-registry",
        registry_path.to_str().expect("registry path"),
    ]);

    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(!output.status.success(), "expected command to fail");
    assert!(
        stderr.contains("does not allow permission changes"),
        "stderr:\n{}",
        stderr
    );
}

#[test]
fn lens_update_requires_manual_approval_when_declared() {
    let temp = tempfile::tempdir().expect("tempdir");
    let registry_path = temp.path().join("meta-registry.json");
    write_registry(&registry_path);

    let output = run_lens_update(&[
        "lens",
        "update",
        "--from-lens",
        "lens:default@0",
        "--kind",
        "permission_policy_update",
        "--payload-ref",
        "payload:test@1",
        "--route",
        "bucket:trust_debt=1:risk_points",
        "--change-permissions",
        "--meta-registry",
        registry_path.to_str().expect("registry path"),
    ]);

    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(!output.status.success(), "expected command to fail");
    assert!(
        stderr.contains("requires manual approval"),
        "stderr:\n{}",
        stderr
    );
}

#[test]
fn lens_update_rejects_to_lens_binding_hash_mismatch() {
    let temp = tempfile::tempdir().expect("tempdir");
    let registry_path = temp.path().join("meta-registry.json");
    write_registry(&registry_path);

    let output = run_lens_update(&[
        "lens",
        "update",
        "--from-lens",
        "lens:default@0",
        "--kind",
        "constraint_tuning",
        "--payload-ref",
        "payload:test@1",
        "--to-lens",
        "lens:candidate@1",
        "--route",
        "bucket:trust_debt=1:risk_points",
        "--change-constraints",
        "--meta-registry",
        registry_path.to_str().expect("registry path"),
    ]);

    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(!output.status.success(), "expected command to fail");
    assert!(
        stderr.contains("hash mismatch for to_lens binding"),
        "stderr:\n{}",
        stderr
    );
}
