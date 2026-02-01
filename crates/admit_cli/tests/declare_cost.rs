use std::fs;
use std::path::PathBuf;

use admit_cli::{declare_cost, DeclareCostError, DeclareCostInput};
use sha2::{Digest, Sha256};

fn golden_path(name: &str) -> PathBuf {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    base.join("..")
        .join("..")
        .join("testdata")
        .join("golden-witness")
        .join(name)
}

fn read_bytes(name: &str) -> Vec<u8> {
    fs::read(golden_path(name)).expect("read golden file")
}

fn read_hash(name: &str) -> String {
    fs::read_to_string(golden_path(name))
        .expect("read golden hash")
        .trim()
        .to_string()
}

fn snapshot_data() -> (String, Vec<u8>, String) {
    let snapshot = serde_json::json!({
        "schema_id":"vault-snapshot/0",
        "schema_version":0,
        "concepts":[],
        "diagnostics":[],
        "domains":[],
        "projections":[],
        "papers":[],
        "meta":[],
        "support":[],
        "rulesets":[]
    });
    let bytes = vault_snapshot::canonical_json_bytes(&snapshot).expect("canonical bytes");
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    (
        format!("{:x}", hasher.finalize()),
        vault_snapshot::canonical_json_bytes(&snapshot).expect("canonical bytes"),
        "vault-snapshot/0".to_string(),
    )
}

fn temp_artifacts_dir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("admit-artifacts-{}", nanos))
}

#[test]
fn tampered_hash_fails_verification() {
    let witness_json = read_bytes("allow-erasure-trigger.json");
    let (snapshot_hash, snapshot_bytes, snapshot_schema) = snapshot_data();
    let input = DeclareCostInput {
        witness_json: Some(witness_json),
        witness_cbor: None,
        witness_sha256: Some("deadbeef".to_string()),
        witness_schema_id: None,
        compiler_build_id: Some("test-build".to_string()),
        snapshot_hash: Some(snapshot_hash),
        snapshot_canonical_bytes: Some(snapshot_bytes),
        snapshot_schema_id: Some(snapshot_schema),
        program_bundle_canonical_bytes: None,
        program_bundle_schema_id: None,
        program_module: None,
        program_scope: None,
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        artifacts_root: Some(temp_artifacts_dir()),
        meta_registry_path: None,
    };

    let err = declare_cost(input).expect_err("expected hash mismatch");
    match err {
        DeclareCostError::WitnessHashMismatch { .. } => {}
        other => panic!("unexpected error: {}", other),
    }
}

#[test]
fn identical_input_produces_same_event_id() {
    let witness_json = read_bytes("allow-erasure-trigger.json");
    let hash = read_hash("allow-erasure-trigger.cbor.sha256");
    let (snapshot_hash, snapshot_bytes, snapshot_schema) = snapshot_data();

    let input = DeclareCostInput {
        witness_json: Some(witness_json),
        witness_cbor: None,
        witness_sha256: Some(hash),
        witness_schema_id: Some("admissibility-witness/1".to_string()),
        compiler_build_id: Some("test-build".to_string()),
        snapshot_hash: Some(snapshot_hash),
        snapshot_canonical_bytes: Some(snapshot_bytes),
        snapshot_schema_id: Some(snapshot_schema),
        program_bundle_canonical_bytes: None,
        program_bundle_schema_id: None,
        program_module: None,
        program_scope: None,
        timestamp: "2026-01-01T00:00:00Z".to_string(),
        artifacts_root: Some(temp_artifacts_dir()),
        meta_registry_path: None,
    };

    let event_a = declare_cost(input.clone()).expect("first event");
    let event_b = declare_cost(input).expect("second event");

    assert_eq!(event_a.event_id, event_b.event_id);
}
