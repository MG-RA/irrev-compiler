use std::path::PathBuf;

use admit_cli::{
    append_checked_event, append_event, append_executed_event, check_cost_declared, declare_cost,
    execute_checked, DeclareCostInput,
};
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
    std::fs::read(golden_path(name)).expect("read golden file")
}

fn read_hash(name: &str) -> String {
    std::fs::read_to_string(golden_path(name))
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

fn temp_ledger_path() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("admit-ledger-exec-{}.jsonl", nanos))
}

fn temp_artifacts_dir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("admit-artifacts-exec-{}", nanos))
}

#[test]
fn execute_appends_admissibility_executed_event() {
    let witness_json = read_bytes("allow-erasure-trigger.json");
    let hash = read_hash("allow-erasure-trigger.cbor.sha256");
    let artifacts_dir = temp_artifacts_dir();
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
        artifacts_root: Some(artifacts_dir.clone()),
    };

    let cost_event = declare_cost(input).expect("cost event");
    let ledger_path = temp_ledger_path();
    append_event(&ledger_path, &cost_event).expect("append cost");

    let checked = check_cost_declared(
        &ledger_path,
        Some(artifacts_dir.as_path()),
        &cost_event.event_id,
        "2026-01-01T00:00:00Z".to_string(),
        Some("check-build".to_string()),
        None,
    )
    .expect("check event");
    append_checked_event(&ledger_path, &checked).expect("append checked");

    let executed = execute_checked(
        &ledger_path,
        Some(artifacts_dir.as_path()),
        &checked.event_id,
        "2026-01-01T00:00:00Z".to_string(),
        Some("exec-build".to_string()),
    )
    .expect("execute event");
    append_executed_event(&ledger_path, &executed).expect("append executed");

    let contents = std::fs::read_to_string(&ledger_path).expect("read ledger");
    let lines: Vec<_> = contents.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 3);

    let event: serde_json::Value =
        serde_json::from_str(lines[2]).expect("parse executed event");
    assert_eq!(
        event.get("event_type").and_then(|v| v.as_str()),
        Some("admissibility.executed")
    );
    assert_eq!(
        event.get("admissibility_checked_event_id")
            .and_then(|v| v.as_str()),
        Some(checked.event_id.as_str())
    );
    assert_eq!(
        event.get("cost_declared_event_id")
            .and_then(|v| v.as_str()),
        Some(cost_event.event_id.as_str())
    );

    let _ = std::fs::remove_file(ledger_path);
}
