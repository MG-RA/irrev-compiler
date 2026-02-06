use std::path::PathBuf;

use admit_cli::{
    append_checked_event, append_event, append_executed_event, check_cost_declared, declare_cost,
    execute_checked, verify_ledger, DeclareCostInput, ScopeGateMode,
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
    std::env::temp_dir().join(format!("admit-ledger-verify-{}.jsonl", nanos))
}

fn temp_artifacts_dir() -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("admit-artifacts-verify-{}", nanos))
}

#[test]
fn verify_ledger_reports_no_issues_for_valid_chain() {
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
        meta_registry_path: None,
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
        None,
        ScopeGateMode::Warn,
    )
    .expect("check event");
    append_checked_event(&ledger_path, &checked).expect("append checked");

    let executed = execute_checked(
        &ledger_path,
        Some(artifacts_dir.as_path()),
        &checked.event_id,
        "2026-01-01T00:00:00Z".to_string(),
        Some("exec-build".to_string()),
        None,
        ScopeGateMode::Warn,
    )
    .expect("execute event");
    append_executed_event(&ledger_path, &executed).expect("append executed");

    let report = verify_ledger(&ledger_path, Some(artifacts_dir.as_path()))
        .expect("verify ledger");
    assert_eq!(report.issues.len(), 0);

    let _ = std::fs::remove_file(ledger_path);
}

// ---------------------------------------------------------------------------
// Helpers shared by scope-gate and ledger-meaning tests
// ---------------------------------------------------------------------------

fn temp_dir(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("admit-vl-{}-{}", label, nanos))
}

fn write_registry(path: &PathBuf, value: serde_json::Value) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create dir");
    }
    let text = serde_json::to_string(&value).expect("serialize");
    std::fs::write(path, text).expect("write registry");
}

fn full_registry_json() -> serde_json::Value {
    serde_json::json!({
        "schema_id": "meta-registry/0",
        "schema_version": 0,
        "registry_version": 0,
        "stdlib": [{ "module_id": "module:irrev_std@1" }],
        "schemas": [
            { "id": "meta-registry/0",        "schema_version": 0, "kind": "meta_registry", "canonical_encoding": "canonical-cbor" },
            { "id": "admissibility-witness/1","schema_version": 1, "kind": "witness",        "canonical_encoding": "canonical-cbor" },
            { "id": "vault-snapshot/0",       "schema_version": 0, "kind": "snapshot",       "canonical_encoding": "canonical-json" },
            { "id": "program-bundle/0",       "schema_version": 0, "kind": "program_bundle", "canonical_encoding": "canonical-json" },
            { "id": "facts-bundle/0",         "schema_version": 0, "kind": "facts_bundle",   "canonical_encoding": "canonical-json" },
            { "id": "plan-witness/1",         "schema_version": 1, "kind": "plan_witness",   "canonical_encoding": "canonical-cbor" },
            { "id": "select-path-witness/0",  "schema_version": 0, "kind": "witness",        "canonical_encoding": "canonical-cbor" }
        ],
        "scopes": [
            { "id": "scope:meta.registry", "version": 0 },
            { "id": "scope:main",          "version": 0 },
            { "id": "scope:select.path",   "version": 0 }
        ]
    })
}

/// Registry missing scope:main (all schemas present).
fn registry_without_main_scope() -> serde_json::Value {
    serde_json::json!({
        "schema_id": "meta-registry/0",
        "schema_version": 0,
        "registry_version": 0,
        "stdlib": [{ "module_id": "module:irrev_std@1" }],
        "schemas": [
            { "id": "meta-registry/0",        "schema_version": 0, "kind": "meta_registry", "canonical_encoding": "canonical-cbor" },
            { "id": "admissibility-witness/1","schema_version": 1, "kind": "witness",        "canonical_encoding": "canonical-cbor" },
            { "id": "vault-snapshot/0",       "schema_version": 0, "kind": "snapshot",       "canonical_encoding": "canonical-json" },
            { "id": "program-bundle/0",       "schema_version": 0, "kind": "program_bundle", "canonical_encoding": "canonical-json" },
            { "id": "facts-bundle/0",         "schema_version": 0, "kind": "facts_bundle",   "canonical_encoding": "canonical-json" },
            { "id": "plan-witness/1",         "schema_version": 1, "kind": "plan_witness",   "canonical_encoding": "canonical-cbor" },
            { "id": "select-path-witness/0",  "schema_version": 0, "kind": "witness",        "canonical_encoding": "canonical-cbor" }
        ],
        "scopes": [
            { "id": "scope:meta.registry", "version": 0 },
            { "id": "scope:select.path",   "version": 0 }
        ]
    })
}

/// Registry missing admissibility-witness/1 schema (scope:main present).
fn registry_without_witness_schema() -> serde_json::Value {
    serde_json::json!({
        "schema_id": "meta-registry/0",
        "schema_version": 0,
        "registry_version": 0,
        "stdlib": [{ "module_id": "module:irrev_std@1" }],
        "schemas": [
            { "id": "meta-registry/0",        "schema_version": 0, "kind": "meta_registry", "canonical_encoding": "canonical-cbor" },
            { "id": "vault-snapshot/0",       "schema_version": 0, "kind": "snapshot",       "canonical_encoding": "canonical-json" },
            { "id": "program-bundle/0",       "schema_version": 0, "kind": "program_bundle", "canonical_encoding": "canonical-json" },
            { "id": "facts-bundle/0",         "schema_version": 0, "kind": "facts_bundle",   "canonical_encoding": "canonical-json" },
            { "id": "plan-witness/1",         "schema_version": 1, "kind": "plan_witness",   "canonical_encoding": "canonical-cbor" },
            { "id": "select-path-witness/0",  "schema_version": 0, "kind": "witness",        "canonical_encoding": "canonical-cbor" }
        ],
        "scopes": [
            { "id": "scope:meta.registry", "version": 0 },
            { "id": "scope:main",          "version": 0 },
            { "id": "scope:select.path",   "version": 0 }
        ]
    })
}

fn declare_and_append(
    artifacts_dir: &PathBuf,
    ledger_path: &PathBuf,
    registry_path: Option<&PathBuf>,
) -> admit_cli::CostDeclaredEvent {
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
        artifacts_root: Some(artifacts_dir.clone()),
        meta_registry_path: registry_path.cloned(),
    };

    let cost_event = declare_cost(input).expect("declare cost");
    append_event(ledger_path, &cost_event).expect("append cost");
    cost_event
}

// ---------------------------------------------------------------------------
// Scope gate: Warn mode allows unknown scope
// ---------------------------------------------------------------------------

#[test]
fn scope_gate_warn_allows_unknown_scope() {
    let dir = temp_dir("scope-warn");
    let artifacts_dir = dir.join("artifacts");
    let ledger_path = dir.join("ledger.jsonl");

    // Declare with full registry (scope:main present), then check with a
    // registry missing scope:main in Warn mode — must not block.
    let full_reg_path = dir.join("full_registry.json");
    write_registry(&full_reg_path, full_registry_json());
    let cost_event = declare_and_append(&artifacts_dir, &ledger_path, Some(&full_reg_path));

    let restricted_reg_path = dir.join("restricted_registry.json");
    write_registry(&restricted_reg_path, registry_without_main_scope());

    let result = check_cost_declared(
        &ledger_path,
        Some(artifacts_dir.as_path()),
        &cost_event.event_id,
        "2026-01-01T00:00:00Z".to_string(),
        Some("check-build".to_string()),
        None,
        Some(restricted_reg_path.as_path()),
        ScopeGateMode::Warn,
    );

    assert!(
        result.is_ok(),
        "scope gate Warn must not block: {:?}",
        result.err()
    );
}

// ---------------------------------------------------------------------------
// Scope gate: Error mode rejects unknown scope
// ---------------------------------------------------------------------------

#[test]
fn scope_gate_error_rejects_unknown_scope() {
    use admit_cli::DeclareCostError;

    let dir = temp_dir("scope-error");
    let artifacts_dir = dir.join("artifacts");
    let ledger_path = dir.join("ledger.jsonl");

    let full_reg_path = dir.join("full_registry.json");
    write_registry(&full_reg_path, full_registry_json());
    let cost_event = declare_and_append(&artifacts_dir, &ledger_path, Some(&full_reg_path));

    let restricted_reg_path = dir.join("restricted_registry.json");
    write_registry(&restricted_reg_path, registry_without_main_scope());

    let result = check_cost_declared(
        &ledger_path,
        Some(artifacts_dir.as_path()),
        &cost_event.event_id,
        "2026-01-01T00:00:00Z".to_string(),
        Some("check-build".to_string()),
        None,
        Some(restricted_reg_path.as_path()),
        ScopeGateMode::Error,
    );

    match result {
        Err(DeclareCostError::MetaRegistryMissingScopeId(scope)) => {
            assert_eq!(scope, "scope:main");
        }
        other => panic!(
            "scope gate Error must reject unknown scope, got: {:?}",
            other
        ),
    }
}

// ---------------------------------------------------------------------------
// Ledger meaning-at-ingestion: legacy semantics when registry_hash absent
// ---------------------------------------------------------------------------

#[test]
fn verify_ledger_legacy_no_registry_hash_is_clean() {
    let dir = temp_dir("legacy");
    let artifacts_dir = dir.join("artifacts");
    let ledger_path = dir.join("ledger.jsonl");

    // Declare without any registry — event will have registry_hash: null
    let cost_event = declare_and_append(&artifacts_dir, &ledger_path, None);
    assert!(
        cost_event.registry_hash.is_none(),
        "legacy event must have no registry_hash"
    );

    let report =
        verify_ledger(&ledger_path, Some(artifacts_dir.as_path())).expect("verify");
    assert!(
        report.issues.is_empty(),
        "legacy event (no registry_hash) must pass verification: {:?}",
        report.issues
    );
}

// ---------------------------------------------------------------------------
// Ledger drift: verify_ledger catches scope missing from pinned registry
// ---------------------------------------------------------------------------

#[test]
fn verify_ledger_detects_scope_drift() {
    use admit_cli::registry_build;

    let dir = temp_dir("scope-drift");
    let artifacts_dir = dir.join("artifacts");
    let ledger_path = dir.join("ledger.jsonl");

    // Declare with full registry, then patch the ledger to point at a
    // registry missing scope:main.  verify_ledger must flag the drift.
    let full_reg_path = dir.join("full_registry.json");
    write_registry(&full_reg_path, full_registry_json());
    let cost_event = declare_and_append(&artifacts_dir, &ledger_path, Some(&full_reg_path));

    let restricted_reg_path = dir.join("restricted_registry.json");
    write_registry(&restricted_reg_path, registry_without_main_scope());
    let restricted_ref =
        registry_build(&restricted_reg_path, &artifacts_dir).expect("build restricted");

    let ledger_text = std::fs::read_to_string(&ledger_path).expect("read ledger");
    let patched = ledger_text.replace(
        cost_event.registry_hash.as_ref().unwrap().as_str(),
        &restricted_ref.sha256,
    );
    std::fs::write(&ledger_path, patched).expect("write patched ledger");

    let report =
        verify_ledger(&ledger_path, Some(artifacts_dir.as_path())).expect("verify drift");
    let has_scope_issue = report.issues.iter().any(|i| {
        i.message.contains("registry missing scope_id") && i.message.contains("scope:main")
    });
    assert!(
        has_scope_issue,
        "verify_ledger must detect scope drift; issues: {:?}",
        report.issues
    );
}

// ---------------------------------------------------------------------------
// Ledger drift: verify_ledger catches schema missing from pinned registry
// ---------------------------------------------------------------------------

#[test]
fn verify_ledger_detects_schema_drift() {
    use admit_cli::registry_build;

    let dir = temp_dir("schema-drift");
    let artifacts_dir = dir.join("artifacts");
    let ledger_path = dir.join("ledger.jsonl");

    let full_reg_path = dir.join("full_registry.json");
    write_registry(&full_reg_path, full_registry_json());
    let cost_event = declare_and_append(&artifacts_dir, &ledger_path, Some(&full_reg_path));

    // Build a registry missing admissibility-witness/1 schema.
    let no_witness_reg_path = dir.join("no_witness_registry.json");
    write_registry(&no_witness_reg_path, registry_without_witness_schema());
    let no_witness_ref =
        registry_build(&no_witness_reg_path, &artifacts_dir).expect("build no-witness registry");

    let ledger_text = std::fs::read_to_string(&ledger_path).expect("read ledger");
    let patched = ledger_text.replace(
        cost_event.registry_hash.as_ref().unwrap().as_str(),
        &no_witness_ref.sha256,
    );
    std::fs::write(&ledger_path, patched).expect("write patched ledger");

    let report =
        verify_ledger(&ledger_path, Some(artifacts_dir.as_path())).expect("verify schema drift");
    let has_schema_issue = report.issues.iter().any(|i| {
        i.message.contains("registry missing schema_id")
            && i.message.contains("admissibility-witness/1")
    });
    assert!(
        has_schema_issue,
        "verify_ledger must detect schema drift; issues: {:?}",
        report.issues
    );
}
