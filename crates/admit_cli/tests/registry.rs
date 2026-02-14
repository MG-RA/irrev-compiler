use std::path::PathBuf;

use admit_cli::{registry_build, registry_init, DeclareCostError, MetaRegistryV0};
use sha2::Digest;

fn temp_dir(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("admit-registry-{}-{}", label, nanos))
}

fn write_registry(path: &PathBuf, value: serde_json::Value) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create dir");
    }
    let text = serde_json::to_string(&value).expect("serialize registry");
    std::fs::write(path, text).expect("write registry");
}

#[test]
fn registry_init_includes_foundational_scope_bootstrap_entries() {
    let dir = temp_dir("init-foundational");
    let path = dir.join("meta-registry.json");
    registry_init(&path).expect("registry init");
    let bytes = std::fs::read(&path).expect("read registry");
    let registry: MetaRegistryV0 = serde_json::from_slice(&bytes).expect("decode registry");
    for scope_id in [
        "scope:hash.verify",
        "scope:git.snapshot",
        "scope:git.diff",
        "scope:git.provenance",
        "scope:identity.delegate",
        "scope:identity.verify",
        "scope:patch.plan",
    ] {
        assert!(
            registry
                .scopes
                .iter()
                .any(|scope| scope.id == scope_id && scope.version == 0),
            "missing {} in registry_init output",
            scope_id
        );
    }
    for schema_id in [
        "git-snapshot-witness/0",
        "git-diff-witness/0",
        "git-provenance-witness/0",
    ] {
        assert!(
            registry.schemas.iter().any(|schema| schema.id == schema_id),
            "missing {} in registry_init output",
            schema_id
        );
    }
}

fn base_registry_json() -> serde_json::Value {
    serde_json::json!({
        "schema_id": "meta-registry/0",
        "schema_version": 0,
        "registry_version": 0,
        "generated_at": null,
        "stdlib": [
            { "module_id": "module:irrev_std@1" },
            { "module_id": "module:extra@1" }
        ],
        "schemas": [
            { "id": "meta-registry/0", "schema_version": 0, "kind": "meta_registry", "canonical_encoding": "canonical-cbor" },
            { "id": "admissibility-witness/1", "schema_version": 1, "kind": "witness", "canonical_encoding": "canonical-cbor" },
            { "id": "vault-snapshot/0", "schema_version": 0, "kind": "snapshot", "canonical_encoding": "canonical-json" }
        ],
        "scopes": [
            { "id": "scope:main", "version": 0 },
            { "id": "scope:meta.registry", "version": 0 }
        ]
    })
}

#[test]
fn registry_hash_is_order_independent_for_arrays() {
    let dir = temp_dir("order");
    let artifacts_dir = dir.join("artifacts");
    let path_a = dir.join("registry_a.json");
    let path_b = dir.join("registry_b.json");

    let registry_a = base_registry_json();
    let mut registry_b = base_registry_json();

    // Reverse arrays in B to ensure different input order.
    registry_b["stdlib"].as_array_mut().unwrap().reverse();
    registry_b["schemas"].as_array_mut().unwrap().reverse();
    registry_b["scopes"].as_array_mut().unwrap().reverse();

    write_registry(&path_a, registry_a);
    write_registry(&path_b, registry_b);

    let ref_a = registry_build(&path_a, &artifacts_dir).expect("build A");
    let ref_b = registry_build(&path_b, &artifacts_dir).expect("build B");

    assert_eq!(
        ref_a.sha256, ref_b.sha256,
        "registry hash must be order-independent for arrays"
    );
}

#[test]
fn registry_rejects_duplicate_schema_ids() {
    let dir = temp_dir("dup-schema");
    let artifacts_dir = dir.join("artifacts");
    let path = dir.join("registry.json");

    let mut registry = base_registry_json();
    let schemas = registry["schemas"].as_array_mut().unwrap();
    schemas.push(serde_json::json!({
        "id": "vault-snapshot/0",
        "schema_version": 0,
        "kind": "snapshot",
        "canonical_encoding": "canonical-json"
    }));

    write_registry(&path, registry);

    let err = registry_build(&path, &artifacts_dir).expect_err("duplicate schema id");
    match err {
        DeclareCostError::MetaRegistryDuplicateSchemaId(_) => {}
        other => panic!("unexpected error: {}", other),
    }
}

#[test]
fn registry_rejects_duplicate_scope_ids() {
    let dir = temp_dir("dup-scope");
    let artifacts_dir = dir.join("artifacts");
    let path = dir.join("registry.json");

    let mut registry = base_registry_json();
    let scopes = registry["scopes"].as_array_mut().unwrap();
    scopes.push(serde_json::json!({
        "id": "scope:main",
        "version": 0
    }));

    write_registry(&path, registry);

    let err = registry_build(&path, &artifacts_dir).expect_err("duplicate scope id");
    match err {
        DeclareCostError::MetaRegistryDuplicateScopeId(_) => {}
        other => panic!("unexpected error: {}", other),
    }
}

#[test]
fn registry_rejects_duplicate_stdlib_modules() {
    let dir = temp_dir("dup-stdlib");
    let artifacts_dir = dir.join("artifacts");
    let path = dir.join("registry.json");

    let mut registry = base_registry_json();
    let stdlib = registry["stdlib"].as_array_mut().unwrap();
    stdlib.push(serde_json::json!({
        "module_id": "module:irrev_std@1"
    }));

    write_registry(&path, registry);

    let err = registry_build(&path, &artifacts_dir).expect_err("duplicate stdlib module");
    match err {
        DeclareCostError::MetaRegistryDuplicateStdlibModule(_) => {}
        other => panic!("unexpected error: {}", other),
    }
}

#[test]
fn registry_rejects_invalid_canonical_encoding() {
    let dir = temp_dir("bad-encoding");
    let artifacts_dir = dir.join("artifacts");
    let path = dir.join("registry.json");

    let mut registry = base_registry_json();
    registry["schemas"][1]["canonical_encoding"] = serde_json::Value::String("weird".to_string());

    write_registry(&path, registry);

    let err = registry_build(&path, &artifacts_dir).expect_err("invalid encoding");
    match err {
        DeclareCostError::MetaRegistryInvalidCanonicalEncoding(_) => {}
        other => panic!("unexpected error: {}", other),
    }
}

#[test]
fn registry_requires_self_schema_entry() {
    let dir = temp_dir("missing-self");
    let artifacts_dir = dir.join("artifacts");
    let path = dir.join("registry.json");

    let mut registry = base_registry_json();
    let schemas = registry["schemas"].as_array_mut().unwrap();
    schemas.retain(|entry| entry["id"] != "meta-registry/0");

    write_registry(&path, registry);

    let err = registry_build(&path, &artifacts_dir).expect_err("missing self schema");
    match err {
        DeclareCostError::MetaRegistryMissingSelfSchema => {}
        other => panic!("unexpected error: {}", other),
    }
}

// ---------------------------------------------------------------------------
// Determinism: pinned canonical hash for the shipped meta-registry/0
// ---------------------------------------------------------------------------

fn shipped_registry_json() -> serde_json::Value {
    serde_json::json!({
        "schema_id": "meta-registry/0",
        "schema_version": 0,
        "registry_version": 0,
        "generated_at": null,
        "stdlib": [
            { "module_id": "module:irrev_std@1" }
        ],
        "schemas": [
            { "id": "meta-registry/0",        "schema_version": 0, "kind": "meta_registry", "canonical_encoding": "canonical-cbor" },
            { "id": "admissibility-witness/1","schema_version": 1, "kind": "witness",        "canonical_encoding": "canonical-cbor" },
            { "id": "vault-snapshot/0",       "schema_version": 0, "kind": "snapshot",       "canonical_encoding": "canonical-json" },
            { "id": "program-bundle/0",       "schema_version": 0, "kind": "program_bundle", "canonical_encoding": "canonical-json" },
            { "id": "facts-bundle/0",         "schema_version": 0, "kind": "facts_bundle",   "canonical_encoding": "canonical-json" },
            { "id": "plan-witness/2",         "schema_version": 2, "kind": "plan_witness",   "canonical_encoding": "canonical-cbor" },
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

/// Pin: the canonical-CBOR hash of the shipped meta-registry/0 must not change
/// without an intentional registry version bump.
#[test]
fn registry_canonical_hash_is_pinned() {
    let dir = temp_dir("pin");
    let artifacts_dir = dir.join("artifacts");
    let path = dir.join("registry.json");

    write_registry(&path, shipped_registry_json());
    let artifact_ref = registry_build(&path, &artifacts_dir).expect("build shipped registry");

    assert_eq!(
        artifact_ref.sha256, "78737229c3737c4a2fcaa7c0f04f22159bcd1c0e15fbf8c3f1648675b153e3ba",
        "pinned registry hash changed - update pin or bump registry_version"
    );
}

/// Normalization sorts schemas, scopes, and stdlib before encoding.
/// Two stdlib entries supplied in reverse order must yield the same hash
/// as when supplied in sorted order.
#[test]
fn registry_list_order_policy_sorts_before_hash() {
    let dir = temp_dir("list-order");
    let artifacts_dir = dir.join("artifacts");

    let mut sorted = shipped_registry_json();
    sorted["stdlib"] = serde_json::json!([
        { "module_id": "module:irrev_std@1" },
        { "module_id": "module:zzz@1" }
    ]);

    let mut reversed = shipped_registry_json();
    reversed["stdlib"] = serde_json::json!([
        { "module_id": "module:zzz@1" },
        { "module_id": "module:irrev_std@1" }
    ]);
    reversed["schemas"].as_array_mut().unwrap().reverse();
    reversed["scopes"].as_array_mut().unwrap().reverse();

    let path_sorted = dir.join("sorted.json");
    let path_reversed = dir.join("reversed.json");
    write_registry(&path_sorted, sorted);
    write_registry(&path_reversed, reversed);

    let ref_sorted = registry_build(&path_sorted, &artifacts_dir).expect("build sorted");
    let ref_reversed = registry_build(&path_reversed, &artifacts_dir).expect("build reversed");

    assert_eq!(
        ref_sorted.sha256, ref_reversed.sha256,
        "list order policy: sorted and reverse-sorted inputs must produce identical hash"
    );
}

// ---------------------------------------------------------------------------
// Schema gate: refusal for unknown schema_id
// ---------------------------------------------------------------------------

#[test]
fn registry_schema_gate_refuses_unknown_schema() {
    let dir = temp_dir("schema-gate");
    let path = dir.join("registry.json");
    write_registry(&path, shipped_registry_json());

    let bytes = std::fs::read(&path).expect("read registry");
    let registry: MetaRegistryV0 = serde_json::from_slice(&bytes).expect("decode registry");

    // Known schemas must be present
    assert!(registry
        .schemas
        .iter()
        .any(|s| s.id == "admissibility-witness/1"));
    assert!(registry.schemas.iter().any(|s| s.id == "vault-snapshot/0"));
    assert!(registry.schemas.iter().any(|s| s.id == "meta-registry/0"));

    // Unknown schema must be absent
    assert!(!registry
        .schemas
        .iter()
        .any(|s| s.id == "nonexistent-schema/99"));
}

#[test]
fn registry_v1_canonical_hash_from_init_is_pinned() {
    let dir = temp_dir("pin-v1");
    let artifacts_dir = dir.join("artifacts");
    let path = dir.join("meta-registry.json");
    registry_init(&path).expect("registry init");

    let artifact_ref = registry_build(&path, &artifacts_dir).expect("build v1 registry");
    assert_eq!(
        artifact_ref.sha256,
        "77b89745cecd4352898fe67dca13ca872caa6a8a6dcab56b401f20cc947123e4",
        "pinned v1 registry hash changed - update pin or bump registry_version"
    );
}

#[test]
fn default_lens_v0_canonical_hash_is_pinned() {
    let lens_value = serde_json::json!({
        "lens_id": "lens:default@0",
        "version": 0,
        "kind": "default",
    });
    let canonical =
        admit_core::encode_canonical_value(&lens_value).expect("encode default lens canonical");
    let hash = hex::encode(sha2::Sha256::digest(&canonical));
    assert_eq!(
        hash,
        "29fa7bf20f869e1cfbbf0b0299a5a6567262d560133c5f38d9a6502c5b279702",
        "default lens canonical hash changed - this is a governance-level breaking change"
    );
}
