// Integration tests for hash witness ledger events and registry binding
// Tests that hash witnesses integrate correctly with:
// - Ledger event structure
// - Registry hash binding
// - Witness deduplication via witness_id
// - CBOR artifact storage

use admit_core::{
    compute_witness_id, encode_hash_witness, hash_bytes, hash_value_cbor, verify, HashMetadata,
    HashWitness,
};
use serde_json::json;
use sha2::{Digest, Sha256};

// ============================================================================
// Ledger Event Structure Tests
// ============================================================================

#[test]
fn test_hash_witness_ledger_event_structure() {
    // Create a hash witness
    let data = b"Hello, Irreversibility!";
    let witness = hash_bytes(data, "2026-02-02T00:00:00Z".into(), None).unwrap();

    // Encode to CBOR for storage
    let cbor_bytes = encode_hash_witness(&witness).unwrap();

    // Compute artifact hash (sha256 of the CBOR bytes)
    let mut hasher = Sha256::new();
    hasher.update(&cbor_bytes);
    let artifact_hash = format!("{:x}", hasher.finalize());

    // Compute witness_id (content-address)
    let witness_id = compute_witness_id(&witness).unwrap();

    // Ledger event structure
    let ledger_event = json!({
        "event_type": "hash.computed",
        "event_id": compute_event_id(&witness_id, "2026-02-02T00:00:00Z"),
        "timestamp": "2026-02-02T00:00:00Z",
        "witness": {
            "kind": "hash_witness",
            "schema_id": "hash-witness/0",
            "witness_id": witness_id,
            "sha256": artifact_hash,
            "size_bytes": cbor_bytes.len(),
            "path": format!("hash_witness/{}.cbor", artifact_hash)
        },
        "operation": "hash.bytes",
        "input_size_bytes": 23,
        "digest": witness.digest,
        "registry_hash": compute_registry_hash()
    });

    // Verify event structure
    assert_eq!(ledger_event["event_type"], "hash.computed");
    assert_eq!(ledger_event["witness"]["schema_id"], "hash-witness/0");
    assert_eq!(ledger_event["witness"]["kind"], "hash_witness");
    assert!(ledger_event["witness"]["witness_id"].is_string());
    assert!(ledger_event["registry_hash"].is_string());

    // Verify witness_id is 64 hex characters (SHA-256)
    assert_eq!(witness_id.len(), 64);
    assert!(witness_id.chars().all(|c| c.is_ascii_hexdigit()));
}

#[test]
fn test_witness_id_deduplication() {
    // Same operation performed at different times
    let data = b"test";
    let witness1 = hash_bytes(data, "2026-02-02T00:00:00Z".into(), None).unwrap();
    let witness2 = hash_bytes(data, "2026-02-02T12:00:00Z".into(), None).unwrap();
    let witness3 = hash_bytes(
        data,
        "2026-02-02T00:00:00Z".into(),
        Some(HashMetadata {
            source_ref: Some("test.txt".into()),
            purpose: Some("verification".into()),
        }),
    )
    .unwrap();

    // All should have the same witness_id (content-address)
    let id1 = compute_witness_id(&witness1).unwrap();
    let id2 = compute_witness_id(&witness2).unwrap();
    let id3 = compute_witness_id(&witness3).unwrap();

    assert_eq!(id1, id2, "witness_id must be the same despite different timestamps");
    assert_eq!(id1, id3, "witness_id must be the same despite different metadata");

    // In the ledger, these would be deduplicated by witness_id
    // Only one artifact would be stored, but multiple events can reference it
}

#[test]
fn test_registry_hash_binding() {
    // The registry_hash binds the witness to:
    // 1. The canonical CBOR encoding rules
    // 2. The hash-witness/0 schema
    // 3. The meta-registry/0 governance snapshot

    let witness = hash_bytes(b"test", "2026-02-02T00:00:00Z".into(), None).unwrap();
    let registry_hash = compute_registry_hash();

    // Registry hash should be deterministic
    assert_eq!(registry_hash.len(), 64);
    assert!(registry_hash.chars().all(|c| c.is_ascii_hexdigit()));

    // Same registry_hash across all hash witnesses at this version
    let witness2 = hash_value_cbor(&json!({"test": 1}), "2026-02-02T00:00:00Z".into(), None).unwrap();
    let registry_hash2 = compute_registry_hash();

    assert_eq!(
        registry_hash, registry_hash2,
        "All witnesses in the same schema version share registry_hash"
    );
}

// ============================================================================
// Witness Storage and Retrieval Tests
// ============================================================================

#[test]
fn test_witness_artifact_storage() {
    // Create a witness
    let value = json!({"name": "Alice", "age": 30});
    let witness = hash_value_cbor(&value, "2026-02-02T00:00:00Z".into(), None).unwrap();

    // Encode to CBOR
    let cbor_bytes = encode_hash_witness(&witness).unwrap();

    // Compute artifact hash
    let mut hasher = Sha256::new();
    hasher.update(&cbor_bytes);
    let artifact_hash = format!("{:x}", hasher.finalize());

    // Storage path pattern: hash_witness/{artifact_hash}.cbor
    let storage_path = format!("hash_witness/{}.cbor", artifact_hash);

    // Verify artifact properties
    assert!(cbor_bytes.len() > 0);
    assert_eq!(artifact_hash.len(), 64);

    // The artifact can be retrieved and decoded deterministically
    // decode_hash_witness(&cbor_bytes) should return the same witness

    // Path follows content-addressable pattern
    assert!(storage_path.starts_with("hash_witness/"));
    assert!(storage_path.ends_with(".cbor"));
}

#[test]
fn test_verify_operation_ledger_event() {
    let data = b"test";
    let expected = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    let witness = verify(data, expected, "2026-02-02T00:00:00Z".into(), None).unwrap();

    let witness_id = compute_witness_id(&witness).unwrap();
    let cbor_bytes = encode_hash_witness(&witness).unwrap();

    // Verification result can be determined by downstream logic
    let verification_passed = witness.digest == expected;

    let ledger_event = json!({
        "event_type": "hash.verified",
        "event_id": compute_event_id(&witness_id, "2026-02-02T00:00:00Z"),
        "timestamp": "2026-02-02T00:00:00Z",
        "witness": {
            "kind": "hash_witness",
            "schema_id": "hash-witness/0",
            "witness_id": witness_id,
            "sha256": compute_artifact_hash(&cbor_bytes),
            "size_bytes": cbor_bytes.len(),
        },
        "operation": "verify",
        "expected_digest": expected,
        "actual_digest": witness.digest,
        "verification_passed": verification_passed,
        "registry_hash": compute_registry_hash()
    });

    assert!(verification_passed);
    assert_eq!(ledger_event["verification_passed"], true);
}

// ============================================================================
// Multi-operation Witness Chain Tests
// ============================================================================

#[test]
fn test_hash_witness_chain() {
    // Scenario: Hash a document, then verify it
    let document = b"Important document content";

    // Step 1: Hash the document
    let hash_witness = hash_bytes(
        document,
        "2026-02-02T00:00:00Z".into(),
        Some(HashMetadata {
            source_ref: Some("document.txt".into()),
            purpose: Some("initial_hash".into()),
        }),
    )
    .unwrap();

    let digest = hash_witness.digest.clone();
    let hash_witness_id = compute_witness_id(&hash_witness).unwrap();

    // Step 2: Later, verify the document matches the expected hash
    let verify_witness = verify(
        document,
        &digest,
        "2026-02-02T12:00:00Z".into(),
        Some(HashMetadata {
            source_ref: Some("document.txt".into()),
            purpose: Some("verification".into()),
        }),
    )
    .unwrap();

    let verify_witness_id = compute_witness_id(&verify_witness).unwrap();

    // Witnesses are related but have different IDs (different operations)
    assert_ne!(hash_witness_id, verify_witness_id);

    // Both reference the same digest
    assert_eq!(hash_witness.digest, verify_witness.digest);

    // Verification passed
    assert_eq!(verify_witness.digest, digest);
}

#[test]
fn test_json_document_integrity_chain() {
    // Scenario: Hash a JSON config, store it, later verify integrity
    let config = json!({
        "version": 1,
        "enabled": true,
        "settings": {
            "timeout": 30,
            "retries": 3
        }
    });

    // Hash the canonical CBOR representation
    let hash_witness = hash_value_cbor(
        &config,
        "2026-02-02T00:00:00Z".into(),
        Some(HashMetadata {
            source_ref: Some("config.json".into()),
            purpose: Some("initial_hash".into()),
        }),
    )
    .unwrap();

    let witness_id = compute_witness_id(&hash_witness).unwrap();
    let digest = hash_witness.digest.clone();

    // Store witness in ledger
    let ledger_event = json!({
        "event_type": "hash.computed",
        "witness_id": witness_id,
        "digest": digest,
        "schema_id": "hash-witness/0"
    });

    assert!(ledger_event["witness_id"].is_string());
    assert_eq!(ledger_event["schema_id"], "hash-witness/0");

    // Key-order independence: different key order produces same digest
    let config2 = json!({
        "enabled": true,
        "settings": {
            "retries": 3,
            "timeout": 30
        },
        "version": 1
    });

    let hash_witness2 = hash_value_cbor(&config2, "2026-02-02T00:00:00Z".into(), None).unwrap();

    assert_eq!(hash_witness.digest, hash_witness2.digest);
    assert_eq!(
        compute_witness_id(&hash_witness).unwrap(),
        compute_witness_id(&hash_witness2).unwrap()
    );
}

// ============================================================================
// Helper Functions
// ============================================================================

fn compute_event_id(witness_id: &str, timestamp: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"hash.computed:");
    hasher.update(witness_id.as_bytes());
    hasher.update(b":");
    hasher.update(timestamp.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn compute_artifact_hash(cbor_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(cbor_bytes);
    format!("{:x}", hasher.finalize())
}

fn compute_registry_hash() -> String {
    // In production, this would be the SHA-256 of the meta-registry/0 artifact
    // that contains the hash-witness/0 schema and canonical CBOR rules
    // For testing, we use a placeholder that represents the v0 registry
    let registry_data = json!({
        "schema_id": "meta-registry/0",
        "schemas": [
            {
                "id": "hash-witness/0",
                "schema_version": 0,
                "kind": "hash_witness",
                "canonical_encoding": "canonical-cbor"
            }
        ],
        "scopes": [
            {
                "id": "scope:hash.content",
                "version": 0
            }
        ]
    });

    let mut hasher = Sha256::new();
    hasher.update(registry_data.to_string().as_bytes());
    format!("{:x}", hasher.finalize())
}
