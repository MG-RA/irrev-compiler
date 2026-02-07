// Golden Fixtures for std.hash scope
// These tests lock the wire format and ensure deterministic behavior

use admit_core::{
    compute_witness_id, encode_hash_witness, encode_hash_witness_id_payload, hash_bytes,
    hash_value_cbor, verify, HashInput, HashMetadata, HashOperation, HashWitness,
};
use serde_json::json;

// ============================================================================
// Fixture 1: hash_bytes("Hello, Irreversibility!")
// ============================================================================

#[test]
fn fixture_1_hash_bytes_hello_irreversibility() {
    let data = b"Hello, Irreversibility!";
    let witness = hash_bytes(data, "2026-01-01T00:00:00Z".into(), None).unwrap();

    // Golden digest
    assert_eq!(
        witness.digest,
        "e2591a3e8ae381c4595cab8d112fe8d45442b0e1e9ac94365aec5850ef85dfc6"
    );
    assert_eq!(witness.input_size_bytes, 23);
    assert_eq!(witness.algorithm, "sha256");
    assert_eq!(witness.operation, HashOperation::HashBytes);

    // Validate match invariant
    if let HashInput::Bytes { sha256 } = &witness.input {
        assert_eq!(sha256, &witness.digest);
    } else {
        panic!("Expected Bytes input");
    }
}

// ============================================================================
// Fixture 2: JSON value CBOR determinism (key-order independence)
// ============================================================================

#[test]
fn fixture_2_json_value_cbor_determinism() {
    // Same JSON data with different key orderings
    let value1 = json!({"name": "Alice", "age": 30, "city": "NYC"});
    let value2 = json!({"city": "NYC", "name": "Alice", "age": 30});
    let value3 = json!({"age": 30, "city": "NYC", "name": "Alice"});

    let witness1 = hash_value_cbor(&value1, "2026-01-01T00:00:00Z".into(), None).unwrap();
    let witness2 = hash_value_cbor(&value2, "2026-01-01T00:00:00Z".into(), None).unwrap();
    let witness3 = hash_value_cbor(&value3, "2026-01-01T00:00:00Z".into(), None).unwrap();

    // All must produce the same digest (key-order independence)
    assert_eq!(witness1.digest, witness2.digest);
    assert_eq!(witness2.digest, witness3.digest);

    // All must produce the same canonical CBOR hex
    if let HashInput::ValueCbor {
        canonical_cbor_hex: hex1,
    } = &witness1.input
    {
        if let HashInput::ValueCbor {
            canonical_cbor_hex: hex2,
        } = &witness2.input
        {
            if let HashInput::ValueCbor {
                canonical_cbor_hex: hex3,
            } = &witness3.input
            {
                assert_eq!(hex1, hex2);
                assert_eq!(hex2, hex3);
            } else {
                panic!("Expected ValueCbor input");
            }
        } else {
            panic!("Expected ValueCbor input");
        }
    } else {
        panic!("Expected ValueCbor input");
    }

    // Nested objects should also be deterministic
    let nested1 = json!({
        "outer": {"b": 2, "a": 1},
        "data": [1, 2, 3]
    });
    let nested2 = json!({
        "data": [1, 2, 3],
        "outer": {"a": 1, "b": 2}
    });

    let witness_nested1 = hash_value_cbor(&nested1, "2026-01-01T00:00:00Z".into(), None).unwrap();
    let witness_nested2 = hash_value_cbor(&nested2, "2026-01-01T00:00:00Z".into(), None).unwrap();

    assert_eq!(witness_nested1.digest, witness_nested2.digest);
}

// ============================================================================
// Fixture 3: hash_bytes("test")
// ============================================================================

#[test]
fn fixture_3_hash_bytes_test() {
    let data = b"test";
    let witness = hash_bytes(data, "2026-01-01T00:00:00Z".into(), None).unwrap();

    // Golden digest
    assert_eq!(
        witness.digest,
        "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    );
    assert_eq!(witness.input_size_bytes, 4);
}

// ============================================================================
// Fixture 4: Wire format lock (pin exact CBOR hex)
// ============================================================================

#[test]
fn fixture_4_wire_format_lock_hash_witness_id_payload() {
    // Create a known witness
    let witness = HashWitness {
        algorithm: "sha256".into(),
        operation: HashOperation::HashBytes,
        input: HashInput::Bytes {
            sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".into(),
        },
        digest: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08".into(),
        input_size_bytes: 4,
        created_at: "2026-01-01T00:00:00Z".into(),
        metadata: None,
    };

    // Encode HashWitnessIdPayload (5-element array, excludes created_at and metadata)
    let cbor_bytes = encode_hash_witness_id_payload(&witness).unwrap();
    let cbor_hex = hex_encode(&cbor_bytes);

    // GOLDEN WIRE FORMAT LOCK - HashWitnessIdPayload
    // This hex MUST NOT CHANGE - it locks the CBOR encoding rules
    let expected_hex = concat!(
        "85667368613235368100820078403966383664303831383834633764363539613266656161306335356164303135",
        "61336266346631623262306238323263643135643663313562306630306130387840396638366430383138383463",
        "3764363539613266656161306335356164303135613362663466316232623062383232636431356436633135623066",
        "303061303804"
    );

    assert_eq!(
        cbor_hex, expected_hex,
        "CBOR wire format has changed! This breaks all existing hash witnesses."
    );

    // Verify witness_id is deterministic
    let witness_id = compute_witness_id(&witness).unwrap();
    assert_eq!(witness_id.len(), 64); // SHA-256 hex
}

#[test]
fn fixture_4_wire_format_lock_full_hash_witness() {
    // Create a known witness with metadata
    let witness = HashWitness {
        algorithm: "sha256".into(),
        operation: HashOperation::HashValueCbor,
        input: HashInput::ValueCbor {
            canonical_cbor_hex: "a1646e616d65654172746875".into(),
        },
        digest: "0000000000000000000000000000000000000000000000000000000000000000".into(),
        input_size_bytes: 13,
        created_at: "2026-01-15T12:00:00Z".into(),
        metadata: Some(HashMetadata {
            source_ref: Some("test-source".into()),
            purpose: Some("fixture".into()),
        }),
    };

    // Encode full HashWitness (7-element array)
    let cbor_bytes = encode_hash_witness(&witness).unwrap();
    let cbor_hex = hex_encode(&cbor_bytes);

    // GOLDEN WIRE FORMAT LOCK - Full HashWitness with metadata
    let expected_hex = "87667368613235368101820178186131363436653631366436353635343137323734363837357840303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030300d74323032362d30312d31355431323a30303a30305a826b746573742d736f757263656766697874757265";

    assert_eq!(
        cbor_hex, expected_hex,
        "CBOR wire format has changed! This breaks all existing hash witnesses."
    );
}

#[test]
fn fixture_4_wire_format_lock_verify_operation() {
    // Test Verify operation encoding
    let witness = HashWitness {
        algorithm: "sha256".into(),
        operation: HashOperation::Verify {
            expected_digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .into(),
        },
        input: HashInput::Bytes {
            sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        },
        digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        input_size_bytes: 10,
        created_at: "2026-01-01T00:00:00Z".into(),
        metadata: None,
    };

    let cbor_bytes = encode_hash_witness_id_payload(&witness).unwrap();
    let cbor_hex = hex_encode(&cbor_bytes);

    // GOLDEN WIRE FORMAT LOCK - Verify operation
    let expected_hex = "8566736861323536820278406161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616182007840626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262627840626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262620a";

    assert_eq!(
        cbor_hex, expected_hex,
        "CBOR wire format for Verify operation has changed!"
    );
}

// ============================================================================
// Witness ID Determinism Tests
// ============================================================================

#[test]
fn test_witness_id_determinism_hash_bytes() {
    let data = b"test";
    let witness1 = hash_bytes(data, "2026-01-01T00:00:00Z".into(), None).unwrap();
    let witness2 = hash_bytes(
        data,
        "2026-01-01T00:00:00Z".into(),
        Some(HashMetadata {
            source_ref: Some("different".into()),
            purpose: None,
        }),
    )
    .unwrap();

    // witness_id must be the same (metadata doesn't affect it)
    let id1 = compute_witness_id(&witness1).unwrap();
    let id2 = compute_witness_id(&witness2).unwrap();
    assert_eq!(id1, id2, "witness_id must exclude metadata");

    // Run multiple times to verify determinism
    for _ in 0..10 {
        let id = compute_witness_id(&witness1).unwrap();
        assert_eq!(id, id1, "witness_id must be deterministic");
    }
}

#[test]
fn test_witness_id_determinism_hash_value_cbor() {
    let value = json!({"name": "Alice", "age": 30});
    let witness1 = hash_value_cbor(&value, "2026-01-01T00:00:00Z".into(), None).unwrap();
    let witness2 = hash_value_cbor(&value, "2099-12-31T23:59:59Z".into(), None).unwrap();

    // witness_id must be the same (created_at doesn't affect it)
    let id1 = compute_witness_id(&witness1).unwrap();
    let id2 = compute_witness_id(&witness2).unwrap();
    assert_eq!(id1, id2, "witness_id must exclude created_at");

    // Run multiple times to verify determinism
    for _ in 0..10 {
        let id = compute_witness_id(&witness1).unwrap();
        assert_eq!(id, id1, "witness_id must be deterministic");
    }
}

#[test]
fn test_witness_id_determinism_verify() {
    let data = b"test";
    let expected = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

    let witness1 = verify(data, expected, "2026-01-01T00:00:00Z".into(), None).unwrap();
    let witness2 = verify(
        data,
        expected,
        "2026-01-01T00:00:00Z".into(),
        Some(HashMetadata {
            source_ref: Some("test".into()),
            purpose: Some("verification".into()),
        }),
    )
    .unwrap();

    // witness_id must be the same
    let id1 = compute_witness_id(&witness1).unwrap();
    let id2 = compute_witness_id(&witness2).unwrap();
    assert_eq!(id1, id2, "witness_id must exclude metadata");

    // Run multiple times to verify determinism
    for _ in 0..10 {
        let id = compute_witness_id(&witness1).unwrap();
        assert_eq!(id, id1, "witness_id must be deterministic");
    }
}

#[test]
fn test_witness_id_different_for_different_content() {
    let witness1 = hash_bytes(b"test1", "2026-01-01T00:00:00Z".into(), None).unwrap();
    let witness2 = hash_bytes(b"test2", "2026-01-01T00:00:00Z".into(), None).unwrap();

    let id1 = compute_witness_id(&witness1).unwrap();
    let id2 = compute_witness_id(&witness2).unwrap();

    assert_ne!(
        id1, id2,
        "Different inputs must produce different witness_ids"
    );
}

// ============================================================================
// Helper Functions
// ============================================================================

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
