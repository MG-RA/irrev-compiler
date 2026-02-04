// Golden Fixtures for scope:encode.canonical@0
// These tests lock the wire format and ensure deterministic canonical CBOR encoding

use admit_core::encode_canonical_value;
use serde_json::json;

// ============================================================================
// Fixture 1: Basic types encoding (lock wire format for primitives)
// ============================================================================

#[test]
fn fixture_1_encode_canonical_basic_types() {
    // Null
    let value = json!(null);
    let cbor = encode_canonical_value(&value).unwrap();
    assert_eq!(hex_encode(&cbor), "f6", "null → CBOR 0xF6");

    // Boolean true
    let value = json!(true);
    let cbor = encode_canonical_value(&value).unwrap();
    assert_eq!(hex_encode(&cbor), "f5", "true → CBOR 0xF5");

    // Boolean false
    let value = json!(false);
    let cbor = encode_canonical_value(&value).unwrap();
    assert_eq!(hex_encode(&cbor), "f4", "false → CBOR 0xF4");

    // Integer: 0
    let value = json!(0);
    let cbor = encode_canonical_value(&value).unwrap();
    assert_eq!(hex_encode(&cbor), "00", "0 → CBOR 0x00");

    // Integer: 1
    let value = json!(1);
    let cbor = encode_canonical_value(&value).unwrap();
    assert_eq!(hex_encode(&cbor), "01", "1 → CBOR 0x01");

    // Integer: 23 (largest single-byte positive)
    let value = json!(23);
    let cbor = encode_canonical_value(&value).unwrap();
    assert_eq!(hex_encode(&cbor), "17", "23 → CBOR 0x17");

    // Integer: 24 (requires extra byte)
    let value = json!(24);
    let cbor = encode_canonical_value(&value).unwrap();
    assert_eq!(hex_encode(&cbor), "1818", "24 → CBOR 0x18 0x18");

    // Integer: 42
    let value = json!(42);
    let cbor = encode_canonical_value(&value).unwrap();
    assert_eq!(hex_encode(&cbor), "182a", "42 → CBOR 0x18 0x2A");

    // Integer: 255 (largest u8)
    let value = json!(255);
    let cbor = encode_canonical_value(&value).unwrap();
    assert_eq!(hex_encode(&cbor), "18ff", "255 → CBOR 0x18 0xFF");

    // Integer: 256 (requires u16)
    let value = json!(256);
    let cbor = encode_canonical_value(&value).unwrap();
    assert_eq!(hex_encode(&cbor), "190100", "256 → CBOR 0x19 0x0100");

    // Integer: 1000
    let value = json!(1000);
    let cbor = encode_canonical_value(&value).unwrap();
    assert_eq!(hex_encode(&cbor), "1903e8", "1000 → CBOR 0x19 0x03E8");

    // Integer: -1
    let value = json!(-1);
    let cbor = encode_canonical_value(&value).unwrap();
    assert_eq!(hex_encode(&cbor), "20", "-1 → CBOR 0x20");

    // Integer: -24
    let value = json!(-24);
    let cbor = encode_canonical_value(&value).unwrap();
    assert_eq!(hex_encode(&cbor), "37", "-24 → CBOR 0x37");

    // Integer: -25
    let value = json!(-25);
    let cbor = encode_canonical_value(&value).unwrap();
    assert_eq!(hex_encode(&cbor), "3818", "-25 → CBOR 0x38 0x18");

    // Integer: -100
    let value = json!(-100);
    let cbor = encode_canonical_value(&value).unwrap();
    assert_eq!(hex_encode(&cbor), "3863", "-100 → CBOR 0x38 0x63");

    // String: empty
    let value = json!("");
    let cbor = encode_canonical_value(&value).unwrap();
    assert_eq!(hex_encode(&cbor), "60", "\"\" → CBOR 0x60");

    // String: "test"
    let value = json!("test");
    let cbor = encode_canonical_value(&value).unwrap();
    assert_eq!(
        hex_encode(&cbor),
        "6474657374",
        "\"test\" → CBOR 0x64 + UTF-8"
    );

    // String: "Hello"
    let value = json!("Hello");
    let cbor = encode_canonical_value(&value).unwrap();
    assert_eq!(
        hex_encode(&cbor),
        "6548656c6c6f",
        "\"Hello\" → CBOR 0x65 + UTF-8"
    );

    // Array: empty
    let value = json!([]);
    let cbor = encode_canonical_value(&value).unwrap();
    assert_eq!(hex_encode(&cbor), "80", "[] → CBOR 0x80");

    // Array: [1, 2, 3]
    let value = json!([1, 2, 3]);
    let cbor = encode_canonical_value(&value).unwrap();
    assert_eq!(
        hex_encode(&cbor),
        "83010203",
        "[1,2,3] → CBOR 0x83 0x01 0x02 0x03"
    );

    // Object: empty
    let value = json!({});
    let cbor = encode_canonical_value(&value).unwrap();
    assert_eq!(hex_encode(&cbor), "a0", "empty object → CBOR 0xA0");

    // Object: {"a": 1}
    let value = json!({"a": 1});
    let cbor = encode_canonical_value(&value).unwrap();
    assert_eq!(
        hex_encode(&cbor),
        "a1616101",
        "single entry map → CBOR 0xA1 + key + value"
    );
}

// ============================================================================
// Fixture 2: Map key ordering determinism (key-order independence)
// ============================================================================

#[test]
fn fixture_2_map_key_ordering_determinism() {
    // Test 1: Simple key reordering
    let value1 = json!({"b": 2, "a": 1});
    let value2 = json!({"a": 1, "b": 2});

    let cbor1 = encode_canonical_value(&value1).unwrap();
    let cbor2 = encode_canonical_value(&value2).unwrap();

    assert_eq!(
        cbor1, cbor2,
        "Map key order must not affect canonical encoding"
    );

    // Test 2: Length-first sorting
    // Keys of different lengths: shorter keys come first
    let value = json!({
        "longer_key": 3,
        "b": 2,
        "a": 1
    });
    let cbor = encode_canonical_value(&value).unwrap();

    // Expected order: "a" (len 1), "b" (len 1), "longer_key" (len 10)
    // Within same length, lexicographic: "a" < "b"
    let expected = concat!(
        "a3",       // Map with 3 entries
        "616101",   // "a" (0x61 0x61) → 1 (0x01)
        "616202",   // "b" (0x61 0x62) → 2 (0x02)
        "6a6c6f6e6765725f6b657903" // "longer_key" → 3
    );

    assert_eq!(
        hex_encode(&cbor),
        expected,
        "Keys must be sorted by length first, then lexicographically"
    );

    // Test 3: Multiple different orderings produce same output
    let value1 = json!({"name": "Alice", "age": 30, "city": "NYC"});
    let value2 = json!({"city": "NYC", "name": "Alice", "age": 30});
    let value3 = json!({"age": 30, "city": "NYC", "name": "Alice"});

    let cbor1 = encode_canonical_value(&value1).unwrap();
    let cbor2 = encode_canonical_value(&value2).unwrap();
    let cbor3 = encode_canonical_value(&value3).unwrap();

    assert_eq!(cbor1, cbor2, "Different key orders must produce same CBOR");
    assert_eq!(cbor2, cbor3, "Different key orders must produce same CBOR");

    // Test 4: Nested maps also sorted
    let value1 = json!({
        "outer": {"b": 2, "a": 1},
        "data": [1, 2, 3]
    });
    let value2 = json!({
        "data": [1, 2, 3],
        "outer": {"a": 1, "b": 2}
    });

    let cbor1 = encode_canonical_value(&value1).unwrap();
    let cbor2 = encode_canonical_value(&value2).unwrap();

    assert_eq!(
        cbor1, cbor2,
        "Nested maps must also have deterministic key ordering"
    );
}

// ============================================================================
// Fixture 3: Float rejection (constraint enforcement)
// ============================================================================

#[test]
fn fixture_3_float_rejection() {
    // Test 1: Explicit floats
    let floats = vec![
        json!(3.14),
        json!(0.1),
        json!(-2.5),
        json!(0.00001),
        json!(1.5),
    ];

    for value in floats {
        let result = encode_canonical_value(&value);
        assert!(
            result.is_err(),
            "Float {:?} should be rejected",
            value
        );
        if let Err(err) = result {
            assert!(
                err.0.contains("floats not allowed"),
                "Error message should mention floats: {}",
                err.0
            );
        }
    }

    // Test 2: Floats in nested structures
    let nested_floats = vec![
        json!({"value": 3.14}),
        json!([1, 2, 3.5]),
        json!({"nested": {"value": 0.1}}),
    ];

    for value in nested_floats {
        let result = encode_canonical_value(&value);
        assert!(
            result.is_err(),
            "Nested float in {:?} should be rejected",
            value
        );
    }

    // Test 3: Integer-like floats are allowed (1.0, 2.0, etc.)
    // These are within the FRACTION_TOLERANCE and convert to integers
    let integer_floats = vec![
        json!(1.0),
        json!(0.0),
        json!(-1.0),
        json!(42.0),
    ];

    for value in integer_floats {
        let result = encode_canonical_value(&value);
        assert!(
            result.is_ok(),
            "Integer-like float {:?} should be allowed",
            value
        );
    }
}

// ============================================================================
// Fixture 4: Large nested structures (stress test determinism)
// ============================================================================

#[test]
fn fixture_4_large_nested_structures() {
    // Test 1: Deeply nested objects
    let deep_value = json!({
        "level1": {
            "level2": {
                "level3": {
                    "level4": {
                        "level5": {
                            "value": 42
                        }
                    }
                }
            }
        }
    });

    let cbor1 = encode_canonical_value(&deep_value).unwrap();
    let cbor2 = encode_canonical_value(&deep_value).unwrap();

    assert_eq!(cbor1, cbor2, "Deep nesting must be deterministic");

    // Test 2: Large array
    let large_array = json!((0..100).collect::<Vec<_>>());
    let cbor1 = encode_canonical_value(&large_array).unwrap();
    let cbor2 = encode_canonical_value(&large_array).unwrap();

    assert_eq!(cbor1, cbor2, "Large arrays must be deterministic");

    // Test 3: Complex nested structure with multiple orderings
    let complex1 = json!({
        "users": [
            {"name": "Alice", "age": 30},
            {"name": "Bob", "age": 25}
        ],
        "metadata": {
            "version": 1,
            "timestamp": "2026-01-01T00:00:00Z"
        }
    });

    let complex2 = json!({
        "metadata": {
            "timestamp": "2026-01-01T00:00:00Z",
            "version": 1
        },
        "users": [
            {"age": 30, "name": "Alice"},
            {"age": 25, "name": "Bob"}
        ]
    });

    let cbor1 = encode_canonical_value(&complex1).unwrap();
    let cbor2 = encode_canonical_value(&complex2).unwrap();

    assert_eq!(
        cbor1, cbor2,
        "Complex nested structures must be deterministic regardless of key order"
    );
}

// ============================================================================
// Fixture 5: Edge cases (empty structures, UTF-8, large integers)
// ============================================================================

#[test]
fn fixture_5_edge_cases() {
    // Test 1: Empty structures
    let empty_obj = json!({});
    let cbor_obj = encode_canonical_value(&empty_obj).unwrap();
    assert_eq!(hex_encode(&cbor_obj), "a0", "Empty object");

    let empty_array = json!([]);
    let cbor_array = encode_canonical_value(&empty_array).unwrap();
    assert_eq!(hex_encode(&cbor_array), "80", "Empty array");

    let empty_string = json!("");
    let cbor_string = encode_canonical_value(&empty_string).unwrap();
    assert_eq!(hex_encode(&cbor_string), "60", "Empty string");

    // Test 2: UTF-8 edge cases (emoji, unicode)
    let emoji = json!("Hello 👋");
    let cbor_emoji = encode_canonical_value(&emoji).unwrap();
    assert!(cbor_emoji.len() > 0, "Emoji should encode successfully");

    let unicode = json!("日本語");
    let cbor_unicode = encode_canonical_value(&unicode).unwrap();
    assert!(cbor_unicode.len() > 0, "Unicode should encode successfully");

    let mixed = json!("Test: α β γ δ 🚀");
    let cbor_mixed = encode_canonical_value(&mixed).unwrap();
    assert!(cbor_mixed.len() > 0, "Mixed unicode should encode successfully");

    // Test 3: Large integers (u64 boundaries)
    let max_positive = json!(9007199254740991i64); // 2^53 - 1 (JSON safe integer)
    let cbor_max = encode_canonical_value(&max_positive).unwrap();
    assert!(cbor_max.len() > 0, "Large positive integer should encode");

    let large_negative = json!(-9007199254740991i64);
    let cbor_neg = encode_canonical_value(&large_negative).unwrap();
    assert!(cbor_neg.len() > 0, "Large negative integer should encode");

    // Test 4: Nested empty structures
    let nested_empty = json!({
        "empty_obj": {},
        "empty_array": [],
        "empty_string": ""
    });
    let cbor_nested = encode_canonical_value(&nested_empty).unwrap();
    assert!(cbor_nested.len() > 0, "Nested empty structures should encode");

    // Test 5: Array with mixed types
    let mixed_array = json!([null, true, false, 0, 1, -1, "", "test", [], {}]);
    let cbor_mixed_array = encode_canonical_value(&mixed_array).unwrap();
    assert!(cbor_mixed_array.len() > 0, "Mixed-type array should encode");

    // Test 6: Determinism of edge cases
    for _ in 0..10 {
        let cbor1 = encode_canonical_value(&emoji).unwrap();
        let cbor2 = encode_canonical_value(&emoji).unwrap();
        assert_eq!(cbor1, cbor2, "Edge cases must be deterministic");
    }
}

// ============================================================================
// Witness Identity Determinism Tests (using canonical encoding)
// ============================================================================

#[test]
fn test_canonical_encoding_witness_identity_use_case() {
    // Simulate witness identity computation:
    // witness_id = sha256(canonical_cbor(witness_payload))

    use sha2::{Sha256, Digest};

    // Same payload, different key orders
    let payload1 = json!({
        "algorithm": "sha256",
        "operation": "HashBytes",
        "digest": "abc123"
    });

    let payload2 = json!({
        "digest": "abc123",
        "algorithm": "sha256",
        "operation": "HashBytes"
    });

    let cbor1 = encode_canonical_value(&payload1).unwrap();
    let cbor2 = encode_canonical_value(&payload2).unwrap();

    // Canonical encoding ensures same bytes
    assert_eq!(cbor1, cbor2, "Canonical encoding must normalize key order");

    // Compute witness_id (sha256 of canonical CBOR)
    let mut hasher1 = Sha256::new();
    hasher1.update(&cbor1);
    let witness_id1 = hasher1.finalize();

    let mut hasher2 = Sha256::new();
    hasher2.update(&cbor2);
    let witness_id2 = hasher2.finalize();

    assert_eq!(
        witness_id1, witness_id2,
        "Witness IDs must be identical for same payload regardless of key order"
    );

    // Verify determinism across multiple encodings
    for _ in 0..10 {
        let cbor = encode_canonical_value(&payload1).unwrap();
        assert_eq!(cbor, cbor1, "Encoding must be deterministic");
    }
}

// ============================================================================
// Wire Format Lock (pin exact CBOR bytes for critical structures)
// ============================================================================

#[test]
fn test_wire_format_lock_simple_map() {
    // GOLDEN WIRE FORMAT LOCK - Simple map {"a": 1}
    // This hex MUST NOT CHANGE - it locks the CBOR encoding rules
    let value = json!({"a": 1});
    let cbor = encode_canonical_value(&value).unwrap();
    let cbor_hex = hex_encode(&cbor);

    const EXPECTED_HEX: &str = "a1616101";
    // Breakdown:
    // a1 - map with 1 entry
    // 61 - text string major type with length 1
    // 61 - the byte value 'a' (0x61)
    // 01 - integer 1

    assert_eq!(
        cbor_hex, EXPECTED_HEX,
        "CBOR wire format has changed! This breaks all existing witnesses."
    );
}

#[test]
fn test_wire_format_lock_sorted_map() {
    // GOLDEN WIRE FORMAT LOCK - Map with sorted keys
    let value = json!({"b": 2, "a": 1});
    let cbor = encode_canonical_value(&value).unwrap();
    let cbor_hex = hex_encode(&cbor);

    const EXPECTED_HEX: &str = "a2616101616202";
    // Breakdown:
    // a2 - map with 2 entries
    // 61 61 01 - "a" → 1
    // 61 62 02 - "b" → 2
    // Note: "a" comes before "b" (lexicographic)

    assert_eq!(
        cbor_hex, EXPECTED_HEX,
        "CBOR wire format for sorted maps has changed!"
    );
}

#[test]
fn test_wire_format_lock_nested_structure() {
    // GOLDEN WIRE FORMAT LOCK - Nested structure
    let value = json!({
        "name": "test",
        "value": 42,
        "data": [1, 2, 3]
    });
    let cbor = encode_canonical_value(&value).unwrap();
    let cbor_hex = hex_encode(&cbor);

    const EXPECTED_HEX: &str = "a3646461746183010203646e616d6564746573746576616c7565182a";
    // Breakdown:
    // a3 - map with 3 entries
    // Keys sorted by length then lexicographically:
    // - "data" (len 4)
    // - "name" (len 4)
    // - "value" (len 5)

    assert_eq!(
        cbor_hex, EXPECTED_HEX,
        "CBOR wire format for nested structures has changed!"
    );
}

// ============================================================================
// Helper Functions
// ============================================================================

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
