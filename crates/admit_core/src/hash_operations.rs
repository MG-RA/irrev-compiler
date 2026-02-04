// Hash Operations for std.hash scope
// Implements the three deterministic hash operations:
// 1. hash_bytes - Hash raw bytes
// 2. hash_value_cbor - Hash canonical CBOR of JSON value
// 3. verify - Verify bytes match expected digest

use crate::cbor::encode_canonical_value;
use crate::error::EvalError;
use crate::hash_witness::{HashInput, HashMetadata, HashOperation, HashWitness};
use serde_json::Value;
use sha2::{Digest, Sha256};

const MAX_INPUT_SIZE: usize = 100 * 1024 * 1024;
const MAX_CANONICAL_CBOR_HEX_LEN: usize = 4 * 1024 * 1024;

// ============================================================================
// Operation 1: hash.bytes - Hash raw bytes directly
// ============================================================================

/// Hash raw bytes directly with SHA-256
///
/// Properties:
/// - Fully deterministic
/// - No environment dependencies
/// - Constant-time operation (linear in input size)
pub fn hash_bytes(
    data: &[u8],
    created_at: String,
    metadata: Option<HashMetadata>,
) -> Result<HashWitness, EvalError> {
    // Size limit check
    if data.len() > MAX_INPUT_SIZE {
        return Err(EvalError(format!(
            "input too large: {} bytes (max {})",
            data.len(),
            MAX_INPUT_SIZE
        )));
    }

    // Compute SHA-256
    let mut hasher = Sha256::new();
    hasher.update(data);
    let digest_bytes = hasher.finalize();
    let digest = hex_encode(&digest_bytes);

    let witness = HashWitness {
        algorithm: "sha256".into(),
        operation: HashOperation::HashBytes,
        input: HashInput::Bytes {
            sha256: digest.clone(), // Redundant but required by schema
        },
        digest,
        input_size_bytes: data.len() as u64,
        created_at,
        metadata,
    };

    // Validate invariants
    witness.validate()?;

    Ok(witness)
}

// ============================================================================
// Operation 2: hash.value_cbor - Hash canonical CBOR of structured value
// ============================================================================

/// Hash the canonical CBOR representation of a structured JSON value
///
/// Properties:
/// - Deterministic canonicalization via CBOR (not JSON!)
/// - Suitable for hashing structured data (objects, arrays)
/// - Maps are sorted by key (encoded bytes)
/// - **Rejects floats** - only integer numbers allowed
pub fn hash_value_cbor(
    value: &Value,
    created_at: String,
    metadata: Option<HashMetadata>,
) -> Result<HashWitness, EvalError> {
    // Validate: reject floats
    validate_no_floats(value)?;

    // Encode to canonical CBOR
    let cbor_bytes = encode_canonical_value(value)?;

    // Size limit check
    if cbor_bytes.len() > MAX_INPUT_SIZE {
        return Err(EvalError(format!(
            "canonical CBOR too large: {} bytes (max {})",
            cbor_bytes.len(),
            MAX_INPUT_SIZE
        )));
    }

    // Hex encode for storage
    let canonical_cbor_hex = hex_encode(&cbor_bytes);

    // Check hex size limit (2 MB CBOR = 4 MB hex)
    if canonical_cbor_hex.len() > MAX_CANONICAL_CBOR_HEX_LEN {
        return Err(EvalError(format!(
            "canonical_cbor_hex too large: {} bytes (max {})",
            canonical_cbor_hex.len(),
            MAX_CANONICAL_CBOR_HEX_LEN
        )));
    }

    // Compute SHA-256 of the canonical CBOR bytes
    let mut hasher = Sha256::new();
    hasher.update(&cbor_bytes);
    let digest_bytes = hasher.finalize();
    let digest = hex_encode(&digest_bytes);

    let witness = HashWitness {
        algorithm: "sha256".into(),
        operation: HashOperation::HashValueCbor,
        input: HashInput::ValueCbor { canonical_cbor_hex },
        digest,
        input_size_bytes: cbor_bytes.len() as u64,
        created_at,
        metadata,
    };

    // Validate invariants
    witness.validate()?;

    Ok(witness)
}

/// Validates that a JSON value contains no floats
fn validate_no_floats(value: &Value) -> Result<(), EvalError> {
    match value {
        Value::Number(num) => {
            if num.is_f64() {
                // Check if it's actually a float (has fractional part)
                if let Some(f) = num.as_f64() {
                    if !f.is_finite() || f.fract().abs() > 1e-9 {
                        return Err(EvalError(format!(
                            "floats not allowed in hash.value_cbor: {}",
                            f
                        )));
                    }
                }
            }
            Ok(())
        }
        Value::Array(items) => {
            for item in items {
                validate_no_floats(item)?;
            }
            Ok(())
        }
        Value::Object(map) => {
            for value in map.values() {
                validate_no_floats(value)?;
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

// ============================================================================
// Operation 3: verify - Verify digest matches data (constant-time)
// ============================================================================

/// Verify that data matches an expected digest using constant-time comparison
///
/// Properties:
/// - Constant-time comparison (prevents timing attacks)
/// - Returns witness regardless of match result
/// - Verdict determined by separate admissibility check
///
/// Security:
/// - expected_digest MUST be lowercase hex, exactly 64 chars
/// - Comparison is done on decoded bytes, not strings
/// - Uses constant-time equality to prevent timing side-channels
pub fn verify(
    data: &[u8],
    expected_digest: &str,
    created_at: String,
    metadata: Option<HashMetadata>,
) -> Result<HashWitness, EvalError> {
    // Size limit check
    if data.len() > MAX_INPUT_SIZE {
        return Err(EvalError(format!(
            "input too large: {} bytes (max {})",
            data.len(),
            MAX_INPUT_SIZE
        )));
    }

    // Validate expected_digest format
    if !is_valid_sha256_hex(expected_digest) {
        return Err(EvalError(format!(
            "invalid expected_digest format: {}",
            expected_digest
        )));
    }

    // Compute actual digest
    let mut hasher = Sha256::new();
    hasher.update(data);
    let actual_digest_bytes = hasher.finalize();
    let actual_digest = hex_encode(&actual_digest_bytes);

    // Decode expected digest to bytes
    let expected_digest_bytes = hex_decode(expected_digest)?;

    // Constant-time comparison (result not stored in witness)
    let matches = constant_time_eq(&actual_digest_bytes, &expected_digest_bytes);

    // Note: We don't use the match result in the witness structure.
    // The witness is pure evidence; downstream admissibility logic
    // can check: witness.digest == witness.operation.expected_digest
    let _ = matches; // Explicitly ignore to show this is intentional

    let witness = HashWitness {
        algorithm: "sha256".into(),
        operation: HashOperation::Verify {
            expected_digest: expected_digest.to_string(),
        },
        input: HashInput::Bytes {
            sha256: actual_digest.clone(), // Redundant but required by schema
        },
        digest: actual_digest,
        input_size_bytes: data.len() as u64,
        created_at,
        metadata,
    };

    // Validate invariants
    witness.validate()?;

    Ok(witness)
}

/// Constant-time equality comparison using subtle crate patterns
/// Prevents timing side-channel attacks
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}

// ============================================================================
// Helper Functions
// ============================================================================

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn hex_decode(s: &str) -> Result<Vec<u8>, EvalError> {
    if s.len() % 2 != 0 {
        return Err(EvalError("hex string must have even length".into()));
    }

    if s.len() != 64 {
        return Err(EvalError(format!(
            "SHA-256 digest must be exactly 64 hex characters, got {}",
            s.len()
        )));
    }

    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| EvalError(format!("invalid hex character at position {}", i)))
        })
        .collect()
}

fn is_valid_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_hash_bytes_hello_irreversibility() {
        let data = b"Hello, Irreversibility!";
        let witness = hash_bytes(data, "2026-01-01T00:00:00Z".into(), None).unwrap();

        // Golden fixture: Fixture 1
        assert_eq!(
            witness.digest,
            "e2591a3e8ae381c4595cab8d112fe8d45442b0e1e9ac94365aec5850ef85dfc6"
        );
        assert_eq!(witness.input_size_bytes, 23);
        assert_eq!(witness.algorithm, "sha256");

        // Validate match invariant
        if let HashInput::Bytes { sha256 } = &witness.input {
            assert_eq!(sha256, &witness.digest);
        } else {
            panic!("Expected Bytes input");
        }
    }

    #[test]
    fn test_hash_bytes_test() {
        let data = b"test";
        let witness = hash_bytes(data, "2026-01-01T00:00:00Z".into(), None).unwrap();

        // Golden fixture: Fixture 3
        assert_eq!(
            witness.digest,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );
        assert_eq!(witness.input_size_bytes, 4);
    }

    #[test]
    fn test_hash_value_cbor_integers_only() {
        let value = json!({"name": "Alice", "age": 30});
        let witness = hash_value_cbor(&value, "2026-01-01T00:00:00Z".into(), None).unwrap();

        assert_eq!(witness.algorithm, "sha256");
        assert_eq!(witness.operation, HashOperation::HashValueCbor);
    }

    #[test]
    fn test_hash_value_cbor_rejects_floats() {
        let value = json!({"name": "Alice", "score": 3.14});
        let result = hash_value_cbor(&value, "2026-01-01T00:00:00Z".into(), None);

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .0
            .contains("floats not allowed in hash.value_cbor"));
    }

    #[test]
    fn test_hash_value_cbor_nested_float_rejection() {
        let value = json!({
            "data": {
                "values": [1, 2, 3.5]
            }
        });
        let result = hash_value_cbor(&value, "2026-01-01T00:00:00Z".into(), None);

        assert!(result.is_err());
    }

    #[test]
    fn test_verify_matching_digest() {
        let data = b"test";
        let expected = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";

        let witness = verify(data, expected, "2026-01-01T00:00:00Z".into(), None).unwrap();

        assert_eq!(witness.digest, expected);
        if let HashOperation::Verify { expected_digest } = &witness.operation {
            assert_eq!(expected_digest, expected);
            assert_eq!(&witness.digest, expected_digest); // Match!
        } else {
            panic!("Expected Verify operation");
        }
    }

    #[test]
    fn test_verify_mismatching_digest() {
        let data = b"test";
        let expected = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

        let witness = verify(data, expected, "2026-01-01T00:00:00Z".into(), None).unwrap();

        // Witness is still produced
        assert_eq!(
            witness.digest,
            "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
        );

        if let HashOperation::Verify { expected_digest } = &witness.operation {
            assert_eq!(expected_digest, expected);
            assert_ne!(&witness.digest, expected_digest); // Mismatch!
        } else {
            panic!("Expected Verify operation");
        }
    }

    #[test]
    fn test_verify_invalid_hex() {
        let data = b"test";

        // Uppercase
        let result = verify(
            data,
            "9F86D081884C7D659A2FEAA0C55AD015A3BF4F1B2B0B822CD15D6C15B0F00A08",
            "2026-01-01T00:00:00Z".into(),
            None,
        );
        assert!(result.is_err());

        // Wrong length
        let result = verify(data, "abc", "2026-01-01T00:00:00Z".into(), None);
        assert!(result.is_err());

        // Non-hex
        let result = verify(
            data,
            "gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg",
            "2026-01-01T00:00:00Z".into(),
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_constant_time_eq() {
        let a = vec![1, 2, 3, 4];
        let b = vec![1, 2, 3, 4];
        let c = vec![1, 2, 3, 5];
        let d = vec![1, 2, 3];

        assert!(constant_time_eq(&a, &b));
        assert!(!constant_time_eq(&a, &c));
        assert!(!constant_time_eq(&a, &d));
    }
}
