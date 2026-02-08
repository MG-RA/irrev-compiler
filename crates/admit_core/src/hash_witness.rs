// Hash Witness Implementation for std.hash scope
// Schema: hash-witness/0
// Implements deterministic, foundational identity primitives

use crate::error::EvalError;

/// Maximum size for embedded canonical CBOR hex (2 MB of CBOR = 4 MB hex)
const MAX_CANONICAL_CBOR_HEX_LEN: usize = 4 * 1024 * 1024;

// ============================================================================
// Core Types
// ============================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashWitness {
    /// Optional schema identifier for governance attribution.
    pub schema_id: Option<String>,

    /// Optional engine/tool version attribution.
    pub engine_version: Option<String>,

    /// The hash algorithm used (e.g., "sha256")
    pub algorithm: String,

    /// The operation performed
    pub operation: HashOperation,

    /// The input to the hash operation
    pub input: HashInput,

    /// The resulting digest (hex-encoded, lowercase)
    pub digest: String,

    /// Size of the input in bytes
    pub input_size_bytes: u64,

    /// Timestamp when the witness was created (ISO-8601 UTC)
    pub created_at: String,

    /// Optional metadata for traceability
    pub metadata: Option<HashMetadata>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashOperation {
    /// Hash raw bytes directly: hash.bytes(raw_data)
    HashBytes,

    /// Hash canonical CBOR representation: hash.value_cbor(value)
    HashValueCbor,

    /// Verify a digest matches input
    Verify { expected_digest: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HashInput {
    /// Direct byte input (sha256 of the bytes themselves)
    /// The bytes are not included in the witness for size reasons,
    /// only their hash is recorded for verification
    Bytes { sha256: String },

    /// Canonical CBOR value input
    /// The value itself is included since it's already canonical
    ValueCbor { canonical_cbor_hex: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HashMetadata {
    /// Reference to the source artifact that was hashed
    pub source_ref: Option<String>,

    /// Purpose or context of this hash operation
    pub purpose: Option<String>,
}

// ============================================================================
// Validation
// ============================================================================

impl HashWitness {
    /// Validates all invariants for a hash witness
    pub fn validate(&self) -> Result<(), EvalError> {
        // Algorithm support
        if self.algorithm != "sha256" {
            return Err(EvalError(format!(
                "unsupported algorithm: {}",
                self.algorithm
            )));
        }

        // Digest format validation
        if !is_valid_sha256_hex(&self.digest) {
            return Err(EvalError(format!("invalid digest format: {}", self.digest)));
        }

        // Operation-specific validation
        match &self.operation {
            HashOperation::Verify { expected_digest } => {
                if !is_valid_sha256_hex(expected_digest) {
                    return Err(EvalError(format!(
                        "invalid expected_digest format: {}",
                        expected_digest
                    )));
                }
            }
            _ => {}
        }

        // Input validation
        match &self.input {
            HashInput::Bytes { sha256 } => {
                if !is_valid_sha256_hex(sha256) {
                    return Err(EvalError(format!(
                        "invalid input.sha256 format: {}",
                        sha256
                    )));
                }

                // Invariant: For HashBytes and Verify, input.sha256 must match digest
                match &self.operation {
                    HashOperation::HashBytes | HashOperation::Verify { .. } => {
                        if sha256 != &self.digest {
                            return Err(EvalError(format!(
                                "input.sha256 ({}) does not match digest ({})",
                                sha256, self.digest
                            )));
                        }
                    }
                    _ => {}
                }
            }
            HashInput::ValueCbor { canonical_cbor_hex } => {
                // Size limit check
                if canonical_cbor_hex.len() > MAX_CANONICAL_CBOR_HEX_LEN {
                    return Err(EvalError(format!(
                        "canonical_cbor_hex too large: {} bytes (max {})",
                        canonical_cbor_hex.len(),
                        MAX_CANONICAL_CBOR_HEX_LEN
                    )));
                }

                // Must be valid hex
                if !canonical_cbor_hex
                    .chars()
                    .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
                {
                    return Err(EvalError("canonical_cbor_hex must be lowercase hex".into()));
                }
            }
        }

        // Timestamp validation (basic ISO-8601 check)
        if !self.created_at.ends_with('Z') {
            return Err(EvalError(format!(
                "created_at must be ISO-8601 UTC (end with Z): {}",
                self.created_at
            )));
        }

        Ok(())
    }
}

/// Validates that a string is a valid SHA-256 hex digest
fn is_valid_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
}

// ============================================================================
// CBOR Encoding (Manual, Canonical)
// ============================================================================

/// Encodes HashWitnessIdPayload (5-element array) for identity calculation
/// Excludes created_at and metadata to ensure deterministic identity
pub fn encode_hash_witness_id_payload(witness: &HashWitness) -> Result<Vec<u8>, EvalError> {
    let mut buf = Vec::new();

    // CBOR array header (5 items)
    buf.push(0x85);

    // 0: algorithm (text string)
    encode_text(&mut buf, &witness.algorithm);

    // 1: operation (array)
    encode_operation(&mut buf, &witness.operation)?;

    // 2: input (array)
    encode_input(&mut buf, &witness.input)?;

    // 3: digest (text string)
    encode_text(&mut buf, &witness.digest);

    // 4: input_size_bytes (uint)
    encode_uint(&mut buf, witness.input_size_bytes);

    Ok(buf)
}

/// Encodes full HashWitness (7-element array) for storage
pub fn encode_hash_witness(witness: &HashWitness) -> Result<Vec<u8>, EvalError> {
    let mut buf = Vec::new();

    // CBOR array header (7 items)
    buf.push(0x87);

    // 0: algorithm (text string)
    encode_text(&mut buf, &witness.algorithm);

    // 1: operation (array)
    encode_operation(&mut buf, &witness.operation)?;

    // 2: input (array)
    encode_input(&mut buf, &witness.input)?;

    // 3: digest (text string)
    encode_text(&mut buf, &witness.digest);

    // 4: input_size_bytes (uint)
    encode_uint(&mut buf, witness.input_size_bytes);

    // 5: created_at (text string)
    encode_text(&mut buf, &witness.created_at);

    // 6: metadata (HashMetadata array or null)
    encode_metadata(&mut buf, &witness.metadata)?;

    Ok(buf)
}

fn encode_operation(buf: &mut Vec<u8>, op: &HashOperation) -> Result<(), EvalError> {
    match op {
        HashOperation::HashBytes => {
            // [0]
            buf.push(0x81); // array of 1 item
            buf.push(0x00); // variant index 0
        }
        HashOperation::HashValueCbor => {
            // [1]
            buf.push(0x81); // array of 1 item
            buf.push(0x01); // variant index 1
        }
        HashOperation::Verify { expected_digest } => {
            // [2, expected_digest]
            buf.push(0x82); // array of 2 items
            buf.push(0x02); // variant index 2
            encode_text(buf, expected_digest);
        }
    }
    Ok(())
}

fn encode_input(buf: &mut Vec<u8>, input: &HashInput) -> Result<(), EvalError> {
    match input {
        HashInput::Bytes { sha256 } => {
            // [0, sha256_hex]
            buf.push(0x82); // array of 2 items
            buf.push(0x00); // variant index 0
            encode_text(buf, sha256);
        }
        HashInput::ValueCbor { canonical_cbor_hex } => {
            // [1, canonical_cbor_hex]
            buf.push(0x82); // array of 2 items
            buf.push(0x01); // variant index 1
            encode_text(buf, canonical_cbor_hex);
        }
    }
    Ok(())
}

fn encode_metadata(buf: &mut Vec<u8>, metadata: &Option<HashMetadata>) -> Result<(), EvalError> {
    match metadata {
        None => {
            // CBOR null
            buf.push(0xf6);
        }
        Some(meta) => {
            // [source_ref, purpose] - 2-element array
            buf.push(0x82);
            encode_optional_text(buf, &meta.source_ref);
            encode_optional_text(buf, &meta.purpose);
        }
    }
    Ok(())
}

fn encode_text(buf: &mut Vec<u8>, text: &str) {
    encode_major(3, text.len() as u64, buf);
    buf.extend_from_slice(text.as_bytes());
}

fn encode_optional_text(buf: &mut Vec<u8>, text: &Option<String>) {
    match text {
        None => buf.push(0xf6), // CBOR null
        Some(s) => encode_text(buf, s),
    }
}

fn encode_uint(buf: &mut Vec<u8>, value: u64) {
    encode_major(0, value, buf);
}

fn encode_major(major: u8, value: u64, buf: &mut Vec<u8>) {
    if value <= 23 {
        buf.push((major << 5) | value as u8);
    } else if value < 256 {
        buf.push((major << 5) | 24);
        buf.push(value as u8);
    } else if value < 65536 {
        buf.push((major << 5) | 25);
        buf.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value < 4294967296 {
        buf.push((major << 5) | 26);
        buf.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        buf.push((major << 5) | 27);
        buf.extend_from_slice(&(value as u64).to_be_bytes());
    }
}

// ============================================================================
// Witness ID Calculation
// ============================================================================

/// Computes the witness_id = sha256(canonical_cbor(HashWitnessIdPayload))
/// This is the content-address for the witness (excludes created_at and metadata)
pub fn compute_witness_id(witness: &HashWitness) -> Result<String, EvalError> {
    use sha2::{Digest, Sha256};

    let cbor_bytes = encode_hash_witness_id_payload(witness)?;
    let mut hasher = Sha256::new();
    hasher.update(&cbor_bytes);
    let result = hasher.finalize();

    Ok(hex_encode(&result))
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

#[cfg(test)]
fn hex_decode(s: &str) -> Result<Vec<u8>, EvalError> {
    if s.len() % 2 != 0 {
        return Err(EvalError("hex string must have even length".into()));
    }

    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| EvalError(format!("invalid hex character at position {}", i)))
        })
        .collect()
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_valid_sha256_hex() {
        // Valid
        assert!(is_valid_sha256_hex(
            "e2591a3e8ae381c4595cab8d112fe8d45442b0e1e9ac94365aec5850ef85dfc6"
        ));

        // Invalid: too short
        assert!(!is_valid_sha256_hex("abc"));

        // Invalid: too long
        assert!(!is_valid_sha256_hex(
            "e2591a3e8ae381c4595cab8d112fe8d45442b0e1e9ac94365aec5850ef85dfc6ff"
        ));

        // Invalid: uppercase
        assert!(!is_valid_sha256_hex(
            "E2591A3E8AE381C4595CAB8D112FE8D45442B0E1E9AC94365AEC5850EF85DFC6"
        ));

        // Invalid: non-hex character
        assert!(!is_valid_sha256_hex(
            "e2591a3e8ae381c4595cab8d112fe8d45442b0e1e9ac94365aec5850ef85dfcg"
        ));
    }

    #[test]
    fn test_hash_witness_validation() {
        let witness = HashWitness {
            schema_id: None,
            engine_version: None,
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

        assert!(witness.validate().is_ok());
    }

    #[test]
    fn test_hash_witness_validation_digest_mismatch() {
        let witness = HashWitness {
            schema_id: None,
            engine_version: None,
            algorithm: "sha256".into(),
            operation: HashOperation::HashBytes,
            input: HashInput::Bytes {
                sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            },
            digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            input_size_bytes: 4,
            created_at: "2026-01-01T00:00:00Z".into(),
            metadata: None,
        };

        assert!(witness.validate().is_err());
    }

    #[test]
    fn test_encode_operation() {
        let mut buf = Vec::new();

        // HashBytes -> [0]
        encode_operation(&mut buf, &HashOperation::HashBytes).unwrap();
        assert_eq!(buf, vec![0x81, 0x00]);

        buf.clear();

        // HashValueCbor -> [1]
        encode_operation(&mut buf, &HashOperation::HashValueCbor).unwrap();
        assert_eq!(buf, vec![0x81, 0x01]);

        buf.clear();

        // Verify -> [2, expected_digest]
        encode_operation(
            &mut buf,
            &HashOperation::Verify {
                expected_digest: "test".into(),
            },
        )
        .unwrap();
        // 0x82 = array(2), 0x02 = int(2), 0x64 = text(4), "test"
        assert_eq!(buf, vec![0x82, 0x02, 0x64, b't', b'e', b's', b't']);
    }

    #[test]
    fn test_encode_input() {
        let mut buf = Vec::new();

        // Bytes -> [0, sha256_hex]
        encode_input(
            &mut buf,
            &HashInput::Bytes {
                sha256: "ab".into(),
            },
        )
        .unwrap();
        // 0x82 = array(2), 0x00 = int(0), 0x62 = text(2), "ab"
        assert_eq!(buf, vec![0x82, 0x00, 0x62, b'a', b'b']);

        buf.clear();

        // ValueCbor -> [1, canonical_cbor_hex]
        encode_input(
            &mut buf,
            &HashInput::ValueCbor {
                canonical_cbor_hex: "cd".into(),
            },
        )
        .unwrap();
        // 0x82 = array(2), 0x01 = int(1), 0x62 = text(2), "cd"
        assert_eq!(buf, vec![0x82, 0x01, 0x62, b'c', b'd']);
    }

    #[test]
    fn test_hex_encode_decode() {
        let bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let hex = hex_encode(&bytes);
        assert_eq!(hex, "deadbeef");

        let decoded = hex_decode(&hex).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn test_hex_decode_invalid() {
        assert!(hex_decode("zz").is_err());
        assert!(hex_decode("abc").is_err()); // odd length
    }
}
