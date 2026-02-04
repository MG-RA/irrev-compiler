# Hash Witness Schema v0

**Schema ID:** `hash-witness/0`
**Canonical Encoding:** `canonical-cbor`
**Kind:** `witness`
**Scope:** `scope:hash.content@0`
**Phase:** P0 (observation/determinism)

---

## Purpose

The hash witness schema defines the deterministic evidence artifact produced by hash operations in the `std.hash` scope. Hash witnesses serve as foundational identity primitives for all content-addressed artifacts in the Irreversibility system.

---

## Schema Structure

### HashWitness

```rust
pub struct HashWitness {
    /// The hash algorithm used (e.g., "sha256")
    pub algorithm: String,

    /// The operation performed
    pub operation: HashOperation,

    /// The input to the hash operation
    pub input: HashInput,

    /// The resulting digest (hex-encoded)
    pub digest: String,

    /// Size of the input in bytes
    pub input_size_bytes: u64,

    /// Timestamp when the witness was created (ISO-8601)
    pub created_at: String,

    /// Optional metadata for traceability
    pub metadata: Option<HashMetadata>,
}

pub enum HashOperation {
    /// Hash raw bytes directly: hash.bytes(raw_data)
    HashBytes,

    /// Hash canonical CBOR representation: hash.value_cbor(value)
    HashValueCbor,

    /// Verify a digest matches input
    Verify { expected_digest: String },
}

pub enum HashInput {
    /// Direct byte input (sha256 of the bytes themselves)
    /// The bytes are not included in the witness for size reasons,
    /// only their hash is recorded for verification
    Bytes { sha256: String },

    /// Canonical CBOR value input
    /// The value itself is included since it's already canonical
    ValueCbor { canonical_cbor_hex: String },
}

pub struct HashMetadata {
    /// Reference to the source artifact that was hashed
    pub source_ref: Option<String>,

    /// Purpose or context of this hash operation
    pub purpose: Option<String>,
}
```

---

## Canonical CBOR Wire Format

Following RFC 8949 canonical CBOR specification with **explicit wire format** to prevent encoding drift:

### Struct Encoding: CBOR Arrays (Positional)

All structs are encoded as **CBOR arrays** (major type 4) with fixed positions. This eliminates key-sorting ambiguity and makes encoding deterministic.

**HashWitness** CBOR array positions:
```
[
  0: algorithm (string),
  1: operation (array, see below),
  2: input (array, see below),
  3: digest (string, lowercase hex),
  4: input_size_bytes (uint),
  5: created_at (string, ISO-8601 UTC),
  6: metadata (HashMetadata array or null)
]
```

**HashMetadata** CBOR array positions:
```
[
  0: source_ref (string or null),
  1: purpose (string or null)
]
```

### Enum Encoding: CBOR Arrays (Variant Index + Data)

**HashOperation** CBOR array encoding:
```
[0] = HashBytes
[1] = HashValueCbor
[2, expected_digest] = Verify { expected_digest: string }
```

**HashInput** CBOR array encoding:
```
[0, sha256_hex] = Bytes { sha256: string }
[1, canonical_cbor_hex] = ValueCbor { canonical_cbor_hex: string }
```

### CBOR Type Rules

1. **Minimal Representation:**
   - Integers use smallest possible encoding (uint8, uint16, etc.)
   - Strings use major type 3 (UTF-8 text string)
   - Arrays use major type 4
   - No major type 5 (maps) for structs/enums
   - No CBOR tags (major type 6) for witness structures

2. **Type Constraints:**
   - No floating-point numbers (prevents ambiguous representation)
   - All strings must be valid UTF-8
   - All hex strings must be lowercase
   - Timestamps in ISO-8601 UTC format (e.g., "2026-02-02T00:00:00Z")

3. **Optional Fields:**
   - `None` values encoded as CBOR null (`0xf6`)
   - `Some(value)` encoded as the value directly (no wrapper)

4. **Map Key Sorting (for JSON value encoding):**
   - Maps MUST be encoded as CBOR maps (major type 5) with keys sorted by their encoded CBOR byte sequence
   - Sorting: first by byte length, then lexicographically (bytewise)
   - Since JSON object keys are text strings, this reduces to sorting by UTF-8 byte length, then lexicographic over UTF-8 bytes
   - Example: keys `"id"` (2 bytes) sorts before `"name"` (4 bytes) sorts before `"tags"` (4 bytes, lexicographically after "name")

---

## Identity Property

The witness identity is defined as:

```
witness_id = sha256(canonical_cbor(HashWitnessIdPayload))
```

Where `HashWitnessIdPayload` is `HashWitness` **excluding** `created_at` and `metadata`:

```
HashWitnessIdPayload CBOR array:
[
  0: algorithm,
  1: operation,
  2: input,
  3: digest,
  4: input_size_bytes
]
```

**Critical:** The identity hash is computed over the canonical CBOR encoding of this exact 5-element array. No `created_at`, no `metadata`, no trailing nulls, no CBOR tags. Implementations MUST NOT reuse the full `HashWitness` encoding and "skip fields" - the identity payload is a distinct, smaller array structure.

**Rationale:** `created_at` provides provenance context but does not affect identity. Same operation on same input must produce same `witness_id` regardless of when it was performed. This makes witnesses true identity primitives.

This ensures:
- Same inputs → same witness → same witness_id (deterministic)
- Witness artifacts are self-certifying
- Witness_id can be used as a content address in ledger events
- Timestamps track emission context without breaking identity

---

## Operations

### 1. hash.bytes(raw_data) → HashWitness

**Purpose:** Hash raw bytes directly with SHA-256

**Input:** Arbitrary byte array

**Output:** HashWitness with:
- `algorithm`: "sha256"
- `operation`: `HashOperation::HashBytes`
- `input`: `HashInput::Bytes { sha256: hex(sha256(raw_data)) }`
- `digest`: `hex(sha256(raw_data))`
- `input_size_bytes`: `len(raw_data)`

**Properties:**
- Fully deterministic
- No environment dependencies
- Constant-time operation (linear in input size)

**Example:**
```rust
let data = b"Hello, Irreversibility!";
let witness = hash_bytes(data);
// witness.digest == "e2591a3e8ae381c4595cab8d112fe8d45442b0e1e9ac94365aec5850ef85dfc6"
```

---

### 2. hash.value_cbor(value) → HashWitness

**Purpose:** Hash the canonical CBOR representation of a structured value

**Input:** JSON-compatible value (will be encoded as canonical CBOR)

**Output:** HashWitness with:
- `algorithm`: "sha256"
- `operation`: `HashOperation::HashValueCbor`
- `input`: `HashInput::ValueCbor { canonical_cbor_hex: hex(canonical_cbor(value)) }`
- `digest`: `hex(sha256(canonical_cbor(value)))`
- `input_size_bytes`: `len(canonical_cbor(value))`

**Properties:**
- Deterministic canonicalization via CBOR (not JSON!)
- Suitable for hashing structured data (objects, arrays)
- Maps are sorted by key (encoded bytes)

**Type Restrictions:**
- **Numbers MUST be integers only:** `serde_json::Number` values MUST be representable as i64 or u64
- **Floats are rejected:** Any non-integer number (including JSON floats like `1.5`, `3.14`, etc.) MUST cause an error
- This prevents ambiguous CBOR encoding and maintains determinism
- Rationale: Floating-point representations are not canonical (precision, rounding, NaN/Inf handling)

**Size Limits:**
- `canonical_cbor_hex` field is limited to 2 MB of encoded CBOR bytes (4 MB hex string)
- Larger values MUST be rejected or stored as external artifacts (referenced via `metadata.source_ref`)
- This prevents witness bloat and ledger storage abuse

**Example:**
```rust
let value = json!({"name": "Alice", "age": 30});  // age is integer: OK
let witness = hash_value_cbor(&value);
// witness.digest == "4f2a..." (deterministic, order-independent)

let bad_value = json!({"name": "Alice", "score": 3.14});  // score is float: ERROR
```

---

### 3. verify(raw_data, expected_digest) → HashWitness

**Purpose:** Verify that data matches an expected digest

**Input:**
- Byte array to verify
- Expected digest (hex string)

**Output:** HashWitness with:
- `algorithm`: "sha256"
- `operation`: `HashOperation::Verify { expected_digest }`
- `input`: `HashInput::Bytes { sha256: hex(sha256(raw_data)) }`
- `digest`: `hex(sha256(raw_data))`
- Match result embedded in verdict (separate from witness structure)

**Properties:**
- Constant-time comparison (prevents timing attacks)
- Returns witness regardless of match result
- Verdict determined by separate admissibility check

**Security Requirements:**

1. **Hex validation:**
   - `expected_digest` MUST be lowercase hex (`[0-9a-f]` only)
   - MUST be exactly 64 characters (32 bytes for SHA-256)
   - Invalid hex or wrong length MUST cause an error (not silent mismatch)

2. **Constant-time comparison:**
   - Decode `expected_digest` hex to `[u8; 32]`
   - Compute actual digest as `[u8; 32]`
   - Compare bytes using constant-time equality (e.g., `subtle::ConstantTimeEq`)
   - **Never** compare strings with `==` or `str::eq` (leaks timing information)

3. **Match result:**
   - The comparison result (match/mismatch) is NOT stored in the witness
   - Downstream admissibility logic can check: `witness.digest == witness.operation.expected_digest`
   - This allows the witness to remain a pure evidence artifact

---

## Schema Constraints

### Determinism Requirements

1. **No Time Dependencies:**
   - `created_at` is excluded from `witness_id` calculation (identity = operation + inputs only)
   - For reproducible testing, `created_at` can be provided as an explicit parameter
   - Production code may use current timestamp, but it doesn't affect identity
   - **Invariant:** Same operation on same inputs produces same `witness_id` regardless of `created_at`

2. **No IO Dependencies:**
   - All inputs must be provided explicitly as function parameters
   - No file system access during hash computation
   - No network access
   - No reading from stdin or environment

3. **No Environment Dependencies:**
   - No system state (env vars, locale, timezone)
   - No random number generation
   - Pure function semantics: output determined solely by explicit inputs
   - Constant-time operations where security-relevant (verification)

### Input Validation

1. **Algorithm Support:**
   - Currently only "sha256" is supported
   - Future: "sha3-256", "blake3" may be added in v1

2. **Size Limits:**
   - Maximum input size: 100 MB (configurable)
   - Prevents resource exhaustion
   - Large files should use streaming (future work)

3. **Encoding Validation:**
   - All hex strings must be lowercase
   - All timestamps must be ISO-8601 UTC
   - CBOR values must be canonical

### Witness Invariants

These invariants MUST hold for all valid hash witnesses:

1. **Digest matches input:**
   - For `HashBytes` and `Verify`: `input.Bytes.sha256 == digest`
   - For `HashValueCbor`: `digest == sha256(hex_decode(input.ValueCbor.canonical_cbor_hex))`

2. **Size accuracy:**
   - `input_size_bytes` must match the actual byte length of the hashed data

3. **Algorithm consistency:**
   - If `algorithm == "sha256"`, digest must be 64 hex characters (32 bytes)

4. **Canonical hex:**
   - All hex strings (digest, sha256 fields) must be lowercase a-f, 0-9

5. **Verification operation:**
   - For `Verify` operations, `operation.expected_digest` may differ from `digest`
   - The comparison result is not stored in the witness (handled by admissibility verdict)

---

## Ledger Integration

When hash witnesses are emitted, ledger events must include:

```json
{
  "event_type": "cost.declared",
  "event_id": "sha256(canonical_cbor(event))",
  "witness": {
    "kind": "witness",
    "schema_id": "hash-witness/0",
    "sha256": "witness_id",
    "size_bytes": 1234
  },
  "program": {
    "module": "module:irrev_std@1",
    "scope": "scope:hash.content"
  },
  "registry_hash": "sha256(canonical_cbor(meta_registry_v0))"
}
```

The `registry_hash` field binds this witness to the registry version that authorized the `hash-witness/0` schema, creating an immutable provenance chain.

---

## Golden Fixture Requirements

Per [scope-addition-protocol-v0.md](../../../meta/oss/scope-addition-protocol-v0.md), the following fixtures must be provided:

### Fixture 1: Stable Hash Identity

**Input:** `b"Hello, Irreversibility!"`

**Expected:**
- `witness.digest` == `"e2591a3e8ae381c4595cab8d112fe8d45442b0e1e9ac94365aec5850ef85dfc6"`
- `sha256(canonical_cbor(HashWitnessIdPayload))` == stable hash (locked in fixture)
- Same `witness_id` across all runs (deterministic identity)

### Fixture 2: Value CBOR Determinism

**Input (JSON value):**
```json
{"name": "Alice", "id": 42, "tags": ["rust", "cbor"]}
```

**Expected:**
- Canonical CBOR encoding: keys sorted by (length, then lexicographic)
- Same canonical CBOR bytes regardless of input JSON key order
- Same `witness.digest` across all runs
- `witness.input.ValueCbor.canonical_cbor_hex` contains the hex-encoded canonical CBOR
- `sha256(hex_decode(canonical_cbor_hex)) == witness.digest`
- Same `witness_id` across all runs

### Fixture 3: Verification Witness

**Input:**
- Data: `b"test"`
- Expected: `"9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"`

**Expected:**
- Witness produced with matching digest
- Constant-time comparison verified
- Hex validation enforced (lowercase, 64 chars)

### Fixture 4: Wire Format Lock (CRITICAL)

**Purpose:** Lock the exact CBOR wire format to prevent encoding drift

**Test Case:**

Create a `HashWitness` with known values:
- `algorithm`: "sha256"
- `operation`: `HashOperation::HashBytes`
- `input`: `HashInput::Bytes { sha256: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08" }`
- `digest`: "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
- `input_size_bytes`: 4
- `created_at`: "2026-01-01T00:00:00Z" (fixed for reproducibility)
- `metadata`: `None`

**Expected: Pin the exact canonical CBOR hex for:**

1. **HashWitnessIdPayload** (5-element array):
   - Encode only `[algorithm, operation, input, digest, input_size_bytes]`
   - Pin the hex: `[TO BE DETERMINED DURING IMPLEMENTATION]`
   - This locks the identity calculation forever

2. **Full HashWitness** (7-element array):
   - Encode `[algorithm, operation, input, digest, input_size_bytes, created_at, metadata]`
   - Pin the hex: `[TO BE DETERMINED DURING IMPLEMENTATION]`
   - This locks the full witness encoding forever

**What this catches:**
- Accidental CBOR tag insertion (major type 6)
- Serde enum tagging drift (map wrappers, tag fields)
- Array length or ordering mistakes
- Optional field encoding errors (null vs absent)
- Integer encoding drift (variable-length integers)

**Verification:**
- Golden test MUST fail if CBOR bytes change
- Round-trip: decode → re-encode → bytes must match exactly
- No additional bytes, no tag markers, no map keys

---

## CBOR Wire Format Governance

**Critical:** The `hash-witness/0` schema ID binds not just the logical structure, but the **exact CBOR wire format**. Any change to the encoding strategy produces different bytes → different `witness_id` → provenance fracture.

### Binding Rules

1. **Array-based encoding is mandatory:**
   - All structs MUST be encoded as CBOR arrays with fixed positions
   - Switching to maps would be a breaking change requiring `hash-witness/1`

2. **Enum encoding is locked:**
   - `[variant_index, ...data]` format is fixed
   - Adding new variants is acceptable (forward compatibility)
   - Changing variant indices breaks identity

3. **Field order is locked:**
   - `HashWitness` array positions [0..6] are frozen
   - `HashWitnessIdPayload` array positions [0..4] are frozen
   - Reordering fields requires new schema version

4. **Optional encoding is locked:**
   - `None` → CBOR null (`0xf6`)
   - `Some(value)` → value directly (no wrapper array)

### Implementation Requirements

1. **No serde drift:**
   - **Preferred:** Implement manual CBOR array encoding (witness structures are small and stable)
   - If using a CBOR library, treat it as a byte-writing tool, not a schema oracle
   - Do not rely on serde defaults without explicit validation
   - Golden fixtures MUST fail if CBOR encoding changes
   - Pin library versions and test against Fixture 4 (wire format lock)

2. **Canonical CBOR enforcement:**
   - Reject non-canonical inputs during deserialization
   - All produced CBOR must pass canonical validation
   - Integer encoding: always use minimal representation
   - No CBOR tags (major type 6) for witness structures
   - Map keys sorted by encoded bytes (for JSON value encoding)

3. **Test coverage:**
   - Golden fixtures lock both `witness.digest` AND `witness_id`
   - Fixture 4 locks the exact CBOR byte sequence (tamper-evident seal)
   - Round-trip tests: encode → decode → encode must produce identical bytes
   - Negative tests: reject floats, invalid hex, oversized inputs
   - Cross-version compatibility tests when v1 is introduced

### Rationale

Hash witnesses are **identity primitives**. A silent encoding change would make:
- Old witnesses unverifiable (hash mismatch)
- Ledger events contain broken references
- Content addressing across the system fails

By binding `registry_hash` to the meta-registry that admits `hash-witness/0`, we create an audit trail: "this witness was valid under encoding rules X."

---

## Versioning & Evolution

### Current Version: v0

- Schema ID: `hash-witness/0`
- Algorithm: SHA-256 only
- Operations: HashBytes, HashValueCbor, Verify
- Encoding: Canonical CBOR

### Future Compatibility

**Breaking changes require new schema version:**
- Adding new required fields → v1
- Changing field types → v1
- Changing CBOR encoding rules → v1

**Non-breaking changes (patch in documentation):**
- Adding optional fields (encoded as CBOR null for v0)
- Adding enum variants (old parsers ignore unknown variants)
- Clarifying documentation

**Erasure Cost: Grade 1**
- Code is reversible
- Emitted witnesses persist in ledger history forever
- Schema changes affect all downstream consumers

---

## References

- [meta-registry-gate-plan.md](./meta-registry-gate-plan.md) - Registry governance
- [foundational-scopes-v0.md](../../oss/foundational-scopes-v0.md) - Hash scope definition
- [scope-addition-protocol-v0.md](../../oss/scope-addition-protocol-v0.md) - Scope addition process
- [witness-registry-spec-v0.md](../../oss/witness-registry-spec-v0.md) - Witness evidence bundles
- RFC 8949: Concise Binary Object Representation (CBOR)

---

## Implementation Checklist

Before implementing `std.hash`, ensure:

### 1. Dependencies
- [ ] `sha2` crate for SHA-256 (or equivalent)
- [ ] CBOR encoder supporting canonical output (ciborium + custom canonical layer, or manual encoding)
- [ ] `hex` crate for hex encoding/decoding
- [ ] `subtle` crate for constant-time comparison (verification)

### 2. Core Types
- [ ] Define `HashWitness`, `HashOperation`, `HashInput`, `HashMetadata` structs
- [ ] Define `HashWitnessIdPayload` (subset of HashWitness for identity calculation)
- [ ] Implement explicit CBOR array encoding (not relying on serde defaults)

### 3. Operations
- [ ] `hash_bytes(data: &[u8], created_at: String, metadata: Option<HashMetadata>) -> HashWitness`
- [ ] `hash_value_cbor(value: &serde_json::Value, created_at: String, metadata: Option<HashMetadata>) -> HashWitness`
- [ ] `verify(data: &[u8], expected_digest: &str, created_at: String, metadata: Option<HashMetadata>) -> HashWitness`
- [ ] `witness_id(witness: &HashWitness) -> String` - computes identity hash

### 4. Invariant Enforcement

- [ ] Validate `input.Bytes.sha256 == digest` for HashBytes/Verify operations
- [ ] Validate `input_size_bytes` matches actual data length
- [ ] Validate hex strings are lowercase `[0-9a-f]` only
- [ ] Validate SHA-256 digests are exactly 64 hex characters
- [ ] Validate timestamps are ISO-8601 UTC
- [ ] Reject floats in JSON values (only allow integer numbers)
- [ ] Enforce 2 MB limit on `canonical_cbor_hex` field
- [ ] Decode expected_digest to bytes before constant-time comparison
- [ ] Use `subtle::ConstantTimeEq` or equivalent for verify operation
- [ ] Never compare digest strings with `==` or `str::eq`

### 5. Golden Fixtures

- [ ] Fixture 1: `b"Hello, Irreversibility!"` → `e2591a3e...dfc6`
- [ ] Fixture 2: JSON value with key ordering test (reject floats)
- [ ] Fixture 3: `b"test"` verification → `9f86d081...0a08`
- [ ] Fixture 4: Wire format lock - pin exact CBOR hex for both `HashWitnessIdPayload` and full `HashWitness`
- [ ] Lock both `witness.digest` AND `witness_id` in all fixtures
- [ ] Test determinism: same inputs → same `witness_id` across runs
- [ ] Test rejection: floats in JSON values must error
- [ ] Test rejection: invalid hex (uppercase, wrong length, non-hex chars) must error

### 6. Registry Updates
- [ ] Add `scope:hash.content@0` to `meta-registry/0`
- [ ] Add `hash-witness/0` schema to `meta-registry/0`
- [ ] Document wire format binding in registry

### 7. Tests
- [ ] Round-trip: encode → decode → encode produces identical bytes
- [ ] CBOR canonical validation
- [ ] Array position tests (ensure correct field ordering)
- [ ] Enum variant encoding tests
- [ ] Negative tests: reject non-canonical CBOR, invalid hex, etc.

---

## Accountability

**Maintainers:** Compiler team
**Authority:** `registry_hash` binds meaning-at-ingestion
**Displacement:** Errors affect all downstream content-addressed artifacts

Hash witnesses are foundational identity primitives. Any error in their generation creates unbounded displacement cost across the entire system.

**Security Note:** The `verify` operation MUST use constant-time comparison to prevent timing side-channels. Never use `==` or `str::eq` for digest comparison.

---

## Critical Implementation Foot-Guns (MUST AVOID)

This section documents the subtle determinism and security traps that will quietly break the system if not handled correctly:

### 1. Identity vs Timestamp (`created_at`)

**Trap:** Including `created_at` in `witness_id` calculation breaks determinism.

**Solution:** `HashWitnessIdPayload` is a distinct 5-element array that excludes `created_at` and `metadata`. The identity hash is computed ONLY over `[algorithm, operation, input, digest, input_size_bytes]`.

### 2. CBOR Map Key Sorting

**Trap:** "Sort struct fields by declaration order" conflicts with "sort map keys canonically."

**Solution:** Structs are encoded as CBOR arrays (positional), not maps. When encoding JSON values, maps use CBOR map type with keys sorted by their encoded byte sequence (length first, then lexicographic).

### 3. Enum Encoding Drift

**Trap:** Serde can change enum representation based on tagging strategy.

**Solution:** Explicit array encoding: `[variant_index, ...data]`. Fixture 4 locks the exact CBOR bytes to catch drift.

### 4. Float Ambiguity

**Trap:** `serde_json::Number` can represent floats, which have ambiguous CBOR encoding.

**Solution:** `hash.value_cbor` MUST reject non-integer numbers. Only i64/u64 are allowed.

### 5. String Comparison Timing Leaks

**Trap:** Comparing `expected_digest` string with `==` leaks timing information.

**Solution:** Decode both to `[u8; 32]` and use `subtle::ConstantTimeEq`. Validate hex strictly (lowercase, 64 chars).

### 6. Hex Validation

**Trap:** Accepting uppercase hex or wrong lengths creates non-canonical witnesses.

**Solution:** All hex MUST be lowercase `[0-9a-f]` only. SHA-256 digests MUST be exactly 64 characters.

### 7. Wire Format Drift

**Trap:** Upgrading CBOR libraries or serde versions can silently change encoding.

**Solution:** Fixture 4 pins the exact CBOR bytes. Golden tests MUST fail if encoding changes.

### 8. Witness Size Bloat

**Trap:** Storing large canonical CBOR values inline can balloon witness size.

**Solution:** 2 MB limit on `canonical_cbor_hex` field. Larger values rejected or externalized.

### 9. Redundant Data (`input.Bytes.sha256` == `digest`)

**Trap:** Storing the same hash twice creates surface area for drift.

**Solution:** Enforce invariant validation. For HashBytes/Verify operations, both MUST match exactly.

### 10. CBOR Tags

**Trap:** Accidentally including CBOR tags (major type 6) breaks identity.

**Solution:** No tags in witness structures. Fixture 4 catches this.

---

## Implementation Recommendations

### Preferred CBOR Strategy

**Manual encoding is safest:**

```rust
// Pseudo-code for manual CBOR array encoding
fn encode_hash_witness_id_payload(w: &HashWitness) -> Vec<u8> {
    let mut buf = Vec::new();

    // CBOR array header (5 items)
    buf.push(0x85);

    // 0: algorithm (text string)
    encode_text(&mut buf, &w.algorithm);

    // 1: operation (array)
    encode_operation(&mut buf, &w.operation);

    // 2: input (array)
    encode_input(&mut buf, &w.input);

    // 3: digest (text string)
    encode_text(&mut buf, &w.digest);

    // 4: input_size_bytes (uint)
    encode_uint(&mut buf, w.input_size_bytes);

    buf
}
```

This approach:
- Makes the wire format explicit and auditable
- Prevents library upgrade drift
- Enables precise control over canonicalization
- Is small enough to maintain (< 200 lines for all encoding)

### If Using a CBOR Library

If you must use ciborium/serde_cbor/minicbor:

1. **Test exhaustively** with Fixture 4
2. **Pin exact versions** in Cargo.toml
3. **Never upgrade** without re-validating all golden fixtures
4. **Implement encode/decode separately** from the ergonomic Rust structs

---
