---
role: support
type: scope-contract
canonical: true
facets:
  - governance
  - protocols
  - identity
phase: P0
deterministic: true
foundational: true
---

# Hash Scope Contract: `scope:hash.content@0`

## Purpose

The `scope:hash.content@0` provides deterministic, foundational identity primitives for the Irreversibility compiler. It implements cryptographic hashing operations that produce tamper-evident witnesses, enabling content-addressable identity for all artifacts in the system.

## Schema

**Schema ID:** `hash-witness/0`
**Canonical Encoding:** `canonical-cbor` (RFC 8949 with deterministic encoding rules)
**Wire Format:** Locked by golden fixtures (see `hash_golden_fixtures.rs`)

## Primitives

The scope declares three deterministic hash operations:

### 1. `hash.bytes(raw_data: bytes) -> HashWitness`

Hash raw bytes directly with SHA-256.

**Properties:**
- Fully deterministic
- No environment dependencies
- Constant-time operation (linear in input size)
- Maximum input size: 100 MB

**Use cases:**
- Hashing file contents
- Hashing binary artifacts
- Generating content addresses for opaque data

**Witness structure:**
```
HashWitness {
  algorithm: "sha256",
  operation: HashBytes,
  input: Bytes { sha256: <digest> },  // Redundant for verification
  digest: <hex_digest>,
  input_size_bytes: <size>,
  created_at: <ISO-8601 UTC>,
  metadata: Option<HashMetadata>
}
```

### 2. `hash.value_cbor(value: JSON) -> HashWitness`

Hash the canonical CBOR representation of a structured JSON value.

**Properties:**
- Deterministic canonicalization via CBOR (not JSON!)
- Suitable for hashing structured data (objects, arrays)
- Maps are sorted by key (lexicographic byte order, length-first)
- **Rejects floats** - only integer numbers allowed
- Maximum CBOR size: 100 MB (2 MB hex representation)

**Canonicalization rules:**
1. Object keys sorted by: length first, then lexicographic byte order
2. No whitespace or formatting variations
3. Numbers encoded as CBOR integers (no floats)
4. UTF-8 text strings
5. Null, bool, arrays, objects supported

**Use cases:**
- Hashing structured configuration
- Content-addressing JSON documents
- Witness identity calculation (`witness_id`)

**Witness structure:**
```
HashWitness {
  algorithm: "sha256",
  operation: HashValueCbor,
  input: ValueCbor { canonical_cbor_hex: <hex> },
  digest: <hex_digest>,
  input_size_bytes: <cbor_size>,
  created_at: <ISO-8601 UTC>,
  metadata: Option<HashMetadata>
}
```

### 3. `verify(data: bytes, expected_digest: hex_string) -> HashWitness`

Verify that data matches an expected digest using constant-time comparison.

**Properties:**
- Constant-time comparison (prevents timing attacks)
- Returns witness regardless of match result
- Verdict determined by downstream admissibility check
- Expected digest MUST be lowercase hex, exactly 64 chars

**Security:**
- Comparison done on decoded bytes, not strings
- Uses constant-time equality to prevent timing side-channels
- No early-exit on mismatch

**Use cases:**
- Verifying artifact integrity
- Tamper detection
- Supply chain verification

**Witness structure:**
```
HashWitness {
  algorithm: "sha256",
  operation: Verify { expected_digest: <hex> },
  input: Bytes { sha256: <actual_digest> },
  digest: <actual_digest>,
  input_size_bytes: <size>,
  created_at: <ISO-8601 UTC>,
  metadata: Option<HashMetadata>
}
```

**Verdict check:**
```
match: witness.digest == witness.operation.expected_digest
```

## Witnesses

All operations emit a `HashWitness` structure with:

1. **algorithm**: Hash algorithm used (only "sha256" in v0)
2. **operation**: Which operation was performed
3. **input**: Input representation (varies by operation)
4. **digest**: The resulting hash (lowercase hex)
5. **input_size_bytes**: Size of input in bytes
6. **created_at**: ISO-8601 UTC timestamp
7. **metadata**: Optional traceability metadata
   - `source_ref`: Reference to source artifact
   - `purpose`: Context/purpose of hash operation

### Witness Identity

Every `HashWitness` has a deterministic **witness_id** computed as:

```
witness_id = sha256(canonical_cbor(HashWitnessIdPayload))
```

Where `HashWitnessIdPayload` is a 5-element CBOR array:
```
[algorithm, operation, input, digest, input_size_bytes]
```

**Invariant:** `witness_id` excludes `created_at` and `metadata` to ensure:
- Same operation on same input = same witness_id
- Deterministic identity across time and context
- Content-addressable witness storage

## Algebraic Laws

The scope obeys these laws:

1. **Determinism:**
   ```
   hash.bytes(data) == hash.bytes(data)  // Same digest every time
   ```

2. **Key-order independence (for CBOR):**
   ```
   hash.value_cbor({"a": 1, "b": 2}) == hash.value_cbor({"b": 2, "a": 1})
   ```

3. **Witness identity determinism:**
   ```
   witness_id(w1) == witness_id(w2)  // If same operation on same input
   ```

4. **Verification invariant:**
   ```
   verify(data, expected).digest == hash.bytes(data).digest
   ```

5. **No collision assumption (SHA-256):**
   ```
   hash.bytes(data1) != hash.bytes(data2)  // With overwhelming probability
   ```

## Constraints

### Forbids

1. **Floats in canonical CBOR:** Any JSON number with fractional part is rejected
2. **Non-deterministic inputs:** No environment variables, timestamps, or IO in hash input
3. **Tags in CBOR:** CBOR semantic tags are not supported in v0
4. **Infinite precision:** Numbers must fit in i64/u64
5. **Large inputs:** Maximum 100 MB for bytes, 2 MB CBOR hex for values

### Requires

1. **Lowercase hex digests:** All digest strings must be lowercase hexadecimal
2. **UTF-8 validity:** All text strings must be valid UTF-8
3. **ISO-8601 timestamps:** `created_at` must end with 'Z' (UTC)
4. **Canonical CBOR:** Manual encoding with deterministic rules (no serde drift)

## Dependencies

This scope depends on:

1. **`scope:encode.canonical@0`:** Provides canonical CBOR encoding for `hash.value_cbor()` operation (implicit implementation dependency)
2. **SHA-256 implementation:** Uses `sha2` crate (version pinned for reproducibility)
3. **Meta-registry/0:** Schema and scope registration

**Note:** The dependency on `scope:encode.canonical@0` is an implicit implementation detail rather than an explicit registry dependency. The hash scope operates independently on raw bytes; canonical encoding is used internally for the convenience operation `hash.value_cbor()` that accepts structured JSON values.

## Wire Format Lock

The exact CBOR wire format is locked by golden fixtures:

- **Fixture 1:** `hash_bytes("Hello, Irreversibility!")`
- **Fixture 2:** JSON key-order independence test
- **Fixture 3:** `hash_bytes("test")`
- **Fixture 4:** Wire format lock tests (3 variants)
  - HashWitnessIdPayload encoding
  - Full HashWitness with metadata encoding
  - Verify operation encoding

**Breaking the wire format requires `hash-witness/1`.**

Any change to CBOR encoding that causes fixture tests to fail is a breaking change that:
- Displaces cost onto all hash witness consumers
- Requires governance approval
- Breaks existing witness_id references
- Has unbounded blast radius across the ecosystem

## Integration

### Ledger Events

Hash witnesses are emitted as ledger events with:
- `witness_id`: Content-address for deduplication
- `schema_id`: "hash-witness/0"
- `registry_hash`: Binds to meta-registry/0 encoding rules

### Registry Binding

The `registry_hash` field in ledger events binds the witness to:
- The canonical CBOR encoding rules at ingestion time
- The hash-witness/0 schema definition
- The meta-registry/0 governance snapshot

This ensures:
1. **Tamper detection:** Any modification to witness CBOR changes the hash
2. **Format lock:** Witnesses can only be decoded with the correct CBOR rules
3. **Governance trail:** Every witness references its encoding authority

## Security Considerations

1. **Timing attacks:** `verify()` uses constant-time comparison
2. **Collision resistance:** SHA-256 provides 128-bit security (2^128 operations)
3. **Preimage resistance:** Computationally infeasible to find input for given digest
4. **Second preimage resistance:** Infeasible to find alternate input with same digest

## Future Work (Out of Scope for v0)

1. **Streaming hashing:** For files >100 MB
2. **Additional algorithms:** SHA-3, BLAKE3 (requires hash-witness/1)
3. **Merkle trees:** For incremental verification
4. **Hardware acceleration:** Using platform-specific instructions

## Acceptance Criteria

- ✅ All 4 golden fixtures pass (including wire format lock)
- ✅ witness_id determinism verified across all operations
- ✅ Registry validation accepts new entries
- ✅ Integration tests verify ledger event structure with registry_hash
- ✅ Scope contract documentation complete
- ✅ No CBOR encoding drift (Fixture 4 catches violations)

## Governance

**Maintainers:** Compiler team
**Breaking changes:** Require hash-witness/1 and ecosystem coordination
**Fixture violations:** Displace cost onto all consumers (unbounded blast radius)
**Registry entries:** Immutable; updates require new schema version

## References

- [Golden Fixtures](../../crates/admit_core/tests/hash_golden_fixtures.rs)
- [Hash Witness Implementation](../../crates/admit_core/src/hash_witness.rs)
- [Hash Operations](../../crates/admit_core/src/hash_operations.rs)
- [Meta-Registry](../../out/meta-registry.json)
- [RFC 8949 - CBOR](https://www.rfc-editor.org/rfc/rfc8949.html)
- [FIPS 180-4 - SHA-256](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
