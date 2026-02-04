---
role: foundation
type: scope-contract
canonical: true
facets:
  - encoding
  - identity
  - foundation
phase: P0
deterministic: true
foundational: true
---

# Encode Canonical Scope Contract: `scope:encode.canonical@0`

## Purpose

The `scope:encode.canonical@0` provides deterministic, foundational canonical encoding primitives for the Irreversibility compiler. It implements RFC 8949 canonical CBOR encoding that produces tamper-evident byte representations, enabling content-addressable identity for all artifacts in the system.

This scope makes **explicit** the universal dependency on canonical encoding that exists throughout the compiler. Every witness identity, registry hash, and ledger event relies on deterministic canonical encoding to ensure reproducibility and tamper-evidence.

## Encoding Algorithm

**Algorithm:** RFC 8949 Canonical CBOR (Section 4.2)
**Determinism:** Fully deterministic (same input always produces same output)
**Wire Format:** Locked by golden fixtures (see `encode_canonical_fixtures.rs`)

### Canonicalization Rules

1. **Map keys sorted by:** Length first, then lexicographic byte order
2. **Smallest encoding:** Use shortest possible length representation
3. **No indefinite-length encoding:** All lengths must be explicit
4. **UTF-8 strings:** All text strings must be valid UTF-8
5. **Integer-only numbers:** Floating-point numbers are rejected
6. **Supported types:** Null, boolean, integers, text strings, arrays, maps

**Canonical ordering example:**
```json
Input:  {"longer_key": 2, "b": 3, "a": 1}
Sorted: {"a": 1, "b": 3, "longer_key": 2}
Reason: "a" and "b" (length 1) come before "longer_key" (length 10)
        Within same length, lexicographic order ("a" < "b")
```

## Primitives

The scope declares two deterministic encoding operations:

### 1. `encode.canonical_value(value: JSON) -> bytes`

Encode a JSON value to canonical CBOR bytes.

**Properties:**
- Fully deterministic
- No environment dependencies
- Constant-time operation (linear in input size)
- Maximum output size: 100 MB CBOR

**Type mapping (JSON → CBOR):**
- `null` → CBOR null (0xF6)
- `true` → CBOR true (0xF5)
- `false` → CBOR false (0xF4)
- Numbers → CBOR integers (i64/u64 only, no floats)
- Strings → CBOR text strings (UTF-8)
- Arrays → CBOR arrays
- Objects → CBOR maps (with sorted keys)

**Constraints:**
- **Rejects floats:** Any JSON number with fractional part is rejected
- **UTF-8 validity:** All text strings must be valid UTF-8
- **Map key ordering:** Maps are sorted by key (length-first, then lexicographic)
- **No CBOR tags:** Semantic tags are not supported in v0
- **Integer range:** Numbers must fit in i64 (-2^63 to 2^63-1) or u64 (0 to 2^64-1)

**Use cases:**
- Witness identity computation (`witness_id`)
- Registry hashing
- Content-addressable storage
- Ledger event identity

**Example:**
```rust
let value = json!({"name": "test", "version": 1});
let cbor_bytes = encode_canonical_value(&value)?;
// cbor_bytes: [0xA2, 0x64, 0x6E, 0x61, 0x6D, 0x65, ...]
```

### 2. `encode.canonical(witness: Witness) -> bytes`

Encode a witness structure to canonical CBOR bytes.

**Properties:**
- Uses `encode.canonical_value()` internally
- Serializes witness to JSON first, then encodes to CBOR
- Deterministic witness identity

**Process:**
1. Serialize witness struct to JSON (via serde)
2. Pass JSON value to `encode.canonical_value()`
3. Return canonical CBOR bytes

**Use cases:**
- Computing `witness_id` for all witness schemas
- Ledger event identity computation
- Witness deduplication

**Example:**
```rust
let witness = HashWitness { /* ... */ };
let cbor_bytes = encode_canonical(&witness)?;
let witness_id = sha256(&cbor_bytes); // Content address
```

## Algebraic Laws

The scope obeys these laws:

1. **Determinism:**
   ```
   encode(value) == encode(value)  // Same bytes every time
   ```

2. **Key-order independence:**
   ```
   encode({"a": 1, "b": 2}) == encode({"b": 2, "a": 1})
   ```

3. **Bijection invariant:**
   ```
   decode(encode(value)) == value  // Lossless round-trip
   ```

4. **Byte-level uniqueness:**
   ```
   encode(v1) != encode(v2)  // If v1 != v2 (structurally)
   ```

5. **Composition invariant:**
   ```
   encode({"nested": encode(inner)}) is deterministic
   ```

## Constraints

### Forbids

1. **Floats in canonical CBOR:** Any JSON number with fractional part is rejected
   - Example: `3.14`, `0.1`, `-2.5` all return `Err`
2. **Non-UTF-8 text:** Invalid UTF-8 byte sequences in strings
3. **CBOR semantic tags:** Tags (major type 6) not supported in v0
4. **Indefinite-length encoding:** All arrays/maps/strings must have explicit length
5. **Large values:** Maximum 100 MB CBOR output (prevents memory exhaustion)
6. **Non-deterministic inputs:** No environment variables, timestamps, or IO in input

### Requires

1. **Valid JSON structure:** Input must be serializable to JSON
2. **UTF-8 validity:** All text strings must be valid UTF-8
3. **Integer numbers only:** No fractional or exponential notation
4. **Finite structures:** No circular references (enforced by JSON serialization)
5. **Sorted map keys:** Canonicalization sorts all object keys deterministically

## Dependencies

This scope depends on:

1. **RFC 8949 specification:** Canonical CBOR encoding rules (Section 4.2)
2. **serde_cbor crate:** CBOR encoding implementation (version pinned)
3. **Meta-registry/0:** Schema and scope registration

**Scopes that depend on this scope (implicitly):**

- **`scope:hash.content@0`:** Uses canonical CBOR internally for `hash.value_cbor()` operation
- **All witness schemas:** Use canonical CBOR for `witness_id` computation
  - `hash-witness/0`
  - `scope-addition-witness/0`
  - `plan-witness/1`
  - `admissibility-witness/1`
- **Meta-registry operations:** Registry hashing uses canonical CBOR
- **Ledger events:** Event identity relies on canonical encoding

**Note:** These dependencies are **implicit** (implementation details) rather than explicit registry dependencies. The hash scope can hash raw bytes independently; using canonical encoding for structured values is a convenience operation.

## Wire Format Lock

The exact CBOR wire format is locked by golden fixtures:

- **Fixture 1:** Basic types encoding (null, bool, integers, strings, arrays)
- **Fixture 2:** Map key ordering determinism (key-order independence)
- **Fixture 3:** Float rejection (constraint enforcement)
- **Fixture 4:** Large nested structures (stress test determinism)
- **Fixture 5:** Edge cases (empty structures, UTF-8, large integers)

**Breaking the wire format requires `scope:encode.canonical@1`.**

Any change to CBOR encoding that causes fixture tests to fail is a breaking change that:
- Displaces cost onto all witness consumers
- Requires governance approval
- Breaks existing `witness_id` references
- Has unbounded blast radius across the ecosystem
- Invalidates all existing content-addressed artifacts

### Encoding Stability Guarantee

The canonical encoding rules are **frozen** for version 0:
- Same input will always produce same bytes (determinism)
- No implementation changes that alter output (wire format lock)
- No dependency updates that change CBOR encoding (version pinning)
- No "optimizations" that change byte representation

**If encoding must change:**
1. Create `scope:encode.canonical@1` with new rules
2. Update all dependent witness schemas to new version
3. Coordinate ecosystem migration
4. Maintain backward compatibility for decoding v0 witnesses

## Security Considerations

1. **Determinism guarantee:** Encoding is pure and deterministic (no side-channels)
2. **No timing attacks:** Encoding time is linear in input size (no data-dependent branches)
3. **No injection attacks:** CBOR type system prevents injection (no string escaping needed)
4. **Memory safety:** Maximum size limits prevent OOM attacks (100 MB cap)
5. **Integer overflow protection:** Numbers validated to fit in i64/u64 range
6. **UTF-8 validation:** Invalid UTF-8 rejected at encoding time

**Threat model:**
- **Malicious inputs:** Encoding rejects invalid inputs (floats, invalid UTF-8)
- **Resource exhaustion:** Size limits prevent unbounded memory allocation
- **Timing side-channels:** Constant-time encoding (linear in size)
- **Format confusion:** CBOR type tags prevent type confusion attacks

## Implementation

**Location:** `crates/admit_core/src/cbor.rs`
**Function:** `encode_canonical_value(value: &serde_json::Value) -> Result<Vec<u8>, EvalError>`

**Implementation strategy:**
- Use `serde_cbor` for base encoding
- Apply canonical ordering rules via custom serializer
- Validate constraints (no floats, valid UTF-8) during encoding
- Return error on invalid input

**Error cases:**
- `EvalError::FloatNotAllowed`: JSON number has fractional part
- `EvalError::InvalidUtf8`: String contains invalid UTF-8
- `EvalError::ValueTooLarge`: CBOR output exceeds 100 MB
- `EvalError::IntegerOutOfRange`: Number doesn't fit in i64/u64

## Future Work (Out of Scope for v0)

1. **Streaming encoding:** For values >100 MB (incremental CBOR generation)
2. **Additional canonical encodings:**
   - JSON-JCS (RFC 8785) - `scope:encode.json@0`
   - MessagePack canonical - `scope:encode.msgpack@0`
   - Protocol Buffers deterministic - `scope:encode.proto@0`
3. **Schema-aware encoding:** Type-safe encoding from schema definitions
4. **Hardware acceleration:** SIMD or platform-specific optimizations (while preserving determinism)
5. **CBOR tags support:** Semantic tags (date/time, bignum, etc.) in v1
6. **Compressed canonical encoding:** Deterministic compression (zstd dictionary)

## Acceptance Criteria

- ✅ All 5 golden fixtures pass (including wire format lock)
- ✅ Determinism verified across all test cases
- ✅ Registry validation accepts new scope entry
- ✅ Scope contract documentation complete
- ✅ No encoding drift (fixtures catch violations)
- ✅ Float rejection enforced
- ✅ Map key ordering deterministic
- ✅ Integration with existing witness schemas preserved

## Governance

**Maintainers:** Compiler team
**Breaking changes:** Require `scope:encode.canonical@1` and ecosystem coordination
**Fixture violations:** Displace cost onto all consumers (unbounded blast radius)
**Registry entries:** Immutable; updates require new scope version
**Wire format:** Locked; any change breaks all existing witnesses

## References

- [Canonical CBOR Implementation](../../crates/admit_core/src/cbor.rs)
- [Golden Fixtures](../../crates/admit_core/tests/encode_canonical_fixtures.rs)
- [Meta-Registry](../../out/meta-registry.json)
- [RFC 8949 - CBOR](https://www.rfc-editor.org/rfc/rfc8949.html)
- [Hash Scope Contract](./hash-scope-contract.md) - Uses canonical encoding
- [Scope Addition Witness Wire Format](./scope-addition-witness-wire-format.md)
