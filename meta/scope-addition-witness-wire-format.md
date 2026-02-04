# Wire Format Specification: scope-addition-witness/0

**Schema ID:** `scope-addition-witness/0`
**Schema Version:** 0
**Canonical Encoding:** Canonical CBOR (RFC 8949 Section 4.2)
**Status:** FROZEN - Breaking changes require schema version bump

## Purpose

This document defines the **frozen wire format** for `ScopeAdditionWitness` structures. The wire format is tamper-evident: any change to the encoding breaks the golden fixture test and requires bumping to `scope-addition-witness/1`.

## Encoding Rules

### 1. Base Encoding

- **Format**: JSON → Canonical CBOR
- **Scope Authority**: `scope:encode.canonical@0` (see [encode-canonical-scope-contract.md](./encode-canonical-scope-contract.md))
- **Process**:
  1. Serialize structure to JSON value
  2. Encode JSON value using `admit_core::encode_canonical_value()`
  3. Apply canonical CBOR encoding (deterministic, sorted keys)

### 2. Canonical CBOR Requirements

Per RFC 8949 Section 4.2:
- Map keys MUST be sorted by encoded bytes (lexicographic order)
- Smallest encoding MUST be used (no unnecessary length bytes)
- No indefinite-length encoding
- UTF-8 strings MUST be valid
- Deterministic: same input always produces same bytes

## Identity Payload Structure

The **identity payload** is used to compute the deterministic `witness_id`. It excludes non-deterministic fields (timestamp, validation messages).

### CBOR Structure

**Type**: Map (major type 5)
**Size**: 7 key-value pairs
**Encoding**: `a7` (map with 7 entries)

### Key-Value Pairs (Canonical Sort Order)

| Index | Key | CBOR Type | Value Type | Notes |
|-------|-----|-----------|------------|-------|
| 1 | `registry_hash_after` | text | String | SHA256 hex (66 bytes UTF-8) |
| 2 | `registry_hash_before` | text | String | SHA256 hex (66 bytes UTF-8) |
| 3 | `registry_version_after` | uint | u32 | Registry version after mutation |
| 4 | `registry_version_before` | uint | u32 | Registry version before mutation |
| 5 | `scope_id` | text | String | Format: `scope:<domain>.<name>` (NO @version) |
| 6 | `scope_version` | uint | u32 | Scope version number |
| 7 | `validation_checks` | array | Vec<String> | Check names only (excludes messages) |

### Golden Fixture (Frozen Bytes)

**Test Case**: Meta scope self-addition
**Scope**: `scope:meta.scope@0`
**Registry Transition**: v0 → v1
**Validation Checks**: `["scope_id_format", "emits_schemas_exist"]`

```
CBOR Hex (163 bytes):
a7
  6873636f70655f6964
    7073636f70653a6d6574612e73636f7065
  6d73636f70655f76657273696f6e
    00
  7176616c69646174696f6e5f636865636b73
    826f73636f70655f69645f666f726d6174
      73656d6974735f736368656d61735f6578697374
  7372656769737472795f686173685f6166746572
    66646566343536
  7472656769737472795f686173685f6265666f7265
    66616263313233
  7672656769737472795f76657273696f6e5f6166746572
    01
  7772656769737472795f76657273696f6e5f6265666f7265
    00
```

**Breaking this encoding requires schema version bump to `scope-addition-witness/1`.**

## Full Witness Structure

The **full witness** includes all fields for human readability and auditability.

### Additional Fields (Not in Identity Payload)

| Field | Type | Purpose | Included in witness_id? |
|-------|------|---------|------------------------|
| `schema_id` | String | Schema identifier | ✅ No (constant for schema) |
| `schema_version` | u32 | Schema version | ✅ No (constant for schema) |
| `validation_timestamp` | String | ISO-8601 UTC | ❌ No (non-deterministic) |
| `validations` | Array | Full validation results | ⚠️ Partial (check names only) |
| `validations[].message` | String | Human-readable message | ❌ No (non-deterministic) |
| `validations[].severity` | Enum | Error/Warn/Info | ❌ No (redundant with check name) |
| `validations[].passed` | bool | Check result | ❌ No (redundant with check name) |

### Witness ID Computation

```rust
fn compute_witness_id(witness: &ScopeAdditionWitness) -> String {
    // 1. Extract identity payload (7 fields)
    let payload = ScopeAdditionWitnessIdPayload {
        scope_id,
        scope_version,
        validation_checks,  // Names only, no messages
        registry_version_before,
        registry_version_after,
        registry_hash_before,
        registry_hash_after,
    };

    // 2. Encode to canonical CBOR
    let json_value = serde_json::to_value(&payload)?;
    let cbor_bytes = admit_core::encode_canonical_value(&json_value)?;

    // 3. Hash with SHA256
    let hash = sha256(cbor_bytes);
    hex::encode(hash)
}
```

## Breaking Change Rules

### Changes That Break Wire Format (Require Schema Bump)

1. **Adding/removing fields** from identity payload
2. **Renaming fields** in identity payload
3. **Changing field types** (e.g., uint → string)
4. **Changing CBOR encoding** (e.g., map → array)
5. **Changing canonical sort order** (library upgrade that changes sorting)
6. **Changing validation check names** (existing checks)

### Changes That DON'T Break Wire Format

1. **Adding new validation checks** (preserves existing check names)
2. **Changing validation messages** (excluded from identity payload)
3. **Changing timestamp format** (excluded from identity payload)
4. **Adding fields to full witness** (not in identity payload)
5. **Changing documentation** or comments

## Tamper-Evident Seal

The golden fixture test `test_golden_fixture_scope_addition_witness_wire_format()` in `scope_validation.rs` pins the exact CBOR bytes.

**If this test fails:**
1. Determine if the change is intentional
2. If intentional: bump schema to `scope-addition-witness/1`
3. If accidental: fix the code to restore frozen encoding
4. Update documentation and contract references

## Versioning Policy

| Schema Version | Status | Encoding | Notes |
|----------------|--------|----------|-------|
| `/0` | **CURRENT** | Canonical CBOR map, 7 keys | Frozen by golden fixture |
| `/1` | *Future* | TBD | Use if wire format must change |

## References

- RFC 8949: Concise Binary Object Representation (CBOR)
- [meta-scope-contract.md](./meta-scope-contract.md) - Governance protocol
- [scope-addition-protocol-v0.md](./oss/scope-addition-protocol-v0.md) - 6-step validation
- Golden fixture: `crates/admit_cli/src/scope_validation.rs::test_golden_fixture_scope_addition_witness_wire_format`

---

**Last Updated:** 2026-02-02
**Frozen Since:** 2026-02-02
**Next Review:** When schema version bump required
