---
role: support
type: scope-contract
canonical: true
facets:
  - governance
  - identity
phase: P0
deterministic: true
foundational: true
---

# Select Path Scope Contract: `scope:select.path@0`

## Purpose

`scope:select.path@0` provides a deterministic projection operator:
given a structured value and a canonical path string, it returns a single
sub-value or a deterministic error. The intent is a shared pointer language
for witnesses and diagnostics without importing domain schemas.

## Value Model

Supported values: `null`, `bool`, `int`, `string`, `array`, `object`.

- Objects use string keys.
- Arrays are ordered.
- Floats are out of scope (aligns with canonical CBOR subset).

## Path Grammar (v0)

### Root

The empty string `""` is a valid path and selects the whole input value.
No `$` prefix is used.

### Segments

A path is a sequence of segments applied left-to-right.

Segment types:
- Object key segment
- Array index segment

### Object Key Segments

#### Dot identifier form (canonical when allowed)

Keys may be written as `.foo` only if `foo` matches:

```
[A-Za-z_][A-Za-z0-9_]*
```

Case-sensitive. ASCII letters, digits, underscore only. No leading digit.

#### Bracketed string form (canonical otherwise)

All other keys must be written as:

```
["..."]
```

The string content follows JSON string escaping with the canonical
restrictions below.

### Array Index Segments

Array segments are written as:

```
[<u64>]
```

Canonical numeric constraints:
- Base-10 digits only.
- No leading zeros unless the entire literal is `0`.
- Must fit in `u64`.

## Canonicalization Rules (v0)

Canonical paths must satisfy:
- No whitespace anywhere.
- Dot form used only when identifier-safe; otherwise bracketed string form.
- Array indices always bracketed.
- No alternate spellings accepted.

The following are rejected as `parse_error` even if equivalent:
- `["foo"]` when `.foo` is identifier-safe
- `.foo["bar"]` when `bar` is identifier-safe
- `.foo[01]` (leading zero)
- `.foo[ 0 ]` (whitespace)
- `['bar']` (single quotes)
- `.foo.` (dangling dot)
- `.foo[]` (missing index)

### Canonical JSON String Escaping (v0)

The bracketed string literal must be valid JSON string syntax with these
canonical restrictions:

- `\/` is **rejected** (optional escape).
- Only the required escapes are permitted:
  - `\"` for `"`
  - `\\` for `\`
  - `\b`, `\f`, `\n`, `\r`, `\t` for control characters
  - `\u00XX` for other control characters `U+0000..U+001F`
- Hex digits in `\u00XX` must be uppercase (`A-F`).
- `\uXXXX` escapes for non-control characters are rejected.
- `\u0008`, `\u0009`, `\u000A`, `\u000C`, `\u000D` are rejected
  (must use `\b`, `\t`, `\n`, `\f`, `\r` respectively).

This ensures a single canonical spelling for each key.

## Evaluation Semantics

Start at the root value. For each segment:

- Object segment:
  - Current value must be object, else `type_mismatch`.
  - If key missing, `key_not_found`.
  - Otherwise descend into that value.
- Array segment:
  - Current value must be array, else `type_mismatch`.
  - If index >= length, `index_out_of_range`.
  - Otherwise descend into that element.

Output is the selected value.

## Errors

Error codes:
- `parse_error`
- `type_mismatch`
- `key_not_found`
- `index_out_of_range`

If an error occurs:
- `at_segment_index` is **0-based** into the parsed segment list.
- For `parse_error`, `at_segment_index` is omitted (null).

## Witness Schema

**Schema ID:** `select-path-witness/0`  
**Canonical Encoding:** `canonical-cbor`

Input:
```
{ value: <Value>, path: <string> }
```

Output (success):
```
{ ok: true, value: <Value> }
```

Output (error):
```
{ ok: false, error: { code, at_segment_index?, message? } }
```

## Determinism

Given the same input value and canonical path string, the output is
deterministic. There is no environment or ordering dependence.

## Dependencies

This scope depends on:
- `meta-registry/0` for scope and schema registration.

## Governance

Maintainers: compiler team  
Breaking changes require `scope:select.path@1` and schema version bump.

## References

- Meta registry: `out/meta-registry.json`
