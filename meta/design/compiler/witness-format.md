# Witness Format (Identity vs Projection)

Status date: 2026-01-29
Applies to: admissibility compiler witnesses and cost declaration artifacts.

This note defines witness encoding at the artifact boundary. It is technical: it
specifies identity bytes, projection bytes, and the hashing rule used for identity.

## Identity encoding

- Canonical bytes: CBOR encoded using RFC 8949 canonical rules.
- Content hash: SHA256 computed over the canonical CBOR bytes only.

## Projection encoding

- JSON is a non-authoritative projection used for review and debugging.
- JSON bytes are not hashed for identity.

## Numeric policy (v0)

- Floating point values are forbidden in canonical CBOR identity bytes.
- If a JSON projection carries numeric values that are representable as integers, the
  identity encoder treats them as integers for canonical CBOR.
- NaN/Infinity are not representable in identity bytes.

## Verification rule (mechanical)

A witness commitment is valid only if:

- `sha256(canonical_cbor(witness_json)) == witness_sha256`

where `canonical_cbor` applies RFC 8949 canonical encoding rules.

