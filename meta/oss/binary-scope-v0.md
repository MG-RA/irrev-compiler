# Binary Domain v0 (`binary.*`)

Status date: 2026-01-30
Owner: mg

## Purpose

This note was drafted while “domain” and “scope” were sometimes used interchangeably. In the current framing:

- **Binary is a domain**: the semantic universe of bytes, byte-level admissibility, canonical forms, and normalization.
- **`binary.*` are scopes**: admissible interfaces into that universe.

Define the binary foundation domain: a minimal, worldview-free substrate that governs raw byte admissibility and canonical binary form. This is bedrock beneath witness durability and proof portability.

This scope belongs in the default distribution (via the `irrev_std@1` standard library).

## Domain

The binary domain adjudicates:

- what counts as "the same bytes"
- what encodings are admissible vs rejected
- canonical form enforcement for binary encodings used by the system

It does not interpret meaning. It only adjudicates bit-level admissibility.

## Governs (precisely)

### 1) Bit identity

- byte model (8-bit bytes, explicitly)
- endianness rules when multi-byte integers appear in encodings
- allowed vs forbidden padding
- trailing bytes discipline

### 2) Canonical form enforcement

The scope must be the authority that can answer:

"Are these bytes canonical under the declared binary ruleset?"

Examples of degrees of freedom to eliminate:

- ambiguous integer encodings
- non-canonical map key ordering
- forbidden float encodings (if floats are disallowed)
- alternate equivalent encodings that would hash differently

## Snapshot (minimal)

`BinarySnapshot` should be tiny and hashable:

- byte model (assume 8-bit bytes)
- canonical encoding spec references (by schema id + hash)
  - e.g. "canonical CBOR (RFC 8949) with integer-only policy" (as used by the witness encoder)
- forbidden encodings list (policy surface)
- hash algorithm identifiers (e.g. sha256) and parameters (if any)

## Scopes, predicates, and mechanisms (v0)

Keep it boring. One predicate family is enough:

- `binary.canonical(artifact_ref)` -> Findings

Findings may include:

- non-canonical encoding detected
- forbidden padding or ambiguous length encoding
- invalid float canonicalization (if floats are restricted)
- trailing bytes present
- invalid map key ordering (for canonical maps)

In boolean positions, Findings is coerced to bool via `exists(findings)` (v0 coercion rule).

### Mechanisms

Two minimal mechanism operations cover most needs:

- `binary.verify`
  - input: bytes + declared binary ruleset/snapshot
  - output: witness findings for canonicality violations

- `binary.normalize`
  - input: bytes + declared binary ruleset/snapshot
  - output: canonical bytes + normalization witness

These mechanisms are infrastructure and should be pure/deterministic.

## Relationship to other foundational scopes

- `binary.*` answers: “are these bytes admissible/canonical (and if not, what is the canonical form)?”
- `hash.content` answers: “what digest do these bytes get?”

Together, they support identity closure for registries and proof portability.

Important separation:

- The **hash domain** does not “depend on binary”.
- Specific pipelines can require binary canonicalization/normalization before hashing (e.g., canonical CBOR identity records), but `hash.content` itself is simply “digest these bytes”.

## Default distribution placement

`binary.*` is standard-library material:

- no worldview or domain policy
- required by every other scope that uses hashes, CBOR identity, or durable evidence

It should ship as part of `irrev_std@1` (either directly or as a depended-on submodule).
