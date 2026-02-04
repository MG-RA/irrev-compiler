# Foundational Scopes v0 (Atoms for Multi-Scope Systems)

Status date: 2026-01-30
Owner: mg

## Purpose

Capture the set of "obvious in hindsight" foundational scopes that act like atoms for larger admissible-effect systems. Each takes an existing utility (time, hashing, schemas, etc.) and turns it into a **scope authority** that can issue attestations and verify proof objects.

## Domain vs scope (clarification)

This note was drafted while “domain” and “scope” were sometimes used interchangeably. Going forward:

- **Domain** = semantic universe (meaning)
- **Scope** = admissible interface into that universe (an access path that emits witnesses and/or governs effects)

**Foundational** is a property of a *scope* (bootable, universal dependency), not a domain.

Naming convention:

- Prefer `domain.scope` names (domains are nouns; scopes are verbs/modes).
- In registry IDs, keep the `scope:` prefix as a namespace marker, but make the name itself `domain.scope`, e.g.:
  - `scope:hash.content@1`, `scope:time.now@1`, `scope:registry.core@1`

## Core Idea

Foundational scopes are universal dependencies across many systems. Treating them as scope authorities reduces policy leakage and replaces trust-by-prose with proof-by-witness.

A scope authority should be able to:

- describe itself
- issue attestations/capabilities
- verify witnesses/results
- constrain admissibility for effects within its boundary

## Implicit foundational domains (and their scopes)

The “candidate foundational scopes” below imply a small set of foundational domains that recur everywhere:

- `binary` (byte-level admissibility/canonicalization/normalization)
- `hash` (digest semantics + verification)
- `time` (instants, ordering, windows; includes oracle time)
- `identity` (actors, delegation, capabilities)
- `schema` (schema IDs, compatibility, validation)
- `units` (dimensions/units and compatibility)
- `patch` (changes as canonical objects)
- `verify` (verification plans + attestations)
- `law` (pack binding and policy enforcement)

Other domains like `registry` and `calc` are also foundational in practice (see `meta/Registry Scope Architecture.md` and `meta/oss/calculator-scope-v0.md`), but they are documented separately.

## Candidate foundational scopes (grouped by domain)

### `time` (domain)

Purpose: make time a verifiable input, not vibes.

Provides:
- attested timestamps
- window checks (maintenance windows)
- monotonic ordering constraints

Unlocks: temporal governance (freshness + replay resistance).

Example scopes:
- `time.now` (oracle observation)
- `time.window.check` (derived check)
- `time.sequence.compare` (ordering witness)

### `identity` (domain)

Purpose: make delegation and "who can execute" proof-carrying.

Provides:
- capability token issuance
- signature/attestation verification
- binding tokens to scope/effect types/expiry

Unlocks: capability-carrying plans; cross-terminal collaboration without sharing access.

Example scopes:
- `identity.delegate` (issue capability)
- `identity.verify` (verify capability/attestation)

### `hash` (domain)

Purpose: make identity-by-bytes universally reliable.

Provides:
- canonicalization rules (CBOR/JSON normalization)
- content hashing + verification
- manifest verification

Unlocks: proof portability ("verify anywhere, trust nowhere") and registry correctness.

Example scopes:
- `hash.content` (digest of bytes) ← **IMPLEMENTED** (`@0`)
- `hash.verify` (bytes vs claimed digest)
- `hash.execution` (digest of an execution context; depends on other domains/scopes)

### `encode` (domain)

Purpose: make canonical encoding deterministic and governable.

Provides:
- canonical CBOR encoding (RFC 8949)
- deterministic byte representations
- content-addressable identity primitives

Unlocks: witness identity computation; tamper-evident serialization; independent versioning of encoding rules.

Example scopes:
- `encode.canonical` (JSON → canonical CBOR) ← **IMPLEMENTED** (`@0`)
- `encode.json` (future: canonical JSON-JCS)
- `encode.msgpack` (future: canonical MessagePack)

**Note:** The `encode.canonical@0` scope makes explicit the universal dependency on canonical encoding used throughout the compiler for witness identity computation (`witness_id = sha256(canonical_cbor(payload))`).

### `binary` (related domain)

See `meta/oss/binary-scope-v0.md` for the byte-level canonicality/normalization layer that often feeds witness durability and proof portability.

### `schema` (domain)

Purpose: stop schema drift from eroding proof meaning.

Provides:
- schema IDs and versioning rules
- compatibility checks
- validation of "this blob claims schema X"

Unlocks: semantic stability under evolution.

Example scopes:
- `schema.validate`
- `schema.compat`

### `units` (domain)

Purpose: enforce unit/dimension meaning separately from arithmetic.

Provides:
- unit declarations
- explicit conversion rules
- compatibility checks for add/compare

Unlocks: budget law that doesn't lie; safe thresholds and routing.

Example scopes:
- `units.declare`
- `units.compat`

### `patch` (domain)

Purpose: standardize "a change" as a first-class, attestable object.

Provides:
- canonical patch/diff formats
- touched-surface computation (what is mutated)
- patch plan artifacts

Unlocks: effects-as-patches unifying filesystem/git/vault/config changes.

Example scopes:
- `patch.plan`
- `patch.apply` (effectful; not foundational)

### `verify` (domain)

Purpose: make evidence executable instead of rhetorical.

Provides:
- test/verification plans
- attestations bound to code state hash + plan hash
- reproducible environment hashing

Unlocks: evidence gates (execution requires verification witness).

Example scopes:
- `verify.plan`
- `verify.attest`

### `law` (domain)

Purpose: bind scopes to packs ("local constitutions") and prevent silent policy drift.

Provides:
- binding of scope -> required pack hashes
- conflict/priority rules
- rejection when required witnesses are missing

Unlocks: self-governing scopes become concrete.

Example scopes:
- `law.bind` (scope → pack hashes)
- `law.check` (missing witnesses / conflicts)

## Checklist: Is a Foundational Scope Missing?

Ask:

1. Is it a universal dependency across many scopes?
2. Do failures cause silent drift or false trust?
3. Can it be deterministic and verifiable offline?
4. Would treating it as a scope reduce policy leakage?

If yes, consider formalizing it as a scope authority.

## Suggested Next Picks After `calc` (domain)

Highest leverage options:

- `encode.canonical` + `hash.content` + `hash.verify` ← **DONE** (`encode.canonical@0`, `hash.content@0`)
- `identity.delegate` + `identity.verify` (delegation + self-governing scopes)
- `patch.plan` (unifies most mechanisms under a single change object)
