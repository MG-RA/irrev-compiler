# Meta Registry Gate Plan (Meta-first enforcement)

Status date: 2026-01-31

## Goal

Make “meta is the first domain” enforceable by introducing an authoritative, content-addressed **meta registry artifact** and adding hard gates in Rust:

- unknown `schema_id` → reject
- unknown `scope_id` → reject (or warn during rollout)

Vault rules may *audit* and *diagnose* registry state, but admission gates live in Rust (the court). Vault rules are expert witnesses.

## Phase 1 — Registry Gate (allowlist constitution; no ScopeIR yet)

### Outcome

One authoritative artifact answers:

- which `schema_id`s are allowed
- which `scope_id`s are allowed (name-level only)
- minimal versioning information

This immediately stops “schema_id is just a string passed around”.

### Artifact: `meta-registry/0` (schema id)

Store as canonical JSON bytes (like other artifacts) and content-address it (sha256). Payload shape (v0):

```json
{
  "schema_id": "meta-registry/0",
  "schema_version": 0,
  "registry_version": 0,
  "generated_at": "optional ISO-8601",
  "stdlib": [{ "module_id": "module:irrev_std@1" }],
  "schemas": [
    { "id": "vault-snapshot/0", "schema_version": 0, "kind": "snapshot", "canonical_encoding": "canonical-json" },
    { "id": "admissibility-witness/1", "schema_version": 1, "kind": "witness", "canonical_encoding": "canonical-cbor" }
  ],
  "scopes": [
    { "id": "scope:meta.registry", "version": 0 },
    { "id": "scope:main", "version": 0 }
  ]
}
```

Notes:

- Keep this deliberately small: it is a constitution/allowlist, not a full contract system.
- Use `domain.scope` naming inside the `scope:` namespace (`scope:hash.content`, `scope:time.now`, etc.).

### Enforcement points (Rust)

1. **Program scope gate (compile/check/execute)**
   - Extract `program.scope` from lowered IR and require it exists in `meta-registry`.
   - (Later) also gate on scope usage in program statements once scope references become explicit beyond `program.scope`.

2. **Artifact schema gate (artifact storage / ledger append)**
   - Before writing any artifact that carries a `schema_id`, require that `schema_id` exists in `meta-registry`.
   - Applies to witness artifacts, snapshot artifacts, bundle artifacts, and any future result artifacts.

### Registry location (v0)

Pick a single resolution mechanism:

- CLI flag or env var points at a registry JSON file (authoritative input), e.g. `--meta-registry PATH`.
- On build/init, the CLI also stores the registry itself as an artifact (content-addressed) and can record its hash in events/config.

### Witnessing rejections (so refusals are auditable)

When the registry gate rejects, emit a witness (even though no effect is allowed):

- `meta-registry-missing-schema/0`
- `meta-registry-missing-scope/0`

These should include at minimum:

- the missing id
- the registry hash used
- the action being attempted (e.g. “store_artifact”, “check_program”)

## Phase 2 — Scope Contracts (proto-ScopeIR; still no plugins)

### Outcome

Upgrade the registry from “names exist” to “contracts exist” so meta can enforce:

- phase placement
- determinism/oracle declarations
- witness schemas emitted/consumed
- dependency discipline + semantic deadlock checks

### Artifact: `meta-registry/1` (or split into `meta-scope-registry/1`)

Extend each scope entry:

```json
{
  "id": "scope:hash.content",
  "version": 1,
  "role": "domain|substrate|projection",
  "phase": "P0|P1|P2|P3|P4",
  "determinism": "deterministic|time_bound|oracle",
  "emits": ["hash-witness/0"],
  "consumes": [],
  "deps": [{ "scope_id": "scope:file.observe", "edge_kind": "needs_witness" }]
}
```

### Enforcement you can add immediately

- A scope may only emit witness schemas it declares.
- Determinism/oracle mismatch becomes an error (or a recorded “declared vs observed” finding).
- Run semantic-deadlock analysis over the dependency graph (boot-set + SCC checks).

## Minimal CLI surfaces (enough to make meta real)

Names are flexible; intent is not.

- `admit-cli registry init` → writes a starter registry file.
- `admit-cli registry build --in-place` → canonicalizes + stores registry as artifact (and prints hash).
- `admit-cli registry verify` → scans ledger/artifacts for unknown schema_id/scope_id references; reports drift.

## Why this sequence

- Phase 1 provides immediate governance leverage with minimal redesign.
- Phase 2 upgrades to structural reasoning (phase/determinism/deps) without requiring full domain-DSL plugins.
- `.scope` manifests + true `ScopeIR` generation become mechanical once contracts exist.

