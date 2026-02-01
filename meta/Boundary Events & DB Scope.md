---
role: support
type: design-note
canonical: true
facets:
  - governance
  - protocols
---

# Boundary Events & DB Scope

## Purpose

Capture the new boundary facts/events and the “database scope” idea so we can trace intentions and visualizations that depend on them.

## Boundary facts

### Fact: Boundary Declared

`Fact::BoundaryDeclared { subject_id, boundary_kind, includes, excludes, guard, notes }`

Subjects (scopes/mechanisms/packs/modules/rules) use this fact to state:

* what is inside (`includes`, e.g. resource sets, namespaces, effect types),
* what is outside (`excludes`),
* how crossing is controlled (`guard`, e.g. plan hash ceremony, approvals, required witnesses),
* optional signal notes (links to policies, invariants).

### Fact: Boundary Violation

`Fact::BoundaryViolation { subject_id, violated_by, evidence }`

Use this fact to mark observed touches that exceed declared boundaries; ledger events emit these facts so tooling can list failures.

### Ledger wiring

Add two ledger event types:

* `boundary.declared` → emits `BoundaryDeclared`
* `boundary.violated` → emits `BoundaryViolation`

Enables auditing queries: “Which boundaries declared but not satisfied?”, “Which packs claim closure yet show violations?”, etc.

## Database scope (`scope:db`)

### Intent

A database scope bounds persistent state effects:

* scope id examples: `scope:db:registry` (immutable blobs), `scope:db:ledger` (append-only events), `scope:db:app_state` (mutable data)
* mechanisms: query/mutation/migration/indexing
* packs: admissibility laws (what witnesses/approvals are required, what invariants apply)

The DB becomes a self-governing authority, issuing capabilities tied to namespaces and verifying witnesses for writes.

### Why SurrealDB

SurrealDB leans into CBOR + RPC + multi-model, matching your needs:

* CBOR integration w/ custom tags = canonical encoding
* RPC protocol = natural plan/execute pattern
* Graph + vector models = artifact connections + retrieval

Start by treating it as a runtime mechanism (mechanism protocol over RPC), not a compiler dependency.

### Scope v0 schema

#### `scope:db:registry`

Collections:

* `blob(hash, bytes_ref, size, schema_id, scope_id, created_at)`
* `bundle(hash, manifest_hash, scope_id, tags...)`
* `bundle_index(bundle_hash, role, blob_hash)` where `role` ∈ {plan,witness,snapshot,result}

Immutability rule: re-put must match existing hash and size.

#### `scope:db:ledger`

Collection:

* `event(id, ts, actor_id, scope_id, kind, refs[], payload_hash)`

Only inserts; no updates.

### Mechanism protocol sketch

Use Surreal-inspired RPC (describe/plan/execute):

1. `plan`: describe rows/keys/resources touched + declared costs + guard tokens
2. Compiler evaluates admissibility + emits witness tied to plan hash
3. `execute(plan_hash)`: DB applies the plan once and emits result witness
4. Optional `describe`/`status` for capability discovery + long-running ops

## Boundary panel hook

Use boundary facts + result witnesses to drive the proposed VS Code Boundary Panel:

* show declared includes/excludes/guard
* compare observed touches (from `ResultWitness` or `BoundaryViolation`)
* list guard compliance (required witnesses vs provided ones)

This makes self-governance visible: boundaries are claims with evidence.

