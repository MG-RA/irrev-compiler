---
role: support
type: implementation-plan
canonical: true
facets:
  - governance
  - runtime
  - bootstrap
status_date: 2026-02-05
---

# Runtime + Genesis Bootstrap Implementation Plan

This plan turns the existing **pure compiler** + **governed runtime loop** idea into an implementation you can ship in a batch CLI first, while keeping the architecture compatible with a daemon/watch loop later.

It also defines a **genesis bootstrap** for a governed ruleset (“constitution v0”) without circular dependency: ship *tiny kernel invariants* in Rust, and ship a *genesis ruleset artifact* embedded as bytes that the kernel treats as an allowed authority root.

## Goals

- Start from an empty directory and reach an auditable, governed runtime state:
  - content-addressed artifact store
  - append-only ledger spine
  - pinned `meta-registry` + pinned `ruleset` referenced by authority edges
- Provide a single execution engine:
  - **batch** CLI calls `tick(...)` once per command
  - **daemon** calls `tick(...)` repeatedly (FS events/timers/provider notifications)
- Keep Tier 0 (“kernel”) rules **small, non-bypassable, and boring**.
- Keep the first governed ruleset **shockingly small**, structural, and witnessable.

## Non-goals (v0)

- No always-on server is required.
- No signatures/PKI are required (hash + authority edges + ceremony is enough).
- No “compile arbitrary prose” semantics.
- No full “ruleset is written in `.adm` about `.adm`” reflection requirement; kernel-native meta checks may stand in as long as they emit normal witnesses.

## Definitions

### Tier 0: Kernel invariants (compiled)

Non-negotiable invariants enforced by Rust code, independent of the governed ruleset:

1. **Canonical identity is authoritative**
   - canonical bytes format is fixed per artifact kind
   - `sha256(canonical_bytes)` is the identity
2. **Pure/effect separation**
   - “pure scopes” cannot emit mutation edges or execute mechanisms
3. **All mutations go through the harness**
   - no direct writes to external systems from the evaluator
4. **Effectful artifacts must be traceable**
   - any event that claims a real-world effect must reference:
     - a plan hash
     - an authority state (ruleset hash + registry hash)
     - a result witness hash
5. **Acyclicity constraints**
   - selected edge kinds (e.g. pure dependency / build depends) must be acyclic
6. **Witness requirements for risk classes**
   - kernel defines the risk classes and minimum ceremony (see below)
7. **Deadlock-class invariants**
   - “no scope may require its own verdict to produce its required witnesses”

Kernel invariants must be checkable using only canonical artifacts + ledger events (no network).

### Tier 1: Governed ruleset (data)

A versioned, content-addressed ruleset artifact that:

- can be replaced only by a governed mutation (plan → witnesses → authority transition)
- is referenced by authority state edges in the ledger
- defines additional invariants (policy) that may evolve

### Genesis

A special, embedded ruleset artifact shipped in the binary:

- `ruleset:genesis@0` bytes are compiled into the CLI/runtime
- on first run, the runtime materializes the bytes into the artifact store
- the kernel allows `ruleset:genesis@0` as an authority root *only to bootstrap*

## Concrete artifact set (v0)

### 1) `meta-registry/0` (already exists conceptually)

- Purpose: make IDs (schemas/scopes/modules) **admissible only if declared**
- Encoding: **canonical CBOR map** (JSON is a view only)
- Identity: `meta_registry_hash = sha256(canonical_cbor(meta_registry))`

#### Minimal genesis slice

Keep the genesis registry as a **governance membrane**, not a knowledge base. The kernel only needs enough registry to interpret:

1. scope tags / known prefixes (string IDs + prefix rules)
2. edge policy matrix (allowed edge types + requirements)
3. risk-class ceremony policy (what needs plan/witness/approval)

Do **not** ship full domain registries in genesis; grow under governance later.

### 2) `ruleset/0`

Minimal schema (conceptual):

```text
Ruleset {
  schema_version: 0
  id: "ruleset:genesis@0" | "ruleset:<name>@<ver>"
  version: <u64>
  invariants: [InvariantDecl...]
  scope_matrix: ScopeMatrix
}
```

Rules should be:

- structural (canonicalization, scope separation, authority provenance)
- witnessable (produce failures with spans/refs)
- small enough to audit in one sitting

#### Encoding + hashing (decision)

- Encoding: **canonical CBOR map** (RFC 8949 canonical CBOR)
- Identity: `ruleset_hash = sha256(canonical_cbor(ruleset))`
- JSON is a **projection/view** only:
  - `admit show ruleset --format json` = decode CBOR → render JSON
  - hashing/storage remains CBOR

### 3) `authority-state/0`

Materialize the currently governing “constitution pointer” as an artifact:

```text
AuthorityState {
  schema_version: 0
  authority_id: "authority:local@0" (runtime instance)
  ruleset_ref: <ruleset_hash>
  meta_registry_ref: <meta_registry_hash>
  created_at: <string>? (optional)
}
```

Every governed event that changes the world references the **AuthorityState hash**.

#### Encoding + hashing (decision)

- Encoding: **canonical CBOR map**
- Identity: `authority_state_hash = sha256(canonical_cbor(authority_state))`

## Genesis bootstrap protocol

### CLI surface (recommended)

- `admit init`:
  - creates `out/ledger.jsonl` (or user-selected)
  - creates `out/artifacts/`
  - materializes:
    - `meta-registry/0` artifact (if not present)
    - `ruleset:genesis@0` artifact (embedded)
    - `authority-state/0` pointing at those hashes
  - appends genesis ledger events (append-only)

### Genesis events (suggested)

- `registry.initialized` → refs `meta_registry_hash`
- `ruleset.materialized` → refs `ruleset_hash`
- `authority.set` → refs `authority_state_hash`

### Kernel acceptance rule

Kernel allows exactly one "unwitnessed" transition:

- from empty → genesis authority state

After genesis, **all** rule/registry/authority transitions require governed ceremony.

### Genesis irreversibility cost

The genesis transition is irreversible. If the genesis ruleset or registry is incorrect, correction requires full re-initialization (state wipe and ledger reset).

This cost is accepted because genesis is the bootstrap boundary — there is no prior governed state from which to derive a correction ceremony. The alternative (negotiated genesis with external authority) contradicts the self-governing design stance.

Mitigation: genesis artifacts (registry, rulesets) undergo review discipline before first initialization. Post-genesis, all changes require witnessed ceremony.

## Runtime model: `tick(...)`

## Law governs claims (not behavior)

The runtime is not a moral authority and does not “make decisions about outcomes.” It is a **constitutional machine** that governs which *claims* may exist inside the system.

Practical consequence: admissibility is enforced over **ledger events + artifacts**. If the required structure (refs, witnesses, approvals, authority provenance) cannot be produced, the runtime **refuses to append** the claim event. The “thing” does not become governable/citable because it never enters the governed graph.

### Deny-on-fail vs record-as-violation

Two distinct classes of runtime output must not be mixed:

1. **Claims (deny-on-fail):** events whose presence asserts legitimacy.
   - Failure mode: do not append; return a structured error + a witness artifact describing why it was inadmissible (optional but recommended).
2. **Observations (record-as-violation):** events whose presence asserts that something *was observed* (including violations).
   - Failure mode: append is allowed because the claim is “this observation occurred,” not “this action is legitimate.”

Boundary tracking fits the second class (`BoundaryViolation`): it is evidence of drift, not a valid authorization.

### Minimal claim/event taxonomy (v0)

Recommended high-level ledger kinds, modeled as claims with required refs:

- `plan.created`: claim “this intended effect is specified”; refs a `PlanArtifact` hash.
- `witness.emitted`: claim “this check/eval occurred with these inputs”; refs witness artifact hash + input hashes.
- `approval.granted`: claim “approver X approved plan P under authority A”; refs approval artifact hash + plan hash + authority hash.
- `effect.executed`: claim “provider executed plan P”; refs plan hash + authority hash + provider receipt hash + execution log hash.
- `authority.set`: claim “the governing AuthorityState is now A”; refs authority state hash; only genesis is allowed without prior ceremony.
- `dag.trace` (optional but recommended): claim “this invocation admitted these nodes/edges”; refs a canonical CBOR DAG trace hash and links it to the invoked command + AuthorityState.

Each “effectful” claim must reference the **AuthorityState hash** active at execution time.

### Runtime state

Runtime loads (or derives) at the start of each tick:

- `ledger_head` (append-only event chain)
- `artifact_store` root + index
- current `AuthorityState` (ruleset hash + registry hash)
- derived views (cacheable):
  - scope graph
  - dependency DAG checks
  - pending plans / approvals

### Tick contract

```text
tick(state, command) -> (new_state, emitted_events, written_artifacts, result)
```

Where:

- `state` is reconstructed from ledger + artifacts (authoritative)
- `command` is one CLI request or one daemon “input”
- `result` is a user-facing outcome (JSON, text, exit code)

### Command classes

1. **Pure** (no mutations)
   - compile/check/verify/list/show
   - may write local derived caches if explicitly scoped as build artifacts
2. **Governed** (may mutate world)
   - always requires:
     - a plan artifact
     - admissibility/witness artifacts for the plan
     - authority state reference
     - execution through harness/provider

### Risk classes (kernel-defined)

Map each provider action to a minimum ceremony:

- `risk:ephemeral` (no persistence): plan optional, witness optional
- `risk:persistent` (writes local disk/db): plan required, witness required
- `risk:external` (writes outside repo): plan required, witness required, explicit approval token
- `risk:destructive` (delete/overwrite/irreversible external): plan required, witness required, approval required, external witness required

The governed ruleset may tighten these, but cannot weaken the kernel minimums.

### Approval token (decision)

Approvals are **first-class artifacts**, not env vars.

Recommended `approval/0` artifact (conceptual fields):

- `plan_ref` (hash)
- `authority_hash` (pins authority regime)
- `approver_id` (string)
- `scope` (string)
- `timestamp` (optional; include in bytes only if you want it to affect identity)
- `signature` (optional; can be introduced later as a governed upgrade)

For v0, you can support “weak approval” (no signature) but keep it content-addressed and referenced in the ledger/DAG.

### External witness for destructive operations (decision)

Model “external witness” as a **typed witness bundle** (multiple artifacts) rather than overloading “tests passed” to mean “a human agreed” or “the provider attested execution”.

Minimum recommended components for `risk:destructive`:

- `HumanSignoff` (often required)
- `ProviderAttestation` (often required)
- `ExecutionLog` (required)
- optional `TestAttestation` (scope-dependent)

Linkage pattern:

- `HumanApprovalArtifact -> WitnessOf -> PlanArtifact`
- `ProviderReceipt -> WitnessOf -> MutationExecution`
- `ExecutionLog -> WitnessOf -> MutationExecution`
- `TestReport -> WitnessOf -> PlanArtifact` (or execution)

## What’s in the first governed ruleset (v0)

Keep it structural and enforcement-friendly:

1. **Canonical identity invariant**
   - any governance-participating artifact must declare a canonicalizer and verify its hash
2. **Pure/effect separation**
   - `scope:*.pure` cannot emit mutation edges; runtime refuses execute
3. **Authority provenance**
   - any non-pure event must reference an AuthorityState hash
4. **Witness requirements by risk class**
   - confirm ceremony mapping is adhered to for declared plan kinds
5. **Acyclicity**
   - `BuildDepends` edges acyclic; optionally selected authority edges acyclic
6. **Cost edges attach**
   - cost declarations must attach to a plan or a governed decision event

Recommended “bootstrap invariant 0”: **span completeness** (attribution), because it makes all other violations witnessable.

## Ruleset evolution (first-class ceremony)

### Proposed flow

1. `admit ruleset propose --from <old_hash> --to <new_ruleset_file>`
   - produces a **plan** describing:
     - new ruleset canonical bytes hash
     - impacted invariants (declared)
     - required witnesses (tests/golden fixtures)
2. `admit check --plan <plan_hash>` (pure evaluation)
   - emits witness(es) that the *update itself* is admissible under current rules
3. `admit execute --plan <plan_hash> --witness <hash>`
   - writes new ruleset artifact
   - appends `ruleset.updated` and `authority.set` events

### Required witnesses for ruleset changes (v0)

- deterministic encoding witness (canonical bytes + hash)
- “golden fixture parity” witness for any kernel-adjacent encoding rule change
- any domain-specific witness the ruleset declares (later)

## Providers and harness boundaries

### In-process (simplest)

- providers are Rust traits implemented in the runtime binary
- easiest to keep deterministic and testable
- safest for v0

### JSON-RPC providers (extensible)

Match `meta/Compiler Runtime Loop.md`:

- `describe`
- `snapshot`
- `plan`
- `execute(plan_hash)`
- `verify`

Kernel rule: provider responses must be turned into canonical artifacts and witnessed before being used as authority for mutations.

## SurrealDB approach (DAG + ledger + runtime loop)

SurrealDB is a plausible runtime substrate because the system is two things at once:

1. a governed **artifact graph** (nodes + typed edges + scopes)
2. an append-only **event stream** (ledger, replay, audits, time windows)

Use SurrealDB as the **nervous system** (indexed storage, graph traversal, time-windowed event queries, change notifications) while keeping **identity and admissibility** anchored in Rust (canonical CBOR + hashing + kernel invariants).

### Constitutional rule (do not violate)

The DB must not become the authority for determinism:

- canonical bytes + content hashes are computed/verified in Rust
- witness validity, cycle checks, and admissibility gates are enforced in Rust
- the DB stores canonical blobs and/or projections, but is not the only place correctness “exists”

### Hybrid topology (recommended)

- **Rust (authoritative court):**
  - canonical CBOR encoding + `sha256` identity
  - ruleset/authority gating
  - witness generation + verification
  - cycle detection and other hard invariants
- **SurrealDB (query + projection + stream):**
  - store the DAG (node/edge) for traversal and UI
  - store ledger events for time-range queries and replay
  - provide change feeds / live queries to drive a continuous tick loop

This preserves “rules-as-law over admissibility” while making inspection and continuous workflows practical.

### Alignment with the Governed DAG plan

The concrete DAG model and phase plan live in `meta/DAG.md`. In particular:

- Phase 3 (`--dag-trace`) produces a canonical CBOR DAG trace per tick/command.
- Phase 4 introduces a SurrealDB projection sink for `scope:db:dag` (and later `scope:db:ledger`), matching the hybrid topology described here.
  - Commit: SurrealDB is the default projection/index/runtime-trigger substrate in v0 (`--surrealdb-mode=auto`).
  - Auto mode activates projection only when `SURREAL_NAMESPACE` + `SURREAL_DATABASE` (or flags) are configured and the endpoint is ready.
- Phase 5/6 add harnessed mutation edges and self-governance lint, which become primary inputs to DB-backed inspection and replay tooling.

### Conceptual SurrealDB schema (v0)

You can implement `scope:db:ledger` and `scope:db:dag` per `meta/Boundary Events & DB Scope.md` with tables shaped like:

- `artifact` (optional index)
  - `hash` (sha256 hex) primary key
  - `kind` (ruleset, authority_state, witness, plan, bundle, snapshot, receipt, log, ...)
  - `bytes` (canonical CBOR bytes) or `bytes_ref` (store path)
  - `schema_id`, `scope_id`, `created_at`
- `node`
  - `node_id` (stable id or content-hash keyed, pick one and stick to it)
  - `kind`, `scope_id`, `artifact_hash`, `labels`, `created_at`
- `edge` (as first-class relation records)
  - `from`, `to`
  - `edge_type` (AuthorityDepends, BuildDepends, WitnessOf, Plans, Executes, CostDeclares, ...)
  - `scope_id`, `risk_class`, `timeline`, `seq`, `metadata`
- `ledger_event`
  - `ts`, `seq` (monotonic per timeline), `kind`
  - `payload_hash` (artifact hash), `event_hash`
  - `authority_state_hash`, `plan_hash` (optional, depending on kind)

Rule: ledger events should be append-only at the interface level; updates are either forbidden or treated as a new event.

### Runtime loop via change feeds / live queries

Batch mode remains “one CLI command = one tick,” but continuous mode can be driven by DB notifications:

- subscribe to changes for:
  - new `ledger_event`
  - new `plan.created` needing checks
  - new `approval.granted` unblocking execution
- each notification enqueues a `tick(...)` command

Daemon mode becomes a thin loop driver, not a separate engine.

### Durability + crash/restart discipline (guardrail)

If SurrealDB is used as the primary ledger store:

- choose and document a durability mode explicitly
- add crash/restart tests that ensure:
  - no “lost” appended events
  - no reordering of `(timeline, seq)`
  - replay from the last committed event yields the same derived state

If durability guarantees are unclear, treat SurrealDB as a **projection/index** of a file-backed ledger until proven.

## Implementation milestones (execution-ready)

### M0 — Genesis bootstrap (1–2 days)

- [ ] Define `ruleset/0` + `authority-state/0` schemas (docs + Rust structs)
- [ ] Use **canonical CBOR maps** for both (JSON as a view only)
- [ ] Embed `ruleset:genesis@0` bytes in the CLI (include a pinned hash in tests)
- [ ] Implement `admit init` that materializes:
  - [ ] artifacts: registry + genesis ruleset + authority state
  - [ ] ledger: genesis events
- [ ] Golden test: init in a temp dir yields stable hashes + ledger events

### M1 — Tick engine (2–4 days)

- [ ] Introduce `tick` boundary (library function) used by CLI commands
- [ ] Ensure every governed command:
  - [ ] loads current AuthorityState
  - [ ] checks kernel invariants first
  - [ ] checks governed ruleset next
  - [ ] only then calls harness/provider
- [ ] Add `admit tick --once` (daemon-friendly entrypoint)

### M2 — Minimal governed runtime surfaces (3–6 days)

- [ ] `snapshot` surface for at least one scope (file/vault or registry)
- [ ] `eval` surface that produces a witness artifact tied to inputs + authority state
- [ ] `execute` surface that requires plan + witness + approval tokens for high risk

### M3 — Ruleset update ceremony (2–4 days)

- [ ] `ruleset propose/check/execute` (or integrate into existing `plan` + `execute`)
- [ ] Ledger events: `ruleset.updated`, `authority.set`
- [ ] Witness requirement: tests/golden fixture hash must be referenced by the update plan

### M4 — Daemon wrapper (optional; 2–5 days)

- [ ] `admit daemon` loop:
  - [ ] watches inputs (FS)
  - [ ] calls `tick` with synthesized commands
  - [ ] emits events but never bypasses ceremony

If using SurrealDB notifications, the daemon driver can subscribe to DB change feeds / live queries instead of FS watching (or in addition to it).

## Alternative implementations (choose later)

### A) Storage backend

- File-backed (current default): simplest, auditable, easy to diff
- SQLite: good local performance; still single-file auditable
- SurrealDB (as `scope:db` mechanism): strong fit for DAG + ledger + streaming runtime glue

Two safe deployment shapes:

1. **DB as projection/index** (safest):
   - canonical artifacts + append-only ledger remain file-backed
   - SurrealDB holds derived projections for query/UI and can be rebuilt from the ledger
2. **DB as primary store** (more powerful, higher bar):
   - canonical CBOR blobs stored in DB (or referenced by hash)
   - append-only constraints enforced by runtime + DB policy
   - durability and replay invariants must be tested as part of the kernel-adjacent harness

### B) Genesis distribution

- Embedded bytes (recommended): simplest, avoids “download the constitution”
- Repo-shipped file: easier to inspect, but trust boundary is murkier
- Signed genesis: strongest trust story, but adds key management (defer)

### C) Ruleset representation

- Structured ruleset JSON/CBOR (v0): easiest to validate and evolve
- `.adm` meta module (later): more elegant, but needs introspection and stable reflection
- Hybrid: JSON/CBOR ruleset that *references* `.adm` modules for checkers

### D) Runtime topology

- Batch-only CLI: simplest; every command is a tick
- Daemon: better feedback loops; same `tick` engine
- Remote adjudicator: possible via JSON-RPC, but increases trust surface (defer)

## Open questions (worth deciding explicitly)

Resolved by engineering decisions:

1. Encoding for `ruleset/0` and `authority-state/0`: **canonical CBOR maps**; JSON is projection only.
2. Genesis `meta-registry` slice: **scopes + edge policy matrix + risk ceremony policy only**.
3. Approval token: **content-addressed approval artifact** (optionally signed later).
4. External witness (destructive ops): **typed witness bundle** with separate components (human/provider/log/tests).

Remaining worth deciding explicitly:

1. Exact `ruleset/0` invariant DSL shape (structured predicates vs references to `.adm` meta modules vs hybrid).
2. How to bind `kernel_build_id` (and whether it is part of AuthorityState identity bytes).
3. Provider attestation schema surface (minimum required fields; redaction policy).

## Related

- `meta/Compiler Runtime Loop.md`
- `meta/design/compiler/kernel-stdlib-userspace-plan.md`
- `meta/design/compiler/selfgovernancebootstrap.md`
- `meta/design/compiler/meta-registry-gate-plan.md`
