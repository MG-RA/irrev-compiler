# Governed DAG Model for the Irreversibility Compiler

## Overview

Add a governed DAG layer to the Rust compiler that models compilation as a **graph of content-addressed nodes connected by typed edges**, with scope-bounded evaluation and provider-backed execution. The DAG emerges from existing patterns (content-addressed artifacts, scope dependencies, append-only ledger, phase discipline) rather than being bolted on.

## Status (2026-02-05)

- Phase 0 ✓ Type migration (`ArtifactRef`, `CompilerRef`, `ProgramRef` moved to `admit_core`)
- Phase 1 ✓ `admit_dag` core node/edge/graph types
- Phase 2 ✓ DAG validation (acyclicity, scope enforcement matrix, authority reachability)
- Phase 3 ✓ Tracer + CLI `--dag-trace` (canonical CBOR trace file)

## Crate Structure

New crate **`admit_dag`** between `admit_core` and `admit_cli`:

```
admit_core  (pure types, IR, witnesses, CBOR, hashing)
    ^
admit_dag   (DAG types, builder, validation, provider trait, scope enforcement)
    ^
admit_cli   (commands, ledger I/O, registry — unchanged externally)
```

**Prerequisite:** Move `ArtifactRef`, `CompilerRef`, `ProgramRef` from `admit_cli/src/types.rs` to `admit_core` so `admit_dag` can reference them without depending on CLI.

---

## Phase 0: Type Migration

Move shared reference types from CLI to core.

**Files:**
- [types.rs](irrev-compiler/crates/admit_cli/src/types.rs) — extract `ArtifactRef`, `CompilerRef`, `ProgramRef`
- [admit_core/src/lib.rs](irrev-compiler/crates/admit_core/src/lib.rs) — add `pub mod refs;` with migrated types
- CLI re-exports for backward compatibility

**Verify:** `cargo test` passes, all CLI commands unchanged.

---

## Phase 1: DAG Crate — Types Only

Create `irrev-compiler/crates/admit_dag/` with pure types, no CLI integration.

### Node Schema (`node.rs`)

```rust
/// Content-addressed node identity. Stored as raw bytes, displayed as hex.
/// Avoids normalization bugs and case drift vs String representation.
struct NodeId([u8; 32]);
// impl Display (lowercase hex), FromStr (hex decode), Serialize/Deserialize (hex string)

/// Identity payload — what gets hashed to produce NodeId.
/// Serialized as a canonical CBOR **map** with explicit keys, so encoding changes
/// are obviously versioned, not accidental drift.
///
/// NodeId = sha256(canonical_cbor({
///   "tag": "admit_dag_node_v1",
///   "kind": <NodeKind as canonical CBOR>,
///   "inputs": [<NodeId bytes>...],       // sorted by raw bytes (lexicographic on [u8;32])
///   "params": <params_cbor bytes>        // canonical CBOR of kind-specific params
/// }))
///
/// The outer structure is always a CBOR map with string keys. If the encoding
/// scheme ever changes, the tag version must change.
struct NodeIdPayload {
    tag: &'static str,       // "admit_dag_node_v1" — domain separator + version
    kind: NodeKind,
    inputs: Vec<NodeId>,     // sorted by raw [u8;32] bytes (lexicographic), NOT by hex string
    params_cbor: Vec<u8>,    // canonical CBOR of kind-specific params (storage form)
}
```

**Design decisions:**
- `[u8; 32]` not `String` — cheaper comparisons, no case normalization risk
- Domain separator `"admit_dag_node_v1"` — prevents collision with other SHA256 uses in the system
- Inputs sorted by **raw bytes** (lexicographic on `[u8; 32]`), not by hex string representation
- Hashed as explicit CBOR map with string keys — versioned encoding, not accidental drift
- `scope` is **excluded** from identity hash — same computation in different evaluation contexts produces the same node. Scope is metadata, not identity.

```rust
enum NodeCategory { Source, Derived, Governance }

/// Core kinds as a closed enum. Extension point via `kind_ext` on DagNode.
///
/// CRITICAL: Identity fields must be content-derived, not environment-derived.
/// Paths, names, and environment-specific identifiers go in DagNode.metadata,
/// not in NodeKind fields. This is the #1 place content-addressed systems
/// silently stop being content-addressed.
enum NodeKind {
    // Source — identity via content hash, not path/location
    RulesetSource { content_hash: String },        // NOT path — path goes in metadata
    RegistrySource { content_hash: String },        // content hash of registry state
    // Derived — identity via input content, not module names
    ParsedIR { content_hash: String },              // hash of parsed output
    DependencyGraph { content_hash: String },
    RegistryTable { schema_id: String },
    SnapshotExport { snapshot_hash: String },
    LintReport { content_hash: String },
    FactsBundle { bundle_hash: String },
    CalcPlan { plan_hash: String },
    CalcResult { witness_hash: String },
    // Governance — event_id is fine only if already content-addressed
    PlanArtifact { plan_hash: String, template_id: String },
    Approval { plan_hash: String, approver_hash: String },
    ExecutionLog { log_hash: String },              // hash of log content, not allocated id
    Witness { witness_sha256: String, schema_id: String },
    CostDeclaration { content_hash: String },
    AdmissibilityCheck { content_hash: String },
    AdmissibilityExecution { content_hash: String },
    // Explicit authority root — see "Authority source nodes" below
    AuthorityRoot { authority_id: String, authority_hash: String },
}

struct DagNode {
    id: NodeId,
    category: NodeCategory,
    kind: NodeKind,
    scope: ScopeTag,                        // metadata, not part of identity
    artifact_ref: Option<ArtifactRef>,      // reuses existing type from admit_core
    /// Extension point for experimental kinds. Hashed into identity if present.
    kind_ext: Option<String>,
    kind_meta: Option<Value>,
    /// Non-identity metadata: paths, module names, human labels, timestamps.
    /// Environment-derived identifiers (paths, names) belong HERE, not in NodeKind.
    metadata: Option<Value>,
}
```

**Taxonomy rules:**
- `NodeKind` is a closed enum for stable core kinds. `kind_ext` + `kind_meta` allow experimental kinds without enum explosion — but they're still hashed into identity, so they can't lie.
- **Content-derived fields** (hashes) go in `NodeKind`. **Environment-derived fields** (paths, machine-specific names, allocated IDs) go in `metadata`. This prevents "same content, different NodeId on different machines."
- `AuthorityRoot` is an explicit node kind — makes authority reachability checks unambiguous and testable.

### Edge Schema (`edge.rs`)

Five typed edges ("time arrows") with different acyclicity/governance rules:

```rust
enum EdgeType {
    BuildDepends,
    WitnessOf,
    /// Direction: AuthorityRoot → effectful_node ("authority authorizes this result").
    /// Reads like provenance. Reachability checks: "can I reach this node from an authority root?"
    AuthorityDepends {
        authority_id: String,       // stable identifier
        authority_hash: String,     // content hash of the authority source
    },
    MutationCommitment {
        harness_id: String,
        risk_class: MutationRiskClass,
    },
    CostDisplacement { cost: String, displaced_to: String },
}

/// Mutation risk tiers — lint enforces witness/approval policy per tier.
enum MutationRiskClass {
    LocalReversible,        // cache writes — lowest ceremony
    LocalPersistent,        // exports, generated files
    ExternalDestructive,    // DB wipes, external system mutations — highest ceremony
}

/// Step is scoped to a timeline, not global.
/// Prevents awkwardness with parallel executions or merged traces.
struct TimelineStep {
    timeline: String,   // e.g., harness execution id, or "build" for pure computation
    seq: u64,           // monotonic within timeline
}

/// Edge construction enforces witness requirements at type level.
/// MutationCommitment(LocalPersistent+) and AuthorityDepends (when scope rules require it)
/// MUST carry witness_ref. WitnessOf edges must NOT have witness_ref (they ARE the link).
/// This is enforced by DagEdge constructors, not by post-hoc lint.
struct DagEdge {
    from: NodeId,
    to: NodeId,
    edge_type: EdgeType,
    scope: ScopeTag,
    step: TimelineStep,
    witness_ref: Option<NodeId>,
}

impl DagEdge {
    /// Construct a MutationCommitment edge. witness_ref required for LocalPersistent+.
    fn mutation(from: NodeId, to: NodeId, harness_id: String,
                risk_class: MutationRiskClass, scope: ScopeTag,
                step: TimelineStep, witness_ref: Option<NodeId>) -> Result<Self, String> {
        if matches!(risk_class, MutationRiskClass::LocalPersistent
                                | MutationRiskClass::ExternalDestructive)
            && witness_ref.is_none() {
            return Err("MutationCommitment(LocalPersistent+) requires witness_ref");
        }
        Ok(DagEdge { from, to, edge_type: EdgeType::MutationCommitment { harness_id, risk_class },
                      scope, step, witness_ref })
    }

    /// Construct a WitnessOf edge. witness_ref must be None (this IS the witness link).
    fn witness_of(from: NodeId, to: NodeId, scope: ScopeTag, step: TimelineStep) -> Self {
        DagEdge { from, to, edge_type: EdgeType::WitnessOf,
                  scope, step, witness_ref: None }
    }
}
```

**Design decisions:**
- `AuthorityDepends` direction: **AuthorityRoot -> effectful_node** ("authority authorizes this result"). Reads like provenance. Reachability: "trace forward from authority roots to find all authorized nodes."
- `AuthorityDepends` carries both `authority_id` and `authority_hash` — pins claims to a specific authority state, not just a name
- `MutationRiskClass` tiered — ceremony enforced **at construction**, not just by lint: `LocalPersistent+` must carry `witness_ref`
- `WitnessOf` edges must NOT carry `witness_ref` (they are the witness link themselves)
- `TimelineStep` scoped — `(timeline, seq)` instead of global `u64`, so parallel executions and merged traces don't collide

### ScopeTag (`edge.rs`)

```rust
struct ScopeTag(String);  // "scope:core.pure", "scope:vault.read", "scope:fs.write", etc.
```

Maps directly to existing `MetaRegistryScope.id` format.

### GovernedDag (`graph.rs`)

Container with `BTreeMap<NodeId, DagNode>` + `Vec<DagEdge>`. Borrows the **ensure pattern** from legacy `sas-core` interpreter (idempotent node insertion via map entry API). Provides partial order views:

- `build_order_edges()` — BuildDepends only
- `authority_order_edges()` — AuthorityDepends only
- `mutation_order_edges()` — MutationCommitment, sorted by timeline+seq
- `accounting_order_edges()` — CostDisplacement only

**Verify:** Unit tests for construction, NodeId determinism (golden fixtures with known hashes), edge filtering, serialization roundtrip.

---

## Phase 2: DAG Validation

Add to `admit_dag`:

### Acyclicity (`validation.rs`)

DFS cycle detection on BuildDepends edges. Adapted from existing pattern in [scope_validation.rs](irrev-compiler/crates/admit_cli/src/scope_validation.rs).

### Scope Enforcement (`scope_enforcement.rs`)

**Declarative matrix, not hard-coded rules.** Boundary rules stored as data:

```rust
struct ScopeBoundaryRule {
    from_scope_prefix: String,          // e.g., "scope:core." or "scope:external."
    to_scope_prefix: String,
    edge_type_match: EdgeTypeMatch,     // see below
    allowed: bool,
    requires_witness: bool,
    requires_authority: bool,
    severity: Severity,                 // error | warning
}

/// EdgeTypeMatch must handle parameterized matching — not just "any MutationCommitment"
/// but also "MutationCommitment where risk_class >= LocalPersistent".
enum EdgeTypeMatch {
    Any,
    Exact(EdgeTypeTag),                 // e.g., BuildDepends, WitnessOf
    MutationWithMinRisk(MutationRiskClass),  // "risk_class >= threshold"
    AuthorityWithPrefix(String),        // "authority_id starts with X" (optional)
}
```

Default matrix:

| From | To | Edge Match | Allowed | Witness | Authority |
| --- | --- | --- | --- | --- | --- |
| `scope:core.pure` | `scope:core.pure` | BuildDepends | yes | no | no |
| `scope:core.pure` | `scope:fs.write` | Mutation(LocalPersistent+) | yes | yes | no |
| `scope:fs.write` | `scope:external.*` | Mutation(any) | yes | yes | yes |
| `scope:external.*` | any | Mutation(any) | yes | yes | yes |
| any | any | WitnessOf | yes | no | no |
| any | any | CostDisplacement | yes | no | no |

Compiled into fast prefix-based lookup. `EdgeTypeMatch` prevents reintroducing hard-coded exceptions for risk tiers or authority prefixes. Easy to unit test, easy to extend, produces explainable diagnostics.

### Authority Reachability Check

**"No authority bypass"** — every node in a non-pure scope must be reachable (in the authority-order subgraph) from at least one authority source node. If you produced an effectful artifact, you must show which authority regime authorized it.

**Verify:** Tests with known cyclic/acyclic graphs, forbidden edges, missing authority, authority bypass detection.

---

## Phase 3: Trace Collector + CLI Integration

### Tracer Trait (`trace.rs`)

Use a **trait with noop impl** instead of `enabled: bool`:

```rust
trait Tracer {
    fn timeline(&self) -> &str;
    fn next_step(&mut self) -> TimelineStep;
    fn ensure_node(&mut self, node: DagNode) -> bool;
    fn add_edge(&mut self, edge: DagEdge);
}

struct DagTraceCollector { dag: GovernedDag, timeline: String, next_seq: u64 } // real impl
struct NoopTracer { timeline: String, next_seq: u64 }                          // no-op impl
```

Threading `&mut dyn Tracer` keeps call sites clean — no conditional checks scattered everywhere. In v0, some traces may be reconstructed at the CLI boundary; later phases thread the tracer through library surfaces for deeper coverage.

### CLI Changes

- Implemented (v0):
  - Global `--dag-trace[=PATH]` flag on the `admit-cli` binary.
  - Writes a single canonical CBOR trace file per invocation (default `out/dag-trace.cbor`) and prints `dag_trace` + `dag_trace_sha256` (stderr in JSON mode).
  - Trace emission is wired for: `declare-cost`, `check`, `execute`, `plan new`, `calc plan`, `calc execute`.
  - SurrealDB projection (default `--surrealdb-mode=auto`) which sends the trace DAG into `scope:db:dag` tables via the installed `surreal sql` CLI.
    - In `auto` mode, projection activates only when `SURREAL_NAMESPACE` + `SURREAL_DATABASE` (or `--surrealdb-namespace/--surrealdb-database`) are set and the endpoint is ready.
    - Traces are projected even when `--dag-trace` is not set (file output is optional; DB projection uses in-memory bytes).
    - `--surrealdb-project` still works as a deprecated alias for `--surrealdb-mode=on`.
- Deferred (later phases / follow-up):
  - Thread `&mut dyn Tracer` through the `admit_cli` library surfaces for deeper coverage (instead of reconstructing at the CLI boundary).
  - Persist DAG trace as a content-addressed artifact and add a ledger event (`dag.trace`) that references it.
  - Add `admit-cli dag show <trace-id>` / `dag lint` surfaces once trace IDs are ledgered.

**Verify:** All existing tests pass with and without `--dag-trace`. Trace artifacts contain expected nodes/edges.

---

## Phase 4: Provider Trait + LocalFs

> Update (2026-02-05): align Phase 4 with `meta/design/compiler/runtime-genesis-implementation-plan.md`.
> SurrealDB is the preferred substrate for `scope:db:dag` + `scope:db:ledger` as a projection/index (and can later be promoted to primary store).
> Phase 4 therefore splits storage concerns:
>
> - **Artifact bytes** remain file-backed in v0 (existing `out/artifacts`) to keep bootstrap + determinism simple.
> - **DAG + ledger** are projected into SurrealDB for traversal, time-windowed queries, and change-driven runtime loops.

### Provider trait (`provider.rs`)

```rust
/// Canonical storage format — explicit, not assumed.
enum StoreFormat { CborSha256V1 }

/// Attested write result — proves what was written.
struct WriteReceipt {
    bytes_written: u64,
    content_hash: [u8; 32],   // hash of the actual stored bytes
    location_hint: String,
}

/// Storage model: two-level indirection.
///
/// node_id (computation identity) → content_hash (artifact bytes identity) → bytes
///
/// node_id is NOT the content hash of artifact bytes. It's the identity of the
/// computation that produced them. This gives:
/// - Node identity stability even if storage format changes
/// - Artifact dedup across different nodes that produce identical bytes
/// - Clear separation: "what was computed" vs "what bytes were stored"
///
/// Provider stores: content_hash → bytes
/// DAG stores:      node_id → content_hash (via DagNode.artifact_ref)

trait DagProvider: Send + Sync {
    fn id(&self) -> &str;
    fn capabilities(&self) -> ProviderCapabilities;
    fn canonical_store_format(&self) -> StoreFormat;
    fn serves_scopes(&self) -> Vec<ScopeTag>;
    /// Read by content_hash (from ArtifactRef.sha256), not by node_id.
    fn read_artifact(&self, content_hash: &[u8; 32]) -> Result<Vec<u8>, String>;
    /// Write bytes, returns receipt with computed content_hash.
    /// Caller links node_id → content_hash via DagNode.artifact_ref.
    fn write_artifact(&self, data: &[u8]) -> Result<WriteReceipt, String>;
    /// Check if content exists by hash.
    fn exists(&self, content_hash: &[u8; 32]) -> bool;
}
```

**Design decisions:**
- **Two-level storage:** `node_id` (computation identity) -> `content_hash` (bytes identity) -> bytes. Providers store by content hash, DAG maps node_id to content_hash via `artifact_ref`. This allows dedup and format-independent node identity.
- `canonical_store_format()` — explicit, testable, not assumed. Even if only `CborSha256V1` now.
- `write_artifact` returns `WriteReceipt` — attested result with content hash and size, not just `Ok(())`
- `deterministic` capability is a **claim verified by golden fixtures**, not trusted blindly

### LocalFsProvider

Wraps existing artifact store logic from [artifact.rs](irrev-compiler/crates/admit_cli/src/artifact.rs). When DAG trace is active, artifact operations route through provider. Direct path still works when trace is inactive.

### SurrealDB projection store (recommended)

Add a **projection sink** for governed evolution:

- projects `GovernedDag` traces into `scope:db:dag` tables for graph queries (`RELATE`)
- projects ledger events into `scope:db:ledger` tables for replay/audits/time windows
- supports change feeds/live queries to drive a continuous `tick(...)` loop later

This is not the authority for identity/admissibility (those remain Rust + canonical CBOR + hashes). It is an indexed, queryable projection of governed claims.

Suggested trait (conceptual):

```rust
trait ProjectionStore: Send + Sync {
    fn put_dag_trace(&self, trace_sha256: &str, trace_cbor: &[u8]) -> Result<(), String>;
    fn upsert_node(&self, node: &DagNode) -> Result<(), String>;
    fn upsert_edge(&self, edge: &DagEdge) -> Result<(), String>;
    fn append_ledger_event(&self, event_id: &str, event_json: &serde_json::Value) -> Result<(), String>;
}
```

In v0, you can start with “write trace + nodes/edges” only, and add ledger projection once Phase 5 introduces harnessed mutation events.

### ProviderRegistry

Finds provider by scope + capability requirements.

**Verify:** Provider-routed artifacts match direct artifacts byte-for-byte. Golden fixture verification for determinism claims.

---

## Phase 5: Mutation Harness

### Harness types (`harness.rs`)

```rust
/// Mutation domain — what subsystem is being mutated.
/// Distinct from risk_class: domain says WHERE, risk says HOW DANGEROUS.
/// Ledger mutations are "governance-critical" even though not "destructive."
enum MutationDomain {
    Ledger,       // governance-critical: always requires authority + witness
    Artifacts,    // content-addressed storage
    Registry,     // scope/schema registry
    Cache,        // ephemeral, reversible
    External,     // outside the system boundary
}

struct MutationPlan {
    id: String,
    scope: ScopeTag,
    risk_class: MutationRiskClass,
    domain: MutationDomain,
    target_description: String,
    requires_approval: bool,
    plan_ref: Option<NodeId>,
}

struct MutationWitness {
    mutation_id: String,
    scope: ScopeTag,
    risk_class: MutationRiskClass,
    domain: MutationDomain,
    success: bool,
    residual: Option<Value>,
    erasure_cost: Option<String>,
}

trait MutationHarness {
    fn execute(&self, plan: &MutationPlan, action: FnOnce) -> Result<MutationWitness, String>;
}
```

### Integration

Wrap mutation points in `admit_cli`:
- `append_event` / `append_checked_event` / `append_executed_event` in [ledger.rs](irrev-compiler/crates/admit_cli/src/ledger.rs)
- Artifact writes in [artifact.rs](irrev-compiler/crates/admit_cli/src/artifact.rs)

**Classification for existing mutations (risk_class + domain):**
- Ledger appends → `LocalPersistent` + `Ledger` (governance-critical: always authority + witness)
- Artifact writes → `LocalPersistent` + `Artifacts`
- Registry updates → `LocalPersistent` + `Registry`
- Cache/temp writes → `LocalReversible` + `Cache`
- Future Neo4j operations → `ExternalDestructive` + `External`

**Domain-specific ceremony override:** `MutationDomain::Ledger` always requires authority + witness regardless of risk class, because ledger mutations are governance-critical even when not destructive.

Each mutation through harness produces:
1. `MutationCommitment` edge in the DAG trace (with `risk_class` + `domain`)
2. `mutation.executed` event in the ledger

Update [verify.rs](irrev-compiler/crates/admit_cli/src/verify.rs) to validate new event types.

**Verify:** Ledger verification passes with mutation events. Dry-run mode skips harness. Lint enforces ceremony per risk tier.

---

## Phase 6: Self-Governance Lint

New CLI command: `admit-cli dag lint`

Loads a DAG trace and checks:

1. **BuildDepends acyclicity** — no cycles in pure computation
2. **Scope boundary violations** — checked against declarative matrix from Phase 2
3. **Authority completeness** — AuthorityDepends edges present where required
4. **No authority bypass** — every node in a non-pure scope reachable from an `AuthorityRoot` node in the authority-order subgraph (forward from root)
5. **Mutation witness completeness** — every MutationCommitment has witness_ref (construction-time enforced for `LocalPersistent+`, lint catches any gaps)
6. **Risk-class ceremony** — `ExternalDestructive` requires approval + plan; `LocalPersistent` requires witness; `LocalReversible` is free
7. **Domain-specific ceremony** — `MutationDomain::Ledger` always requires authority + witness regardless of risk class
8. **CostDisplacement accounting** — no orphaned cost edges

Output: violations with severity (error/warning), following existing `LedgerIssue` pattern.

**Verify:** Golden fixture tests with known violations (one fixture per check type).

---

## What to Borrow from Legacy sas-core

| Pattern | Source | Adaptation |
|---|---|---|
| `ensure_node` (idempotent insert) | [interpreter.rs](irrev-surfaces/legacy/sas-core/src/execution/interpreter.rs) L682-811 | `BTreeMap::entry` with content-addressed NodeId |
| Edge with scope + step | interpreter.rs GraphEdge | `DagEdge` with `ScopeTag` + `TimelineStep` |
| Authority stack tracking | interpreter.rs ActionRecord | `AuthorityDepends` edge type with `authority_hash` |
| `finalize()` snapshot | interpreter.rs GraphBuilder | `GovernedDag` serialization to CBOR |
| Scope stack frames | interpreter.rs ScopeFrame | Tracer scope tracking |

**Not borrowed:** SAS parser/tokenizer, domain packs, world model (future phase), async runtime (future phase).

---

## Irreversibility Concept Mapping

| Concept | DAG Representation |
|---|---|
| persistent-difference | Node with `artifact_ref` that persists across rebuilds |
| erasure-cost | `CostDisplacement` edge with cost field |
| residual | `MutationWitness.residual` value on mutation edges |
| constraint-load | Aggregate query over `CostDisplacement` edges (diagnostic) |

---

## File Layout

```
irrev-compiler/crates/admit_dag/
  Cargo.toml
  src/
    lib.rs
    node.rs               -- NodeId ([u8;32]), NodeCategory, NodeKind, DagNode
    edge.rs               -- DagEdge, EdgeType, MutationRiskClass, TimelineStep, ScopeTag
    graph.rs              -- GovernedDag container
    orders.rs             -- Partial order view methods
    validation.rs         -- Acyclicity, authority reachability, completeness
    scope_enforcement.rs  -- Declarative boundary rule matrix + validator
    trace.rs              -- Tracer trait, DagTraceCollector, NoopTracer
    harness.rs            -- MutationHarness trait + DefaultHarness
    provider.rs           -- DagProvider trait, StoreFormat, WriteReceipt, ProviderCapabilities
    provider_registry.rs  -- ProviderRegistry
```

---

## Verification Strategy

1. **Unit tests (admit_dag):** NodeId determinism with domain separator, GovernedDag construction, cycle detection, scope matrix validation, serialization roundtrip
2. **Integration tests (admit_cli):** All existing commands produce identical output without `--dag-trace`; with `--dag-trace`, valid trace artifacts are produced
3. **Golden hash fixtures:** Known DAG traces with expected NodeId hashes — prevents content-addressing drift, verifies domain separator, verifies determinism claims of providers
4. **Frozen serialization fixtures:** Assert exact canonical CBOR encoding for `NodeIdPayload` and `GovernedDag` — prevents "someone switched CBOR library settings and now everything drifted." One fixture per type, committed to repo, byte-for-byte comparison.
5. **Ledger verification:** `verify-ledger` validates new event types (`dag.trace`, `mutation.executed`)
6. **Build check:** `cargo build && cargo test` after each phase
