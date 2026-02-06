# Plan: Improve Compiler Integration with SurrealDB

## Executive Summary

This plan addresses six critical structural issues in the compiler-SurrealDB integration that prevent graceful degradation, create tight coupling, embed business logic in the wrong layers, and lack observability. The improved architecture will make SurrealDB truly optional, enable independent projection phases, extract testable business logic, add configuration and observability, while maintaining all system invariants (phase discipline, decomposition, governance, witness-first claims).

**Critical Architectural Insight**: SurrealDB is **memory/microscope**, NOT **authority/court**. The Rust compiler (court) is authoritative; SurrealDB projections are regenerable accounting artifacts.

## Implementation Progress (2026-02-06)

### [x] Phase 1: Projection Configuration Layer - COMPLETE
**Status**: Implemented and tested
**Location**: `crates/admit_surrealdb/src/projection_config.rs`

- [x] Created `ProjectionConfig` with hash computation for lineage tracking
- [x] Implemented `ProjectionPhases`, `BatchSizes`, `RetryPolicy`, `FailureHandling`
- [x] Added CLI flags: `--projection-enabled`, `--projection-batch-size`, `--projection-failure-mode`, `--vault-prefix`
- [x] Configuration as CBOR witness artifact
- [x] 7 comprehensive unit tests (all passing)
- [x] Documentation: [projection-configuration-guide.md](./projection-configuration-guide.md)
- [x] Demo example: `examples/projection_config_demo.rs`

**Benefits Achieved**:
- All tunable parameters now explicit and externalized
- CLI control over projection behavior
- Configuration becomes inspectable witness artifact
- Foundation for run-scoped configuration tracking

### [x] Phase 0: ProjectionRun Primitive - COMPLETE
**Status**: Implemented and tested
**Location**: `crates/admit_surrealdb/src/projection_run.rs`

- [x] Created `ProjectionRun` with full lifecycle tracking
- [x] Implemented `RunStatus`, `PhaseResult`, `PhaseStatus`, `FailedBatch`
- [x] Stable batch hash computation (survives batch size changes)
- [x] SurrealDB schema with indexes: [projection_run_schema.surql](../meta/surreal/projection_run_schema.surql)
- [x] Store methods: `begin_projection_run()`, `end_projection_run()`, `get_latest_projection_run()`
- [x] Demonstration of `projection_run_id` stamping in SQL generation
- [x] 7 comprehensive unit tests (all passing)
- [x] Total test count: 24 (increased from 10)

**Benefits Achieved**:
- Every DB state now traceable to projection run that created it
- Full lineage: trace -> run -> projector version -> config
- Deterministic retry by stable batch hash
- Foundation for run-to-run diffs and garbage collection
- **Transforms "best-effort vibes" into "auditable accounting"**

**What Changed**:
The "run accounting" primitive (previously only for embeddings via `embed_run`) is now universal:
- `projection_run` tracks ALL projection executions
- Each run has full lineage (trace, config, projector version)
- Failed batches tracked with stable hashes
- Phase-level results tracked independently

### [x] Phase 2A: ProjectionStore Trait - COMPLETE

**Status**: Implemented and tested
**Location**: `crates/admit_surrealdb/src/projection_store.rs`

- [x] Created `ProjectionStoreOps` trait with comprehensive projection operations
- [x] Implemented `NullStore` for graceful degradation (no-op when SurrealDB disabled)
- [x] Implemented trait for `SurrealCliProjectionStore` with run_id stamping
- [x] Added `ProjectionError` and `ProjectionResult` types
- [x] Added `_with_run` variants for SQL generation (nodes, edges, chunks, docs)
- [x] Re-exported key types: `NullStore`, `ProjectionStoreOps`, `ProjectionError`, `ProjectionResult`
- [x] 7 unit tests for NullStore and error types (all passing)
- [x] Total test count: 31 (increased from 24)

**Benefits Achieved**:

- "Optional" is now trait-based, not if/else jungle
- NullStore enables commands to succeed without SurrealDB
- All projections can be stamped with `projection_run_id`
- Foundation for multiple backends (SurrealDB, null, future sqlite/jsonl)
- Testable with mock stores

**What the trait covers**:

- Run lifecycle: `begin_run()`, `end_run()`, `get_latest_run()`
- Schema management: `ensure_schemas()`
- DAG trace projection with run_id stamping
- Document projections: `project_doc_files()`, `project_doc_chunks()`, `project_vault_links()`
- Embedding projections: `project_embeddings()`, `project_title_embeddings()`
- Query operations: `select_doc_files()`, `select_unresolved_links()`, `search_title_embeddings()`

### [x] Phase 2B: Extract Link Resolver - COMPLETE

**Status**: Implemented and tested
**Location**: `crates/admit_surrealdb/src/link_resolver.rs`

- [x] Created pure link resolution module with no database dependencies
- [x] Extracted business logic from `lib.rs`: `VaultLinkResolver` struct
- [x] Data structures: `ObsidianLink`, `ResolutionResult`, `AssetResolution`, `VaultDoc`
- [x] Public helpers: normalization, parsing, indexing functions
- [x] Refactored `lib.rs` to delegate to link_resolver module
- [x] 8 comprehensive unit tests (all passing)
- [x] Total test count: 38 (increased from 31)
- [x] Vault prefixes now parameterized (no hardcoded paths)

**Benefits Achieved**:
- Pure business logic testable without database
- Reusable in LSP/CLI tools
- Clear separation: resolver (pure) vs projector (IO)
- Satisfies decomposition invariant
- **Sprint 1 is now COMPLETE**

### [x] Configuration Wiring - COMPLETE

**Status**: Implemented and tested
**Date**: 2026-02-06

**What Was Wired Up**:

1. **SurrealCliProjectionStore Integration**:
   - [x] Added `projection_config` field to `SurrealCliProjectionStore` struct
   - [x] Created `with_projection_config()` constructor method
   - [x] Added `projection_config()` accessor method

2. **Batch Size Configuration**:
   - [x] Replaced all 12 hardcoded `const BATCH_LIMIT` constants with `self.projection_config.batch_sizes` references
   - [x] Updated projection methods to use configurable batch sizes:
     - `project_doc_embeddings()` -> `doc_chunks`
     - `project_doc_files_from_artifacts()` -> `doc_files`
     - `project_doc_title_embeddings()` -> `doc_chunks`
     - `project_unresolved_link_suggestions()` -> `links`
     - `project_vault_docs()` -> `doc_files`, `headings`, `links`, `stats`
     - `project_dag_trace()` -> `nodes`
     - `project_doc_chunks()` -> `doc_chunks`

3. **CLI Integration**:
   - [x] Updated `build_surreal_projection_store()` to build and pass `ProjectionConfig`
   - [x] Existing CLI flags already functional:
     - `--projection-enabled=<phases>`
     - `--projection-batch-size=<phase:size>`
     - `--projection-failure-mode=<mode>`
     - `--vault-prefix=<prefix>`

4. **Testing**:
   - [x] All 38 tests passing in `admit_surrealdb`
   - [x] Full cargo build succeeds with no errors
   - [x] CLI package builds successfully

**Benefits Achieved**:
- All batch sizes now configurable via CLI flags
- No more hardcoded magic numbers in projection code
- Configuration is externalized and can be tuned without code changes
- Foundation for TOML config file support (Phase 8)
- Configuration as witness artifact (already implemented in Phase 1)

**What This Enables**:
- Users can now override batch sizes: `--projection-batch-size=doc_chunks:100`
- Vault prefixes are parameterized: `--vault-prefix=my-vault/`
- Failure handling modes are configurable: `--projection-failure-mode=fail-fast`
- Phases can be selectively enabled: `--projection-enabled=dag_trace,doc_files`

### [x] Phase 4: Queryable Observability (Projection Events) - COMPLETE

**Status**: Implemented and exercised against a real ingest.

**What was added**:
- Ledger events for projection boundaries (file-backed, survives DB downtime):
  - `projection.run.started`
  - `projection.phase.completed`
  - `projection.run.completed`
- SurrealDB projection table for queryable observability:
  - `projection_event` (indexed by `projection_run_id`, `event_type`, `timestamp`, `trace_sha256`)
- `ingest dir` now creates a `projection_run` and emits these events while running enabled projection phases.
- `verify_ledger` accepts `projection.*` events and checks their `event_id` hashes.

**Practical outcome**:
- Long "silent" runs are now explainable and queryable (phase durations, failures).
- Example run shows exact phase times (e.g. `doc_chunks` took ~66s, `dag_trace` ~49s).

### Next Steps

According to the implementation plan:

**Sprint 1: Store Abstraction + Business Logic** (2 weeks)

- ~~Phase 2A: ProjectionStore trait (abstraction layer)~~ [x] COMPLETE
- ~~Phase 2B: Extract link resolver (pure business logic)~~ [x] COMPLETE

**Sprint 2: Resilience + Observability** (2 weeks)

- ~~Phase 4: Queryable observability via SurrealDB~~ [x] COMPLETE
- ~~Wire up configuration to existing projection code~~ [x] COMPLETE

**Sprint 3: Run-Scoped Operations** (2 weeks)
- Phase 5: Run-scoped replacement (replaces hard deletes)
- Phase 6: Deterministic batch retry

**Sprint 4: Graceful Degradation** (2 weeks)
- Phase 7: Circuit breaker and optional SurrealDB
- Phase 3: Projection coordinator (orchestration)

## Status Update (2026-02-06) [Historical]

This plan predates several improvements which are now implemented. The plan still identifies real structural issues, but it needs to reflect the current integration surface.

**Already implemented**
- SurrealDB projection substrate via `surreal sql` (`SurrealCliProjectionStore`), including doc projections and vault graph projections.
- `.gitignore`-aware directory ingestion (prefers `git ls-files -co --exclude-standard`; falls back to an `ignore`-crate filesystem walk which honors nested `.gitignore` and negation patterns).
- Ingestion protocol v0 (ledger-backed, survives DB downtime):
  - `ingest.run.started` and `ingest.run.completed` events in `out/ledger.jsonl`
  - content-addressed artifacts: `ingest_config`, `ingest_coverage`, `ingest_run`
  - SurrealDB query projections: `ingest_run` and `ingest_event`
- Vault graph fidelity primitives (no silent drop):
  - `obsidian_link` (doc->doc links with explicit resolution outcomes)
  - `obsidian_file_link` (doc->file-path links for asset-style links)
  - `doc_link_unresolved` with explicit `missing`, `heading_missing`, `ambiguous`
- Frontmatter + facets projection on `doc_file`, plus `facet` and `has_facet`.
- Local embeddings (Ollama):
  - `doc_embedding` (chunk embeddings)
  - `doc_embedding_doc` (doc mean-pooled embeddings)
  - `embed_run` (embedding run accounting)
- Propositional repair suggestions for unresolved links:
  - `doc_title_embedding` (title embeddings for candidate search)
  - `unresolved_link_suggestion` (per-link candidate list + recommended doc)
- Surrealist query templates updated in `meta/surreal/views.surql` (including SurrealQL subquery ordering quirks).

**Still true / still needs work**
- Graceful degradation is partial: `ProjectionStoreOps` + `NullStore` exist, but we still need an explicit circuit breaker + clearer mode semantics (auto/off/on) so "DB down" is consistently non-fatal unless explicitly required.
- Projection orchestration is still mostly in the CLI command path (no dedicated coordinator yet), so phase independence and retry policy are not centralized.
- Observability is v0: we have run/phase boundary events, but not batch-level events, per-item counts, or consistent progress output to console.

## The One Thing That Changes Everything

This has now been implemented: `ProjectionRun` + `projection_run_id` stamping across projections turns "best-effort vibes" into "auditable accounting".

This single primitive transforms the entire integration from "best-effort vibes" into "auditable accounting" by:

- Making every DB state traceable to which ingest produced it
- Enabling deterministic retry by stable batch identity
- Supporting run-to-run diffs and garbage collection
- Providing full lineage: trace -> run -> projector version -> config

Without this, you're debugging mysteries. With it, you're querying facts.

**What changed since this section was written**
- The run accounting primitive is now universal (`projection_run`), not embedding-only.
- Link resolution business logic has been extracted into a pure, testable module (`link_resolver`).
- The next missing piece is the event spine (Phase 4) so run/phase/batch outcomes become queryable over time, even when SurrealDB is down.

## Problem Analysis

### Current Architecture

The system implements a **two-loop pattern**:
1. **Compiler loop (pure)**: `.adm` modules -> IR + compile witness (no world state mutations)
2. **Runtime loop (governed effects)**: compiled program + snapshots -> findings, plans, cost declarations, results, witnesses

**SurrealDB's Role**: Regenerable projection/index (NOT authoritative). Authoritative sources: file-backed artifacts + append-only ledger.

### Six Critical Issues Identified

#### Issue 1: Tight Coupling & No Graceful Degradation
- **Location**: `crates/admit_cli/src/main.rs` (`maybe_project_*` helpers; line numbers drift frequently)
- **Problem**: `maybe_project_*()` functions cause entire command to fail if SurrealDB unavailable
- **Impact**: Database outage makes compiler runtime unoperational
- **Root Cause**: No fallback to ledger-only mode, no retry logic, no partial failure handling

#### Issue 2: Non-Composable Sequential Projections
- **Location**: `crates/admit_cli/src/main.rs` (ingest projection sequence; line numbers drift frequently)
- **Problem**: Three sequential projections (trace, doc_chunks, vault_links) are all-or-nothing
- **Impact**: Cannot selectively disable or recover from failures in one projection
- **Root Cause**: No independence between projection phases

#### Issue 3: Business Logic Embedded in Database Layer
- **Location**: [lib.rs:1316-1542](c:\Users\user\code\Irreversibility\irrev-compiler\crates\admit_surrealdb\src\lib.rs#L1316-L1542)
- **Problem**: Link resolution logic (title matching, ambiguity resolution, heading validation) not testable independently
- **Impact**: Hardcoded vault-specific prefixes ("irrev-vault/", "chatgpt/vault/"), not reusable in CLI/LSP
- **Root Cause**: Violation of decomposition invariant - business logic coupled to IO

#### Issue 4: Hardcoded Batch Sizes Without Observability
- **Locations**: Multiple in [lib.rs](c:\Users\user\code\Irreversibility\irrev-compiler\crates\admit_surrealdb\src\lib.rs)
- **Problem**: Different batch sizes hardcoded (nodes: 200, chunks: 50, links: 100, etc.)
- **Impact**: No way to tune without code changes, no performance metrics
- **Root Cause**: Configuration not externalized

#### Issue 5: Self-Cleaning Deletes Without Audit Trail
- **Location**: [lib.rs:385-402](c:\Users\user\code\Irreversibility\irrev-compiler\crates\admit_surrealdb\src\lib.rs#L385-L402)
- **Problem**: `DELETE obsidian_link WHERE from_doc_path = X` is idempotent but silent
- **Impact**: No warning for duplicates or stale entries
- **Root Cause**: No audit logging for cleanup operations

#### Issue 6: Ledger-SurrealDB Write Asymmetry
- **Locations**: Throughout projection code
- **Problem**: Ledger is append-only, SurrealDB does upsert/delete; no transactional guarantee
- **Impact**: Partial failures leave database in inconsistent state (batch 10 of 50 fails -> first 9 already committed)
- **Root Cause**: No batch-level error handling or retry mechanism

### Current Loop Structures

| Loop | Batching | Triggered By | Issues |
|------|----------|--------------|--------|
| DAG trace projection | 200 nodes + 200 edges | Any command with trace | Hardcoded batch size, no retry |
| Doc chunks | 50 text chunks | `ingest_dir` | Hardcoded batch size |
| Doc files | 200 docs | `ingest_dir` | Hardcoded batch size |
| Headings | 200 headings | `ingest_dir` | Hardcoded batch size |
| Link resolution | 100 links per batch | `ingest_dir` | Complex nested loop, embedded business logic |
| Stats materialization | 200 docs | `ingest_dir` | Hardcoded batch size |
| Doc chunk embeddings (Ollama) | 16 per batch (CLI default) | `ingest_dir --ollama-embed` | Long-running, no unified run stamping across all projections |
| Doc title embeddings (Ollama) | 16 per batch (CLI default) | `ingest_dir --ollama-suggest-unresolved` | Used as candidate index; not yet modeled as a separate projection phase |
| Unresolved-link suggestions | 1 query per unresolved target | `ingest_dir --ollama-suggest-unresolved` | Proposal quality needs calibration; must remain propositional (no auto-mutation) |

## Solution Architecture

### Foundational Insight: Court vs Memory vs Projections

**Critical architectural distinction** (from user feedback):

```
                 ┌──────────────────────────────────────────┐
                 │                USERS / CI                │
                 │  edits, ingests, approvals, queries      │
                 └───────────────────────┬──────────────────┘
                                         │
                                         v
┌──────────────────────────────┐   ┌──────────────────────────────┐
│        INGEST DRIVER          │   │          QUERY/UI             │
│  scans dir / repo / vault     │   │ Surrealist / GraphQL / CLI    │
│  produces identity artifacts  │   │ FTS, graph traversals, stats  │
└───────────────┬──────────────┘   └───────────────┬──────────────┘
                │                                  │
                v                                  v
┌───────────────────────────────────────────────────────────────┐
│                 SURREALDB (memory of structure)                │
│  Tables: identity, artifact, dag_trace, doc_file, doc_chunk,   │
│          obsidian_link, unresolved_link, stats, timeseries...  │
│  Relations: RELATE / typed edges / FETCH links / FTS / vectors  │
└───────────────────────────────┬───────────────────────────────┘
                                │
                                v
┌───────────────────────────────────────────────────────────────┐
│                  RUST COMPILER (the court)                     │
│  parse/lower/eval -> witness artifacts (CBOR canonical objects) │
│  enforces invariants, authority-state, approvals, scope rules   │
└───────────────────────────────────────────────────────────────┘
```

**Key principle**: **SurrealDB is not authority. It's the microscope + memory. Rust is the judge.**

This means:
- **Compiler-as-object**: Compiler repo/binary is an identity-addressed artifact that rules can govern
- **Compiler-as-court**: Running Rust binary evaluates admissibility and emits verdicts/witnesses
- **The court can judge a copy of itself, but not redefine the court mid-sentence**

### Design Principles

1. **Authority Separation**: SurrealDB is regenerable projection (microscope); Rust compiler is authority (court)
2. **Graceful Degradation**: Commands succeed without SurrealDB (memory optional, court essential)
3. **Independent Phases**: Each projection phase can fail individually without affecting others
4. **Pure Business Logic**: Extract domain logic from IO concerns
5. **Configuration First**: All tunable parameters externalized
6. **Observability**: Metrics and logging for production debugging
7. **Maintain Invariants**: Respect phase discipline, decomposition, governance, witness-first claims
8. **Self-Governance**: Compiler changes governed by rules, but enforcement via trusted build

### Phase 0: Projection Run Primitive (FOUNDATIONAL)

**Create**: `irrev-compiler/crates/admit_surrealdb/src/projection_run.rs`

**Purpose**: The missing primitive that turns "best-effort vibes" into "auditable accounting"

**Key Types**:
```rust
/// Represents a single projection execution with full lineage
pub struct ProjectionRun {
    pub run_id: String,                    // UUID or timestamp-based
    pub trace_sha256: String,              // Source trace identity
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub projector_version: String,         // Crate version + git sha
    pub config_hash: String,               // Hash of resolved config
    pub phases_enabled: Vec<String>,
    pub status: RunStatus,
    pub phase_results: BTreeMap<String, PhaseResult>,
}

pub enum RunStatus {
    Running,
    Partial,      // Some phases succeeded, some failed
    Complete,     // All enabled phases succeeded
    Failed,       // All phases failed
    Superseded,   // Newer run completed
}

pub struct PhaseResult {
    pub phase: String,
    pub status: PhaseStatus,
    pub total_batches: usize,
    pub successful_batches: usize,
    pub failed_batches: Vec<FailedBatch>,
    pub duration_ms: u64,
    pub error: Option<String>,
}

pub struct FailedBatch {
    pub batch_hash: String,        // hash(item_ids + phase + run_id)
    pub batch_index: usize,
    pub item_ids: Vec<String>,     // Stable item identifiers
    pub error: String,
    pub attempt_count: usize,
}
```

**SurrealDB Schema Addition**:
```sql
DEFINE TABLE projection_run SCHEMALESS;
DEFINE INDEX projection_run_trace ON TABLE projection_run COLUMNS trace_sha256;
DEFINE INDEX projection_run_status ON TABLE projection_run COLUMNS status;
DEFINE INDEX projection_run_started ON TABLE projection_run COLUMNS started_at;
```

**Stamping in Projected Tables**:
Every projected record gets:
- `projection_run_id` field
- Optionally `trace_sha256` for direct lineage

**Benefits**:
- Query "show me DB rows from the latest successful run"
- Garbage-collect by run_id
- Retry "continue run X" instead of "retry whatever failed vaguely"
- Audit trail: which projector version produced which DB state
- **This single addition massively lowers entropy**

### Phase 1: Projection Configuration Layer

**Create**: `irrev-compiler/crates/admit_surrealdb/src/projection_config.rs`

**Purpose**: Centralize all tunable projection parameters

**Key Types**:
```rust
pub struct ProjectionConfig {
    pub enabled_phases: ProjectionPhases,
    pub batch_sizes: BatchSizes,
    pub retry_policy: RetryPolicy,
    pub failure_handling: FailureHandling,
    pub vault_prefixes: Vec<String>,
}

pub struct BatchSizes {
    pub nodes: usize,           // default: 200
    pub edges: usize,           // default: 200
    pub doc_chunks: usize,      // default: 50
    pub doc_files: usize,       // default: 200
    pub headings: usize,        // default: 200
    pub links: usize,           // default: 100
    pub stats: usize,           // default: 200
}

pub enum FailureHandling {
    FailFast,                   // Abort on any error
    WarnAndContinue,            // Log warning, continue
    SilentIgnore,               // No error, no warning
}
```

**Configuration as Witness**:
- Parse CLI/env -> build ProjectionConfig
- Emit `projection.config_resolved@1` artifact (CBOR)
- Coordinator uses that artifact
- **Benefits**: Self-describing system, reduces "hidden config drift"
- **Later**: Add TOML as one more input format

**CLI Additions** in [main.rs](c:\Users\user\code\Irreversibility\irrev-compiler\crates\admit_cli\src\main.rs):
- `--projection-enabled=<phase>[,<phase>...]`
- `--projection-batch-size=<phase>:<size>`
- `--projection-failure-mode=<mode>`
- `--vault-prefix=<prefix>` (repeatable)

**Benefits**: Makes all tunable parameters explicit, enables runtime configuration

### Phase 2A: Projection Store Trait

**Create**: `irrev-compiler/crates/admit_surrealdb/src/projection_store.rs`

**Purpose**: Prevent "Surreal creep" by abstracting storage operations

**Key Trait**:
```rust
/// Trait for projection storage backends
pub trait ProjectionStore {
    // Run lifecycle
    fn begin_run(&self, run: &ProjectionRun) -> Result<String>;  // Returns run_id
    fn end_run(&self, run_id: &str, status: RunStatus) -> Result<()>;
    fn get_latest_run(&self, trace_sha256: &str) -> Result<Option<ProjectionRun>>;

    // Batch operations with run stamping
    fn upsert_doc_files(&self, run_id: &str, batch: &[DocFile]) -> Result<()>;
    fn upsert_doc_chunks(&self, run_id: &str, batch: &[DocChunk]) -> Result<()>;
    fn upsert_links(&self, run_id: &str, batch: &[ResolvedLink]) -> Result<()>;
    fn upsert_nodes(&self, run_id: &str, batch: &[DagNode]) -> Result<()>;
    fn upsert_edges(&self, run_id: &str, batch: &[DagEdge]) -> Result<()>;

    // Batch failure tracking
    fn record_batch_failure(&self, run_id: &str, failed: &FailedBatch) -> Result<()>;

    // Query operations
    fn query_by_run(&self, run_id: &str, table: &str) -> Result<Vec<serde_json::Value>>;
}
```

**Implementations**:
- `SurrealCliProjectionStore` (existing, adapted)
- `NullStore` (no-op for --surrealdb-mode=off)
- **Future**: `JsonlStore` (write projection log artifact for debugging)
- **Future**: `SqliteStore` (local-only, no server)

**Benefits**:
- "Optional" is trait-based, not if/else jungle
- Testing with mock stores
- Multiple backend support without coupling

### Phase 2B: Extract Business Logic

**Create**: `irrev-compiler/crates/admit_surrealdb/src/link_resolver.rs`

**Purpose**: Pure link resolution logic without database dependencies

**Key Type**:
```rust
/// Pure link resolution - no database dependencies
pub struct VaultLinkResolver {
    vault_docs: BTreeMap<String, VaultDoc>,
    title_exact_index: BTreeMap<String, BTreeSet<String>>,
    title_casefold_index: BTreeMap<String, BTreeSet<String>>,
    heading_index: BTreeMap<String, BTreeSet<String>>,
    vault_files: BTreeMap<String, String>,
}

impl VaultLinkResolver {
    pub fn from_dag(
        dag: &GovernedDag,
        artifacts_root: &Path,
        vault_prefixes: &[&str],
    ) -> Result<Self, String>;

    pub fn resolve_link(&self, from: &str, link: &ObsidianLink)
        -> ResolutionResult;

    pub fn resolve_asset(&self, from: &str, target: &str)
        -> Option<AssetResolution>;
}
```

**Functions to Move** from [lib.rs](c:\Users\user\code\Irreversibility\irrev-compiler\crates\admit_surrealdb\src\lib.rs):
- `resolve_obsidian_target` (line ~1527)
- `resolve_obsidian_asset_target` (line ~1397)
- `choose_ambiguous_target` (line ~1678)
- `build_heading_index` (line ~1128)
- `build_file_index` (line ~1152)

**Benefits**:
- Testable without database (unit tests for resolution logic)
- Reusable in LSP/CLI tools
- Vault prefixes become parameters, not hardcoded
- Clear separation: resolver (pure) vs projector (IO)
- Satisfies decomposition invariant

### Phase 3: Projection Coordinator

**Create**: `irrev-compiler/crates/admit_surrealdb/src/projection_coordinator.rs`

**Purpose**: Orchestrate independent projection phases with failure handling

**Key Types**:
```rust
pub struct ProjectionCoordinator {
    store: Arc<SurrealCliProjectionStore>,
    config: ProjectionConfig,
    metrics: ProjectionMetrics,
}

pub struct ProjectionResult {
    pub phase: ProjectionPhase,
    pub success: bool,
    pub duration_ms: u64,
    pub error: Option<String>,
    pub items_processed: usize,
}

impl ProjectionCoordinator {
    /// Project all enabled phases independently
    pub fn project_all(
        &self,
        trace_sha256: &str,
        trace_cbor: &[u8],
        dag: &GovernedDag,
        artifacts_dir: &Path,
    ) -> Vec<ProjectionResult>;

    /// Project individual phase with retry logic
    fn project_phase(&self, ...) -> ProjectionResult;
}
```

**Refactor** [main.rs:1635-1646](c:\Users\user\code\Irreversibility\irrev-compiler\crates\admit_cli\src\main.rs#L1635-L1646):
```rust
// Before
maybe_project_trace(surreal, ...)?;
maybe_project_doc_chunks(surreal, ...)?;
maybe_project_vault_links(surreal, ...)?;

// After
let coordinator = maybe_build_coordinator(&cli)?;
if let Some(results) = coordinator.project_all(...) {
    report_projection_results(&results);
}
```

**Benefits**:
- Each phase fails independently
- Command continues even if projection fails
- Centralized retry logic
- Clear failure handling policy

### Phase 4: Queryable Observability (Ledger-Backed, Projected into SurrealDB)

**Status**: Implemented (v0).

**Purpose**: Make observability queryable, without making SurrealDB the authority.

**Key insight**:
- SurrealDB is the microscope (query/index/trigger substrate).
- The court must be able to re-derive and audit observations without the DB.
- Therefore: emit an append-only event stream as court artifacts, then project those events into SurrealDB for UI and queries.

#### 4.1 Court event spine (authoritative)

Add a minimal append-only event stream to the ledger (file-backed), so "DB down" does not lose observability.

Implemented in `admit_cli`:
- Ledger events for projection boundaries:
  - `projection.run.started`
  - `projection.phase.completed`
  - `projection.run.completed`
- Flags on `ingest dir`:
  - `--ledger` (defaults to `out/ledger.jsonl`)
  - `--no-ledger`
- `verify_ledger` accepts `projection.*` events and verifies their `event_id` hashes.

This event spine is also where the "ineluctability loop" records its laps: a loop lap is an event bundle that points at idea + plan + diagnostics.

#### 4.2 SurrealDB projection_event (non-authoritative view)

**Create**: `irrev-compiler/crates/admit_surrealdb/src/projection_events.rs` (done)

Store a convenient, queryable view of events:
- Rows contain: `event_id`, `projection_run_id`, `phase`, `event_type`, `timestamp`, plus small scalar metrics and optional fields.

**Schema (memory only, derived from the ledger)** (implemented via `ensure_projection_event_schema()`):
```sql
DEFINE TABLE projection_event SCHEMALESS;
DEFINE INDEX projection_event_run ON TABLE projection_event COLUMNS projection_run_id;
DEFINE INDEX projection_event_phase ON TABLE projection_event COLUMNS phase;
DEFINE INDEX projection_event_type ON TABLE projection_event COLUMNS event_type;
DEFINE INDEX projection_event_timestamp ON TABLE projection_event COLUMNS timestamp;
DEFINE INDEX projection_event_trace ON TABLE projection_event COLUMNS trace_sha256;
```

#### Suggested event types (v0)

v0 uses run/phase boundaries (cheap). Batch-level events can be added later (e.g. `projection.batch.failed`).

#### Queries you get immediately
```sql
-- Latest run status
SELECT * FROM projection_run ORDER BY started_at DESC LIMIT 1;

-- Recent failures (phase boundary failures)
SELECT projection_run_id, phase, error, timestamp FROM projection_event
WHERE event_type = 'projection.phase.completed' AND status = 'failed'
ORDER BY timestamp DESC LIMIT 50;
```

**Benefits**:
- Historical queryability (Surrealist is the observability UI)
- SurrealDB can go down without losing the event log
- Replayable: rebuild projections from ledger + artifacts

### Phase 5: Run-Scoped Replacement (Replaces Hard Deletes)

**Modify**: [lib.rs:385-402](c:\Users\user\code\Irreversibility\irrev-compiler\crates\admit_surrealdb\src\lib.rs#L385-L402)

**Purpose**: Replace hard deletes with run-scoped replacement for auditability

**Pattern A: Run-Scoped Replacement (Recommended)**

Instead of `DELETE obsidian_link WHERE from_doc_path = X`:

```rust
// Upsert links with current run_id stamp
for link in resolved_links {
    sql.push_str(&doc_link_relate_sql(
        &link,
        run_id,  // NEW: stamp with current run
    ));
}

// After phase completes, optionally clean old runs
// (or just query "WHERE projection_run_id = latest_run")
```

**Pattern B: Tombstone (Alternative)**

For records that need explicit deactivation:

```rust
pub struct ObsidianLink {
    // ... existing fields
    pub is_active: bool,
    pub deactivated_in_run_id: Option<String>,
    pub deactivation_reason: Option<String>,
}

// Instead of DELETE, mark inactive
sql.push_str(&format!(
    "UPDATE obsidian_link SET is_active = false,
     deactivated_in_run_id = {}, deactivation_reason = {}
     WHERE from_doc_path = {} AND projection_run_id != {}",
    json_string(run_id), json_string("superseded"),
    json_string(&doc.doc_path), json_string(run_id)
));
```

**Compaction Operation** (logged as artifact):

Hard delete becomes separate `projection vacuum` command:
```bash
admit-cli projection vacuum --before-run <id>  # Delete old runs
```

**Benefits**:
- Observability without crime scene (missing evidence)
- Post-mortem debugging possible
- Can diff between runs
- Vacuum is explicit, logged operation

### Phase 6: Deterministic Batch Retry

**Enhance**: All batch processing in [lib.rs](c:\Users\user\code\Irreversibility\irrev-compiler\crates\admit_surrealdb\src\lib.rs)

**Purpose**: Handle partial failures gracefully with stable, deterministic retry

**Key Insight**: Retries must be keyed by stable identity, not "batch index 10/50" (batch boundaries change if batch size changes)

**New Types**:
```rust
pub struct BatchResult {
    pub batch_hash: String,        // hash(item_ids + phase + run_id) - STABLE
    pub batch_index: usize,        // For display only
    pub batch_size: usize,
    pub success: bool,
    pub error: Option<String>,
    pub item_ids: Vec<String>,     // Stable item identifiers
    pub attempt_count: usize,
}

pub struct ProjectionResult {
    pub phase: ProjectionPhase,
    pub total_batches: usize,
    pub successful_batches: usize,
    pub failed_batches: Vec<BatchResult>,
    pub partial_success: bool,
}

fn compute_batch_hash(item_ids: &[String], phase: &str, run_id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(phase.as_bytes());
    hasher.update(run_id.as_bytes());
    for id in item_ids {
        hasher.update(id.as_bytes());
    }
    hex::encode(hasher.finalize())
}
```

**CLI Output Example**:
```
[INFO] projection.vault_links: batch 1/50 succeeded (100 links, hash=abc123...)
[ERROR] projection.vault_links: batch 10/50 failed: timeout (hash=def456...)
[INFO] projection.vault_links: 9/50 batches succeeded, 1 failed
[WARN] Run `admit-cli projection retry --run <id>` to continue
```

**CLI Additions**:
```bash
# Retry specific batch by hash
admit-cli projection retry --run <id> --phase vault_links --batch <hash>

# Retry all failed batches for a run
admit-cli projection retry --run <id>

# Retry all failed batches for a phase
admit-cli projection retry --run <id> --phase <name>
```

**Store in SurrealDB**:
Failed batches stored in projection_run record for queryability:
```sql
SELECT * FROM projection_run WHERE status = 'partial'
```

**Benefits**:
- Deterministic retry regardless of batch size changes
- Query which batches failed
- Partial work never lost
- Clear recovery path

### Phase 7: Make SurrealDB Truly Optional with Circuit Breaker

**Modify**: [main.rs:1719-1761](c:\Users\user\code\Irreversibility\irrev-compiler\crates\admit_cli\src\main.rs#L1719-L1761)

**Purpose**: Commands succeed without SurrealDB, projection becomes enhancement

**Change 1: Default to Off** (line ~47):
```rust
#[arg(long, value_enum, default_value_t = SurrealDbMode::Off)]
surrealdb_mode: SurrealDbMode,
```

**Change 2: Circuit Breaker Pattern**:
```rust
fn maybe_project(
    coordinator: Option<&ProjectionCoordinator>,
    ...
) -> Option<ProjectionSummary> {
    let Some(coordinator) = coordinator else {
        return None;  // Disabled, this is OK
    };

    // Circuit breaker: if DB connection fails, disable for rest of command
    // Don't retry every phase and spam warnings
    match coordinator.check_connection() {
        Err(err) => {
            eprintln!("Warning: SurrealDB unavailable: {}", err);
            eprintln!("Projection disabled for this command (circuit breaker tripped)");
            return None;
        }
        Ok(_) => {}
    }

    match coordinator.project_all(...) {
        Ok(run_summary) => Some(run_summary),
        Err(err) => {
            eprintln!("Warning: projection failed: {}", err);
            None  // Continue command anyway
        }
    }
}
```

**Change 3: Single-Line Summary at Command End**:
```rust
fn print_projection_summary(summary: Option<&ProjectionSummary>) {
    match summary {
        None => println!("Projection: off"),
        Some(s) if s.db_unavailable => println!("Projection: skipped (db unavailable)"),
        Some(s) if s.all_phases_succeeded() => {
            println!("Projection: complete (run_id={})", s.run_id);
        }
        Some(s) => {
            println!("Projection: partial ({}/{} phases succeeded; run_id={})",
                s.successful_phases, s.total_phases, s.run_id);
        }
    }
}
```

**Change 4: Structured Logging**:
```
[INFO] SurrealDB projection: disabled (use --surrealdb-mode=auto)
[INFO] SurrealDB projection: auto, no DB configured (skipping)
[WARN] SurrealDB projection: auto, DB unavailable (circuit breaker tripped)
[ERROR] SurrealDB projection: on mode, DB required but unavailable

// At end:
Projection: complete (run_id=20260205-143022-abc123)
```

**Benefits**:
- Graceful degradation is legible, not mysterious
- Circuit breaker prevents retry spam
- Single-line summary makes status clear
- Clear user expectations

### Phase 8: Configuration File Support

**Create**: Config file parser for `admit.toml`

**Example Configuration**:
```toml
[projection]
enabled = true
failure_mode = "warn"
retry_attempts = 3

[projection.phases]
dag_trace = true
doc_chunks = true
vault_links = true

[projection.batch_sizes]
nodes = 200
doc_chunks = 50
links = 100

[projection.vault]
prefixes = ["irrev-vault/", "chatgpt/vault/"]

[surrealdb]
mode = "auto"
endpoint = "ws://localhost:8000"
namespace = "admit"
database = "compiler_dev"
```

**Priority Order**:
1. CLI flags (highest)
2. Environment variables
3. Config file
4. Compiled defaults (lowest)

**CLI Additions**:
```bash
--config=<path>                    # Default: ./admit.toml
admit-cli config show              # Show resolved config
admit-cli config init              # Create default file
```

**Benefits**: Avoids flag hell, makes configuration declarative and shareable

## The Improved Loop Structure

### Current Loop Problem

The current implementation has **tight coupling in the runtime loop**:

```
Runtime Command (e.g., ingest_dir)
    ↓
Generate DAG trace (pure)
    ↓
Write to ledger (authoritative, append-only) ← MUST succeed
    ↓
Project to SurrealDB (3 phases, sequential) ← Failure kills command
    ├─ project_dag_trace()
    ├─ project_doc_chunks()
    └─ project_vault_links()
    ↓
Command completes or fails
```

**Problem**: Projection failure = command failure, even though ledger write succeeded.

### Improved Loop Structure

The new architecture **decouples court (authority) from memory (projection)**:

```
Runtime Command (e.g., ingest_dir)
    ↓
Generate DAG trace (pure, P1: Derive)
    ↓
Write to ledger (authoritative, append-only, P4: Account) ← MUST succeed
    ↓
Command succeeds ✓
    ↓
[OPTIONAL] Project to SurrealDB (independent, best-effort)
    ├─ Coordinator attempts each phase independently
    ├─ Phase failures logged, metrics recorded
    ├─ Partial success allowed
    └─ Retry path available
    ↓
Memory updated (or will be regenerated later)
```

**Key improvements**:
1. **Ledger write is authoritative** — command success depends ONLY on this
2. **SurrealDB is best-effort memory** — can fail without breaking command
3. **Independent phases** — each can fail individually, partial success supported
4. **Regenerable** — memory can be rebuilt from ledger + artifacts anytime

### Loop Boundary Guarantees

| Boundary | Guarantee | Failure Mode |
|----------|-----------|--------------|
| **Compiler -> Ledger** | Transactional (file atomic write) | Command fails, no side effects |
| **Ledger -> SurrealDB** | Best-effort, logged | Command succeeds, projection deferred |
| **Phase -> Phase** | Independent, no coupling | One phase fails, others continue |
| **Batch -> Batch** | Independent, trackable | One batch fails, others committed, retry available |

### Phase Discipline Compliance (Corrected)

| Phase | Action | Authority | Failure Impact |
|-------|--------|-----------|----------------|
| **P0 (Observe)** | Read vault files, artifacts | Filesystem | Command fails early |
| **P1 (Derive)** | Build DAG trace, compute witnesses, **derive projection inputs** (pure: DocIndex, LinkGraph, ChunkIndex) | Rust compiler (court) | Command fails early |
| **P2 (Verdict)** | Admissibility checks (future) | Rust compiler (court) | Command fails early |
| **P3 (Effect)** | Write ledger (NOT SurrealDB) | Ledger (authoritative) | Command fails, no projection |
| **P4 (Account)** | **Write projection inputs to SurrealDB** (best-effort, regenerable memory mutation) | Projection coordinator (memory) | Command succeeds, warns |

**Critical clarifications**:
- **P1 derives** the projection data structures (pure computation): DocIndex, LinkGraph, ChunkIndex, TraceSummary
- **P4 writes** those structures to SurrealDB (accounting/memory mutation, NOT derive)
- SurrealDB writes are never "derive" semantics; they're "accounting/memory mutation" that's non-authoritative

## Implementation Sequence

**Priority Insight**: Implement ProjectionRun (Phase 0) first — it's the single addition that turns "best-effort vibes" into "auditable accounting."

### Sprint 0: Foundation Primitive (Week 1)
**Priority 1**: ProjectionRun primitive (Phase 0)
- Create `projection_run.rs`
- Add `projection_run` table to SurrealDB schema
- Implement `begin_run()` and `end_run()` lifecycle
- Add `projection_run_id` stamping to all projected tables
- **Critical**: This enables everything else

**Deliverable**: Projection runs are tracked, queryable, and auditable

### Sprint 1: Store Abstraction + Business Logic (2 weeks)
**Week 2**: ProjectionStore trait (Phase 2A)
- Create `projection_store.rs` with trait definition
- Implement `SurrealCliProjectionStore` with run_id stamping
- Implement `NullStore` for --surrealdb-mode=off
- Adapt existing projection code to use trait

**Week 3**: Extract link resolver (Phase 2B)
- Create `link_resolver.rs`
- Move functions from `lib.rs` (resolve_obsidian_target, etc.)
- Write unit tests for resolution logic
- Update projection code to use resolver

**Deliverable**: Clean abstraction boundaries, testable business logic

### Sprint 2: Resilience + Observability (2 weeks)
**Week 4**: Projection configuration (Phase 1)
- Create `projection_config.rs`
- Add CLI flags for batch sizes, failure modes
- Emit config as witness artifact (CBOR)
- Wire up configuration to existing projection code

**Week 5**: Queryable observability (Phase 4)
- Create `projection_events.rs`
- Add `projection_event` table to schema
- Log structured events throughout projection code
- Implement `projection events` and `projection metrics` commands

**Deliverable**: Configurable projections with queryable observability

### Sprint 3: Run-Scoped Operations (2 weeks)
**Week 6**: Run-scoped replacement (Phase 5)
- Replace hard deletes with run-scoped upserts
- Implement `projection vacuum` command for compaction
- Add tombstone pattern for explicit deactivation
- Test run-to-run diff queries

**Week 7**: Deterministic batch retry (Phase 6)
- Add batch hash computation (stable identity)
- Store failed batches in projection_run record
- Implement `projection retry` command with batch hash targeting
- Test partial failure recovery

**Deliverable**: Production-grade error handling and recovery

### Sprint 4: Graceful Degradation (2 weeks)
**Week 8**: Make SurrealDB optional with circuit breaker (Phase 7)
- Change default mode to `Off`
- Implement circuit breaker pattern
- Add single-line summary at command end
- Update error handling to never fail commands

**Week 9**: Projection coordinator (Phase 3)
- Create `projection_coordinator.rs`
- Refactor `main.rs` to use coordinator + store trait
- Implement independent phase execution with ProjectionRun lifecycle
- Wire up all pieces: config, events, retry, circuit breaker

**Deliverable**: Complete, production-ready projection system

### Sprint 5: Polish (1 week)
**Week 10**: Documentation + migration
- Update all documentation
- Write migration guide for breaking changes
- Create example configurations
- Add inline code documentation

**Deliverable**: Excellent developer experience

### Phase 8 (TOML Config): Deferred to Post-MVP
- Config witness artifact already provides self-describing system
- TOML can be added later as "one more input format"
- Focus on mechanical correctness first, ergonomics second

## Critical Files

### Files to Modify

1. **[main.rs](c:\Users\user\code\Irreversibility\irrev-compiler\crates\admit_cli\src\main.rs)** - CLI entry point
   - Lines 47: Change default mode to `Off`
   - Lines 1635-1646: Refactor to use coordinator
   - Lines 1719-1761: Update projection mode handling
   - Lines 1763-1804: Update `maybe_project_*` calls

2. **[lib.rs](c:\Users\user\code\Irreversibility\irrev-compiler\crates\admit_surrealdb\src\lib.rs)** - Core projection
   - Lines 385-402: Add audit trail for deletes
   - Lines 697-726: Enhance batch processing (DAG trace)
   - Lines 200-254: Enhance batch processing (doc chunks)
   - Lines 272-635: Enhance batch processing (vault links)
   - Lines 1128-1152: Move `build_heading_index`, `build_file_index`
   - Lines 1316-1542: Move link resolution logic
   - Lines 1397: Move `resolve_obsidian_asset_target`
   - Lines 1527: Move `resolve_obsidian_target`
   - Lines 1678: Move `choose_ambiguous_target`

### Files to Create

3. **`projection_config.rs`** - Configuration layer
4. **`link_resolver.rs`** - Pure business logic
5. **`projection_coordinator.rs`** - Orchestration
6. **`projection_metrics.rs`** - Observability

### Documentation Files

7. **[Compiler Runtime Loop.md](c:\Users\user\code\Irreversibility\irrev-compiler\meta\Compiler Runtime Loop.md)** - Update with projection details
8. **[surrealdb-dag-ledger-projection.md](c:\Users\user\code\Irreversibility\irrev-compiler\meta\design\compiler\surrealdb-dag-ledger-projection.md)** - Update projection spec

## Verification Plan

### Unit Tests
- Link resolver logic (title matching, ambiguity resolution, heading validation)
- Configuration parsing and priority resolution
- Batch result tracking
- Metrics calculations

### Integration Tests
- Projection with SurrealDB unavailable (should succeed)
- Individual phase failures (should not affect other phases)
- Batch-level failures and retry logic
- Configuration file loading and CLI flag overrides

### End-to-End Tests
1. **Baseline**: Run `ingest_dir` with SurrealDB disabled - verify command succeeds
2. **Auto Mode**: Run with `--surrealdb-mode=auto` and DB unavailable - verify warning, command succeeds
3. **Partial Failure**: Simulate batch failure mid-projection - verify partial success, retry available
4. **Link Resolution**: Run vault ingestion, verify links resolved correctly (compare with baseline)
5. **Configuration**: Create `admit.toml`, verify settings applied correctly
6. **Metrics**: Run projection, verify metrics recorded accurately

### Performance Benchmarks
- Baseline: Current implementation time for `ingest_dir` on sample vault
- Target: < 5% performance regression
- Measure: Projection time per phase with metrics enabled

## Invariant Compliance

| Invariant | How Maintained |
|-----------|----------------|
| **Phase discipline (P0-P4)** | Projection is P1 (Derive), never P3 (Effect) - reads from ledger/artifacts |
| **No semantic deadlock** | Projection consumes witnesses, never requires own verdict to proceed |
| **Decomposition** | Clear boundaries: resolver (pure), projector (IO), coordinator (orchestration) |
| **Governance** | Projection failures logged, optionally auditable, no exemptions |
| **Irreversibility** | Database regenerable from ledger + artifacts (projection not authoritative) |
| **Witness-first** | Projection consumes existing witnesses from runtime, never forges them |
| **Attribution** | Projection reports its identity and version in trace metadata |
| **Non-exemption** | Projection subject to same retry, logging, and audit rules as other components |

## Migration Path

### Breaking Change in v0.X

**SurrealDB projection is now opt-in (default: off)**

**Before**:
```bash
export SURREAL_NAMESPACE=admit
admit-cli ingest dir ./vault  # Projection automatic
```

**After**:
```bash
# Option 1: CLI flag
admit-cli --surrealdb-mode=auto ingest dir ./vault

# Option 2: Config file
cat > admit.toml <<EOF
[projection]
enabled = true
[surrealdb]
mode = "auto"
EOF
admit-cli ingest dir ./vault

# Option 3: Environment variable
export ADMIT_SURREALDB_MODE=auto
admit-cli ingest dir ./vault
```

### Migration Script

Provide `admit-cli config migrate-env` to generate `admit.toml` from current environment variables:

```bash
admit-cli config migrate-env > admit.toml
```

### Deprecation Timeline

- **v0.X**: SurrealDB mode defaults to `off`, old behavior available with `--surrealdb-mode=auto`
- **v0.X+1**: Warning for users relying on environment variables without explicit mode
- **v0.X+2**: Remove automatic mode detection from environment

## Success Criteria

### Must Have
- [ ] Commands succeed without SurrealDB (graceful degradation)
- [ ] Projection phases fail independently (resilience)
- [ ] Business logic testable without database (maintainability)
- [ ] Batch sizes configurable via CLI/config (flexibility)
- [ ] Metrics available for production debugging (observability)
- [ ] Clear error messages for all failure modes (usability)
- [ ] All invariants maintained (correctness)

### Nice to Have
- [ ] Configuration file support (developer experience)
- [ ] Auto-generated config templates (onboarding)
- [ ] Retry command for partial failures (recovery)
- [ ] Health check command (operations)

### Non-Functional
- [ ] No performance regression (< 5% slower on baseline)
- [ ] Test coverage > 80% for new code
- [ ] Documentation complete (README, migration guide, examples)
- [ ] All architectural invariants maintained

## Additional Architectural Insights

### Self-Governance Pattern

**Compiler can be governed as data, not as runtime judge**:

- **Compiler-as-object**: Ingest compiler repo snapshot as identity-addressed artifact (hash -> bytes -> metadata)
  - Makes it *speakable*: rules can point at it, diff it, attach witnesses, track authorities
- **Compiler-as-court**: Running Rust binary evaluates admissibility and emits verdicts/witnesses
  - Don't let "the thing being judged" also be "the final judge" without bootstrapped trust root
  - Prevents self-referential weirdness

**Pattern**: Rules govern *changes to compiler repo*, but enforcement happens via *trusted compiler build* (court) that evaluates rules against ingested compiler snapshot (defendant).

**Philosophical symmetry**: *The court can judge a copy of itself, but not redefine the court mid-sentence.*

### Hash Deduplication vs Semantic Deduplication

**What hashing solves**: Byte-level duplicates (same bytes under same hash)

**What hashing does NOT solve**: Semantic duplicates
- Same Markdown content but different normalization (line endings, whitespace)
- Same meaning but different encoding (JSON vs CBOR canonicalization)
- Same Rust AST but formatted differently

**Future extension**: Add projection layer that canonicalizes text/AST and hashes canonical form.

### SurrealDB Operator Selection for This Project

Based on SurrealDB operators documentation, key operators for vault + compiler + witnesses:

**Full-text search operators** (`@@` and `@1@`):
- Query chunks, score them, highlight them
- Use `search::highlight` and `search::score` for referenced form
- Supports workflow: **FTS hit -> chunk -> file -> graph neighborhood**

**KNN operator for vector search** (`<|K,...|>`):
- When adding embeddings later, use HNSW index for scale
- Keep FTS as baseline, add vectors as optional projection (same identity layer)

**Operator binding power**:
- Critical when generating queries programmatically
- Avoid subtle bugs when composing conditions (AND/OR, nullish operators, casts)

**Index-use realism**:
- `CONTAINS` won't use index but `CONTAINSANY` can
- Performance-critical at scale when feeling latency in Surrealist

### LLM Integration Safety Pattern

**Treat LLM as proposer, never executor**:

**LLM gets read-only access to**:
- Surreal queries (FTS + graph traversals)
- Witness artifacts (court's outputs)
- Schemas / rulesets (as data)

**LLM outputs**:
- Proposed rule diffs / patches
- Proposed ingest/projection changes
- Proposed queries and diagnostics

**Then**:
- Rust compiler (court) evaluates proposed change in sandbox/dry-run mode -> emits witness
- Human (or CI policy) applies **approval token** gate for anything destructive/authoritative

**This answers earlier questions**: LLM helps *draft* structure; only court + explicit approval can *ratify* it.

### Ineluctability Through Instrumentation

**Reducing degrees of freedom requires three continuous practices**:

1. **Instrument**: ingest + projections + witnesses
2. **Canonicalize**: stable identities + stable semantics hashes where needed
3. **Enforce**: court evaluates, not vibes

**When any weaken**: degrees of freedom creep back as ambiguity, silent drift, or "interpretation debt"

**Effect**: "Lower entropy per thought" — system stops rewarding hand-wavy branches, starts rewarding only branches that pay costs in public.

## Trade-offs and Decisions

### Decision 1: Default Mode to Off
**Status**: This is outdated.

The CLI currently defaults to `--surrealdb-mode=auto`, which activates projections only when:
- namespace+database are configured (flags or `SURREAL_NAMESPACE` / `SURREAL_DATABASE`)
- the endpoint is reachable (`surreal is-ready`)

**Rationale (auto default)**: preserves "optional" behavior while enabling day-to-day use without flag friction.
**Trade-off**: confusion about "why didn't projection happen"
**Mitigation**: emit a single-line projection status summary (ready/missing-config/unreachable) and record it in a projection-run record.

### Decision 2: Extract Link Resolver
**Rationale**: Enables testing, reuse, satisfies decomposition invariant
**Trade-off**: More files, indirection
**Mitigation**: Clear module boundaries, comprehensive tests

### Decision 3: Independent Phases
**Rationale**: Resilience, flexibility, partial failure handling
**Trade-off**: More complex coordination, potential inconsistency
**Mitigation**: Clear phase boundaries, audit logging, idempotent operations

### Decision 4: Configuration File
**Rationale**: Better developer experience, avoids flag hell, declarative
**Trade-off**: Another format to learn, priority resolution complexity
**Mitigation**: Excellent defaults, `config show` command, examples

### Decision 5: SurrealDB as Memory, Not Authority
**Rationale**: Follows court vs memory pattern, maintains ledger as source of truth
**Trade-off**: Requires regeneration logic, eventual consistency
**Mitigation**: Clear rebuild path, projection from ledger + artifacts deterministic

## Key Refinements from User Feedback

These refinements transform the plan from "good direction" into "mechanically implementable":

1. **Phase discipline clarity**: P1 derives projection inputs (pure), P4 writes to SurrealDB (accounting)
2. **ProjectionRun primitive**: The missing piece that enables auditable accounting (partially implemented for embeddings as `embed_run`)
3. **ProjectionStore trait**: Prevents "Surreal creep", enables multiple backends
4. **Run-scoped replacement**: Replaces hard deletes, maintains audit trail
5. **Deterministic batch retry**: Stable batch hashes, survives config changes
6. **Circuit breaker pattern**: One DB connection check, no retry spam
7. **Queryable observability**: Events in SurrealDB, not dying in-memory counters
8. **Single-line summary**: Makes graceful degradation legible, not mysterious
9. **Config as witness**: Self-describing system, TOML can wait

## What This Achieves

**Before** (current state):
- Projection failure = command failure
- No audit trail of which run produced which DB state
- Hard deletes without observability
- Batch retry by unstable index
- No circuit breaker (retry spam)
- Business logic embedded in database layer
- Hardcoded batch sizes
- In-memory metrics that die with process

**After** (with this plan):
- Projection failure = warning, command succeeds
- Full lineage: trace -> run -> projector version -> config -> DB state
- Run-scoped replacement with vacuum command
- Deterministic retry by stable batch hash
- Circuit breaker prevents retry spam
- Pure business logic in link_resolver
- Configurable batch sizes (CLI + witness artifact)
- Queryable historical events in SurrealDB
- Single-line summary shows projection status

**Architectural compliance**:
- Court (Rust compiler) vs Memory (SurrealDB) separation maintained
- Phase discipline respected (P1 derive, P4 account)
- Self-governance enabled (compiler as object, rules govern it)
- Decomposition invariant satisfied (resolver pure, projector IO, coordinator orchestration)
- Ineluctability through instrumentation (events logged, runs tracked, costs visible)

## References

- **Conceptual Framework**: [Ineluctability under Irreversibility.md](c:\Users\user\code\Irreversibility\irrev-vault\meta\Ineluctability under Irreversibility.md)
- **Runtime Model**: [Compiler Runtime Loop.md](c:\Users\user\code\Irreversibility\irrev-compiler\meta\Compiler Runtime Loop.md)
- **Projection Spec**: [surrealdb-dag-ledger-projection.md](c:\Users\user\code\Irreversibility\irrev-compiler\meta\design\compiler\surrealdb-dag-ledger-projection.md)
- **Architecture**: [Architecture.md](c:\Users\user\code\Irreversibility\irrev-compiler\meta\Architecture.md)
- **SurrealDB Operators**: [Operators | SurrealQL](https://surrealdb.com/docs/surrealql/operators)

---

**End of Plan**
