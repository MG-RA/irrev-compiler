# Irreversibility Compiler (`irrev-compiler`)

**A Rust-based compiler for expressing, tracking, and verifying irreversible computational actions through scope-governed witnesses and displacement cost accounting.**

[![Status](https://img.shields.io/badge/status-active%20development-yellow)]()
[![Language](https://img.shields.io/badge/language-Rust-orange)]()
[![License](https://img.shields.io/badge/license-check%20repo-blue)]()

---

## Table of Contents

- [Overview](#overview)
- [Core Philosophy](#core-philosophy)
- [Architecture](#architecture)
  - [Crate Organization](#crate-organization)
  - [Data Flow Pipeline](#data-flow-pipeline)
- [Key Concepts](#key-concepts)
  - [Scopes & Boundaries](#scopes--boundaries)
  - [Witnesses](#witnesses)
  - [Displacement & Cost Accounting](#displacement--cost-accounting)
  - [The Governance DAG](#the-governance-dag)
- [Compilation Pipeline](#compilation-pipeline)
- [Intermediate Representation (IR)](#intermediate-representation-ir)
- [Calculator Scope Example](#calculator-scope-example)
- [Registry & Validation](#registry--validation)
- [Witness Format Specification](#witness-format-specification)
- [CLI Usage](#cli-usage)
- [Development](#development)
- [Design Documents](#design-documents)
- [Protocol Conformance](#protocol-conformance)

---

## Overview

The **Irreversibility Compiler** (`irrev-compiler`) is a specialized domain-specific language (DSL) compiler designed to make **irreversible computational actions** explicit, accountable, and auditable. It enforces that:

1. **All state changes are tracked with proofs (witnesses)**
2. **"Erasure costs" quantify the irreversible impact** of those changes
3. **Actions crossing scope boundaries require governance**: witness + authority
4. **Computational validity + admissibility checking** prevent unaccounted state changes

The system implements an **append-only ledger** of governance-relevant artifacts, a **content-addressed DAG** of computational and mutational nodes, and a **scope enforcement mechanism** that ensures non-pure operations have proper authority and witness trails.

**What makes this different:**

- **Irreversibility-first design**: Default deny on state mutations; all costs declared before action
- **Scope algebra**: Boundaries formalize trust transitions (pure → I/O → external systems)
- **Canonical encoding**: RFC 8949 CBOR ensures deterministic witness hashing
- **Witness-centric**: Every admissibility check emits structured proof with facts + displacement traces
- **Self-governed meta-scope**: The compiler's own governance rules are expressed in the same system

---

## Core Philosophy

### The Five Layers

The system is built on five conceptual layers:

1. **Vault = Interpretive space** (claims and structure)
2. **Engine = Diagnostic machinery** (parsing, checks, rule evaluation)
3. **Execution = Effectful operations** (state changes, external side effects)
4. **Projections = Views** (regenerable representations)
5. **Ledger = Proof spine** (append-only provenance for effectful things)

> **Vault says. Engine checks. Execution does. Projections show. Ledger proves.**

### Governance Invariants

The compiler enforces four **vault invariants** on itself and all programs:

1. **Governance**: Rulesets and IR schemas are validated and versioned; changes are auditable
2. **Irreversibility**: Default deny erasure + mandatory erasure cost accounting
3. **Decomposition**: Scopes/modules prevent global namespace soup; dependencies are explicit
4. **Attribution**: Every rule, permission, and cost declaration is source-attributed with spans + module IDs

### Cost Declaration Protocol

Five binding rules govern all transformations:

1. **Declare cost before action**: No transformation is admissible unless its irreversible costs are declared **before** execution
2. **Default deny**: Erasure, scope expansion, and overrides are denied unless explicitly permitted
3. **Cost routing**: Every declared cost must be routed to an explicit sink (`bucket:*`)
4. **Witness-first**: All inadmissibility outcomes must emit structured witnesses with spans
5. **Irreversible declarations**: Cost declarations are ledgered and **never retracted**

---

## Architecture

### Crate Organization

The compiler is structured as a multi-crate Rust workspace:

```
irrev-compiler/
├── crates/
│   ├── admit_core/        # Kernel IR, evaluation engine, witness types (pure, deterministic)
│   ├── admit_dsl/         # .adm DSL parser + AST lowering to IR (uses Chumsky)
│   ├── admit_dag/         # Governance DAG (nodes, edges, scope enforcement, validation)
│   ├── admit_cli/         # CLI commands, ledger operations, registry management
│   ├── admit_surrealdb/   # Knowledge graph persistence (projection store)
│   ├── admit_embed/       # LLM embedding via Ollama
│   ├── vault_snapshot/    # File parsing and snapshot management
│   ├── program_bundle/    # Versioned program artifact collections
│   └── facts_bundle/      # Observation witness bundles
├── meta/                  # Design documents, protocols, scope contracts
├── testdata/              # Golden fixtures, test programs
└── Cargo.toml             # Workspace manifest
```

#### **`admit_core`** — The Semantic Kernel (~5000 LOC)

**Purpose**: Pure, deterministic evaluation engine and witness generation.

**Key Modules**:
- `ir.rs` — Intermediate Representation (8 IR primitives)
- `eval.rs` + `predicates.rs` — Evaluation engine with constraint checking
- `witness.rs` — Witness structures (verdict + facts + displacement trace)
- `calc_ast.rs`, `calc_eval.rs`, `calc_witness.rs` — Pure computation witness system
- `exact_types.rs` — Exact arithmetic (Int, Nat, Rational, Bool; no floats)
- `hash_witness.rs` — SHA256 and CBOR hashing witnesses
- `env.rs` — Environment (diffs, buckets, transforms, permissions, rules, commits, constraints)
- `trace.rs` — Execution trace recording
- `displacement.rs` — Erasure cost computation
- `cbor.rs` — Canonical CBOR encoding (RFC 8949 Section 4.2)

**IR Primitives** (8 core statements):
1. `DeclareDifference` — State difference type
2. `DeclareTransform` — State transformation type
3. `Persist` — Mark difference as persistent under transforms
4. `ErasureRule` — Cost + bucket for difference erasure
5. `AllowErase` / `DenyErase` — Permissions
6. `Constraint` — Inadmissibility conditions (boolean expressions)
7. `Commit` — Assign values to differences
8. `Query` — Admissible, Witness, Delta, Lint

**Predicates** (6 types for constraints):
- `EraseAllowed(diff)` — Has permission to erase?
- `DisplacedTotal(bucket, cmp, qty)` — Bucket cost threshold check
- `HasCommit(diff)` — Value committed?
- `CommitEquals(diff, val)` — Value matches?
- `CommitCmp(diff, cmp, val)` — Value comparison
- `VaultRule(name)` — External vault rule (extensible)
- `CalcWitness(calc_id, inputs, expected_output)` — Computation proof provided?

**Witness Types**:
- **Program Witness** (admissibility) — verdict + facts + displacement
- **Calculator Witness** (computation) — core + envelope with exact arithmetic trace
- **Hash Witness** (identity) — algorithm + operation + input + digest
- **Plan Witness** (action documentation) — 12-question prompts + derived risk grade

#### **`admit_dsl`** — Language Frontend

**Purpose**: Parse `.adm` DSL files and lower to kernel IR.

**Key Modules**:
- `lexer.rs` + `tokens.rs` — Tokenization (keywords, identifiers, numbers, strings)
- `parser.rs` — Chumsky-based PEG parser with recoverable spans
- `ast.rs` — Surface AST (statements, declarations, expressions)
- `lowering.rs` — AST → IR transformation with normalization and validation

**Syntax Example** (`.adm` format):
```adm
module irrev_example@1
depends [module:irrev_std@1]
scope core.pure

difference file_overwrite
bucket fs_mutations

deny_erase file_overwrite
allow_erase file_overwrite
erasure_rule file_overwrite cost 1 "event" -> fs_mutations

commit file_overwrite = true

inadmissible_if DisplacedTotal(fs_mutations, ">", 5 "event")

query admissible
```

#### **`admit_dag`** — Governance DAG

**Purpose**: Graph-based execution tracking with scope enforcement.

**Key Modules**:
- `node.rs` — Content-addressed nodes (RulesetSource, ComputedValue, WitnessArtifact, AuthorityRoot, Query, ProjectionState)
- `edge.rs` — Typed edges (BuildDepends, WitnessOf, AuthorityDepends, MutationCommitment, CostDisplacement)
- `graph.rs` — `GovernedDag` structure with partial order views
- `scope_enforcement.rs` — Boundary rules and violation detection
- `validation.rs` — Cycle detection, reference validation
- `authority.rs` — Authority reachability checking (non-pure scopes must reach AuthorityRoot)

**Scope Boundary Rules**:
- **Pure → Pure**: `BuildDepends` only, no witness needed
- **Pure → I/O**: `MutationCommitment` requires witness
- **I/O → External**: Any mutation requires witness + authority

**Mutation Risk Classes**:
- `LocalReversible` — Undo available (e.g., in-memory cache)
- `LocalPersistent` — Disk writes, Git commits
- `ExternalDestructive` — API calls, database mutations, network effects

#### **`admit_cli`** — Command-Line Interface

**Purpose**: High-level operations, ledger management, registry commands.

**Key Modules**:
- `ledger.rs` — Append/read JSONL events (admissibility.checked, cost.declared, ingest.*, projection.*, court.*)
- `artifact.rs` — Content-addressed artifact storage (CBOR + JSON projections)
- `witness.rs` — Witness lifecycle (declare_cost, verify_witness, check_cost_declared, execute_checked)
- `registry.rs` — MetaRegistry (schema/scope definitions, initialization, normalization)
- `scope_commands.rs` — `scope_add`, `scope_verify`, `scope_list`, `scope_show`
- `scope_validation.rs` — Phase1 (basic) and Phase2 (advanced) validation
- `plan.rs` — Plan creation with diagnostic prompts and risk derivation
- `calc_commands.rs` — `calc_execute`, `calc_verify`
- `ingest_dir.rs` — Parse files into chunks, snapshot hashing

**CLI Commands**:
```bash
admit_cli check <program.adm>              # Admissibility check → witness
admit_cli declare-cost <witness.json>      # Seal witness → cost.declared event
admit_cli ledger append <event>            # Append ledger event
admit_cli verify-ledger                    # Full ledger verification
admit_cli scope add <scope_spec>           # Add scope to registry
admit_cli scope verify <scope_id>          # Verify scope conformance
admit_cli plan new                         # Create plan with risk assessment
admit_cli calc execute <plan> <inputs>     # Execute calculation
admit_cli calc verify <witness>            # Verify calculation witness
```

#### **`admit_surrealdb`** — Knowledge Graph

**Purpose**: Persist DAG and artifacts to SurrealDB for querying.

**Tables**: `doc_chunk_embedding`, `doc_embedding`, `embed_run`, `unresolved_link`, `doc_title_embedding`, `query_artifacts`, `function_artifacts`

#### **`admit_embed`** — LLM Embeddings

**Purpose**: Generate embeddings via Ollama for semantic search.

**Endpoints**: `/api/embed`, `/api/embeddings` (batched HTTP requests)

#### **Bundles** (`program_bundle`, `facts_bundle`, `vault_snapshot`)

**Purpose**: Versioned artifact collections with provenance.

- **ProgramBundle**: Collection of `.adm` modules with versioning
- **FactsBundle**: Observation witnesses (regex scans, domain-specific extractors)
- **VaultSnapshot**: Normalized vault state used as compiler input (hashable provenance)

---

### Data Flow Pipeline

```
┌──────────────────────────────────────────────────────────┐
│              .adm DSL Source File                        │
│   (module, scope, differences, constraints, queries)     │
└────────────────────┬─────────────────────────────────────┘
                     │
                     ▼
         ┌──────────────────────┐
         │  Lexer (tokens)      │
         └──────────┬───────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │  Parser → AST        │
         └──────────┬───────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │  Lowering → IR       │
         │  (admit_core::Program)│
         └──────────┬───────────┘
                    │
                    ▼
         ┌──────────────────────┐
         │  Env Building        │
         │  (extract facts/rules)│
         └──────────┬───────────┘
                    │
       ┌────────────┼────────────┐
       │            │            │
       ▼            ▼            ▼
  ┌────────┐  ┌──────────┐  ┌──────────────┐
  │ Scope  │  │Constraint│  │ Displacement │
  │Changes │  │Evaluation│  │ Trace Build  │
  └───┬────┘  └────┬─────┘  └──────┬───────┘
      │            │               │
      └────────────┼───────────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │  Witness Assembly    │
        │  ├─ Verdict          │
        │  ├─ Reason           │
        │  ├─ Facts            │
        │  └─ Displacement     │
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │ Canonical CBOR       │
        │ Content Hash (SHA256)│
        └──────────┬───────────┘
                   │
                   ▼
        ┌──────────────────────┐
        │ Ledger Event Append  │
        │ + Artifact Storage   │
        └──────────────────────┘
```

---

## Key Concepts

### Scopes & Boundaries

**Scopes** define trust boundaries for governance. The system uses a hierarchical scope taxonomy:

#### **Pure Scopes** (no ceremony needed)
- `scope:core.pure` — Deterministic computation
- `scope:calc.pure` — Calculator operations
- No witness or authority required for pure→pure transitions

#### **I/O Scopes** (witness required)
- `scope:fs.read` — File system reads
- `scope:fs.write` — File system writes
- `scope:obsidian.vault.*` — Obsidian vault operations
- Requires witness for pure→I/O transitions

#### **External Scopes** (witness + authority required)
- `scope:external.*` — External API calls
- `scope:db.write` — Database mutations
- Requires both witness and authority reachability

#### **Scope Modes** (transitions)
- **Widen**: Move to more permissive scope (e.g., `core.pure` → `fs.write`)
  - Requires: `AllowScopeChange` + `ErasureRule` to account for boundary loss
- **Narrow**: Move to more restrictive scope (e.g., `fs.write` → `core.pure`)
  - No ceremony (narrowing always allowed)
- **Translate**: Lateral move (same trust level)
  - Requires witness/authority per boundary rules

#### **Boundary Loss Diffs**
When scopes widen without explicit rules:
- Automatic diff created: `boundary_loss_<from>_<to>`
- Must have `AllowErase` + `ErasureRule` to remain admissible
- Otherwise: "unaccounted boundary change" violation

---

### Witnesses

**Witnesses** are unforgeable proofs of execution. All witnesses follow a two-layer structure:

#### **Core Witness** (content, deterministic)
- Program hash
- Inputs
- Verdict/output
- Facts/trace

#### **Envelope** (metadata, non-deterministic)
- Timestamp
- Compiler version
- Schema ID
- Snapshot hash

#### **Witness Hierarchy**

**Level 0: Program Witness** (Admissibility)
```json
{
  "verdict": "Admissible" | "Inadmissible",
  "reason": "description",
  "facts": [
    {"type": "ConstraintTriggered", "constraint": "..."},
    {"type": "PermissionUsed", "difference": "..."},
    {"type": "ErasureRuleUsed", "difference": "...", "bucket": "..."}
  ],
  "displacement_trace": {
    "mode": "potential",
    "totals": [{"bucket": "...", "amount": 1.0, "unit": "event"}],
    "contributions": [{"difference": "...", "bucket": "...", "cost": {...}}]
  }
}
```

**Level 1: Calculator Witness** (Computation)
```json
{
  "core": {
    "inputs": [{"name": "x", "value": "42", "unit": "kg"}],
    "expression": {"type": "add", "left": {...}, "right": {...}},
    "result": {"value": "84", "unit": "kg"}
  },
  "envelope": {
    "schema_id": "calc-witness/0",
    "timestamp": "2026-02-07T12:00:00Z"
  }
}
```

**Level 2: Hash Witness** (Identity)
```json
{
  "algorithm": "sha256",
  "operation": "hash_bytes" | "hash_cbor",
  "input": "...",
  "digest": "abc123..."
}
```

**Level 3: Plan Witness** (Action Documentation)
```json
{
  "answers": {
    "action_definition": "...",
    "erasure_cost": "1-5 events",
    "reversibility": "irreversible",
    ...
  },
  "derived_risks": {
    "erasure_grade": 2
  },
  "reproducibility": {
    "template_hash": "def456...",
    "answers_hash": "ghi789..."
  }
}
```

---

### Displacement & Cost Accounting

**Displacement** quantifies the irreversible cost of state changes.

#### **Displacement Trace Structure**
```rust
DisplacementTrace {
    mode: "potential" | "actualized",
    totals: Vec<BucketTotal>,      // Aggregated costs per bucket
    contributions: Vec<Contribution> // Individual diff → bucket mappings
}

BucketTotal {
    bucket: String,   // e.g., "bucket:fs_mutations"
    amount: f64,
    unit: String      // e.g., "event", "bytes", "api_call"
}

Contribution {
    difference: String,  // e.g., "difference:file_overwrite"
    bucket: String,
    cost: Quantity { value: f64, unit: String }
}
```

#### **Erasure Rules**
```adm
erasure_rule file_overwrite cost 1 "event" -> fs_mutations
```

- Every allowed erasure must have an `ErasureRule`
- Cost is routed to a specific bucket
- Buckets accumulate costs across all differences
- Constraints can check bucket totals (e.g., `DisplacedTotal(fs_mutations, ">", 5 "event")`)

#### **Cost Declaration Lifecycle**
1. **Propose** (Phase 0): Draft program + cost estimates
2. **Declare Cost** (Phase 1): Seal witness → ledger (`cost.declared` event)
3. **Check** (Phase 2): Verify admissibility → ledger (`admissibility.checked` event)
4. **Execute** (Phase 3): Perform action (gated by prior phases)

---

### The Governance DAG

The **Governance DAG** is a content-addressed graph of computational and mutational actions.

#### **Node Types** (6 kinds)
1. **RulesetSource** — Policy definitions (`.adm` modules)
2. **ComputedValue** — Pure computation results
3. **WitnessArtifact** — Sealed witnesses
4. **AuthorityRoot** — Human approval, policy delegation
5. **Query** — Admissibility queries
6. **ProjectionState** — External system snapshots (e.g., Neo4j state)

#### **Edge Types** (5 kinds)
1. **BuildDepends** — Compilation dependencies (pure)
2. **WitnessOf** — Proof relationship (witness → program)
3. **AuthorityDepends** — Governance chain (action → approval)
4. **MutationCommitment** — Mutation declaration (action → witness)
5. **CostDisplacement** — Cost flow (mutation → bucket)

#### **Scope Enforcement Rules**
```rust
ScopeBoundaryRule {
    from_prefix: "scope:core.pure",
    to_prefix: "scope:fs.write",
    edge_match: MutationWithMinRisk(LocalPersistent),
    allowed: true,
    requires_witness: true,
    requires_authority: false,
    severity: Error
}
```

**Default Rules**:
- Pure↔Pure: `BuildDepends` only
- Pure→I/O: `MutationCommitment` requires witness
- I/O→External: Any mutation requires witness + authority

**Authority Reachability**:
- Non-pure scopes must have a path to `AuthorityRoot` via `AuthorityDepends` edges
- BFS from authority roots validates governance chain
- Missing authority → `ScopeViolation::MissingAuthority`

---

## Compilation Pipeline

### Phase Breakdown

#### **Phase 0: Project Skeleton + IO Contract**
- Define input contracts (vault snapshot, `.adm` source, TOML ruleset)
- Define output contract (witness JSON/CBOR, IR dump)
- Establish versioned schema IDs

#### **Phase 1: Kernel IR + Witness Schema**
- Implement 8 IR primitives (`DeclareDifference`, `DeclareTransform`, `Persist`, `ErasureRule`, `AllowErase`, `DenyErase`, `Constraint`, `Commit`, `Query`)
- Implement witness format (verdict + facts + displacement trace)
- Add identity hashes (program_hash, snapshot_hash, ruleset_hash)

#### **Phase 2: .adm Parser + Lowering**
- Define `.adm` grammar (scope blocks, namespaces, declarations)
- Implement parser with recoverable spans
- Lower AST → kernel IR
- Reserve namespaces (`difference:*`, `transform:*`, `bucket:*`, `constraint:*`, `scope:*`, `module:*`)

#### **Phase 3: Constraint Engine + Predicate Evaluation**
- Boolean algebra + 6 predicates (`EraseAllowed`, `DisplacedTotal`, `HasCommit`, `CommitEquals`, `CommitCmp`, `VaultRule`, `CalcWitness`)
- Deterministic evaluation with monotonic facts
- Unit compatibility for comparisons
- Default deny erasure enforcement

#### **Phase 4: Cost Declaration Protocol**
- CLI commands: `propose`, `declare-cost`, `check`, `execute`
- Ledger events: `cost.declared`, `admissibility.checked`, `admissibility.executed`
- Immutable cost declarations (cannot be retracted)

#### **Phase 5: Vault Snapshot Bridge**
- Python exporter → normalized vault snapshot JSON
- Rust consumes snapshot as canonical input
- Snapshot hash included in witness metadata

#### **Phase 6: Ledger + Witness Integration**
- Emit `constraint.evaluated` / `invariant.checked` events
- Store witness artifacts with content addressing
- Ledger records are append-only

#### **Phase 7: Parity Testing + Replacement Path**
- Comparison harness (Rust vs Python)
- Document predicate gaps
- Transition plan (Python fallback → Rust primary)

---

## Intermediate Representation (IR)

### IR Structure

```rust
pub struct Program {
    pub module: ModuleDecl,
    pub scope: ScopeDecl,
    pub stmts: Vec<Stmt>,
}

pub enum Stmt {
    DeclareDifference { name: String, unit: Option<String>, span: Span },
    DeclareTransform { name: String, span: Span },
    Persist { difference: String, under: Vec<String>, span: Span },
    ErasureRule { difference: String, cost: Quantity, displaced_to: String, span: Span },
    AllowErase { difference: String, span: Span },
    DenyErase { difference: String, span: Span },
    ScopeChange { mode: ScopeMode, from: String, to: String, span: Span },
    Constraint { name: String, condition: BoolExpr, span: Span },
    Commit { difference: String, value: CommitValue, span: Span },
    Query(QueryType),
}

pub enum BoolExpr {
    And(Box<BoolExpr>, Box<BoolExpr>),
    Or(Box<BoolExpr>, Box<BoolExpr>),
    Not(Box<BoolExpr>),
    Pred(Predicate),
}

pub enum Predicate {
    EraseAllowed(String),                         // Has permission?
    DisplacedTotal { bucket: String, cmp: Cmp, qty: Quantity },
    HasCommit(String),                            // Value committed?
    CommitEquals { difference: String, value: CommitValue },
    CommitCmp { difference: String, cmp: Cmp, value: CommitValue },
    VaultRule(String),                            // External rule
    CalcWitness { calc_id: String, inputs: Vec<CalcInput>, expected_output: Option<CalcValue> },
}
```

### Evaluation Rules

1. **Declarations** are order-insensitive (serialized sorted by namespace+name)
2. **Constraints** evaluate in file order
3. **Facts** are sorted stably by type then span
4. **Displacement mode** is `"potential"` in v0 (no explicit erasure actions yet)
5. **Default deny**: `AllowErase` must have matching `ErasureRule`

### Canonical Encoding

All IR and witness artifacts use **RFC 8949 Canonical CBOR**:
- Map keys sorted by encoded bytes (lexicographic order)
- Smallest encoding used (no unnecessary length bytes)
- No indefinite-length encoding
- UTF-8 strings must be valid
- Deterministic: same input → same bytes

**Identity Hash**: `SHA256(canonical_cbor(artifact))`

---

## Calculator Scope Example

The **Calculator Scope** (`scope:calc.pure`) demonstrates pure computation witnesses.

### Plan Creation

**12-Question Template**:
1. Action definition
2. Reason/purpose
3. Erasure cost estimate
4. Reversibility assessment
5. Scope/domain
6. Input requirements
7. Output expectations
8. Failure modes
9. Attribution/ownership
10. Approval needed?
11. Validation criteria
12. Final check

**Derived Risk Grade** (0-3):
- Grade 0: No erasure
- Grade 1: 1-5 events
- Grade 2: 6-20 events
- Grade 3: 21+ events

### Calculation Definition

```json
{
  "schema_id": "calc-plan/0",
  "schema_version": 0,
  "mechanism_id": "mechanism.calc.pure",
  "expression": {
    "type": "add",
    "left": {"type": "input_ref", "name": "x"},
    "right": {"type": "literal", "value": "10", "value_type": "nat", "unit": "kg"}
  },
  "inputs": [
    {"name": "x", "expected_type": "nat", "expected_unit": "kg"}
  ],
  "unit_rules": [
    {
      "from_unit": "g",
      "to_unit": "kg",
      "factor": {"type": "rational", "numerator": "1", "denominator": "1000"}
    }
  ],
  "expected_output_unit": "kg"
}
```

### Witness Proof

**Evaluator Steps**:
1. Input validation (type + unit checking)
2. Expression evaluation (exact arithmetic with `num-rational`)
3. Result validation (output type + unit)
4. Trace recording (operation sequence)
5. Witness assembly (core + envelope)

**Witness Output**:
```json
{
  "core": {
    "inputs": [{"name": "x", "value": "42", "unit": "kg"}],
    "expression": {"type": "add", ...},
    "result": {"value": "52", "unit": "kg"}
  },
  "envelope": {
    "schema_id": "calc-witness/0",
    "timestamp": "2026-02-07T12:00:00Z",
    "plan_hash": "abc123..."
  }
}
```

### Verification

**Proof Rules**:
- ✅ `CalcWitness` witness_hash matches schema
- ✅ Plan hash matches expected (formula unchanged)
- ✅ Output matches expected (if pre-specified)
- ✅ All inputs resolved and validated
- ✅ No arithmetic overflow

---

## Registry & Validation

### Meta Registry Structure

```json
{
  "schema_id": "irrev-meta-registry/0",
  "schemas": [
    {
      "id": "calc-plan/0",
      "version": 0,
      "canonical_encoding": "cbor"
    }
  ],
  "scopes": [
    {
      "id": "calc.pure",
      "version": 0,
      "deterministic": true,
      "foundational": true,
      "phase": "phase1",
      "role": "runtime",
      "snapshot_schema_id": "calc-plan/0",
      "emits": ["calc-witness/0"],
      "consumes": [],
      "deps": []
    }
  ],
  "stdlib": [
    {
      "module_id": "module:irrev_std@1",
      "scope_id": "scope:core.pure"
    }
  ]
}
```

### Scope Addition Protocol (6-Step)

1. **Load** existing registry
2. **Parse** scope ID (or derive from `--scope ID@version`)
3. **Build** `MetaRegistryScope` from CLI args
4. **Hash** registry before mutation
5. **Validate** with `ScopeValidator` (Phase1 or Phase2)
6. **Check** ERROR-severity validations
7. **Add** to registry, increment version
8. **Normalize** (sort, dedup)
9. **Hash** after mutation
10. **Return** witness (before/after hashes, version bumps)

### Validation Levels

**Phase1** (Basic):
- ID format (`scope:<domain>.<name>`)
- No duplicates
- Required fields present
- Schema IDs exist

**Phase2** (Advanced):
- Dependency resolution (all deps in registry)
- Graph coherence (no cycles)
- Role compatibility (runtime vs governance)
- Contract reference validation

### Scope Addition Witness Format

**Identity Payload** (7 fields):
```json
{
  "scope_id": "scope:meta.scope",
  "scope_version": 0,
  "validation_checks": ["scope_id_format", "emits_schemas_exist"],
  "registry_version_before": 0,
  "registry_version_after": 1,
  "registry_hash_before": "abc123",
  "registry_hash_after": "def456"
}
```

**Full Witness** (includes metadata):
```json
{
  "schema_id": "scope-addition-witness/0",
  "schema_version": 0,
  "witness_id": "sha256(...)",
  "scope_id": "scope:meta.scope",
  "scope_version": 0,
  "validation_timestamp": "2026-02-07T12:00:00Z",
  "validations": [
    {
      "check": "scope_id_format",
      "passed": true,
      "message": "ID format valid",
      "severity": "error"
    }
  ],
  "registry_version_before": 0,
  "registry_version_after": 1,
  "registry_hash_before": "abc123",
  "registry_hash_after": "def456"
}
```

**Golden Fixture** (frozen bytes):
```
CBOR Hex (163 bytes):
a7 6873636f70655f6964 7073636f70653a6d6574612e73636f7065
   6d73636f70655f76657273696f6e 00
   7176616c69646174696f6e5f636865636b73 826f73636f70655f69645f666f726d6174
   73656d6974735f736368656d61735f6578697374
   ...
```

**Breaking this encoding requires schema version bump to `scope-addition-witness/1`.**

---

## Witness Format Specification

### Wire Format Rules

**Encoding**: JSON → Canonical CBOR (RFC 8949 Section 4.2)

**Scope Authority**: `scope:encode.canonical@0`

**Process**:
1. Serialize structure to JSON value
2. Encode JSON value using `admit_core::encode_canonical_value()`
3. Apply canonical CBOR encoding (deterministic, sorted keys)

### Witness ID Computation

```rust
fn compute_witness_id(witness: &ScopeAdditionWitness) -> String {
    // 1. Extract identity payload (excludes non-deterministic fields)
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

### Breaking Change Rules

**Changes that break wire format** (require schema bump):
1. Adding/removing fields from identity payload
2. Renaming fields in identity payload
3. Changing field types (e.g., uint → string)
4. Changing CBOR encoding (e.g., map → array)
5. Changing canonical sort order
6. Changing validation check names (existing checks)

**Changes that DON'T break wire format**:
1. Adding new validation checks
2. Changing validation messages
3. Changing timestamp format
4. Adding fields to full witness (not in identity payload)
5. Changing documentation

### Tamper-Evident Seal

Golden fixture test `test_golden_fixture_scope_addition_witness_wire_format()` pins exact CBOR bytes.

**If test fails**:
1. Determine if change is intentional
2. If intentional: bump schema to `scope-addition-witness/1`
3. If accidental: fix code to restore frozen encoding
4. Update documentation and contract references

---

## CLI Usage

### Basic Commands

```bash
# Check admissibility
admit_cli check testdata/programs/hello_world.adm

# Declare cost (seal witness)
admit_cli declare-cost witness.json --schema calc-plan/0

# Verify ledger
admit_cli verify-ledger --ledger-path .irrev/ledger.jsonl

# Registry operations
admit_cli registry init
admit_cli scope add --scope calc.pure@0 --deterministic --foundational
admit_cli scope verify calc.pure
admit_cli scope list --phase phase1

# Calculator operations
admit_cli calc execute calc_plan.json --input x=42
admit_cli calc verify witness.json

# Plan creation
admit_cli plan new
```

### Ledger Events

**Event Types**:
- `admissibility.checked` — Program verification result
- `admissibility.executed` — Action performed
- `cost.declared` — Cost witness sealed (immutable)
- `ingest.*` — File ingestion events
- `projection.*` — View generation events
- `court.*` — Governance artifacts

**Event Format** (JSONL):
```json
{"event_id": "evt_123", "event_type": "cost.declared", "timestamp": "2026-02-07T12:00:00Z", "witness_ref": "abc123..."}
{"event_id": "evt_124", "event_type": "admissibility.checked", "timestamp": "2026-02-07T12:00:01Z", "program_hash": "def456..."}
```

### Artifact Storage

**Path Structure**:
```
artifacts/
  <artifact_kind>/
    <sha256_hash>.cbor   # Canonical encoding
    <sha256_hash>.json   # Projection (human-readable)
```

**Artifact Kinds**:
- `witness` — Admissibility witnesses
- `calc_witness` — Computation witnesses
- `hash_witness` — Identity witnesses
- `plan_witness` — Action documentation
- `file_blob` — File snapshots
- `text_chunk` — Text fragments

---

## Development

### Building

```bash
# Build all crates
cargo build --release

# Run tests
cargo test

# Run specific crate tests
cargo test -p admit_core
cargo test -p admit_dsl
cargo test -p admit_cli

# Run golden fixture tests
cargo test --test hash_golden_fixtures
cargo test --test encode_canonical_fixtures
```

### Testing Strategy

**Golden Fixtures**:
- Wire format tests pin exact CBOR bytes
- Any change breaking golden fixture requires schema bump
- Located in `crates/*/tests/` directories

**Unit Tests**:
- Each module has inline `#[cfg(test)]` tests
- Focus on pure functions and deterministic evaluation

**Integration Tests**:
- `crates/admit_cli/tests/` — End-to-end CLI workflows
- `testdata/` — Example programs and expected outputs

### Code Organization Principles

1. **`admit_core` stays pure**: No I/O, no external effects
2. **Effects live in `admit_cli`**: Ledger writes, artifact storage
3. **Content addressing**: All artifacts hashed via canonical CBOR
4. **Idempotent operations**: `ensure_node`, registry normalization
5. **Exact arithmetic**: Rationals, no floats, overflow checking
6. **Trace recording**: All facts captured for witness reconstruction

---

## Design Documents

The `meta/` directory contains design documents, protocols, and scope contracts:

### Core Architecture
- [Architecture.md](meta/Architecture.md) — System layers and governance model
- [Irreversibility-First Design.md](meta/Irreversibility-First%20Design.md) — Core philosophy
- [Scope Primitives & Algebras.md](meta/Scope%20Primitives%20%26%20Algebras.md) — Scope theory

### Compiler Design
- [compiler-rs-plan.md](meta/design/compiler/compiler-rs-plan.md) — Rust compiler implementation plan
- [admissibility-ir.md](meta/design/compiler/admissibility-ir.md) — IR specification
- [adm-wellformedness.md](meta/design/compiler/adm-wellformedness.md) — Language well-formedness
- [compiler-rs-phase3-checklist.md](meta/design/compiler/compiler-rs-phase3-checklist.md) — Phase 3 tasks

### Protocols
- [semantics-authority.md](meta/protocols/semantics-authority.md) — Authority protocol
- [compiler-progress-tracking.md](meta/protocols/compiler-progress-tracking.md) — Development tracking

### OSS Specifications
- [scope-addition-protocol-v0.md](meta/oss/scope-addition-protocol-v0.md) — Scope addition 6-step protocol
- [scope-authority-protocol-v0.md](meta/oss/scope-authority-protocol-v0.md) — Authority rules
- [mechanism-protocol-v0.md](meta/oss/mechanism-protocol-v0.md) — Mechanism contracts
- [witness-registry-spec-v0.md](meta/oss/witness-registry-spec-v0.md) — Witness format registry

### Scope Contracts
- [meta-scope-contract.md](meta/meta-scope-contract.md) — Meta-scope governance
- [hash-scope-contract.md](meta/hash-scope-contract.md) — Hash evidence scope
- [encode-canonical-scope-contract.md](meta/encode-canonical-scope-contract.md) — Canonical encoding scope
- [select-path-scope-contract.md](meta/select-path-scope-contract.md) — Path selection scope

### Wire Formats
- [scope-addition-witness-wire-format.md](meta/scope-addition-witness-wire-format.md) — Frozen CBOR encoding
- [vault-snapshot-schema-v0.md](meta/design/compiler/vault-snapshot-schema-v0.md) — Snapshot format
- [hash-witness-schema-v0.md](meta/design/compiler/hash-witness-schema-v0.md) — Hash witness format

---

## Protocol Conformance

### Cost Declaration Protocol (5 Rules)

✅ **Rule 1: Declare cost before action**
- Enforced by CLI command ordering: `declare-cost` → `check` → `execute`
- `execute` command checks for prior `cost.declared` event

✅ **Rule 2: Default deny**
- Parser enforces: no implicit `AllowErase`
- Evaluator enforces: `DenyErase` is default permission
- Scope widening requires explicit `AllowScopeChange`

✅ **Rule 3: Cost routing**
- `ErasureRule` must specify `displaced_to: bucket`
- Displacement trace validates bucket routing
- Unrouted costs → inadmissible verdict

✅ **Rule 4: Witness-first**
- All verdicts produce structured `Witness` with spans
- Inadmissible outcomes include `reason` + triggered facts
- No silent failures

✅ **Rule 5: Irreversible declarations**
- Ledger is append-only JSONL
- `cost.declared` events never retracted
- Content-addressed artifacts are immutable

### Vault Invariants (4 Constraints)

✅ **Governance**
- Schema ID versioning: `<name>/<version>` format
- Registry normalization (sort, dedup)
- Witness includes `registry_hash_before/after`

✅ **Irreversibility**
- Default deny erasure in evaluator
- `AllowErase` requires matching `ErasureRule`
- Displacement trace mandatory for all verdicts

✅ **Decomposition**
- Namespaced identifiers: `difference:*`, `bucket:*`, `scope:*`, `module:*`
- Explicit dependencies via `depends` declarations
- Module isolation (no cross-module refs without deps)

✅ **Attribution**
- All IR nodes carry `Span` (file, line, column)
- Facts include source attribution
- Module ID in witness envelope

---

## Key Design Patterns

1. **Content Addressing**: All artifacts hashed via canonical CBOR
2. **Immutable Events**: Ledger is append-only JSONL
3. **Idempotent Operations**: `ensure_node`, registry normalization
4. **Exact Arithmetic**: Rationals, no floats, overflow checking
5. **Trace Recording**: All facts captured for witness reconstruction
6. **Scope Tagging**: All edges tagged with scope for governance
7. **Two-Layer Witnesses**: Core (content) + envelope (metadata)
8. **Deterministic Plans**: Separate plan artifact from execution
9. **Projection Abstraction**: DAG → SurrealDB extensible
10. **Registry Versioning**: Schemas + scopes with version history

---

## Future Directions

### Admissibility Lattice (Path Finding)

Treat admissibility as a lattice of states ordered by "has at least these commitments/constraints/permissions."

**State**:
- Permissions (allow/deny per difference)
- Erasure rules (routing + cost per difference)
- Commits (diff → value)
- Constraints (inadmissible_if predicates)
- Derived totals (bucket accumulations)

**Ordering**: A ≤ B if B contains all facts/constraints/permissions in A plus more.

**Path Finding**:
- Edges are typed deltas (small IR patches: add `Commit`, add `Constraint`, etc.)
- Weights are displacement costs + governance friction
- Targets are structural predicates (e.g., "admissible and constraint X not triggered")
- Path output is sequence of (delta, witness) pairs

**Guardrail**: Path finding is a query; it must not be framed as a recommendation engine.

---

## FAQ

**Q: Why canonical CBOR instead of JSON?**
A: Canonical CBOR (RFC 8949) ensures deterministic encoding: same data → same bytes. This is critical for content addressing and witness verification. JSON has multiple valid representations (whitespace, key order, number formats).

**Q: Why no floats?**
A: Floats have non-deterministic edge cases (NaN, -0.0, rounding) that break canonical encoding. We use exact arithmetic (rationals) for all numeric operations.

**Q: What is a "witness"?**
A: A witness is an unforgeable proof of execution. It contains the verdict (admissible/inadmissible), the reason, all facts recorded during evaluation, and the displacement trace. Witnesses are content-addressed and immutable.

**Q: What is "displacement"?**
A: Displacement quantifies the irreversible cost of state changes. It tracks which differences contribute to which buckets, and enforces that all costs are explicitly declared before execution.

**Q: Why are scopes hierarchical?**
A: Scopes formalize trust boundaries. Pure computation needs no governance. I/O operations need witnesses. External mutations need witnesses + authority. Hierarchical scopes enforce that widening (increasing risk) requires ceremony.

**Q: How does the registry work?**
A: The MetaRegistry is a versioned collection of schemas (artifact formats) and scopes (boundary contracts). Adding a scope increments the registry version and produces a witness with before/after hashes. This makes registry mutations auditable.

**Q: What is the "meta-scope"?**
A: The meta-scope (`scope:meta.scope`) governs the compiler itself. It defines how scopes are added, validated, and versioned. The compiler is self-governed: its own rules are expressed in the same system it enforces.

**Q: Why append-only ledger?**
A: Append-only ledgers ensure provenance and auditability. Once a cost is declared, it cannot be retracted. This prevents accidental or malicious erasure of governance records.

---

## License

See repository root for license information.

---

## Contributing

Design documents and protocols are canonical. Code changes must:

1. ✅ Preserve deterministic evaluation
2. ✅ Maintain canonical CBOR encoding
3. ✅ Update golden fixtures if wire format changes
4. ✅ Include spans for attribution
5. ✅ Emit structured witnesses
6. ✅ Pass all tests + ledger verification

---

## References

- RFC 8949: Concise Binary Object Representation (CBOR)
- [Chumsky Parser Combinator](https://github.com/zesterer/chumsky)
- [SurrealDB](https://surrealdb.com/)
- [Ollama](https://ollama.ai/)

---

**Last Updated**: 2026-02-07
**Compiler Version**: 0.1.0 (Phase 3)
**Status**: Active Development

