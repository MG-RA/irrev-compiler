# Scope Addition Protocol v0

Status date: 2026-01-30
Owner: mg

## Purpose

Provide a crisp, repeatable procedure for adding new scopes to `admitc` without expanding the core into a grab bag. The procedure is treated as a governed artifact (documented, checkable, and test-backed), not tribal knowledge.

Core rule: **don’t expand core, expand by scopes**.

## Domain vs scope (clarification)

This protocol uses “scope” as the unit of extension (because that is what gets registered, versioned, and enforced). Under the newer separation:

- A **domain** names a semantic universe (meaning).
- A **scope** names an admissible interface into that universe.

Naming convention: prefer `domain.scope` for the scope name.

- Example: instead of treating “hash” as one scope, use `hash.content`, `hash.verify`, `hash.execution`, etc.
- In registry IDs, keep the `scope:` prefix as a namespace marker, e.g. `scope:hash.content@1`.

## Core vs Scope Packages

### Core (keep tiny)

Core should remain focused on:

- IR + evaluator
- witness schema + canonical encoding + hashing
- pack/module loading + dependency resolution
- predicate provider interface (static, versioned)
- mechanism protocol interface (if runtime exists)

### Scope packages (where new capability lives)

Everything domain-specific lives in a scope package:

- snapshot schema + canonical hashing rules
- predicate family (usually one, parameterized)
- mechanisms (plan/execute/check) if needed
- `.adm` packs that define the scope’s admissibility law
- golden fixtures + determinism tests

## Scope Addition Steps (v0)

### Step 0: Name + Boundary

Define:

- `scope_id` (example: `scope:math:proof@1`)
- transformation-space: what counts as “the same thing” inside this scope?

For `scope:math:proof@1`:

- “same” = same theorem statement under same assumptions, same library set, and same proof checker kernel version.

### Step 1: Snapshot Schema (facts of the world)

Create a deterministic, hashable snapshot for the scope.

For math:

- `MathSnapshot` includes:
  - prover kernel name + version (Lean/Coq/etc.)
  - library set + hashes
  - environment flags (axioms enabled, classical logic, etc.)
  - optional: module graph for proof files

This is the math analogue of `VaultSnapshot`.

### Step 2: Predicate Family (observations)

Prefer one predicate family, not many keywords. Example patterns:

- `math_rule(rule_id, args...) -> Findings`
- `proof_check(theorem_ref | proof_blob_hash) -> Findings`

Each finding should be structured:

- theorem/goal identifier
- location (file/span)
- error kind (type mismatch, missing lemma, unsolved goals)
- bounded evidence payload (checker excerpt)

In boolean positions, `Findings` is coerced to `bool` via `exists(findings)` (v0 coercion rule).

### Step 3: Mechanism Family (moves)

Math scopes are a clean fit for mechanisms because proof checking is an effectful computation that should still be reproducible.

Minimum mechanisms:

- `math.snapshot` (pure)
- `math.check` (deterministic given snapshot + proof blob)
- optional: `math.normalize` (rewrite normalization)

Mechanisms produce:

- `PlanArtifact`: “check this proof object under snapshot S”
- `ResultWitness`: pass/fail + findings

### Step 4: Packs define admissibility law

Write `.adm` packs that bind scope rules into admissibility decisions.

Examples:

- `pack:math_strict@1`
  - forbid classical axioms
  - require proof check success
  - require all obligations discharged
- `pack:math_explore@1`
  - allow classical axioms
  - allow incomplete proofs but emit `info` findings

### Step 5: Golden fixtures + determinism tests (non-negotiable)

For every new scope package:

- same inputs -> same witness hash
- stable ordering of findings
- schema id locked

This is the “scope is real” check.

### Step 6: Registry + release

Register and publish:

- `scope_id`
- snapshot schema id
- predicate ids + signatures
- mechanism ids

Ship as a crate or (preferred for hard boundaries) a separate repo.

## Procedures as First-Class Governance

Two meanings of “procedure” are relevant:

### 1) Development procedure (expanding the system)

Encode in policy + CI:

- any new predicate must declare signature + version
- any witness schema change must bump schema id
- nondeterminism is rejected without golden fixtures

This makes the compiler self-governing.

### 2) Operational procedure (user workflows)

Encode as proof-carrying playbooks:

- snapshot -> plan -> declare cost -> check -> execute -> verify
- each step emits evidence bundles that can be stored in the witness registry

## Core Extension Protocol (CEP) (when you must expand core)

Sometimes core must grow. Gate it:

1. Justification: enables >= 2 independent scopes
2. Minimality: add one primitive, not a framework
3. Versioning: schema ids bump; compatibility story stated
4. Witness impact: determinism + sort order impact stated
5. Golden updates: fixtures updated and pinned

## Why math is the best next scope template

Math provides the cleanest prove-ability story:

- snapshot determinism
- proof checking as a verification witness
- “perfect within scope” semantics
- minimal physical-world feedback loops

It’s a reference implementation for adding scopes safely.
