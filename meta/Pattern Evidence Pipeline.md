---
role: meta
type: pattern-evidence-pipeline
canonical: true
facets:
  - governance
  - protocols
---

# Pattern Evidence Pipeline

## Purpose

Define a cross-substrate strategy for detecting and checking scope patterns across Markdown (vault), Rust (engine), and ADM (packs) without turning pattern checking into format-specific parsing or "vibe detection".

Core rule:

- Pattern checkers never parse MD/Rust/ADM directly.
- Substrate adapters emit deterministic snapshots.
- Snapshots are projected into a shared, typed PatternEvidence fact space.
- Pattern rules run only over PatternEvidence facts.

## Three-layer pipeline

### Layer A: Substrate adapters (MD / Rust / ADM)

Each adapter reads its native substrate and emits a deterministic snapshot.

- Markdown vault -> `VaultSnapshot`
- Rust repo -> `RustSnapshot` (AST-lite + metadata)
- ADM modules -> `AdmSnapshot` (already available via parser + lowering)

### Layer B: PatternEvidence projection

Each snapshot is projected into a shared schema of boring, cross-domain facts, e.g.:

- `DeclaresPattern { subject_id, pattern_id }`
- `DeclaresBoundary { subject_id, boundary_kind, boundary_spec }`
- `RequiresWitness { subject_id, witness_kind }`
- `UsesCanonicalForm { subject_id, canonical_spec_id }`
- `HasBridgeStep { subject_id, from_scope, to_scope, ceremony }`
- `HasDeterminismFixture { subject_id, fixture_hash }`

The goal is stable evidence, not perfect understanding.

### Layer C: Pattern checker

Patterns are rules over PatternEvidence facts, e.g.:

- If a subject declares `pattern:foundation`, it must have determinism fixtures.
- If a subject declares `pattern:canonicalization`, it must specify a canonical form and rejection/normalization behavior.
- If a bridge exists, it must require ceremony (plan hash, approvals/cost routing witnesses, etc.).

## Subject identity (`subject_id`)

Everything needs a stable identity so rules can refer to "subjects" uniformly.

Examples:

- Vault notes: `vault://<path>#<heading-or-block>`
- Rust items: `rust://<crate>/<module>::<Item>` plus span
- ADM items: `adm://<module>@<major>/constraint:<id>` plus span

## Adapter strategy (v0)

### Vault (Markdown) adapter

Prefer explicit, governance-friendly signals:

- frontmatter keys (`role`, `type`, `facets`, etc.)
- standard headings (`## Purpose`, `## Definition`, `## See also`, etc.)
- wikilinks + anchors
- callout blocks (`[!note]`)
- standardized disclaimers (e.g. "Non-claim")

Projection examples (illustrative):

- frontmatter includes a pattern declaration -> `DeclaresPattern`
- a "Non-claim" block -> `DeclaresBoundary` (diagnostic vs prescriptive)
- a note declares canonicalization rules -> `UsesCanonicalForm`

### Rust adapter

v0 does not require full semantic analysis. "AST-lite + metadata" is enough:

- crate graph, module graph
- use sites of canonical CBOR helpers / hashing utilities
- witness emission call sites
- static registries (predicate/mechanism registration)
- tests and golden fixtures presence

Projection examples:

- `HasDeterminismFixture` from golden witness fixture tests
- `UsesCanonicalForm` from canonical serializer usage

### ADM adapter

ADM already has a structured representation (AST):

- constraints
- tags (e.g. `tag pattern foundation`)
- queries (e.g. `query witness`, `query lint fail_on ...`)
- predicate calls

Projection examples:

- `DeclaresPattern` from `tag pattern ...`
- `RequiresWitness` from `query witness`

## Detection strategy: declaration-first

Two detection modes exist:

### 1) Declaration-first (recommended)

Patterns are detected because artifacts explicitly declare them:

- MD frontmatter: `patterns: [...]` (or equivalent)
- Rust: attribute/macro marker (e.g. `#[pattern(foundation)]`)
- ADM: `tag pattern <id>`

Then checks are strict: "declared pattern implies required structure exists".

### 2) Inference (use sparingly)

Infer patterns from signals (audit-only):

- canonicalization code implies canonicalization pattern
- plan/execute split implies bridge pattern

Inference findings should default to `info` until confirmed by explicit declaration.

## Smallest useful slice (recommended v0 implementation)

Start with 2-3 patterns with crisp signatures:

- Foundation: requires determinism fixtures
- Canonicalization: requires canonical spec + rejection/normalization rule
- Bridge: requires plan-hash ceremony + required witnesses

Emit minimal facts per substrate:

- Vault: `DeclaresPattern`
- Rust: `HasDeterminismFixture`
- ADM: `DeclaresPattern`

Run one strict rule:

- "Any subject declaring `pattern:foundation` must have `HasDeterminismFixture`."

## Where this belongs

Treat pattern checking as its own scope package:

- `scope:pattern`
- predicate family: `pattern_rule(pattern_id)` over PatternEvidence facts
- pack: `pattern_std@1` describing required structure per pattern

Substrate adapters become fact providers feeding this scope.

## See also

- [[Scope Patterns]]
- [[Scope Wiki]]
- [[Architecture]]

