# `irrev-compiler/meta` — Design Notes Index

This folder is the compiler/runtime’s **design + governance notebook**: what the system is, how it grows, and which documents are intended to be canonical vs process notes.

## Start here (mental model)

1. [Architecture Map](Architecture.md)
2. [Scope Primitives & Algebras](Scope%20Primitives%20%26%20Algebras.md)
3. [Irreversibility-First Design](Irreversibility-First%20Design.md)
4. [Context Checkpoint Compaction](context-checkpoint-compaction.md)
5. Governance + authority:
   - [Meta-Scope Governance](Meta%20Scope%20Governance.md)
   - [Semantics Authority Protocol](protocols/semantics-authority.md)
6. Patterns (vocabulary → publication model → enforcement pipeline):
   - [Scope Patterns](Scope%20Patterns.md)
   - [Scope Wiki](Scope%20Wiki.md)
   - [Pattern Evidence Pipeline](Pattern%20Evidence%20Pipeline.md)
7. Registry + deadlock discipline:
   - [Semantic Deadlock & Scope Registry](Semantic%20Deadlock%20%26%20Scope%20Registry.md)
   - [Registry Scope Architecture](Registry%20Scope%20Architecture.md)
8. Execution story + boundaries:
   - [Compiler + Runtime Loop](Compiler%20Runtime%20Loop.md)
   - [Boundary Events & DB Scope](Boundary%20Events%20%26%20DB%20Scope.md)

## Start here (implementation / project status)

- Status snapshot: [Compiler Progress Summary](compiler-progress-summary.md)
- Bridge from “status” to “kernel”: [Scope Primitives & Algebras](Scope%20Primitives%20%26%20Algebras.md)
- Process discipline: [Compiler Progress Tracking Protocol](protocols/compiler-progress-tracking.md)
- Rust compiler plan + kernel specs:
  - [Rust Admissibility Compiler Plan](design/compiler/compiler-rs-plan.md)
  - [Admissibility IR (kernel + witness format)](design/compiler/admissibility-ir.md)
  - [.adm Well-Formedness Checklist](design/compiler/adm-wellformedness.md)
  - [Implementation Plan: Chumsky Determinism + .adm Well-Formedness](design/compiler/adm-implementation-plan.md)
  - [Schema Registry (Compiler + Vault)](design/compiler/schema-registry.md)
  - [Meta Registry Gate Plan (Meta-first enforcement)](design/compiler/meta-registry-gate-plan.md)
  - [Kernel vs Stdlib vs User Space (Ship boundaries)](design/compiler/kernel-stdlib-userspace-plan.md)
  - [Ledger Export + DB Projection (Log as authority, DB as view)](design/compiler/ledger-export-and-db-projection.md)
  - [Semantic Providers Plan (Vault + ADM Packs)](design/compiler/semantic-providers-plan.md)
  - [Vault Snapshot Schema v0](design/compiler/vault-snapshot-schema-v0.md)

## Scope candidates / examples

These are useful as “worked examples” and future scope seeds:

- [Calculator Scope](calculator-scope.md)
- [Language Scopes](language-scopes.md)
- [Registry + deadlock examples](Registry%20Scope%20Architecture.md), (Semantic%20Deadlock%20%26%20Scope%20Registry.md)

## Doc taxonomy (how to interpret notes)

- **Canonical maps/vocabulary:** Architecture, Scope primitives/algebra, Patterns, Wiki, Meta-scope governance.
- **Protocols (binding rules / process):** `protocols/`
- **Implementation design:** `design/compiler/`
- **Status summaries:** progress summaries and phase trackers.
