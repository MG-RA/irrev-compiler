# Compiler Progress Summary

Status date: 2026-01-30

## 1. Progress vs Phase plan

The tracking protocol (`meta/protocols/compiler-progress-tracking.md`) still reports Phase 7 as �Not started,� but all Phases 0-6 (including 5.5/5.6 subphases) are marked complete with documented evidence. The workspace now contains:

| Phase | Key evidence | Notes |
| --- | --- | --- |
| 0-2 | `admit_core`, `admit_dsl` sources, `compiler-rs-phase2-checklist.md` | IR + parser + lowering finished and tested. |
| 3 | `admit_core` predicates/eval/witness/cbor + `cargo test` | Constraint engine + deterministic witnesses + canonical CBOR done. |
| 4 | `admit_cli` declare/check/execute/verify + golden ledger fixtures | Cost declaration CLI surface + ledger integrity checks are in place. |
| 5-5.6 | `vault_snapshot`, `program_bundle`, `facts_bundle`, vault exporters | Snapshot+bundle/facts bridges implemented and hashed fixtures locked. |
| 6 | Artifact-backed ledger + CLI listing/test harness | Witness/artifact references, ledger fixture chain, and listing commands pass tests. |

Phase 7 (parity testing + replacement path) is ready to target once the registry audit (currently flagged as `registry-drift`) is resolved.

## 2. Design docs aligned with implementation

New meta documents now live under `irrev-compiler/meta/` so the compiler repo owns the design story and the scope catalog:

* **Architecture Map**, **Irreversibility-First Design**, **Scope Patterns**, and **Scope Wiki** (all relocated from `irrev-vault/meta/`) keep the high-level mental model and pattern vocabulary with the compiler team.
* **Boundary Events & DB Scope** � defines `BoundaryDeclared/BoundaryViolation` facts, ledger events, and a SurrealDB-aligned database scope for registry/ledger storage.
* **Compiler Runtime Loop** � models the pure compile loop vs governed runtime loop, runtime configuration, artifact flow, and JSON-RPC provider interface.
* **Pattern Evidence Pipeline** � sketches the adapter?fact?checker flow, pattern fact schema, and assembly path for `scope:pattern`.
* **Meta Scope Governance** � names the meta-scope layers (compiler admissibility, scope contracts, registry/versioning), decomposition patterns, dependency discipline, and Scope IR as the compiler�s clerk.
* **Semantic Deadlock & Scope Registry** � adds detection heuristics (typed edges, phases, boot sets, oracle tracking), typed registry shape, schema evolution rules, `.scope` manifest guidance, and the fatal invariant: no scope may require its own verdict to produce its witness.
* **Calculator Scope**, **Language Scopes**, and **Context Checkpoint Compaction** notes document the new math/language scope ideas and the cost-front-loading procedure so future teams inherit the checkpoints.

Moving these documents from the vault into the compiler metadata keeps the compiler repo accountable for the infrastructure you now rely on and keeps the scope catalog in the same source tree as the executor.

## 3. Proposed next actions (not yet executed)

1. Resolve the `registry-drift` error by re-running `irrev -v <vault> registry build --in-place` so Phase 4/6 ledger artifacts stay synced.
2. Use the new boundary facts + Scope IR to populate the planned VS Code Boundary Panel (documented in Boundary Events & DB Scope).
3. Continue Phase 7 work once the registry/diff fix is in place, using Semantic Deadlock & Scope Registry for scoped guardrails and Pattern Evidence Pipeline for new pattern packs.
