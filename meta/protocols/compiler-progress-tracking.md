# Compiler Progress Tracking Protocol

Status date: 2026-01-29
Applies to: Rust admissibility compiler plan `meta/design/compiler/compiler-rs-plan.md`

## Purpose

Provide a single, auditable, append-only record of progress for each compiler phase. This protocol is updated after each phase transition (start, completion, or declared block) to make the workstream status explicit and reviewable.

## Scope

- Applies to the Rust admissibility compiler effort described in `meta/design/compiler/compiler-rs-plan.md`.
- Tracks Phase 0 through Phase 7 as defined in that plan.
- Does not replace technical design docs, code reviews, or test logs.

## Roles

- **Driver**: person or team executing the phase work.
- **Reviewer**: person confirming completion evidence.
- **Recorder**: person updating this protocol document (can be the Driver).

## Status Definitions

- **Not started**: no work initiated; no evidence logged.
- **In progress**: work started; partial evidence logged.
- **Blocked**: blocked by external dependency; blocker recorded.
- **Complete**: acceptance criteria met; evidence recorded.

## Required Updates (after each phase change)

Every phase transition **must** update this document in two places:

1. **Current Phase Status** table
2. **Progress Log** (append-only entry)

No entries are deleted. Corrections are added as new log entries.

## Phase Index (canonical)

0. Project skeleton + IO contract
1. Kernel IR + Witness schema
2. `.adm` parser + lowering
3. Constraint engine + predicate evaluation
4. Cost Declaration Protocol
5. Vault snapshot bridge
6. Ledger + witness integration
7. Parity testing + replacement path

## Evidence Requirements (minimum)

Each phase completion **must** include at least:

- One code or doc artifact reference (path or PR/commit id)
- One test or verification note (even if manual)
- A short outcome summary (1-3 sentences)

If tests are not run, record why and a plan to validate later.

## Current Phase Status

| Phase | Status | Driver | Reviewer | Start (YYYY-MM-DD) | End (YYYY-MM-DD) | Evidence |
| --- | --- | --- | --- | --- | --- | --- |
| 0 | Complete | mg | gpt ai review | 2026-01-29 | 2026-01-29 | execution/compiler-rs/Cargo.toml, execution/compiler-rs/crates/admit_core/src/lib.rs |
| 1 | Complete | mg | gpt ai review | 2026-01-29 | 2026-01-29 | execution/compiler-rs/crates/admit_core/src/ir.rs |
| 2 | Complete | mg | gpt ai review | 2026-01-29 | 2026-01-29 | execution/compiler-rs/crates/admit_dsl/src/parser.rs |
| 3 | Complete | mg | gpt ai review | 2026-01-29 | 2026-01-29 | execution/compiler-rs/crates/admit_core/src/witness.rs, execution/compiler-rs/crates/admit_core/src/displacement.rs, execution/compiler-rs/testdata/golden-witness/scope-widen-accounted.json |
| 4 | Complete | mg | gpt ai review | 2026-01-29 | 2026-01-29 | execution/compiler-rs/crates/admit_cli/src/main.rs, execution/compiler-rs/crates/admit_cli/src/lib.rs, execution/compiler-rs/crates/admit_cli/tests/declare_cost.rs, execution/compiler-rs/crates/admit_cli/tests/ledger_append.rs, execution/compiler-rs/crates/admit_cli/tests/check.rs, execution/compiler-rs/crates/admit_cli/tests/execute.rs, execution/compiler-rs/crates/admit_cli/tests/verify_ledger.rs |
| 5 | Complete | mg | gpt ai review | 2026-01-29 | 2026-01-29 | meta/design/compiler/vault-snapshot-schema-v0.md, execution/irrev/irrev/commands/snapshot.py, execution/compiler-rs/crates/vault_snapshot/src/lib.rs, execution/compiler-rs/testdata/snapshot/snapshot.json |
| 5.5 | Complete | mg | gpt ai review | 2026-01-29 | 2026-01-29 | meta/design/compiler/semantic-providers-plan.md, execution/compiler-rs/crates/program_bundle/src/lib.rs, execution/irrev/irrev/commands/projection.py |
| 5.6 | Complete | mg | gpt ai review | 2026-01-29 | 2026-01-29 | execution/compiler-rs/crates/facts_bundle/src/lib.rs, execution/compiler-rs/crates/facts_bundle/tests/observation_witness.rs, execution/compiler-rs/crates/admit_cli/src/main.rs |
| 6 | Complete | mg | gpt ai review | 2026-01-29 | 2026-01-29 | execution/compiler-rs/crates/admit_cli/src/lib.rs, execution/compiler-rs/crates/admit_cli/src/main.rs |
| 7 | Not started | TBD | TBD |  |  |  |

## Progress Log (append-only)

### Entry Template

```
Date: YYYY-MM-DD
Phase: <number + name>
Status: <Not started | In progress | Blocked | Complete>
Driver: <name>
Reviewer: <name or TBD>
Evidence:
- <paths/PR/commit ids>
- <tests or verification notes>
Summary:
- <1-3 sentence outcome>
Blockers (if any):
- <explicit blocker + next action>
```

### Log Entries

(append new entries below)

Date: 2026-01-29
Phase: 1 - Kernel IR + Witness schema
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- meta/design/compiler/compiler-rs-plan.md
- execution/compiler-rs/Cargo.toml
- execution/compiler-rs/crates/admit_core/Cargo.toml
- execution/compiler-rs/crates/admit_core/src/lib.rs
Summary:
- Phase 1 started.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 3 - Constraint engine + predicate evaluation
Status: Complete
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_core/src/eval.rs
- execution/compiler-rs/crates/admit_core/src/predicates.rs
- execution/compiler-rs/crates/admit_core/src/witness.rs
- execution/compiler-rs/testdata/golden-witness/scope-widen-accounted.json
- execution/compiler-rs/testdata/golden-witness/scope-widen-accounted.cbor.sha256
- cargo test (workspace)
Summary:
- Deterministic predicate evaluation, displacement tracing, and witness assembly are complete with canonical CBOR hashing and golden fixtures.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 3.1 - Boundary kernel (closure)
Status: Complete
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_core/src/boundary.rs
- execution/compiler-rs/crates/admit_dsl/src/lowering.rs
- execution/compiler-rs/crates/admit_core/src/tests.rs
- epistemics/vault/concepts/scope-change.md
- epistemics/vault/concepts/boundary-crossing.md
Summary:
- Boundary-loss helper and displacement contribution tests are in place; vault concepts and examples are aligned to the kernel semantics.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 4 - Cost Declaration Protocol
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_cli/src/main.rs
- execution/compiler-rs/crates/admit_cli/src/lib.rs
- execution/compiler-rs/crates/admit_cli/tests/declare_cost.rs
- execution/compiler-rs/crates/admit_core/src/lib.rs
- cargo test (workspace)
Summary:
- Added the `admit_cli` crate with `declare-cost`, canonical witness verification, and append-only JSONL ledger emission; tests cover hash mismatch rejection and deterministic event IDs.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 4 - Cost Declaration Protocol (design note)
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- meta/design/compiler/cost-declaration.md
Summary:
- Documented the minimal `cost.declared` envelope and the mechanized verifier rule that binds canonical witness bytes to a hash.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 4 - Cost Declaration Protocol (Hello World)
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- meta/design/compiler/cost-declaration.md
- meta/design/compiler/hello-world.md
Summary:
- Added the Hello World narrative that frames scope widening as the atomic irreversible boundary and codified the inadmissible/admissible `.adm` programs that make the boundary visible.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 4 - Cost Declaration Protocol (check + verify)
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_cli/src/main.rs
- execution/compiler-rs/crates/admit_cli/src/lib.rs
- execution/compiler-rs/crates/admit_cli/tests/check.rs
- execution/compiler-rs/crates/admit_cli/tests/ledger_append.rs
- execution/compiler-rs/testdata/programs/hello-world-inadmissible.adm
- execution/compiler-rs/testdata/programs/hello-world-accounted.adm
- cargo test (workspace)
Summary:
- Added `check` command that validates `cost.declared` integrity and appends `admissibility.checked` events; added `witness-verify` helper, duplicate-event test, and Hello World `.adm` fixtures.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 4 - Cost Declaration Protocol (check event integrity)
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_cli/src/lib.rs
- execution/compiler-rs/crates/admit_cli/src/main.rs
- execution/compiler-rs/crates/admit_cli/tests/check.rs
- cargo test (workspace)
Summary:
- Added integrity verification for `cost.declared` events (payload hash + witness CBOR hash) and a `check` command that appends `admissibility.checked` records.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 4 - Cost Declaration Protocol (execute gate)
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_cli/src/lib.rs
- execution/compiler-rs/crates/admit_cli/src/main.rs
- execution/compiler-rs/crates/admit_cli/tests/execute.rs
- cargo test (workspace)
Summary:
- Added `execute` command that requires a valid `admissibility.checked` event and appends `admissibility.executed` with immutable backreferences.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 4 - Cost Declaration Protocol
Status: Complete
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_cli/src/main.rs
- execution/compiler-rs/crates/admit_cli/src/lib.rs
- execution/compiler-rs/crates/admit_cli/tests/declare_cost.rs
- execution/compiler-rs/crates/admit_cli/tests/check.rs
- execution/compiler-rs/crates/admit_cli/tests/execute.rs
- cargo test (workspace)
Summary:
- Phase 4 command surface is in place: `declare-cost`, `witness-verify`, `check`, and `execute`, with append-only ledger events and integrity checks.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 4 - Cost Declaration Protocol (verify-ledger)
Status: Complete
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_cli/src/main.rs
- execution/compiler-rs/crates/admit_cli/src/lib.rs
- execution/compiler-rs/crates/admit_cli/tests/verify_ledger.rs
- cargo test (workspace)
Summary:
- Added `verify-ledger` command to recompute event hashes, validate back-references, require snapshot hashes, and parse witness CBOR as `Witness`.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 4 - Cost Declaration Protocol (ledger verifier + witness binding)
Status: Complete
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_cli/src/lib.rs
- execution/compiler-rs/crates/admit_cli/src/main.rs
- execution/compiler-rs/crates/admit_cli/tests/verify_ledger.rs
- cargo test (workspace)
Summary:
- Ledger verifier now recomputes event hashes, checks reference ordering, validates snapshot presence, and decodes canonical CBOR into `Witness` before accepting it as valid.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 4 - Cost Declaration Protocol (snapshot hardening + fixtures)
Status: Complete
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_cli/src/lib.rs
- execution/compiler-rs/crates/admit_cli/tests/declare_cost.rs
- execution/compiler-rs/testdata/ledger/cost.declared.json
- execution/compiler-rs/testdata/ledger/admissibility.checked.json
- execution/compiler-rs/testdata/ledger/admissibility.executed.json
- cargo test (workspace)
Summary:
- Snapshot hash is now required for declarations and carried through check/execute.
- Added golden JSON fixtures for all Phase 4 event types to make schema drift visible.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 4 - Cost Declaration Protocol (P2 CLI outputs)
Status: Complete
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_cli/src/main.rs
- meta/design/compiler/cost-declaration.md
- cargo test (workspace)
Summary:
- Added `--json` output mode for declare/check/execute/verify-ledger and `--dry-run` for declare/check/execute.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 5 - Vault snapshot bridge (schema + exporter)
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- meta/design/compiler/vault-snapshot-schema-v0.md
- execution/irrev/irrev/commands/snapshot.py
- execution/irrev/irrev/surfaces/cli.py
Summary:
- Defined snapshot schema v0 with canonical JSON rules and added a Python exporter command to emit `snapshot.json` + `.sha256`.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 5 - Vault snapshot bridge
Status: Complete
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/vault_snapshot/src/lib.rs
- execution/compiler-rs/crates/vault_snapshot/tests/snapshot_hash.rs
- execution/compiler-rs/testdata/snapshot/snapshot.json
- execution/compiler-rs/testdata/snapshot/snapshot.json.sha256
- cargo test -p vault_snapshot
Summary:
- Added a canonical snapshot fixture and hash, plus a Rust test that verifies snapshot hashing against the fixture.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 5.5 - Program bundle bridge (plan)
Status: Not started
Driver: mg
Reviewer: gpt ai review
Evidence:
- meta/design/compiler/semantic-providers-plan.md
- meta/design/compiler/compiler-rs-plan.md
Summary:
- Added a ProgramBundle bridge plan and inserted Phase 5.5 into the compiler plan to sequence vault projection and ADM pack providers.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 5.5 - Program bundle bridge (implementation)
Status: Complete
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/program_bundle/src/lib.rs
- execution/compiler-rs/crates/program_bundle/tests/bundle_hash.rs
- execution/compiler-rs/testdata/bundle/program-bundle.json
- execution/compiler-rs/testdata/bundle/program-bundle.json.sha256
- execution/irrev/irrev/commands/projection.py
- execution/irrev/irrev/surfaces/cli.py
- cargo test (workspace)
Summary:
- Added ProgramBundle schema loader, canonical hash tests + fixtures, and a vault projection exporter (`irrev projection adm-export`).
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 5.6 - Facts bundle + observation runner (plan)
Status: Not started
Driver: TBD
Reviewer: TBD
Evidence:
- meta/design/compiler/compiler-rs-plan.md
Summary:
- Added Phase 5.6 plan for a canonical facts bundle, minimal observation provider, and CLI wiring into `admit check`.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 5.6 - Facts bundle + observation runner (implementation)
Status: Complete
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/facts_bundle/src/lib.rs
- execution/compiler-rs/crates/facts_bundle/tests/observation_witness.rs
- execution/compiler-rs/testdata/facts/facts-bundle.json
- execution/compiler-rs/testdata/golden-witness/facts-prescriptive-count.json
- execution/compiler-rs/crates/admit_cli/src/main.rs
- cargo test -p facts_bundle
- cargo test -p admit_cli
Summary:
- Added facts bundle schema + canonical hashing, a regex-style observation runner, and an `admit observe` CLI; `admit check` now records facts bundle hashes and golden fixtures lock witness identity.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 2 - .adm parser + lowering
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/Cargo.toml
- execution/compiler-rs/crates/admit_dsl/Cargo.toml
- execution/compiler-rs/crates/admit_dsl/src/lib.rs
Summary:
- Phase 2 started with admit_dsl crate skeleton and AST placeholders; chumsky selected.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 2 - .adm parser + lowering
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_dsl/src/lib.rs
Summary:
- Added chumsky lexer/parser for v0 .adm grammar, basic bool exprs, and lowering to admit_core.
- Added a minimal parse+lower test fixture.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 2 - .adm parser + lowering
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_dsl/src/lib.rs
- meta/design/compiler/compiler-rs-plan.md
Summary:
- Added `depends [...]` to the .adm grammar and enforced required `module:irrev_std@1` dependency during lowering.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 2 - .adm parser + lowering
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_core/src/lib.rs
- execution/compiler-rs/crates/admit_dsl/src/lib.rs
Summary:
- Added dependency emission to the IR program shape and introduced structured parse errors with spans.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 2 - .adm parser + lowering
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- meta/design/compiler/compiler-rs-phase2-checklist.md
- execution/compiler-rs/crates/admit_dsl/src/lib.rs
- execution/compiler-rs/crates/admit_core/src/lib.rs
- execution/compiler-rs/testdata/programs/basic.adm
Summary:
- Implemented Phase 2 checklist items: namespace validation, dependency enforcement, erasure-rule checks, deterministic decl ordering, line/col spans, fixtures, and round-trip tests.
- Tests added but not run in this update.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 2 - .adm parser + lowering
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_dsl/src
- execution/compiler-rs/crates/admit_core/src
Summary:
- Modularized admit_dsl and admit_core into focused submodules to keep files small and maintainable.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: Plan update - Canonical CBOR encoding
Status: Complete
Driver: mg
Reviewer: gpt ai review
Evidence:
- meta/design/compiler/compiler-rs-plan.md
- meta/design/compiler/admissibility-ir.md
Summary:
- Specified RFC 8949 canonical CBOR for artifact identity, JSON as projection, and strict float rules.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 2 - .adm parser + lowering
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/testdata/programs/basic.adm
- execution/compiler-rs/crates/admit_dsl/src/parser.rs
- meta/design/compiler/compiler-rs-plan.md
- meta/design/compiler/admissibility-ir.md
Summary:
- Simplified DSL surface (short names, optional module: prefix) and documented builtin `erase` transform.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 1 - Kernel IR + Witness schema
Status: Complete
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_core/src/lib.rs
- Kernel IR + witness schema types defined in Rust; no tests run yet.
Summary:
- Phase 1 completed with core IR and witness schema types implemented in admit_core.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: Plan update - Admissibility lattice + path finding
Status: Complete
Driver: mg
Reviewer: gpt ai review
Evidence:
- meta/design/compiler/compiler-rs-plan.md
Summary:
- Integrated lattice/path-finding framing and guardrails into the compiler plan.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: Plan update - Explicit dependency enforcement
Status: Complete
Driver: mg
Reviewer: gpt ai review
Evidence:
- meta/design/compiler/compiler-rs-plan.md
Summary:
- Added explicit dependency enforcement and mandatory core module dependency rule.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 1 - Kernel IR + Witness schema
Status: Complete
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_core/src/ir.rs
- execution/compiler-rs/crates/admit_core/src/witness.rs
- execution/compiler-rs/crates/admit_core/src/tests.rs
Summary:
- Phase 1 reconfirmed complete after modularization; schema and witness types live in dedicated modules.
- Tests exist but have not been run in this update.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 2 - .adm parser + lowering
Status: Complete
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_dsl/src/parser.rs
- execution/compiler-rs/crates/admit_dsl/src/lowering.rs
- execution/compiler-rs/crates/admit_dsl/src/tests.rs
- execution/compiler-rs/testdata/programs/basic.adm
Summary:
- Phase 2 completed with chumsky parser, lowering, validations, fixtures, and tests.
- Tests added but not run in this update.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: Plan update - CBOR primer
Status: Complete
Driver: mg
Reviewer: gpt ai review
Evidence:
- meta/design/compiler/compiler-rs-plan.md
Summary:
- Added a short CBOR primer explaining canonical encoding, hash identity, and float policy.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 3 - Constraint engine + predicate evaluation
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- meta/design/compiler/compiler-rs-phase3-checklist.md
- TEST_BASELINE.md
Summary:
- Captured the Phase 3 task list: env building, predicate engine, displacement trace, witness assembly, CBOR discipline, and associated fixtures.
- Baseline note includes the (failed) `cargo check` attempt because `chumsky` is unavailable offline.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 3 - Constraint engine + predicate evaluation
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_core/src/predicates.rs
- execution/compiler-rs/crates/admit_core/src/tests.rs
- cargo test (admit_core + admit_dsl)
Summary:
- Commit predicates now log `Fact::CommitUsed`, enabling witnesses to trace commit consumption; unit tests verify the fact appears.
- `cargo test` now runs cleanly and confirms both admit_core and admit_dsl suites as well as document tests pass after the predicate/lexer tweaks.
Blockers (if any):
- None noted; remaining Phase 3 work still focuses on environment normalization, witness assembly, and canonical CBOR encoding.

Date: 2026-01-29
Phase: 3 - Constraint engine + predicate evaluation
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_dsl/src/lexer.rs
- execution/compiler-rs/crates/admit_dsl/src/parser.rs
- execution/compiler-rs/crates/admit_dsl/src/tests.rs
- cargo test (admit_core + admit_dsl)
Summary:
- Hardened the admit_dsl lexer/token surface (keyword handling + numeric newtype) and aligned the tests to the current IR fixture so the suite executes cleanly.
- `cargo test` now passes for both crates, keeping the Phase 3 entry surface stable while the evaluation/predicate/displacement work continues.
Blockers (if any):
- None noted; next steps remain building `admit_core::env`, `bool_expr`/`predicates`, `displacement`, `constraints`, `witness`, and CBOR helper modules per the Phase 3 checklist.

Date: 2026-01-29
Phase: 3 - Constraint engine + predicate evaluation
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_core/src/bool_expr.rs
- execution/compiler-rs/crates/admit_core/src/predicates.rs
- cargo test (admit_core + admit_dsl)
Summary:
- Predicate evaluation now emits canonical strings (`predicate_to_string`) so `Fact::PredicateEvaluated` is deterministic, and the bool expr recorder reuses the helper.
- `cargo test` continues to pass, confirming the canonical predicate string and commit logging produce stable facts.
Blockers (if any):
- None noted; next up is completing witness assembly/displacement ordering and the canonical CBOR helper.

Date: 2026-01-29
Phase: 3 - Constraint engine + predicate evaluation
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_core/src/displacement.rs
- execution/compiler-rs/crates/admit_core/src/eval.rs
- cargo test (admit_core + admit_dsl)
Summary:
- Displacement trace and contribution ordering are now deterministic, and `eval` assigns a meaningful reason string (`constraints triggered` vs `admissible`) before assembling the witness.
- `cargo test` still passes, validating the updated ordering and reason while Phase 3 continues toward witness assembly and CBOR discipline.
Blockers (if any):
- None noted; next focus remains finishing the witness builder (aggregated facts + displacement trace) and wiring in the canonical CBOR helper.

Date: 2026-01-29
Phase: 3 - Constraint engine + predicate evaluation
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_core/src/witness.rs
- cargo test (admit_core + admit_dsl)
Summary:
- Added `WitnessBuilder` that accepts program metadata, the trace (or facts), and the displacement trace, sorts facts deterministically, and produces the witness with deterministic reason strings/predicate representations for hashing.
- `cargo test` stays green, confirming the builder integrates smoothly with existing evaluation paths.
Blockers (if any):
- None noted; next step is to plug the canonical CBOR helper + golden witness fixtures.

Date: 2026-01-29
Phase: 0 - Project skeleton + IO contract
Status: Complete
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/Cargo.toml
- execution/compiler-rs/crates/admit_core/src/lib.rs
Summary:
- Established the workspace and admit_core skeleton that define the IO contract referenced by the plan; no tests were necessary for this initial scaffolding.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 3 - Constraint engine + predicate evaluation (toolchain note)
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- Cargo.lock
Summary:
- Pinned `chumsky = 0.9` via the workspace lock so the offline environment can resolve dependencies and `cargo test` now succeeds, eliminating the earlier “chumsky unavailable” blocker.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 3 - Constraint engine + predicate evaluation
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_core/src/witness.rs
- execution/compiler-rs/crates/admit_core/src/eval.rs
- execution/compiler-rs/crates/admit_core/src/tests.rs
- cargo test (admit_core + admit_dsl)
Summary:
- Updated the witness assembly pipeline so the builder accepts `WitnessProgram` metadata, consumes `Trace` facts, and exposes sorted predicate strings that can be hashed deterministically, then wired the new API into `eval` and the unit tests.
- Added a regression test that proves the canonical predicate-string helper keeps predicate facts in deterministic order so serialized witnesses stay stable.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 3 - Constraint engine + predicate evaluation
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_core/src/cbor.rs
- execution/compiler-rs/crates/admit_core/src/tests.rs
- execution/compiler-rs/crates/admit_core/Cargo.toml
- execution/compiler-rs/Cargo.lock
- execution/compiler-rs/testdata/golden-witness/allow-erasure-trigger.json
- execution/compiler-rs/testdata/golden-witness/allow-erasure-trigger.cbor.sha256
- cargo test (admit_core + admit_dsl)
Summary:
- Added the canonical CBOR encoder (integer-only, RFC 8949) plus golden JSON/hash fixtures and tests so every witness now has a stable projection and hashable identity.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 3 - Constraint engine + predicate evaluation (ScopeChange primitive)
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- meta/design/compiler/scope-change.md
- epistemics/vault/concepts/scope-change.md
- execution/compiler-rs/crates/admit_core/src/ir.rs
- execution/compiler-rs/crates/admit_core/src/eval.rs
- execution/compiler-rs/crates/admit_core/src/witness.rs
- execution/compiler-rs/crates/admit_dsl/src/parser.rs
- execution/compiler-rs/crates/admit_dsl/src/lowering.rs
- execution/compiler-rs/crates/admit_core/src/tests.rs
- execution/compiler-rs/testdata/golden-witness/scope-widen-unaccounted.json
- execution/compiler-rs/testdata/golden-witness/scope-widen-unaccounted.cbor.sha256
- execution/compiler-rs/testdata/golden-witness/scope-widen-accounted.json
- execution/compiler-rs/testdata/golden-witness/scope-widen-accounted.cbor.sha256
- execution/compiler-rs/testdata/golden-witness/scope-two-changes-accounted.json
- execution/compiler-rs/testdata/golden-witness/scope-two-changes-accounted.cbor.sha256
- cargo test (admit_core + admit_dsl)
Summary:
- Introduced `ScopeChange` as a first-class IR statement with deterministic evaluation semantics: widen/translate are inadmissible unless boundary-loss accounting exists, with structured witness facts and golden JSON/CBOR hash fixtures to lock identity-by-hash.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 3.1 - Boundary kernel (ScopeChange clarification + helper)
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- epistemics/vault/concepts/scope-change.md
- meta/design/compiler/scope-change.md
- execution/compiler-rs/crates/admit_core/src/boundary.rs
- execution/compiler-rs/crates/admit_core/src/eval.rs
- execution/compiler-rs/crates/admit_dsl/src/lowering.rs
- execution/compiler-rs/crates/admit_core/src/tests.rs
- cargo test (admit_core + admit_dsl)
Summary:
- Added a minimal vocabulary block and a canonical `.adm` example for scope-change, formalized boundary-loss diff naming as a first-class helper, and added an explicit test that shows boundary-loss accounting appears in the displacement trace.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 3.1 - Boundary kernel (vault stabilization)
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- epistemics/vault/concepts/witness.md
- epistemics/vault/concepts/boundary.md
- epistemics/vault/concepts/scope.md
- meta/design/compiler/witness-format.md
Summary:
- Added minimal concept notes for witness/boundary/scope and a compiler-facing witness format note (canonical CBOR identity vs JSON projection) so the vocabulary matches the implemented boundary primitive.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: Plan update - .adm implementation plan + sugar kickoff
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- meta/design/compiler/adm-implementation-plan.md
- execution/compiler-rs/crates/admit_dsl/src/lexer.rs
- execution/compiler-rs/crates/admit_dsl/src/parser.rs
- execution/compiler-rs/crates/admit_dsl/src/tokens.rs
- execution/compiler-rs/crates/admit_dsl/src/tests.rs
Summary:
- Added the implementation plan for Chumsky determinism and well-formedness, then began parser updates to support sugar forms and deterministic tokens.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 6 - Ledger + witness integration
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_cli/src/lib.rs
- execution/compiler-rs/crates/admit_cli/src/main.rs
- execution/compiler-rs/crates/admit_cli/tests/check.rs
- execution/compiler-rs/crates/admit_cli/tests/execute.rs
- execution/compiler-rs/crates/admit_cli/tests/verify_ledger.rs
- execution/compiler-rs/testdata/ledger/cost.declared.json
Summary:
- Added artifact store wiring in `admit_cli` (witness artifacts, refs, and verification), updated CLI to pass artifact roots, and started updating ledger fixtures/tests for artifact-based events.
- Subphase note: 6.1–6.3 done; 6.4 in progress (fixtures + event id regeneration).
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 6 - Ledger + witness integration (fixtures)
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/testdata/artifacts/witness/5429b6067c816d04251ae8c2f5e3e9d0e838d8a2501b99ed91dcdf6448019151.cbor
- execution/compiler-rs/testdata/artifacts/witness/5429b6067c816d04251ae8c2f5e3e9d0e838d8a2501b99ed91dcdf6448019151.json
- execution/compiler-rs/testdata/artifacts/witness/5429b6067c816d04251ae8c2f5e3e9d0e838d8a2501b99ed91dcdf6448019151.cbor.sha256
- execution/compiler-rs/testdata/ledger/cost.declared.json
- execution/compiler-rs/testdata/ledger/admissibility.checked.json
- execution/compiler-rs/testdata/ledger/admissibility.executed.json
Summary:
- Added a golden witness artifact fixture (CBOR + JSON projection + sha256) and regenerated ledger fixture event IDs and references to match artifact-based payloads.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 6 - Ledger + witness integration (fixtures test)
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/testdata/ledger/ledger.jsonl
- execution/compiler-rs/crates/admit_cli/tests/verify_ledger_fixtures.rs
Summary:
- Added a fixture ledger JSONL file and a verification test that ensures the artifact-backed chain verifies cleanly.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 6.5 - Artifact listing + inspection
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_cli/src/lib.rs
- execution/compiler-rs/crates/admit_cli/src/main.rs
- execution/compiler-rs/crates/admit_cli/tests/artifact_list.rs
Summary:
- Added artifact listing/inspection helpers and CLI commands (`list-artifacts`, `show-artifact`) with a fixture-based test for the witness artifact.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 6 - Ledger + witness integration (refinement)
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_cli/src/lib.rs
- execution/compiler-rs/crates/admit_cli/src/main.rs
- execution/compiler-rs/testdata/artifacts/snapshot
- execution/compiler-rs/testdata/artifacts/program_bundle
- execution/compiler-rs/testdata/artifacts/facts_bundle
- execution/compiler-rs/testdata/ledger/ledger.jsonl
Summary:
- Dropped legacy inline witness support and expanded provenance: snapshot, program bundle, and facts bundle are stored as artifacts and referenced by events; fixtures regenerated to include new refs.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: 6 - Ledger + witness integration
Status: Complete
Driver: mg
Reviewer: gpt ai review
Evidence:
- execution/compiler-rs/crates/admit_cli/src/lib.rs
- execution/compiler-rs/crates/admit_cli/src/main.rs
- execution/compiler-rs/crates/admit_cli/tests/verify_ledger_fixtures.rs
- execution/compiler-rs/testdata/artifacts/witness
- execution/compiler-rs/testdata/artifacts/snapshot
- execution/compiler-rs/testdata/artifacts/program_bundle
- execution/compiler-rs/testdata/artifacts/facts_bundle
- execution/compiler-rs/testdata/ledger/ledger.jsonl
Summary:
- Phase 6 complete: artifact-backed witness/snapshot/program/facts refs, ledger verification, fixture chain, and CLI surface for artifact inspection.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: Migration plan - Python to Rust authority
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- meta/design/compiler/python-to-rust-migration.md
Summary:
- Drafted the Python → Rust migration plan with phased deliverables and risk controls.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: Migration plan - Schema registry
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- meta/design/compiler/schema-registry.md
Summary:
- Added a schema registry with active and planned IDs, aligned to the migration plan.
Blockers (if any):
- None noted.

Date: 2026-01-29
Phase: Migration plan - Semantics authority protocol
Status: In progress
Driver: mg
Reviewer: gpt ai review
Evidence:
- meta/protocols/semantics-authority.md
Summary:
- Declared Rust as the sole semantic authority; Python limited to structure extraction.
Blockers (if any):
- CI guard not yet implemented.
