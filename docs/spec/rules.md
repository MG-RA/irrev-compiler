# Rulebook (Normative)

Version: 0.1  
Status date: 2026-02-11

## Interpretation

The key words `MUST`, `SHALL`, `MUST NOT`, and `SHALL NOT` are normative.

## Rule Index

| ID | Title | Severity | Enforced in |
|---|---|---|---|
| R-010 | No effect without check witness | S0 | `admit_cli::witness::execute_checked`, provider `execute` contract |
| R-020 | Canonical bytes define identity | S0 | `admit_core::cbor`, hash witness codecs |
| R-030 | Extensions only through ProviderRegistry | S1 | `admit_core::predicates`, `admit_core::provider_registry` |
| R-040 | Providers declare closure assumptions | S1 | `admit_core::provider_types::ProviderDescriptor` |
| R-050 | Provider predicates are centrally witnessed | S1 | `admit_core::bool_expr`, `admit_core::predicates` |
| R-060 | Emitted witnesses and ledgered artifacts include schema IDs | S1 | `admit_core::witness`, `admit_cli::artifact::store_artifact` |
| R-070 | Evaluation output is deterministic | S1 | `admit_core::env`, `admit_core::witness` |
| R-080 | Identity fields and metadata are explicitly separated | S1 | witness/hash schema definitions and codec tests |

## Rules

## Executable Artifact

Rules execute from a canonical artifact with schema id `ruleset/admit@1`.

Minimum fields:

- `schema_id`
- `ruleset_id`
- `enabled_rules`
- `bindings[]` where each binding includes:
  - `rule_id`
  - `severity`
  - `when.scope_id`
  - `when.predicate`
  - `when.params`
- `fail_on`

Execution model:

1. Resolve each binding through `ProviderRegistry`.
2. Execute predicate calls deterministically.
3. Record `rule_evaluated` and resulting findings in witness facts.
4. Derive verdict from `fail_on`.

Reference example:

- `docs/spec/ruleset-git-working-tree.example.json` demonstrates ruleset bindings for `git.working_tree` predicates (`dirty_state`, `untracked_file`).
- `docs/spec/ruleset-text-metrics.example.json` demonstrates ruleset bindings for `text.metrics` predicates (`lines_exceed`, `line_length_exceed`, `todo_present`).
- `docs/spec/ruleset-deps-manifest.example.json` demonstrates ruleset bindings for `deps.manifest` predicates (`git_dependency_present`, `wildcard_version_present`, `lockfile_missing`).

Recommended default guardrail profile:

- `docs/spec/ruleset-git-deps-guardrails.example.json` is the strict default profile for Git + dependency hygiene.
- It blocks dirty tree + untracked files, git-sourced dependencies, wildcard dependency versions, and missing lockfiles.

## R-010 - No effect without check witness

**Rule:** Any irreversible execute/apply operation MUST require evidence of a prior admissibility check bound to the same content identity.

**Rationale:** This blocks bypass channels and keeps effect attribution auditable.

**Enforcement point:** `crates/admit_cli/src/witness.rs` (`execute_checked` flow), and provider implementations of `execute`.

**Witness obligation:** If the required binding is missing or mismatched, execution MUST fail with a hard error and MUST NOT mutate state.

## R-020 - Canonical bytes define identity

**Rule:** Artifact identity MUST be computed from canonical encoding bytes only.

**Rationale:** Deterministic identity requires stable byte-level canonicalization.

**Enforcement point:** `crates/admit_core/src/cbor.rs`, `crates/admit_core/src/hash_witness.rs`, `crates/admit_core/tests/hash_golden_fixtures.rs`.

**Witness obligation:** Encoding or hash mismatch MUST produce a verification failure and prevent acceptance.

## R-030 - Extensions only through ProviderRegistry

**Rule:** Extension predicate dispatch MUST go through `ProviderRegistry` and MUST NOT use hardcoded per-provider predicate variants.

**Rationale:** A single extension path prevents drift and hidden side channels.

**Enforcement point:** `crates/admit_core/src/predicates.rs` (`ProviderPredicate` branch), `crates/admit_core/src/provider_registry.rs`.

**Witness obligation:** Missing registry or unknown scope MUST hard-fail predicate evaluation.

## R-040 - Providers declare closure assumptions

**Rule:** Every provider MUST publish closure requirements (`fs`, `network`, `db`, `process`) in its descriptor.

**Rationale:** Determinism claims are only auditable when external dependencies are explicit.

**Enforcement point:** `crates/admit_core/src/provider_types.rs` (`ClosureRequirements`, `ProviderDescriptor`), provider `describe()` implementations.

**Witness obligation:** Descriptor output MUST include closure flags; misdeclared behavior is a governance violation in audits.

## R-050 - Provider predicates are centrally witnessed

**Rule:** Every predicate evaluation MUST emit a predicate-evaluated witness fact, including provider predicates.

**Rationale:** Predicate outcomes must be legible and replayable from witnesses.

**Enforcement point:** `crates/admit_core/src/bool_expr.rs` (`Fact::PredicateEvaluated`), `crates/admit_core/src/predicates.rs` (`Fact::LintFinding` from provider findings).

**Witness obligation:** Witnesses MUST contain predicate evaluation facts for all evaluated predicates.

## R-060 - Emitted witnesses and ledgered artifacts include schema IDs

**Rule:** Emitted admissibility witnesses and ledgered artifacts MUST carry schema identifiers.

**Rationale:** Schema IDs are required for compatibility checks and registry governance.

**Enforcement point:** `crates/admit_core/src/witness.rs` (`DEFAULT_WITNESS_SCHEMA_ID`), `crates/admit_cli/src/artifact.rs` (`store_artifact`).

**Witness obligation:** Missing required schema IDs MUST fail artifact registration or verification.

## R-070 - Evaluation output is deterministic

**Rule:** Evaluation order and witness fact ordering SHALL be deterministic for identical inputs.

**Rationale:** Reproducibility is mandatory for witness trust and stable hashing.

**Enforcement point:** `crates/admit_core/src/env.rs` (`BTreeMap`/`BTreeSet` state), `crates/admit_core/src/witness.rs` (`fact_sort_key` sorting), golden tests.

**Witness obligation:** Non-deterministic output MUST be treated as a test failure and release blocker.

## R-080 - Identity fields and metadata are explicitly separated

**Rule:** Schemas and codecs MUST define which fields are identity-bearing and which are metadata-only.

**Rationale:** Hash stability requires explicit treatment of timestamps and auxiliary metadata.

**Enforcement point:** witness/hash schema docs plus codec tests (`encode_canonical_fixtures`, hash witness ID tests).

**Witness obligation:** Identity verification MUST ignore approved metadata-only fields and reject identity-field mismatch.
