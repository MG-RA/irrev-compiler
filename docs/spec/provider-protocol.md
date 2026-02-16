# Provider Protocol (Normative)

Version: 0.1  
Status date: 2026-02-11

## Scope

This spec defines the binding provider ceremony and extension predicate contract.

## Interface Contract

Providers MUST implement the `Provider` protocol in `admit_core`:

- `describe()`
- `snapshot()`
- `plan()`
- `execute()`
- `verify()`
- `eval_predicate()`

Default `plan/execute/verify` stubs may return structured `ProviderError` when unsupported.

## Phase Contract

| Phase | Method | Required output |
|---|---|---|
| Describe | `describe` | `ProviderDescriptor` with scope id, schema ids, closure requirements, predicates |
| Snapshot | `snapshot` | `SnapshotResult` with `FactsBundle` and witness |
| Plan | `plan` | `PlanResult` with `PlanBundle` and witness, or structured unsupported error |
| Execute | `execute` | `ExecutionResult` bound to approved plan hash, or structured unsupported error |
| Verify | `verify` | `VerifyResult` for artifact re-check, or structured unsupported error |

## Descriptor Requirements

`ProviderDescriptor` MUST declare:

- `scope_id`
- `schema_ids`
- `supported_phases`
- `deterministic`
- `closure` (`requires_fs`, `requires_network`, `requires_db`, `requires_process`)
- `predicates` (if provider supports extension predicates)

Each `PredicateDescriptor` SHOULD declare:

- `predicate_id` (`<scope_id>/<predicate_name>@<major>`)
- `result_kind` (currently `bool`)
- `emits_findings`
- `param_schema` (policy inputs only; no transport plumbing like `facts`)
- `evidence_schema` (optional)

Provider pack identity hash:

- `admit_core::provider_pack_hash()` computes canonical descriptor identity hash.
- `doc` text is excluded from identity hash.
- Hash input normalization sorts schema IDs, approvals, phases, and predicates.

## Extension Predicate Contract

Kernel predicates may delegate to providers through:

`ProviderPredicate { scope_id, name, params }`

Normative requirements:

1. Dispatch MUST resolve provider by `scope_id` through `ProviderRegistry`.
2. Missing registry or missing provider MUST hard-fail evaluation.
3. The kernel MUST emit `Fact::PredicateEvaluated` for all predicates.
4. Provider findings returned from `eval_predicate` MUST be recorded as witness findings.

Predicate evaluation context:

- Kernel passes `PredicateEvalContext { facts, snapshot_hash, facts_schema_id }`.
- Providers SHOULD read facts from context first.
- Compatibility window: providers MAY still accept legacy `params.facts`.

## Identity and Metadata Rules

For provider artifacts:

- Identity-bearing fields MUST be schema-defined and deterministically encoded.
- Metadata-only fields (for example timestamps) MUST be explicitly documented as non-identity.
- Verification MUST check canonical encoding and hash consistency for identity-bearing fields.

Current `ingest.dir` behavior:

- `FactsBundle.snapshot_hash` is computed over deterministic facts.
- `FactsBundle.created_at` may be caller-provided (`created_at`) for deterministic tests.

## Error Contract

Provider failures MUST return `ProviderError` with:

- `scope`
- `phase`
- `message`

Errors MUST be serializable and stable across surfaces (CLI/LSP/RPC).
