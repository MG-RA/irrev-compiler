# Patch Plan Scope Contract: `scope:patch.plan@0`

Status date: 2026-02-07

## Purpose

`scope:patch.plan@0` standardizes planned changes as canonical, attestable objects.
It answers: "what change is proposed?" before any side effects execute.

## v0 Scope Surface

- `patch.plan.create(before, after) -> patch_plan`
- `patch.plan.validate(patch_plan, policy) -> validation_result`

## Patch Plan Shape (v0)

- `target` (logical surface identifier)
- `operations` (ordered, deterministic list)
- `touched_paths` (normalized sorted set)
- `risk_class` (declared effect risk)
- `constraints` (policy hints for admissibility checks)

## Determinism

- Canonical encoding: `scope:encode.canonical@0`
- Stable identity hash: `scope:hash.content@0`
- Operation ordering is deterministic and canonical.

## Notes

`patch.plan` is intentionally non-effectful. Applying patches is out of scope for v0.
This keeps planning evidence separate from mutation execution.

