# Agent Plan Contract (`plan-artifact/0` + `proposal-manifest/0`)

## Purpose
- Make planner and implementer outputs typed, hash-addressed, and machine-checkable.
- Keep core witness envelope unchanged while adding CI-visible contract status.

## Artifacts
- Plan artifact schema: `.admit/schemas/plan-artifact.v0.schema.json`
- Proposal manifest schema: `.admit/schemas/proposal-manifest.v0.schema.json`
- Planner/implementer prompts: `.admit/prompts/`

## Identity Model
- `plan_hash = sha256(canonical_cbor(plan_without_plan_id))`
- `plan_id = "plan:" + plan_hash`
- `manifest_hash = sha256(canonical_cbor(manifest_without_manifest_id))`
- `manifest_id = "manifest:" + manifest_hash`
- `proposal-manifest/0.plan_id` must equal plan `plan_id`.

## Validator
Command:

```bash
admit plan check --plan <plan.json> [--manifest <manifest.json>] [--changed-paths <paths.json>] --rollout advisory|enforce --json
```

Behavior:
- Structure validation is local and deterministic.
- `changed_paths_observed` is authoritative input (CI/system truth).
- `changed_paths_claimed` is manifest claim (advisory mismatch is reported).
- Emits `failure_classification`:
  - `none`
  - `mechanical`
  - `semantic`
  - `unknown`

## Hard-Stop Reasons
- `touches_github_workflows`
- `meta_schema_change`
- `meta_prompt_change`
- `meta_registry_change`
- `secrets_detected`
- `semantic_ci_failure`

If any hard-stop reason is present, `requires_manual_approval=true`.

## Exit Codes (Stable API)
- `0`: Contract accepted (including advisory warnings).
- `2`: Enforced contract violation/manual-approval requirement.
- `1`: Tooling/runtime error.

## CI Integration
- `admit ci --json` includes:
  - `plan_contract` object
  - `requires_manual_approval`
  - `stop_reasons`
- Witness schema remains `admissibility-witness/2`.
- Plan-contract status is attached through CI summary and witness lint fact (`rule_id=plan/contract`).
