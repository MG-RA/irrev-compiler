# Mechanism Protocol v0 (Runtime Adapters)

Status date: 2026-01-30
Owner: mg

## Purpose

Define a minimal, strict mechanism protocol so effectful systems can be retrofitted without expanding the compiler into a runtime monolith. The compiler decides admissibility; mechanisms execute vetted plans.

## Scope

This protocol governs runtime adapters ("mechanisms") that execute real-world effects under a content-addressed plan + witness flow. It is not a general RPC for arbitrary commands.

## Principles

- **Plan-first**: execution is only allowed for a previously issued plan hash.
- **Content-addressed**: every artifact is hashable and immutable.
- **Deterministic**: plan and witness outputs are stable under the same inputs.
- **Governed**: no dynamic plugins in v0; static registry only.
- **Minimal**: only the verbs needed to plan and execute safely.

## Transport (v0)

- **stdio JSON-RPC** is the default transport.
- No network exposure by default.

## Protocol Verbs (v0)

- `describe`
  - Returns mechanism id + version, supported operations, schemas, and capability scope.
- `plan`
  - Input: parameters + optional snapshot/facts references.
  - Output: `PlanArtifact` (content-addressed) + preview (optional).
- `declare_cost` (optional)
  - Output: `CostWitness` (content-addressed) if cost is computed by the mechanism.
- `execute`
  - Input: **plan hash** + approval/force-ack token.
  - Output: `ResultArtifact` + `ResultWitness`.
- `status` (optional)
  - Used only for long-running executions.

## PlanArtifact (minimum fields)

- `mechanism_id` + version
- `inputs` (hashes of snapshots/facts used)
- `intended_effects` (typed)
- `touches` (paths/resources)
- `estimated_costs` (optional)
- `exec_recipe` (structured; avoid raw shell strings if possible)

## ResultArtifact (minimum fields)

- `plan_hash`
- `status` (success/failure)
- `effects_applied` (typed)
- `evidence` (structured proof, logs, diffs, or hashes)

## Governance Guardrails (v0)

- A mechanism executes only by **plan hash**; never executes arbitrary requests.
- The compiler produces admissibility + witness for the plan before execution.
- Destructive operations require explicit force-ack in the approval chain.
- Mechanism declares capability scope; compiler policy can restrict by scope.

## Example Runtime Adapter Targets

- `mechanism.git_apply_patch`
- `mechanism.terraform_plan_apply`
- `mechanism.kubectl_apply`
- `mechanism.vault_autofix`

## Suggested v0 Rollout

- Implement the mechanism protocol over stdio JSON-RPC.
- Ship a single mechanism server that supports `describe` + `plan`.
- Add `execute` only after force-ack gating is implemented end-to-end.

