# Scope Authority Protocol v0 (Multi-Scope Effects)

Status date: 2026-01-30
Owner: mg

## Purpose

Define a small, governable protocol that lets multiple systems coordinate effectful plans across scopes without collapsing into a monolith. This turns "wrappers" into a multi-scope platform while preserving admissibility, evidence, and plan-hash execution.

## Core Idea

A **scope** is not just a label. A scope is a boundary that can speak for itself:

- what it is
- what it allows
- what evidence it requires

Actors do not "own" scopes by authority; they hold **capabilities** delegated by the scope.

## Effect Classes (bounded surface area)

To avoid a zoo of bespoke adapters, mechanisms map tools into a small set of canonical effect types:

- `patch.apply`
- `git.commit`
- `k8s.apply`
- `terraform.apply`
- `db.migrate`
- `artifact.publish`

These effect classes can wrap many tools while keeping the protocol stable.

## Scope As Routing + Capability Boundary

Each scope constrains:

- what can be planned
- what can execute
- what costs must be declared
- what evidence must be emitted

Example scopes:

- `scope:vault:content`
- `scope:repo:engine`
- `scope:k8s:staging`
- `scope:k8s:prod`

## Scope Authority Protocol (v0)

Minimal verbs for a self-governing scope:

1. `describe_scope()`
   - identity, resources, risk class, supported effect types
2. `policy(program_hash, plan_hash)`
   - required costs, approvals, or disallowed effects
3. `delegate(actor_id, capability_request)`
   - issue a capability token or deny with rationale
4. `verify(witness_or_result)`
   - accept/reject evidence against scope requirements

## Capabilities (proof-carrying permissions)

Capability tokens are the currency between actors:

- `scope_id`
- allowed effect types
- max risk class
- expiry
- optional secondary-approval requirements
- issuer signature

Actors without direct access can still negotiate plans, verify tokens, and validate witnesses.

## Cross-Scope Coordination (two-actor pattern)

Terminal B (no access):

- builds candidate plans
- compiles policy locally
- emits cost witness drafts
- sends plan bundle + witnesses to Terminal A

Terminal A (has access):

- requests scope policy
- executes **plan hash** with capability token
- returns result witness with scope attestation

Both parties share the immutable spine: plan hash, cost witness, result witness.

## Witness Spine (interface invariance)

Minimum fields that every scope must include in its witness:

- `scope_id`
- `plan_hash`
- `capability_id` (or null)
- `actor_id`
- `cost_declaration_refs`
- `result_summary`
- `evidence[]` (structured)

This prevents each scope from inventing a private religion.

## Transport

Use stdio JSON-RPC for v0 (same rationale as the mechanism protocol).

## Naming

"Mercury" is a good conceptual name for the cross-scope courier:

- moves plans across boundaries
- carries proofs instead of trust
- lets different substrates govern themselves yet interoperate

