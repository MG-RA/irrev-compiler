---
role: support
type: scope-infrastructure
canonical: true
facets:
  - governance
  - protocols
---

# Semantic Deadlock & Scope Registry

## Purpose

Document semantic deadlock detection and the typed scope registry/schema/IR infrastructure so the compiler meta layer can reason about scopes without letting meaning circle back on itself.

## Semantic deadlock

Definition: a set of scopes where producing the witness required to admit an action already requires that action’s verdict/effect, so evaluation cannot reach a stable fixpoint without illicit assumptions.

### Example: binary ↔ hash

Split into layered scopes:

* `file.observe` (P0) → bytes
* `hash.content` (P1) → canonical hash
* `binary.identity` (P1) → uses hash + metadata
* `hash.execution` (P1/P2) → hashes env + binary identity

`hash.content` must not depend on `binary.identity`.

## Deadlock detection

1. **Typed dependencies.**
   * `needs_witness(scope, witness_id)`
   * `requires_verdict(scope, verdict_id)`
   * `requires_effect(scope, effect_id)`
   * Cycles containing `requires_verdict` without a pure witness base signal deadlock.

2. **Phase labels.**
   * `P0 Observations`, `P1 Witness`, `P2 Verdict`, `P3 Effects`, `P4 Accounting`.
   * Dependencies must align with declared phases; upward violations raise flags.

3. **Boot set analysis.**
   * Start with `P0/P1` scopes.
   * Propagate bootability.
   * Remaining scopes requiring verdicts but not bootable indicate deadlock or missing oracles.

4. **Oracle dependencies.**
   * Tag nondeterministic inputs (clock, network) as `oracle`.
   * Require explicit allowance or downgrade when oracles appear.

## Typed scope registry

Registry entries are contractual:

* `ScopeId { name, semver }`
* `ScopeKind`: `Witness | Authority | Effect`
* `Capabilities { reads, writes }`
* `Emits`: witness schema ids
* `Consumes`: witness schema ids
* `Phase`: `P0..P4`
* `Determinism`: `Deterministic | TimeBound | Oracle`
* `IrreversibilityGrade`: `reversible`, `costly`, `external`

Registration equals policy publication.

## Scope schema & evolution

`scope:schema` guarantees witness shapes. Meta-scope enforces:

* backward-compatible changes unless major version bump,
* migration operators when shapes evolve,
* old schemas remain readable for audit.

## Scope IR

Compiler’s internal map:

* registry fields above,
* typed dependency edges,
* rule constraints (allowed surfaces + phases),
* canonical contract hash.

Semantic deadlock detection runs over Scope IR.

## `.scope` files

Declarative companion to `.adm`:

* declare contract (inputs, outputs, witnesses, phase),
* declare typed dependencies,
* declare determinism/oracle profile,
* declare irreversibility grade + erasure-cost behavior.

Store under `scopes/<name>/<version>.scope` or similar.

## `.adm` imports

Programs import scope contracts:

* top-level imports list required scope IDs + schema versions,
* scoped blocks specify which authority/witness is active.

Compiler errors when registry requirements cannot be met.

## Invariant

No scope may require a verdict to produce the witness that is required to obtain that verdict.
