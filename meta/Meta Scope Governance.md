---
role: support
type: meta-scope
canonical: true
facets:
  - governance
  - protocols
---

# Meta-Scope Governance

## Purpose

Define the meta-scope—the “scope of scopes”—that governs how the compiler, runtime, and future scopes can declare contracts, obey dependency discipline, and enforce irreversibility accounting without blowing up core.

This document lives in the compiler meta directory (`irrev-compiler/meta`).

## Three layers of meta constraint

1. **Compiler admissibility**
   * only the compiler issues admissibility verdicts; other subsystems emit findings/evidence.
   * determinism guarantee: identical inputs → identical IR + witness.
   * replay guarantee: any effect can be reproduced from recorded inputs (plan + snapshots).
   * self-audit: compiler must expose which invariant rejected a request without prescribing a fix.

2. **Scope admissibility**
   * every scope is a contract: declares what it can observe, what effects it can produce, what witnesses it emits, and which failure modes are acceptable.
   * meta-scope ensures those declarations exist and are auditable via PatternEvidence facts (see `Pattern Evidence Pipeline`).

3. **Scope registry + versioning**
   * scopes have stable identities (name + semantic version).
   * compatibility rules are explicit (pack expectations, required schema versions).
   * migration/erasure costs are accounted for when retiring scopes.

## Scope decomposition patterns (meta-level)

A) Interface vs Implementation

* Interface: contract (inputs, outputs, witness schema, determinism).
* Implementation: plumbing (git/db/fs/clock).

Meta-scope reasons only about interfaces + proofs.

B) Read/Write split

Declare paired scopes when possible:

* `file.observe` vs `file.mutate`
* `db.observe` vs `db.migrate`
* `git.observe` vs `git.commit`

Read-only “observe” scopes produce evidence with zero side-effects; “write” scopes admit irreversibility and carry extra guard fields.

C) Evidence vs Authority

* Evidence scopes produce evidence artifacts (hashes, diffs, timestamps).
* Authority scopes issue admissibility verdicts.

Keep roles distinct even if both live in Rust; evidence ≠ verdict.

D) Stratification by irreversibility

Low → medium → high irreversibility determines gate strength (read-only vs migration vs cross-system effects).

Meta-scope enforces stronger ceremonies as irreversibility rises.

## Scope dependency discipline

Explicit, typed, acyclic dependencies:

* Good: `git` depends on `file.observe`, `db` depends on `time+hash`.
* Bad: mutual dependencies without phased evaluation (`hash` depends on `db` and vice versa).

Patterns:

1. **Layered DAG** (foundation → derived → high-effect)
2. **Two-phase evaluation**: witnesses (phase A) → admissibility (B) → effects (C) → ledger (D)

## Meta-scope linting

Once scopes declare contracts, invariants can enforce:

* verdict vs write separation
* nondeterminism declarations
* erasure-cost bookkeeping for destructive scopes
* registry entry + witness schema requirement for any new scope

This keeps growth disciplined.

## Next concrete artifact

Define a `Scope IR` that all scopes compile to:

* `ScopeId@version`
* `capabilities { reads, writes }`
* `witness_types`
* `dependencies { scope_id, kind }`
* `determinism_grade`
* `irreversibility_grade`
* `allowed_surfaces`

Meta-scope validates Scope IR, not the raw implementation, enabling the compiler to remain the judge
