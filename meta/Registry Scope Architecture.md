---
role: support
type: scope-architecture
canonical: true
facets:
  - governance
  - protocols
---

# Registry Scope Architecture

## Purpose

Document the foundational `registry` scope (core vs projection), the `scope.{other scope}` composition pattern, and the domain/substrate/projection roles so the compiler meta layer keeps authority crisp without semantic deadlock.

## Registry as foundational scope

`registry` answers:

* what scopes exist (IDs + versions)
* what schemas they emit/consume
* what capabilities they claim (read/write, phase, determinism)
* what dependencies they declare (typed edges)
* what compatibility constraints apply

It is a **domain scope** that must boot independently of `db`.

## Two-part decomposition

1. `registry.core` (authoritative)
   * Boot sources: `.scope` files + observable inputs (`file.observe`, `hash.content`)
   * Outputs canonical `ScopeIR` and registry hash
   * Deterministic, offline, no DB dependency

2. `registry.db` (projection)
   * Input: `ScopeIR`
   * Provides indexes, graph traversals, and joins with ledger/artifacts
   * Rebuildable from `registry.core`; never the source of truth

Invariant: `registry.db` may be accelerated, but it must be deletable and rebuildable from `registry.core`.

## Scope composition pattern

Scopes fall into three roles:

* **Domain scopes:** contracts (`registry`, `ledger`, `vault_snapshot`, `artifact_store`)
* **Substrate scopes:** capabilities (`file.observe`, `hash.content`, `git.commit`, `db.migrate`, `time.now`)
* **Projection scopes:** composition (`registry.core`, `registry.db`, `ledger.git`, `vault_snapshot.hash`)

`scope.{other scope}` expresses interpreting a domain scope over a substrate. It’s the same contract with a different implementation layer.

## Naming guidance

Avoid exposing implementation in domain names. Prefer:

* `registry.core` (authority)
* `registry.query` (interface API)
* `registry.db` (optional acceleration)

`registry.query` is what `.adm` and compiler target; it can resolve to either backend at runtime, but verdicts cite witnesses from `registry.core`.

## Meta-insight

Your meta-scope is exactly this pattern:  
Domain = scope contract;  
Substrate = file/git/db/time/hash;  
Projection = ScopeIR + analysis.  
Treating it explicitly keeps the algebra consistent across layers.
