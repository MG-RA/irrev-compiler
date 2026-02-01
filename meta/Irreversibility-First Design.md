---
role: meta
type: design-procedure
canonical: true
facets:
  - governance
  - protocols
---

# Irreversibility-First Design

## Purpose

Define a repeatable procedure for designing and extending systems under irreversibility: pay cognitive cost early (scope + primitives) to reduce downstream drift, rework, and hidden commitments.

This is not a productivity heuristic. It is a governance procedure: it specifies what counts as "enough foundation" before higher-level work proceeds.

## Core Move (Design As Cost Declaration)

Treat design as an irreversible act:

- executing implementation before clarifying scope boundaries is an irreversible commitment
- ambiguity compounds; early foundations amortize cost across many futures

## Procedure (v0)

Given a goal `G`:

1. Identify implied scopes `S = implied_scopes(G)`.
2. For each scope `s` in `S`:
   - enumerate primitives(s)
   - classify primitives as foundational vs derived
   - estimate irreversibility amplification (what breaks if wrong)
3. Order scope work bottom-up by:
   - dependency depth (lower layers first)
   - irreversibility amplification (highest amplification first)
   - cross-scope reuse (highest reuse first)
4. Formalize foundations (snapshot + predicates + witness rules) before adding mechanisms or higher-level packs.
5. Stop when marginal clarity gain < marginal cost, and record the stopping rationale.

## Output Artifacts (evidence of doing the procedure)

Minimum evidence per scope that is treated as "foundation started":

- boundary statement (what is in/out)
- snapshot schema or data model (deterministic, hashable)
- predicate family surface (prefer one parameterized family)
- witness evidence shape (what findings/facts exist, sort order)
- at least one golden fixture proving determinism (same input -> same witness hash)

## Why This Works

This procedure shifts cost from late-stage failure modes:

- reinterpretation ("what did we mean?")
- re-architecture ("we built on sand")
- social negotiation ("who decided this?")

...into early-stage, checkable foundations:

- scope boundaries
- primitives and invariants
- stable evidence objects (witnesses)

## Notes

- "Core" grows only when the change enables multiple independent scopes, with explicit versioning and golden updates.
- Prefer expanding capability by adding scopes/packs over adding ad-hoc features.

