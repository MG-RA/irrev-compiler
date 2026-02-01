---
role: meta
type: scope-wiki
canonical: true
facets:
  - governance
  - protocols
---

# Scope Wiki

## Purpose

Define the concept of a "Wikipedia of scopes": a public, structured atlas of admissibility where entries describe boundaries, admissible moves, failure modes, and composition rules.

This is not a wiki of topics. It is a wiki of constraint patterns.

## Core Idea

Each entry is an epistemic object of the form:

- what boundary exists here
- what it admits
- what it forbids
- how it fails
- how it composes

Prose is secondary to structure. Disagreement is allowed, but must be explicit.

## Pattern As First-Class Dependency

The central move is to treat patterns as things scopes can depend on:

- `depends_on pattern:canonicalization@1`
- `uses pattern:bridge@2`
- `violates pattern:closure@1` (as a check result, not a claim)

This turns patterns from advice into structural contracts.

## `scope:pattern` (pattern entries as governed artifacts)

Define a scope dedicated to validating pattern descriptions:

- required fields
- admissible structure for dependencies
- failure modes (missing fields, circular deps, ungrounded claims)

### Suggested fields for a pattern entry (v0)

- `pattern_id` (e.g., `pattern:canonicalization@1`)
- `type` (foundation, bridge, closure, conservation, attestation, etc.)
- `intent` (what failure mode it addresses)
- `boundary` (what it constrains)
- `admissible_moves`
- `failure_modes`
- `known_instances` (named instantiations; not proofs)
- `dependencies` (other patterns and foundational scopes)
- `anti_patterns` (common violations and their failure signatures)

## Pattern Dependency Graph

Patterns can depend on other patterns. The resulting dependency graph is a diagnostic object:

- cycles are suspicious (require explicit explanation)
- deep dependency chains signal foundational importance

This enables static analysis of design constraints.

## Why this differs from a topic encyclopedia

Topic encyclopedias tend to accumulate narrative and social authority. A scope wiki aims for:

- explicit boundaries
- explicit failure modes
- explicit dependencies
- witnesses for checkable claims (when available)

The target is not crowdsourced truth. The target is crowdsourced constraint mapping.

## Minimal v0 shape

To avoid philosophy soup, v0 can be intentionally small:

1. A schema for pattern entries (machine-readable)
2. A starter set of patterns:
   - foundation
   - canonicalization
   - closure
   - bridge
   - conservation
   - attestation
3. A linter that checks:
   - required fields present
   - pattern dependency cycles
   - schema id/version discipline
4. A publishable pack/repo that is browsable and machine-readable

