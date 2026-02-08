---
role: meta
type: terminology-boundary
canonical: true
audit_ref: compiler-docs-audit F-01, F-02, F-03, F-04
---

# Terminology Boundary Note

This note declares the structural status of terms used across compiler documentation. It prevents metaphor-to-infrastructure creep by making each term's role explicit.

## Classification rule

A term constrains nothing unless referenced by a protocol. Metaphors explain; operational concepts define interfaces; artifact types name outputs; scope roles name producers.

## Do not use (in canonical docs)

| Term | Canonical docs? | Tutorials? | Replacement |
| --- | --- | --- | --- |
| court | No | Yes (metaphor) | kernel authority, admissibility engine |
| witness scope | No | No | evidence scope |
| risky (as bare adjective) | No | No | specific risk characterization |
| structurally impossible | No | No | enforcement mechanism + bypass paths |

## Metaphor-only terms

**Court.** Working metaphor for the kernel's role as admissibility arbiter. In structural or protocol docs, use "kernel authority" or "admissibility engine." Reserve "court" for narrative, pedagogical, or historical contexts only.

The `engine_version` field on witness structs and the `engine-query/1`, `engine-function/1` schema IDs replace the former `court_version` / `court-*` naming.

## Operational concepts

**Ceremony.** A gated effectful operation that makes boundary crossing auditable. Components: plan artifact (intent), required witnesses (preconditions), approval mechanism (if high-irreversibility), execution gate (enforces plan-witness-execute sequence). Strength varies by irreversibility grade. See Scope Patterns 11 (Ceremony Pattern) for the vault-level pattern; see Architecture.md Known Non-Enforcements for current ceremony exceptions.

**Provider.** Compiler-meta term for extensibility interfaces that supply facts, predicates, or semantic evaluations to the admissibility engine. Providers are not vault primitives; they are specific to the compiler runtime architecture.

Known provider failure modes:

- Nondeterminism (provider returns different results for same inputs)
- Unverifiable output (no witness trail for provider claims)
- Hidden side effects (provider mutates state during evaluation)
- Unversioned interface drift (provider contract changes without schema bump)

**Pressure.** Diagnostic measurement across four lanes (structural, hygiene, semantic, quantitative). Pressure is a projection, not a truth oracle. See ineluctability-loop-v0.md for lane definitions and vault concept anchoring.

## Artifact types

| Artifact | Description |
| --- | --- |
| witness | Structured evidence bundle recording admissibility verdict |
| plan | Intent declaration artifact (plan-witness schema) |
| snapshot | Point-in-time state capture (vault-snapshot, git-snapshot) |
| bundle | Grouped input artifacts (program-bundle, facts-bundle) |

## Scope roles

| Role | Description |
| --- | --- |
| Evidence scope | Produces witness artifacts without issuing verdicts (hashes, diffs, timestamps) |
| Authority scope | Issues admissibility verdicts |
| Meta scope | Governs other scopes (registration, validation) |

"Evidence scope" replaces the former "witness scope" to avoid collision with the artifact type. See witness.md Term senses for the full disambiguation.
