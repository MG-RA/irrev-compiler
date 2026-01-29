# Hello World (scope widening)

Status date: 2026-01-29

This note describes the canonical **Hello World** for the admissibility compiler. The
goal is not to print text, it is to make the smallest irreversible boundary visible.

## Concept

> **Hello World = take something local and attempt to make it global.**

The simplest irreversible act is: “I used to make this decision here; now I want it to
apply everywhere.” The system should refuse that widening until boundary loss is
accounted. That refusal is evidence, not advice.

## Minimal `.adm` example (no accounting)

```adm
module demo@1
depends [irrev_std@1]
scope local

scope_change local -> global widen

query admissible
```

Outcomes:

- Verdict: **inadmissible**
- Witness facts include:
  - `scope_change_used` (local → global)
  - `unaccounted_boundary_change`
- Displacement trace: empty (no boundary-loss routing)
- Point: widening without declaring loss is refused with evidence.

## Hello World with accounting

```adm
module demo@1
depends [irrev_std@1]
scope local

scope_change local -> global widen

bucket boundary_loss
allow_scope_change local -> global
scope_change_rule local -> global cost 1 "unit" -> boundary_loss

query admissible
```

Outcomes:

- Verdict: **admissible**
- Witness facts:
  - `scope_change_used`
  - (depending on implementation) `permission_used`, `erasure_rule_used`
- Displacement trace:
  - Contains a boundary-loss contribution routed to `bucket:boundary_loss`
- Point: the same boundary crossing becomes admissible once accounting routes the loss.

## Why it matters

- Engineers see “blast radius” (local → global).
- Governance sees “jurisdictional expansion”.
- Crypto folks see “finality enforced by hash-bound witness”.
- Language folks see “speech acts” (declare, record, refuse).

The Hello World demonstrates:

1. Permission alone is insufficient.
2. Loss must be declared before any global change.
3. Refusal happens before action and produces a witness.

## Non-goals

- No toy arithmetic.
- No domain-specific metaphors.
- No simulated “crew fatigue”.
- Just the boundary; nothing else complicates the story.
