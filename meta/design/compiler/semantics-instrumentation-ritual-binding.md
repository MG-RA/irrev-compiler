# Semantics, Instrumentation, Ritual Binding

This note fixes a minimal three-layer model and keeps the layers separate. Each
layer has one job and does not reach into the others.

## Layer 1: Semantics (.adm modules)

Semantics defines the admissibility context:

- which differences exist
- which costs exist and how they route
- which boundaries matter
- which constraints are active

Semantics is declarative and static. It answers:

> If the world looks like X, is that admissible?

Semantics does not observe reality and does not act.

## Layer 2: Instrumentation (observation → facts)

Instrumentation turns reality into facts without evaluation.

Examples:

- count hours in a log
- count prescriptive claims in a document
- measure a git diff size
- count scope-change events

Output is a facts bundle (commit-style facts). Example facts:

- commit difference:hours_committed = 52 "hours"
- commit difference:prescriptive_claims = 14
- commit difference:scope_widen_events = 1

Instrumentation does not judge admissibility. It only reports.

## Layer 3: Ritual binding (check / declare-cost / execute)

Ritual binding is the point where action requires permission.

This is where:

- `check` evaluates admissibility
- `declare-cost` binds canonical witness bytes to a cost declaration
- `execute` records that the action occurred

Ritual binding is the only layer that touches action. It is a checkpoint, not a
policy engine.

## Separation invariant

These layers do not touch:

- Semantics never reads the world.
- Instrumentation never decides admissibility.
- Ritual binding never invents facts or rules.

This separation keeps governance non-prescriptive and witnessable, and keeps
hash identity stable for artifacts.

## Links

- `meta/design/compiler/compiler-rs-plan.md`
- `meta/design/compiler/cost-declaration.md`
- `meta/design/compiler/vault-snapshot-schema-v0.md`
