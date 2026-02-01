---
role: meta
type: scope-primitives-and-algebras
canonical: true
facets:
  - governance
  - protocols
---

# Scope Primitives & Algebras

## Purpose

Make explicit what a “scope” *is* before it is implemented, so `scope:calc`, `scope:hash`, `scope:schema`, `scope:plan`, etc. feel like instances of one shape rather than special cases.

This is the missing bridge between the high-level system map ([Architecture](Architecture.md)) and the kernel/IR documents (e.g. [Admissibility IR](design/compiler/admissibility-ir.md)).

## Definition (what a scope is made of)

A scope is defined by four things:

1. **Primitives (atoms)**
   - The irreducible objects the scope can talk about.
   - Examples: bytes, hashes, units, schema IDs, plans, witnesses.

2. **Operations (legal transformations)**
   - The admissible moves over primitives: what can be constructed, checked, compared, normalized, composed.
   - “Algebra” here means: operations are *closed* over the primitives and have explicit composition/ordering rules.

3. **Witnesses (evidence schemas)**
   - The deterministic evidence objects the scope emits when it observes, checks, plans, or executes.
   - Witnesses are the unit of auditability: they are what other scopes depend on, and what the ledger can anchor.

4. **Laws (meta-constraints)**
   - The constraints that make the scope governable:
     - phase placement (P0 observation → P1 witness → P2 verdict → P3 effects → P4 accounting)
     - determinism grade (deterministic vs oracle/time-bound)
     - authority role (witness vs verdict vs effect)
     - dependency discipline (typed edges; no semantic deadlock)

Implementation details (Rust/Python/DB/RPC) are projections of this contract, not part of the definition.

## Domains vs scopes (ontology vs admissible access)

To keep the ontology clean and future-proof, separate:

- **Domain = semantic universe (meaning)**
- **Scope = admissible interface into that universe (power / access path)**

This answers two questions separately:

1. *What kind of thing is this?* (domain)
2. *How is the system allowed to touch it?* (scope)

### Naming rule

Prefer `domain.scope` names:

- `hash.content`, `hash.verify`, `hash.execution`
- `time.now`, `time.window.check`
- `registry.core`, `registry.query`, `registry.db`
- `file.observe`, `file.mutate`

Avoid baking implementations into names (`db.hash`, `scope.hash.db`, etc.). Implementations are substrates/projections; the contract is domain+scope.

Heuristic: **domains are nouns; scopes are verbs or modes** (sentence fragments read well: “hash content”, “file observe”, “registry query”).

### Foundational ≠ domain

“Foundational” is a **property of a scope**, not a domain.

- Domains can have both foundational and non-foundational scopes.
- **Foundational scopes** are the *boot set*: they can run (and emit witnesses) without requiring prior authority/verdicts from other scopes.

This is what makes foundational scope sets composable and what prevents “semantic deadlock” from being confused with “the domain depends on X”.

## Domains as DSLs (extensibility)

A domain is a semantic universe (meaning). A **domain DSL** is the surface syntax for stating things *in that universe*. The compiler’s job is to check whether those statements are **admissible**, potentially requiring witnesses from other domains/scopes.

This keeps “how users extend the system” clean:

- Add a **new domain DSL** to add meanings/judgments.
- Add a **new scope** to add admissible observation/effect paths (and witnesses about reality).

### What it means to “plug in a domain DSL”

A governable domain DSL plugin has three parts:

1. **Domain definition (semantics)**
   - vocabulary (symbols/types)
   - invariants (laws)
   - allowed judgment forms (what can be derived vs merely asserted)

2. **DSL frontend (syntax)**
   - parse text → AST
   - well-formedness checks (WF)
   - lower AST → Domain IR

3. **Checkers + witness rules (admissibility)**
   - how Domain IR claims are checked/validated
   - what witness schemas it emits
   - what external witness schemas it may require

If a plugin provides only syntax, it’s a serializer. If it provides semantics without witness discipline, it’s a belief generator.

### The “Domain IR” stabilizer

Each domain should have a typed, versioned **Domain IR** so the core can operate on IR rather than text:

`domain text → AST → DomainIR → admissibility check → witnesses (canonical encoding)`

This generalizes the existing `.adm` pipeline described in [Admissibility IR](design/compiler/admissibility-ir.md).

### Cross-domain composition rule

Domains should not import each other’s internals. They compose via **witness schemas**:

- “To admit judgment J, I require witness schemas W1/W2 from other domains/scopes.”
- The registry records these schema dependencies and the determinism/oracle profile so the system can refuse missing schemas, illegal cycles, or undeclared oracle usage.

Hard rule: **domains may not import authority; they may only import witnesses**. Authority stays in the admissibility kernel/governance layer.

## Why schemas, plans, and scopes converge

Decomposition usually yields a schema because the system has three equivalent views of the same structure:

- **Operational view:** scopes define what transformations are allowed (operations + laws).
- **Structural view:** schemas define what evidence of those transformations looks like (witness shapes).
- **Intentional view:** plans define intended compositions of transformations before effects (plan → witness → execute ceremony).

In other words:

- a **scope** defines *what can be done*,
- a **schema** defines *what proof of doing it looks like*,
- a **plan** defines *what is intended to be done next*.

This is the same object seen through different interfaces.

## Minimal checklist (when you say “we should add a scope”)

Before implementing anything, be able to answer:

- What are the primitives?
- What are the operations (and their composition/ordering rules)?
- What witnesses exist, and what are their schema IDs/versions?
- What are the laws: phase, determinism, authority role, dependencies?
- What are the declared boundaries and bridge ceremonies? (See [Boundary Events & DB Scope](Boundary%20Events%20%26%20DB%20Scope.md).)

If you can’t answer these, the scope isn’t defined yet; it’s a desire.

## Where this fits

Reading order insertion:

- For newcomers: [Architecture](Architecture.md) → this doc → [Irreversibility-First Design](Irreversibility-First%20Design.md)
- For implementers: [Compiler Progress Summary](compiler-progress-summary.md) → this doc → [Admissibility IR](design/compiler/admissibility-ir.md)

Related infrastructure documents:

- Registry/deadlock discipline: [Semantic Deadlock & Scope Registry](Semantic%20Deadlock%20%26%20Scope%20Registry.md), [Registry Scope Architecture](Registry%20Scope%20Architecture.md)
- Execution ceremony: [Compiler + Runtime Loop](Compiler%20Runtime%20Loop.md)
- Pattern enforcement approach: [Pattern Evidence Pipeline](Pattern%20Evidence%20Pipeline.md)
