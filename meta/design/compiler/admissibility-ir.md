# Admissibility IR (kernel + witness format)

This document specifies a **minimal admissibility IR** for implementing `compilerIdea.md`.

It is a design target for the executable system: a “compiler” whose output is **admissibility and witnesses**, not action.

## Epistemic constraints (from the vault)

This IR is constrained by the vault’s reasoning framework (`epistemics/vault/index.md`, `epistemics/vault/diagnostics/Prompting Guide.md`, `epistemics/vault/diagnostics/Failure Modes of the Irreversibility Lens.md`):

- **Concept-locked primitives**: meanings come from `/concepts`. The IR must not introduce new primitives at the ontology layer; it can only name structures already definable in concept terms.
- **Non-prescriptive diagnostics**: the language is about **conditions observed** and admissibility, not recommendations (Failure Mode #3).
- **Anti-reification**: bookkeeping terms (e.g. `[[constraint-load]]`) must not silently become “the thing we optimize” (Failure Mode #1).
- **Witness-first**: failures are not scolded; they are witnessed as minimal structural incompatibilities.
- **Self-auditing**: the language and ruleset must be auditable using the same admissibility machinery (Failure Mode #10).

Concept alignment (semantic anchors):

- [[difference]] — a detectable distinction between states
- [[transformation-space]] — the set of all possible state changes
- [[persistence]] — state that survives across boundaries or time
- [[persistent-difference]] — differences that cannot be undone
- [[erasure-cost]] — resources consumed to eliminate a difference
- [[displacement]] — prior state forced out by new state
- [[residual]] — traces left by transformation
- [[constraint]] — rules reducing the feasible set
- [[feasible-set]] — transformations still available after constraints
- [[admissibility]] — the subset of feasible moves permitted by rules

(Full definitions: irrev-vault/concepts/)

## Design stance

### Surface syntax (v0)

Use `.adm` as the primary front-end for the new compiler, with a **temporary** TOML-to-IR lowering path for parity:

- Policy-as-data lives in `epistemics/vault/meta/rulesets/*.toml` during the transition.
- The current AST is already `RulesetDef`/`RuleDef` (`execution/irrev/irrev/constraints/schema.py`).
- `.adm` is the forward-facing syntax; TOML is a compatibility surface only.

Erasure note (v0):

- `erase` is a builtin transform concept; it does not require a `transform` declaration in `.adm`.

### Determinism + monotonicity (semantic contract)

- Evaluation is deterministic.
- Facts/commits are **monotone** within a scope: you can add facts, but not retract them.
- Adding constraints can only reduce admissibility.
- “Exceptions” are allowed only as **explicit, typed overrides** that emit their own proof/witness facts (never silent).

### Default deny erasure (semantic boundary)

Default: **no erasures are allowed**.

An erasure becomes admissible only when:

1. an explicit permission exists (`AllowErase(diff)`), and
2. the erasure has an accounting rule (`ErasureRule(diff, …)`), so displacement is legible.

This is not a safety feature; it is the topology that makes “no rollback assumptions” structurally enforceable.

## Namespaces, identifiers, and spans

### Identifier namespaces (reserved concepts)

Identifiers are separated by namespace to avoid semantic collisions:

- `difference:*` — named differences
- `transform:*` — named transformations
- `bucket:*` — displacement sinks (cost routing totals)
- `constraint:*` — named constraints (optional IDs)
- `scope:*` — scope identifiers (evaluation domains)
- `module:*` — module identifiers (importable rule modules)

Surface syntax may allow short names, but IR must carry fully-qualified names.

### Spans (compiler ergonomics)

Every IR node carries a source `Span` for witness attribution:

```
Span = { file: str, start: int, end: int }  // byte offsets (or line/col via a mapping table)
```

For vault Markdown sources, line-based spans are acceptable as an intermediate representation:

```
Span = { file: str, line: int, col: int }
```

Winners are spans that can survive refactors and are stable under tooling (byte offsets + file hash is ideal).

## Kernel IR: data model

The kernel is intentionally small and brutal. Everything (including legacy checks) must lower into it.

### Core types

```
ModuleId = "module:<name>@<major>"     // version pin (v0 uses ruleset_id+version)
ScopeId  = "scope:<name>"              // scope boundary (see Scope below)

SymbolRef = { ns: "difference|transform|bucket|constraint|scope|module", name: str }

UnitRef = str                           // e.g. "kg", "days", "risk_points"

Quantity = { value: number, unit: UnitRef }
```

Notes on quantities:

- Numeric comparisons (`>`, `<`, `>=`, …) require compatible units.
- If a unit is absent, the value is treated as an opaque scalar usable only for equality (avoid fake measurement).
- This preserves the vault’s warning: many bookkeeping concepts have “no privileged unit”.

### Program container

```
Program = {
  module: ModuleId,
  scope: ScopeId,
  statements: [Stmt],
}
```

Scope and module exist to prevent “global soup”. Rule meaning is always relative to scope + transformation space.

### Statements (8 primitives)

1) Declare a difference

```
DeclareDifference {
  diff: SymbolRef(ns="difference"),
  unit?: UnitRef,
  span: Span,
}
```

2) Declare a transform

```
DeclareTransform {
  transform: SymbolRef(ns="transform"),
  span: Span,
}
```

3) Persistence claim

```
Persist {
  diff: SymbolRef(ns="difference"),
  under: [SymbolRef(ns="transform")],
  span: Span,
}
```

4) Erasure accounting rule (cost routing)

```
ErasureRule {
  diff: SymbolRef(ns="difference"),
  cost: Quantity,
  displaced_to: SymbolRef(ns="bucket"),
  span: Span,
}
```

5) Explicit permission boundary (allow/deny erase)

```
AllowErase { diff: SymbolRef(ns="difference"), span: Span }
DenyErase  { diff: SymbolRef(ns="difference"), span: Span }
```

6) Constraint (small boolean algebra only)

```
Constraint {
  id?: SymbolRef(ns="constraint"),
  expr: BoolExpr,
  span: Span,
}
```

7) Commit (facts about current state)

```
Commit {
  diff: SymbolRef(ns="difference"),
  value: Quantity | str | bool,
  span: Span,
}
```

8) Query

```
Query = Admissible | Witness | Delta | Lint { fail_on: Error|Warning|Info }

QueryStmt { query: Query, span: Span }
```

### Boolean expressions (bounded)

To keep witnesses crisp and evaluation decidable, boolean algebra is deliberately limited:

```
BoolExpr =
  | And([BoolExpr])
  | Or([BoolExpr])
  | Not(BoolExpr)
  | Pred(Predicate)

Predicate =
  | EraseAllowed(diff: SymbolRef)
  | DisplacedTotal(bucket: SymbolRef, op: CmpOp, value: Quantity)
  | HasCommit(diff: SymbolRef)
  | CommitEquals(diff: SymbolRef, value: Quantity|str|bool)
  | CommitCmp(diff: SymbolRef, op: CmpOp, value: Quantity)   // unit-checked
  | ProviderPredicate(scope_id: ScopeId, name: str, params: json)

CmpOp = "==" | "!=" | ">" | ">=" | "<" | "<="
```

This is a minimal starter set.

### Extension predicate contract (implemented)

`ProviderPredicate` is the generic extension point. It replaces hardcoded
provider-specific predicates and is dispatched through the provider registry:

- `scope_id` selects the provider instance.
- `name` selects the provider-declared predicate.
- `params` is provider-specific JSON input.

Kernel witness obligations:

- The evaluator must always emit `Fact::PredicateEvaluated` for every predicate.
- Provider findings returned by predicate evaluation are recorded as
  `Fact::LintFinding`.
- If the registry is missing or `scope_id` is unregistered, evaluation fails
  with a structured error.

This keeps extension predicates witness-visible without adding custom IR
variants per provider.

### Kernel extension: scope boundary changes

In addition to the core primitives above, code currently includes:

```
ScopeChange { from: ScopeId, to: ScopeId, mode: ScopeMode, span: Span }
```

This statement models boundary shifts directly in IR so witness emission can
attribute boundary effects to explicit source spans.

## Semantics (what evaluation means)

Evaluation occurs in a scope with a fixed program:

1. Collect declarations (`Declare*`) into an environment.
2. Collect permissions. Apply **default deny**: for any difference not explicitly allowed, `EraseAllowed(diff)=false`.
3. Collect erasure rules. If a diff is allowed to be erased but has no erasure rule, that is an admissibility failure (unaccounted erasure).
4. Compute displacement totals:

   - If `EraseAllowed(diff)` is true, add `ErasureRule(diff).cost` to `displaced_to` bucket total.
   - (Future extension) Multiple erasure actions can be modeled explicitly; v0 can treat “allowed erasures” as the potential cost surface.

5. Apply all `Constraint(expr)` statements. If any constraint evaluates true (meaning “inadmissible_if …”), verdict becomes inadmissible.

`Admissible` vs `Inadmissible` is always about whether the proposed commitments lie inside the current `[[feasible-set]]` under declared constraints.

## Witness / proof object (stable output schema)

Witness is the physical object that makes disputes legible. It is treated like an artifact format.

For v0, witness **minimization is a non-goal**; prioritize determinism and completeness.

### Witness schema (JSON-level)

```
Witness = {
  verdict: "admissible" | "inadmissible",
  program: {
    module: ModuleId,
    scope: ScopeId,
    ruleset_id?: str,
    ruleset_version?: int,
    content_id?: str,               // hash of the surface source (TOML) if available
    program_hash?: str,             // hash of normalized IR
    snapshot_hash?: str,            // hash of vault snapshot input
    ruleset_hash?: str,             // hash of TOML ruleset if lowered
  },
  reason: str,                       // short, non-prescriptive summary
  facts: [Fact],                     // minimal witness set (best-effort minimization)
  displacement_trace: {
    mode: "potential" | "actual",
    totals: [{ bucket: SymbolRef, total: Quantity }],
    contributions: [{ diff: SymbolRef, bucket: SymbolRef, cost: Quantity, rule_span: Span }],
  },
}

Fact = one of:
  - { type: "constraint_triggered", constraint_id?: SymbolRef, span: Span }
  - { type: "permission_used", kind: "allow|deny", diff: SymbolRef, span: Span }
  - { type: "erasure_rule_used", diff: SymbolRef, bucket: SymbolRef, cost: Quantity, span: Span }
  - { type: "commit_used", diff: SymbolRef, value: Quantity|str|bool, span: Span }
  - { type: "predicate_evaluated", predicate: str, result: bool, span: Span }
```

### Relationship to the artifact ledger

The repo already has a ledger event spine (`artifact.jsonl`) and structured constraint events (`constraint.evaluated`, `invariant.checked` in `execution/irrev/irrev/artifact/events.py`).

The witness/proof object can be stored as:

- a new artifact type (e.g. `proof` or `witness`), or
- a `lint_report` artifact with a stable `Witness` payload.

Either way, the key is: **store the full witness payload as content**, and reference it via `artifact_id` so downstream tooling can be deterministic.

## Witness encoding profile (v1)

Canonical encoding is part of artifact semantics for hashing and ledger identity.

- **Identity encoding:** CBOR with RFC 8949 canonical encoding rules.
- **Projection encoding:** JSON for review/debugging (non-authoritative).
- **Content hash:** computed over canonical CBOR bytes only.

Numeric policy (v0):

- Prefer integer or fixed-point quantities.
- If floats appear, they must be finite; NaN/inf are forbidden.
- Encoders must normalize `-0.0` to `0.0` in the canonical stream.

## Lowering: TOML rulesets → kernel IR (compat path)

This is a compatibility path for parity with the existing rulesets.

### Current starting point

- TOML parses into `RulesetDef`/`RuleDef` (`execution/irrev/irrev/constraints/schema.py`).
- Many rules use `legacy_lint_rule`, which calls procedural checks in `execution/irrev/irrev/vault/rules.py`.

### Target: rules-as-commitments

Introduce TOML sections (or a parallel TOML format) that lower directly to kernel statements:

- `differences` → `DeclareDifference`
- `transforms` → `DeclareTransform`
- `persistence` → `Persist`
- `erasure_rules` → `ErasureRule`
- `permissions` → `AllowErase` / `DenyErase`
- `constraints` → `Constraint(expr)`
- `commits` (optional) → `Commit`
- `query` → `QueryStmt`

Legacy lint rules can be wrapped as a temporary lowering that emits `Commit` and `Constraint` nodes (rather than directly emitting a `LintResult`), so the witness pipeline is exercised even before all rules are rewritten.

## Implementation mapping (current code touchpoints)

This document is a spec, but it is grounded in existing modules:

- Frontend (vault loader): `execution/irrev/irrev/vault/loader.py`, `parser.py`, `graph.py`
- Ruleset AST: `execution/irrev/irrev/constraints/schema.py`, `load.py`
- Constraint engine: `execution/irrev/irrev/constraints/engine.py`, `predicates.py`
- Ledger spine: `execution/irrev/irrev/artifact/events.py`, `ledger.py`
- Harness validation hook (already emits constraint events): `execution/irrev/irrev/harness/harness.py::_validate_with_constraints`

The missing piece is an explicit IR module plus witness artifact emission; this doc defines the target shapes.

## Worked example (toy)

Surface (language-neutral):

```
DeclareDifference difference:crew_fatigue unit "risk_points"
DeclareBucket bucket:safety_risk
ErasureRule crew_fatigue -> cost 8 risk_points displaced_to safety_risk
DenyErase crew_fatigue                       // default deny explicit
Constraint inadmissible_if DisplacedTotal(safety_risk) > 3 risk_points
Query Admissible
```

If later someone adds `AllowErase(crew_fatigue)` without adjusting thresholds, the witness should show:

- the permission span
- the erasure rule span
- the displacement contribution
- the constraint span

…with no advice, no blame, and no claims about what should be done—only what is structurally inadmissible.
