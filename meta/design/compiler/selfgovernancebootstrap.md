# Self-Governance Bootstrap

Invariants "enter" the moment an invariant stops being a label on rules and becomes a
**semantic gate** that the rest of the system must pass through. In practice, you do
not "add irreversibility later"; you bootstrap it first, because it defines what
counts as an admissible program at all.

This note is the bootstrap framing: where invariants live, what to implement first,
and how to make the rule enforceable (witnessable + hashable).

---

## 1) Where invariants live in the architecture

You'll have three layers, each with a different job:

### A) Kernel semantics (Phase 3)

This is where irreversibility is structural:

- default deny erasure
- allow_erase => erasure_rule
- displacement trace
- deterministic witnesses + canonical bytes (RFC 8949 CBOR + SHA256)

This is irreversibility as physics.

### B) Meta ruleset (invariants-as-programs)

This is where "invariants" become admissibility programs about programs:

- "all statements must have complete spans" (attribution)
- "no unpinned module deps" (governance)
- "no cross-scope imports without explicit module boundary" (decomposition)
- "no allow_erase without accounting + routing" (irreversibility)

Important v0 detail: until the DSL can introspect programs-as-data, the "meta ruleset"
is implemented as compiler-native meta checks that emit normal witnesses. Later, those
checks can be expressed as `.adm` once reflection exists.

This is invariants as law.

### C) CI / workflow gates

This is where invariants become enforced:

- you cannot merge without an admissible witness under meta invariants

This is invariants as jurisdiction.

The key: the first time you "code an invariant", it should land in B, but it must be
supported by A (deterministic evaluation + witness discipline + canonical bytes).

---

## 2) When does the irreversibility invariant enter?

It enters at two moments:

### Moment 1: already (kernel)

If your evaluator enforces default deny and accounting, irreversibility is already
present as semantics. That's why Phase 3 is pivotal.

### Moment 2: when you make it govern modules and rulesets

That's the "vault-like" step: the system can lint its own lens.

This happens when you run meta invariants that check things like:

- "any module that introduces AllowErase must include ErasureRule"
- "no rule/module may claim to erase without routing"
- "no witness may be emitted without displacement trace mode declared"
- "no cost declaration without canonical bytes + hash verification"

That's the first time irreversibility becomes a governor of future growth, not just a
rule inside evaluation.

---

## 3) The first invariant rule to code (the real bootstrap)

If you want one rule that everything else can safely depend on, code this one first:

> Attribution invariant (Span completeness)
> "No statement is admissible unless it has a complete Span."

Make "complete" mechanically checkable (v0, `.adm`-sourced statements):

- `span.file` is non-empty
- `span.line` is `Some`
- `span.col` is `Some`
- (recommended, not required in v0) `span.start` and `span.end` are `Some`

Why this first, even though irreversibility is the star?

Because invariants only work if violations are witnessable. Without spans, you cannot
reliably point to what caused the failure. So attribution is the power supply that
makes all other invariants enforceable.

In vault terms: without attribution, governance and irreversibility become moralizing.

Bootstrap sequence:

1. Attribution: spans everywhere
2. Irreversibility: default deny + routing required
3. Decomposition: scopes/modules prevent global soup
4. Governance: version pinning, meta ruleset auditable

This does not demote irreversibility. It ensures it can be enforced without ambiguity.

---

## 4) What "coding the invariant" looks like concretely

Create a meta module, like:

- `module:irrev_meta@1`

Conceptually, it evaluates programs-as-data. You can do this in two ways:

### Option A (fast): compiler-native meta checks

Implement a small set of meta checks in Rust first (hardcoded), emit witnesses.
Then later "lower" those checks into `.adm` once you add reflection.

Phase 4 integration (merge-gate-ready):

- `compiler declare-cost` runs meta checks on the target module(s) first.
- If meta checks fail, `declare-cost` refuses to emit `cost.declared`.
- If meta checks pass, `declare-cost` emits a witness artifact with canonical CBOR
  bytes + SHA256 hash, and records that as the byte-level commitment.

### Option B (pure): reflection in IR

Add a "program introspection snapshot" as commits, for example:

- `commit meta:has_span(statement_id)=true`
- `commit meta:allow_erase_count=...`

Then your `.adm` meta rules are just constraints over these commits.

v0 reality: Option A is faster and still consistent, as long as meta checks emit
witness facts with spans pointing into the source.

---

## 5) The first irreversibility invariant rule (after spans)

Once spans exist, the first irreversibility meta rule is:

> No Erasure Without Accounting
>
> If any module includes an `allow_erase` for a diff, it must include an `erasure_rule`
> for that diff, and the erasure_rule must route to a bucket.

You already enforce this in kernel semantics for evaluation. The meta invariant adds:

- it must be true for stdlib and meta modules too
- it must be true even if nobody queries displaced_total today

That is exactly "vault-like": the lens governs itself.

---

## 6) The "derived and depend like the vault" moment

That moment arrives when:

1. `irrev_meta@1` exists
2. CI runs meta checks and produces a canonical witness artifact (CBOR bytes + SHA256)
3. `compiler declare-cost` refuses to emit `cost.declared` unless the verifier rule holds:
   `sha256(canonical_cbor(witness_json)) == witness_sha256` (RFC 8949 canonical)
4. Merge is blocked unless a valid `cost.declared` exists (or override is explicit and witnessed)

At that point, any new module is born under invariants.

That's the vault pattern:

- constraints are upstream
- drift is expensive
- exceptions are audible

---

## 7) Minimal next action you can take

If you want the cleanest next increment:

1. Add a meta check pass that asserts span completeness and emits a witness
2. Run it on:
   - `irrev_std@1`
   - `irrev_meta@1` (itself)
3. Store the witness JSON projection + canonical CBOR hash as golden fixtures

Once that works, you've lit the first self-governing candle.

---

If you want, I can draft the first `irrev_meta@1` constraints (just 3-5) and the
exact witness facts you should expect when it fails, so you can implement it with
confidence and keep it non-prescriptive.

---

## Related

- `meta/design/compiler/semantics-instrumentation-ritual-binding.md`
