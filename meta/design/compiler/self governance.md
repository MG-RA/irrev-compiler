## Threshold A: Proto self-governance (earliest possible)

This happens when the system can treat *its own rules and schemas* as inputs and emit witnesses about them.

Concretely, you need:

1. **A stable artifact type for rules**

* `.adm` modules (and later compiled `.admc` / IR) are artifacts with hashes.

2. **A meta-ruleset** that talks about admissibility artifacts
   Examples (structural, not prescriptive):

* “Any `allow_erase` must have a matching `erasure_rule`”
* “Any `inadmissible_if` must reference declared buckets/differences”
* “No floats in witness schema”
* “All statements must have spans”
* “Module IDs must be pinned (no unversioned depends)”

3. **A pipeline that runs the compiler on itself**

* compile the stdlib + rulesets + schemas
* emit a witness artifact about *that evaluation*

At this stage, governance exists as **auditable evidence**, but it doesn’t block changes yet.

You’ll feel it when you can ask:

> “Is the compiler admissible under its own invariants?”

and you get a structured witness back.

---

## Threshold B: Enforced self-governance (when it becomes code law)

This is when the witness becomes a **merge gate**.

The condition is simple:

> Any change to compiler/rulesets must produce a witness, and merging is inadmissible unless that witness is admissible (or explicitly overridden with an auditable override).

This requires:

* deterministic compilation (canonical bytes)
* stable witness schema
* CI integration that refuses merges without the required witness artifacts and ledger references (or a “pending witness” state)

The moment you wire that, governance isn’t a document anymore, it’s infrastructure.

---

## The “new code” moment you’re asking about

You asked: *“at one point can the self governance of the invariant applications as new code occur?”*

The answer:

### As soon as **Phase 3** exists (deterministic evaluator) and you have a **stdlib module**.

Because now you can express invariants **as admissibility programs** and evaluate them deterministically.

But it becomes meaningfully self-governing only when:

### You stop trusting humans to remember, and you make CI require witnesses.

So, timeline-wise in your plan:

* **After Phase 3**: you can run invariants on `.adm` rules/modules and emit witnesses.
* **After Phase 6**: you can ledger those witnesses as immutable facts tied to changesets.
* **After Phase 7**: you can enforce parity and replacement, making the Rust path authoritative.

The first “self-governing” behavior can start right after Phase 3. The first “self-governing enforcement” lands when you add the merge gate.

---

## Related

- `meta/design/compiler/semantics-instrumentation-ritual-binding.md`

## What does “invariants as new code” look like?

You’ll have a **meta module** in `.adm` (or a few), something like:

* `module:irrev_meta@1`

  * constraints about:

    * schema versions
    * default deny erasure
    * required spans
    * deterministic ordering requirements
    * banned constructs (floats, unscoped modules, etc.)

And then you compile-check:

* `irrev_meta@1` against:

  * `irrev_std@1`
  * all other modules
  * itself

That last part is the self-audit loop.

---

## The safe pattern: “Witness-first governance”

To avoid turning governance into brittle policing, do it in two steps:

1. **Warn-only phase**

* CI produces witness artifacts but doesn’t block merges.
* You collect real failure modes and tune the meta invariants.

2. **Block phase**

* Start blocking only on a small kernel:

  * canonical CBOR required for witness
  * spans required
  * allow_erase requires erasure_rule
  * no unpinned module depends

Then expand as confidence grows.

This mirrors your irreversibility stance: pay the cost up front, but don’t pretend omniscience.

---

## A crisp trigger condition you can adopt

You can say:

> Self-governance starts when the compiler produces a canonical witness artifact about changes to its own semantics, and that witness is required to accept those changes.

That’s the exact “new code law” moment.

---
