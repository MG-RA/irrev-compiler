1) Standard library foundation pack

You want a small set of scopes that make everything else composable:

✅ hash.content@0 (done)

✅ meta.scope@0 (done)

Next:

encode.canonical@0 (make canonicalization explicit)

calc.pure@0 (tiny, total ops to write real checks)

select.path@0 (optional: extract fields deterministically)

diff.struct@0 (optional: structural diffs as evidence)


Yep—`calc.pure@0` is the right “next brick.” And your two optional follow-ons are basically **leverage tools**: they don’t create truth, they make truth *cheap to demonstrate*.

### `select.path@0` — what it’s for (and when it’s not worth it)

**Usefulness:** it gives you a *deterministic projection operator*:

> take a structured value and extract a sub-value by an agreed path syntax, with agreed failure modes.

That sounds small, but it’s the difference between:

* every scope re-inventing “how do I pick `foo.bar[3].baz`?” (and disagreeing subtly), vs
* a single canonical way to *name* and *extract* parts of an artifact.

**Where it pays off hard**

1. **Witnesses that need to reference a part of another witness/artifact**

   * e.g. “this lint is about `manifest.dependencies[‘serde’]`”
   * You want that pointer to be stable and machine-checkable.

2. **Proof packs / diagnostics**

   * A proof wants to say: “Here is the exact field that violates the rule.”
   * The selector path becomes a *coordinate system* for evidence.

3. **Cross-scope composition**

   * A rule in one scope can point into artifacts owned by another scope without importing their entire schema logic.

**Key design choice:** path semantics must be *boring and exact*:

* allowed segments (object key, array index)
* escaping rules for weird keys
* canonical representation (no multiple spellings for same path)
* error behavior (missing key = error vs null vs “no match”)
* output determinism (single value vs set of matches; I recommend single-value only for v0)

**When it’s not worth it**

* If your checks are always schema-native and never need “pointing,” you can postpone it.
* But if you’re building a diagnostic system (you are), this becomes the shared “pointer language.”

**My take:** `select.path@0` is optional only in the sense that you can postpone it. Architecturally, it tends to become inevitable once you start emitting rich witnesses.

---

### `diff.struct@0` — what it’s for (and why it’s dangerously powerful)

**Usefulness:** it gives you a *standard evidence generator*:

> given two structured values, produce a deterministic, canonical list of differences.

This matters because a lot of admissibility disputes are not “is it different?” but:

> *how* is it different, and can we prove the delta is only in allowed places?

If you have a deterministic structural diff, you can do checks like:

* “Registry changed only by adding this scope entry”
* “Wire format lock failed: show exact byte/field differences”
* “This witness is identical except `timestamp` field” (which might be forbidden)
* “This refactor is semantics-preserving under allowed rewrite rules” (later)

**Where it pays off hard**

1. **Governance & review**

   * Diffs become *portable evidence*.
   * “Here’s the exact delta” is how you prevent social arguments.

2. **Snapshot drift detection**

   * Compare two snapshots and emit a witness that explains drift precisely.

3. **Minimal-change proofs**

   * You can assert constraints like “only additive changes allowed.”

**The danger:** diff semantics can explode if you let it.
You want v0 to be intentionally limited, e.g.:

* operate on your supported JSON subset (same as encode.canonical)
* output as a list of operations like:

  * `add(path, value)`
  * `remove(path)`
  * `replace(path, old, new)`
* deterministic ordering of diff ops
* no “smart” heuristics (like moved blocks) in v0

Also: **map key ordering + canonicalization matters** for diff stability. If encode canonical is your ground truth ordering, diff should reuse the same ordering so the same pair always yields the same diff.

**My take:** `diff.struct@0` is *high leverage* once you start doing governance/registry/snapshot comparisons. It’s less “needed to compute verdicts” and more “needed to explain verdicts with receipts.”

---

### How they relate to `calc.pure@0`

Think of the trilogy:

* `calc.pure@0` = **compute** (total, tiny, deterministic ops)
* `select.path@0` = **address** (point to the part you mean)
* `diff.struct@0` = **explain change** (produce structured evidence)

If your compiler is going to be persuasive to skeptics (or future you), you want “compute + address + explain.” Otherwise you get verdicts that feel like oracles.

