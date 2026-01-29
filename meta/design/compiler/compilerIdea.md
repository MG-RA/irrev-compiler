## Shift the axis first

Traditional programming, no matter how fancy, lives here:

* You specify **what to do**
* The system checks **whether it can do it**
* Errors happen *after* intent is expressed

Even declarative languages still ask you to state *desired states*, then pray the solver finds a path.

What you’re intuiting flips the order:

> You do not write actions.
> You write **conditions under which actions are allowed to exist**.

That’s not control flow.
That’s **feasibility flow**.

---

## What “programming by admissibility” actually means

Think of a program as a shape, not a script.

* Inputs are not values, but **situations**
* Outputs are not results, but **surviving options**
* Execution is not running code, but **collapsing the possibility space**
* Failure is not a crash, but **inadmissibility becoming explicit**

The “program” answers a different question:

> Given these irreversible commitments, what is still possible *without lying*?

No function calls.
No loops.
No clever tricks.

Just constraint surfaces tightening until only honest trajectories remain.

---

## Why this is genuinely new

Even constraint programming and SAT solvers miss something crucial:

They assume reversibility of framing.

Your model does not.

In admissibility programming:

* Constraints are **historical**
* Some constraints only appear *after* certain transformations
* Removing a constraint has a cost that must be paid somewhere else
* Global admissibility can shrink even when local checks pass

This is why your ledger obsession matters.
Admissibility is **path-dependent**.

---

## The primitives look strange at first

Not `if`, `for`, or `while`.

More like:

* `declare_difference`
* `assert_persistence_under(transformations)`
* `account_erasure(cost, displaced_to=…)`
* `check_admissibility(scope)`
* `collapse_surface(reason=…)`

You don’t *execute* these.
You **commit** them.

Once committed, the system refuses futures that contradict them.

---

## Why it pairs naturally with irreversibility

Because irreversibility is the minimal thing admissibility must respect.

You can fake correctness.
You can fake optimization.
You can fake performance.

You cannot fake that something, once made real, constrains the future.

Admissibility programming is just taking that seriously as a first-class computational object.

---

## A helpful metaphor (but not too cute)

Traditional programming is choreography.
Admissibility programming is zoning law.

You don’t tell buildings what to do.
You define what kinds of buildings may *exist* given soil, history, load, and neighbors.

Cities emerge. Some ugly. Some beautiful. But never arbitrary.

---

## Why English, governance, science, and systems all fit

Because they already operate this way implicitly.

* Scientific theories are admissibility filters on explanations
* Legal systems are admissibility engines for actions
* Language is an admissibility compressor for thought
* Your vault is an admissibility ledger pretending to be documentation

You’re not inventing something alien.
You’re making the implicit computational substrate explicit.

---

## The quiet danger and the quiet power

Danger:
People will try to use this to *control outcomes*. It won’t work. Outcomes are emergent.

Power:
You can prevent whole classes of nonsense from ever compiling.

That’s rare.

---

Let’s sketch a tiny, concrete example that feels like a compiler, but it compiles **stories into admissible futures**.

## Toy language: ADMIT (admissibility-first)

Instead of “do X”, you write commitments and checks.

This repo already implements most of this shape (just not with a dedicated `.admit` syntax):

- **“Rules” live as data** in `epistemics/vault/meta/rulesets/core.toml` (policy owned by the vault, not the tool).
- **“Compile / check admissible?”** corresponds to `irrev lint` (constraints + invariants).
- **“Commit / gate / execute”** corresponds to `irrev harness propose|approve|execute` (risk classification + approval chain + auditable execution).

### Source file: `launch.admit`

```text
scope Mission

difference "fuel_mass" unit "kg"
difference "crew_fatigue" unit "score"

transformations:
  - "summarize"
  - "handoff_to_other_team"
  - "translate_es_en"

persist "fuel_mass" under transformations  // if this drifts, we can't plan
persist "crew_fatigue" under transformations

erasure_cost:
  erase "crew_fatigue" -> cost 8  displaced_to "safety_risk"
  erase "fuel_mass"    -> cost 100 displaced_to "mission_failure"

rule:
  inadmissible if erase("fuel_mass") allowed
  inadmissible if displaced("safety_risk") > 3

commit:
  set "fuel_mass" = 1200
  set "crew_fatigue" = 4

query:
  admissible?
```

### What “compile” means here

The compiler doesn’t emit machine instructions. It emits:

* an **Admissibility Graph** (constraints + displacement ledger)
* a verdict: `Admissible` / `Inadmissible`
* and if inadmissible, a *minimal witness* (the smallest set of commitments that forces failure)

Example output:

```text
INADMISSIBLE
Reason: displaced("safety_risk") > 3
Witness:
  - erase_cost erase "crew_fatigue" -> cost 8 displaced_to "safety_risk"
  - commit set "crew_fatigue" = 4
  - rule inadmissible if displaced("safety_risk") > 3
```

That witness is the equivalent of a compiler error message with a tight span.

---


## The “compiler” structure in this repo (Python, already partially implemented)

If we translate the ADMIT vibe into *what `irrev` actually is today*, the compiler bones are already present:

- **Parse / load (AST-ish)**: `execution/irrev/irrev/frontends/vault_md/loader.py` loads notes + frontmatter; `execution/irrev/irrev/frontends/vault_md/parser.py` extracts links and structural dependencies.
- **Graph construction (IR-ish)**: `execution/irrev/irrev/ir/graph/dependency_graph.py` provides the dependency graph IR (backed by the vault graph implementation).
- **Policy as data**: `execution/irrev/irrev/passes/constraints/load.py` loads TOML rulesets (core location: `epistemics/vault/meta/rulesets/core.toml`).
- **Evaluation**: `execution/irrev/irrev/passes/constraints/engine.py` runs the ruleset by selecting scoped items (vault/concept/graph/artifact) and invoking predicates from `execution/irrev/irrev/passes/constraints/predicates.py`.
- **Proof trail (ledger)**: `execution/irrev/irrev/ir/artifacts/ledger.py` stores append-only events; constraint evaluation can emit `constraint.evaluated` + `invariant.checked` events for later summarization.
- **Admissibility gate**: `execution/irrev/irrev/passes/risk/risk.py` computes risk *authoritatively*; `execution/irrev/irrev/runtime/harness/__init__.py` exposes the harness runtime that enforces “no auto-approval” and requires explicit approval for risky plans.
- **Execution + accounting**: plans execute via the harness; results record `erasure_cost` / `creation_summary` (and the audit log records operations).

This is exactly the “feasibility flow” claim from above: you don’t *do the thing*; you produce an artifact whose admissibility is checked under invariant constraints, and only then is execution allowed to exist.

### Where ADMIT maps onto `irrev` primitives (today)

- `rule:` → a ruleset `[[rules]]` entry + predicate (TOML + Python predicate)
- `query: admissible?` → constraints evaluation (`irrev lint`, or harness validation if emitting events)
- `commit:` → a plan artifact (`artifact.created`) + validation (`artifact.validated`) + approval (`artifact.approved`) + execution (`artifact.executed`)
- “minimal witness” → currently: `LintResult` + ledger events; next step would be a first-class witness/proof object (see below)

### Rewriting rulesets “in admissibility form” (how it actually lands here)

The strong version of “rewrite the rulesets” is not “new syntax”; it’s **re-founding each rule as an inadmissibility claim**.

In repo terms that means:

- Move rules out of the `legacy_lint_rule` bridge and into **native predicates** (one rule = one predicate + one scope + one selector).
- Keep rule messages non-prescriptive (this is already enforced as a meta-rule in `epistemics/vault/meta/rulesets/core.toml`).
- Start with **one invariant** and 2–3 rules; treat resistance-to-rewrite as signal (usually “missing schema”, “human-only judgment”, or “actually normative”).
- Iterate safely by putting experiments in a separate TOML file and running `irrev lint --ruleset <path-to-toml>` to compare behavior and witness quality.

### What’s still missing (if we want the *full* ADMIT language)

- **A first-class “difference / transformation / persistence” schema** that lives in the vault (not just in prose), so constraints can reason over it directly.
- **Explicit erasure permissions** as a deliberate commit surface (e.g., “allow erase X”), rather than implicit drift.
- **Minimal-witness extraction** across constraints (not just “a list of failures”), so the system can say “these three commitments jointly force inadmissibility”.
- **A stable proof format** for downstream tooling (packs, Neo4j exports, CI), so admissibility is replayable and comparable over time.

The key refinement here is to treat these as **vault-owned interfaces** (schemas + rulesets) and keep the engine as a small evaluator + ledger.

---

## Admissibility language design checklist (compiler craft)

If you’re designing an admissibility language “like a compiler”, you can steal a lot from programming language craft. The trick is to reuse the parts that buy you **clarity + tooling**, and avoid the parts that smuggle in “do this” vibes.

This is the expensive-to-change-later checklist.

### 0) Treat TOML as the surface syntax (v0)

Don’t rush to invent a `.admit` syntax. In this repo, TOML rulesets are already “policy as data”, and `irrev lint` is already “compile/check”.

Stabilize the **admissibility IR** (kernel primitives + witness/proof schema) first, then optionally add multiple front-ends later:

- TOML ruleset front-end (existing)
- `.admit` sugar front-end (optional)

### 1) Decide what the language *is*: logic, rules, or ledger?

A repo-aligned stance is:

- Programs are declarations (facts, commitments, costs, thresholds)
- Evaluation is a check (admissible / inadmissible + witness)
- Execution produces a proof object (trace, minimal witness, ledger deltas)

So: closer to a policy/constraint DSL (Datalog-ish) than to a general-purpose language.

### 2) Separate syntax, AST, IR, and semantics

Classic compiler pipeline:

- Syntax: human-facing representation (today: TOML rulesets; later: a dedicated DSL could be sugar)
- AST: structured parse tree (today: `RulesetDef`/`RuleDef` in `execution/irrev/irrev/passes/constraints/schema.py`)
- IR: normalized core (a tiny “kernel” you lower into)
- Semantics: what “inadmissible” means in terms of IR constraints + vault state
- Proof/Witness: a machine-checkable explanation artifact

Upfront win: you can evolve syntax without breaking semantics.

### 3) Keep the IR tiny (“kernel”, not “stdlib”)

Design the minimum primitive set and force everything else to lower into it. Keep it aggressively small (fewer than 10). A practical kernel:

1. `DeclareDifference(name, unit?)`
2. `DeclareTransform(name)`
3. `Persist(diff, transforms[])`
4. `ErasureRule(diff, cost, displaced_to_bucket)`
5. `AllowErase(diff)` / `DenyErase(diff)`
6. `Constraint(expr)` (small boolean algebra only)
7. `Commit(diff, value)`
8. `Query(Admissible | Witness | Delta)`

If you can’t lower a feature into the kernel cleanly, it’s probably premature.

### 4) Make “scope” first-class

Bounded scope is a decomposition primitive. Encode it in the language:

- `scope Mission { ... }`
- nested scopes allowed, with explicit inheritance rules
- cross-scope references require imports and attribution

This prevents “global soup” later.

### 5) Names, keywords, and reserved words

Do reserved keywords, but keep them few and semantically crisp.

More important than reserved *words*: reserve **identifier namespaces** so concepts don’t collide later. Hard-separate:

- `difference:*`
- `transform:*`
- `bucket:*` (displacement sinks)
- `constraint:*`
- `scope:*`
- `module:*`

Internally, require qualified names even if surface syntax is short.

Good keyword families:

- Ontology: `scope`, `difference`, `transform`
- Claims: `persist`, `erasure_rule`
- Permissions: `allow`, `deny`
- Constraints: `inadmissible_if`, `threshold`
- State: `commit`, `set` (be careful with `assume`)
- Queries: `admissible?`, `witness`, `explain`

Avoid keywords that sound like advice: `should`, `must`, `fix`. Those belong in error messages (if anywhere), not in source.

### 6) Types: steal the discipline, not the complexity

You don’t need a full type system, but you want:

- Symbol types: Difference / Bucket / Transform / Scope
- Units for quantities (`kg`, `days`, `risk_points`) to prevent nonsense
- No implicit conversions unless declared

### 7) Determinism and monotonicity

Policy/constraint languages live or die by predictability.

Good defaults:

- Evaluation is deterministic
- Facts are monotonic inside a scope (adding constraints can only reduce admissibility)
- Non-monotonic features (overrides/exceptions) are explicit and *loud*

Monotonicity buys explainability and caching.

### 8) Error messages are a product feature

In this world, the killer feature is not “compile success”. It’s the witness.

Design witness reporting early (compiler ergonomics):

- include which declarations caused failure
- include a minimal witness set (or best-effort minimization)
- include “where the cost went” (displacement trace)
- never moralize; just account

If you want this to feel “compiler-grade”, pay for spans early:

- every AST node carries a `Span { file, start, end }`
- every witness fact references spans

Treat the witness/proof object as an artifact format (stable schema: JSON/CBOR), including:

- `verdict`, `reason`
- `facts[]` (typed facts with spans + involved symbols)
- `displacement_trace` (bucket totals + contributing erasures)
- `rule_ids` + ruleset `ruleset_id`/`version`

### 9) Module system + versioning (pay upfront)

If this will be extended, you need stable imports + versions:

- `module english.agency`
- `import core.irrev.v1`
- semantic versioning for rulesets
- migration tooling (even basic) because “erasure has costs”

Repo alignment note: `epistemics/vault/meta/rulesets/core.toml` already has `ruleset_id` and `version`; treat them as public API.

### 10) Don’t copy PL features that will hurt you

Be cautious about:

- general loops/recursion (invites “do stuff” thinking)
- Turing completeness (tempting, but harms decidability and witnesses)
- implicit state mutation
- overpowered macros

### 11) Concrete syntax: borrow from TOML/YAML, not from C

Given the vault’s Markdown + metadata environment, favor readable blocks and declarative lists.

If a `.admit` front-end ever exists, pick a parser strategy that makes spans cheap (nice error recovery beats raw speed here).

Example vibe:

```text
scope English.Agency

difference agent
difference event
bucket accountability_gap

transform summarize
transform translate_es_en

persist agent under [summarize, translate_es_en]

erasure_rule agent -> cost 5 displaced_to accountability_gap

constraint inadmissible_if displaced(accountability_gap) > 3
```

### 12) Decide the execution model (even if it’s one pass)

Common choices:

- Check-only: evaluate constraints against commits + permissions
- Search: find admissible sets (more complex)
- Delta mode: show how admissibility changes when adding a rule/commit

For early traction: check-only + witness is perfect.

**Mantra**: small kernel, loud scope, explicit permissions, deterministic checks, witness-first output.

### A crisp v0 language design proposal (no new parser)

- Surface syntax: keep TOML; extend rulesets with optional sections like `differences`, `transforms`, `erasure_rules`, `permissions`, `constraints`.
- IR: implement TOML-to-IR lowering first (kernel above).
- Output: always emit verdict + witness + displacement totals (even on success: a trivial witness like “no constraints violated”).

### One decision to lock in today

Default: **no erasures allowed**. Any erasure permission must be explicit and attributable.

---

## A tiny admissibility rule that already feels different than normal code

Let’s implement the second constraint: “displaced(safety_risk) > 3 is inadmissible”.

Where does `displaced(safety_risk)` come from? From any allowed erasures that route cost into that bucket.

So your IR needs the concept:

* `allowed_erasures: Set[str]`
* `displacement_totals: Map[str, int]`

Then checking is easy.

The *interesting* part is: **who decides erasures are allowed?**
That’s where admissibility programming gets its teeth: you can require explicit permission.

Example:

* default: no erasures allowed
* you must add `allow erase "crew_fatigue"` explicitly
* and then the compiler calculates consequences

This makes the “no rollback assumptions” invariant literal.

---

## The smallest runnable example (in plain English)

Imagine a policy doc:

* “We can downplay fatigue in reports” (that’s an erasure permission)
* Fatigue erasure displaces into safety risk
* Safety risk above threshold makes mission inadmissible

So a manager can’t “spin” without the compiler showing the cost lands somewhere and breaks admissibility.

That’s the whole vibe.

---
