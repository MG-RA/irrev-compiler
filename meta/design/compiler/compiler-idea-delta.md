# Compiler idea delta (current ↔ desired)

This note now documents the **reasoning framework inside the vault**, maps it onto the **existing tooling**, and explicitly states the **gap between the current implementation and the desired “compiler by admissibility” state** you outlined in `compilerIdea.md`.

## 1. Reasoning framework (vault epistemics)

The vault is intentionally structured as a **constraint-first diagnostic lens**—see `epistemics/vault/index.md`. It insists that:

- `/concepts` define primitives; agents must “reason only using `/concepts`” and avoid introducing new primitives (Prompting Guide section “Core rule”).
- Diagnostics consist of **failure-mode aware prompts** that keep interpretation grounded in bookkeeping, not prescription (Prompting Guide gold-standard prompts).
- The lens self-reflexively audits itself (Failure Mode #10), and it warns against reifying bookkeeping terms or moralizing structural patterns (Failure Modes #1, #3, #4).

These directives mean the compiler idea must (a) lock definitions to concepts, (b) keep language use structural/accounting, (c) treat witnesses as ledger-backed artifacts, and (d) make the ruleset itself subject to admissibility checks.

## 2. Current state (tools / docs / infrastructure)

### Syntax / policy-as-data

- `epistemics/vault/meta/rulesets/core.toml` is the current surface syntax. `ruleset_id`/`version` metadata act as the ruleset’s API. (`reference/rulesets/core.toml` mirrors it for tooling.)
- `execution/irrev/irrev/constraints/load.py` decodes TOML into `RulesetDef` and `RuleDef` (§ AST), then `run_constraints_lint` dispatches to predicates in `execution/irrev/irrev/constraints/predicates.py`. Many rules still use `legacy_lint_rule`.

### Loader / AST

- `execution/irrev/irrev/vault/loader.py`, `parser.py`, and `graph.py` are the loader pass: they parse Markdown/frontmatter, extract links, structural dependencies, and build the dependency graph IR.
- There is no intermediate admissibility IR beyond concept objects and `LintResult`s.

### Passes / semantics

- `execution/irrev/irrev/commands/lint.py` orchestrates linting: vault + graph → `run_constraints_lint`/legacy rules. It sorts `LintResult`s, groups them by invariant, and prints results.
- CLI entrypoints (`execution/irrev/irrev/cli.py`) expose lint, registry, harness, etc.; the harness and artifact subsystem (`execution/irrev/irrev/artifact/*`, `plan_manager`, `ledger`, `harness`) provide the gated runtime (propose → validate → approve → execute).

### Proof / witness

- The witness today is a list of `LintResult`s enhanced by ledger events when constraint lint runs with `emit_events=True`. There is no structured witness artifact with spans/displacement traces.

### Surfaces / documentation

- CLI surfaces, Neo4j adapters, and Quartz docs rely on the vault’s concept graph. Documentation notes (e.g., `meta/design/`, `compilerIdea.md`) describe the desired direction but do not yet define the admissibility kernel.

## 3. Desired state (compilerIdea vision)

- **Minimal kernel IR:** 8 primitives (differences, transforms, persistence, erasure rules, allow/deny permissions, constraints, commits, queries) that everything lowers into.
- **Rules as commitments:** each rule becomes an inadmissibility claim; resistance-to-rewrite signals missing schema or normative content.
- **Witness artifact:** structured format (JSON/CBOR) carrying verdict, reason, rule IDs, spans, displacement totals, and linked facts.
- **Default deny erasure:** erasures require explicit permission and attribution, tied to scopes/modules to prevent global soup.
- **Modular surfaces:** use `.adm` as primary syntax v0, keep TOML as a compatibility surface, reserve identifier namespaces (`difference:*`, `transform:*`, etc.), and treat ruleset metadata as API during the transition.
- **Deterministic, monotonic semantics:** evaluation is predictable, facts monotonic, overrides explicit and audible.
- **Self-admissible rulesets:** apply admissibility programming to the ruleset itself—lint it, emit events, enforce invariants (aligns with Failure Mode #10).

## 4. Delta analysis (why change matters)

| Area | Current reality | Desired shift | Reasoning anchor |
| --- | --- | --- | --- |
| **Syntax → IR** | TOML → `RuleDef` → predicate; no admissibility IR yet. | Lower TOML into the kernel (DeclareDifference, Commit, etc.); treat rules as commitments, not checks. | Concept-locked reasoning (Prompting Guide) demands explicit primitives and avoids new nouns. |
| **Rule semantics** | Many checks wrapped in `legacy_lint_rule`; messages risk slipping into prescription. | Build native predicates over the kernel and keep messages non-prescriptive (enforced by meta-rule `ruleset_messages_non_prescriptive`). | Failure Modes #1/#3 warn against reifying bookkeeping and prescribing behavior; diagnostics must stay structural. |
| **Proof / witness** | `LintResult` + event log; no span/displacement trace. | Emit structured witness artifacts that include spans, rule IDs, displacement buckets, and verdicts. | Failure Modes #1/#8 require accounting clarity and transparency; this also mirrors the “witness-first” mantra. |
| **Execution / permissions** | Erasure permissions are implicit inside rules. | Default deny erasure; require explicit `allow` statements tied to scopes/modules, and log them via `PlanManager`/`Ledger`. | The lens emphasizes “scope before scale” and “no rollback assumptions.” |
| **Rulesets auditing** | Rules run but aren’t themselves governed beyond general lint. | Treat the ruleset like any other artifact: emit constraint events, apply invariants, support rewrites via `irrev lint --ruleset`. | Failure Mode #10—audit the lens with its own questions. |
| **Documentation / surfaces** | Docs describe ideas but aren’t aligned with the future folder layout. | Map notes to the `/epistemics`, `/reference`, `/execution`, `/surfaces`, `/meta` structure, tie design notes into `meta/design/` and `compilerIdea.md`. | The charge is “Links, not sequence”; clarity about responsibilities prevents confusion. |

## 5. Analysis takeaways

1. The reasoning framework insists that we **never prescribe**; the compiler must only expose structural constraints, witness them, and keep moralizing or quantifying language out of syntax/messages.
2. Tools already provide a gated runtime (harness, ledger, CLI). The key work is **rewriting rules** into the admissibility kernel, **issuing structured witness artifacts**, and **defaulting to deny erasure**.
3. The delta doc should guide future work: define the IR schema (with spans/displacement traces), implement lowering, rewrite rules to use the new predicates, and ensure the ruleset itself is governed by the same admissibility architecture.

Once those gaps are closed, the compiler idea will be grounded in the vault’s reasoning framework, the python runtime, and the documented mental model—turning manifesto into implementable engineering.
