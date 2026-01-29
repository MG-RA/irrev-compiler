# Compiler idea context

This note summarizes the pieces of `quartz` that are directly relevant to implementing the vision in `compilerIdea.md`. The new structure you sketched (epistemics/reference/execution surfaces) is aspirational, but the content listed below maps the current repo layout to that future blueprint so you can see what already exists and where to build next.

## Epistemics (meaning, vocab, policy-as-data)

- `epistemics/vault/` – the Obsidian-style vault with `concepts/`, `diagnostics/`, `domains/`, `meta/`, etc. Source of the shared vocabulary.
- `meta/design/` – planning notes, including this file and other design docs (the proposed future `/meta/plan` equivalent if reordered).
- `compilerIdea.md` – still-tentative research/idea note; serves the same role as `/languages/admit` in the future structure.

## Reference (normative data)

- `epistemics/vault/meta/rulesets/` – the TOML rulesets (`core.toml`, `domains/` rules) that already function as “policy as data”; these are the “surface syntax v0” of the admissibility language. (`reference/rulesets/` mirrors this for tooling.)
- `execution/irrev/irrev/constraints/schema.py` – defines the AST (`RuleDef`, `RulesetDef`) that TOML deserializes into.
- `execution/irrev/irrev/constraints/load.py` & `run_constraints_lint` – responsible for loading the rulesets and executing them against the vault state.
- `execution/irrev/irrev/constraints/*.py` – predicates, engine, etc., form the evaluation runtime _for_ the admissibility language.

## Execution (compiler + runtime)

- `execution/irrev/irrev/frontends/vault_md` (currently `execution/irrev/irrev/vault/loader.py` / `parser.py` / `graph.py`) – loads Markdown sources and builds the dependency graph IR.
- `execution/irrev/irrev/passes/constraints` (currently `execution/irrev/irrev/constraints/*`) – evaluates the constraints ruleset.
- `execution/irrev/irrev/harness/` + `execution/irrev/irrev/artifact/` – the runtime/artifact IR for plan proposal/approval/execution, along with risk classification.
- `execution/irrev/irrev/artifact/ledger.py` – the proof/witness infrastructure through ledger events.
- `execution/irrev/irrev/commands/` + `execution/irrev/irrev/cli.py` – surfaces (CLI) for users (maps to `/execution/.../surfaces/cli`).

## Surfaces (non-Python entrypoints)

- `quartz/` – docs site that reads the vault for publishing; matches the `/surfaces/quartz` placeholder.

## Design implications for `compilerIdea.md`

1. Use `.adm` as the primary syntax front-end; treat TOML rulesets in `epistemics/vault/meta/rulesets` as a compatibility surface and plan the `.adm` front-end under `execution/irrev/irrev/frontends/admit_dsl` (notes live in `compilerIdea.md`).
2. Treat `execution/irrev/irrev/vault/*` as the “syntax → AST” loader pass; `execution/irrev/irrev/constraints` as the “IR → semantics” pass; `execution/irrev/irrev/harness` as the runtime with ledger-backed witnesses.
3. Reference `PlanManager`, `ArtifactLedger`, and `RiskClass` when you describe proof/witness expectations or execution gating.
4. Keep new research/spec notes in `compilerIdea.md` (or adjacent notes) and link to `meta/design/` for broader planning context.
