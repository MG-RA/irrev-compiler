# admitc OSS Plan (Engine Public, Policy Packs Private)

Status date: 2026-01-30
Owner: mg

## Goal

Open-source the admissibility compiler as `admitc` (engine + minimal standard library), without shipping the private vault or private policy packs.

Principle: **engine is public**; **policy is modular**; **semantic authority is the compiler**.

## Non-goals (v0)

- Publishing or bundling the private vault content.
- Shipping doctrine/ontology as part of the standard library.
- Dynamic plugin loading (dylibs, arbitrary runtime code injection).

## Decision (2026-01-30)

- Vault lint lives in a **separate repo**: `admitc-vault`.
- Core repo `admitc` stays vault-free (no scanning, markdown parsing, or vault-specific providers).

## Phase 0 - Boundary + Naming

- Choose scope:
  - `admitc` ships parser/lowering, kernel IR, evaluator, witness emission, canonical encoding/hashing, and CLI.
  - `admitc` does not ship the vault or project-specific rule packs.
- Rename repo identity to `admitc` (repo name + docs). Keep crate names as-is initially if churn is risky.
- Add a short README doctrine: engine vs packs; compiler is semantic authority; packs are optional.

## Phase 1 - Repo Reshape (Mechanical)

- Establish a public-friendly top-level layout:
  - `crates/` (engine crates)
  - `stdlib/irrev_std@1/` (or `stdlib/irrev_std@1.adm`)
  - `examples/` (toy programs; no private content)
  - `docs/` (language, witness, packs)
- Remove or gate any tests/fixtures that reference private paths (no `../irrev-vault` assumptions).
- Ensure the workspace builds/tests cleanly from a fresh clone with no external assets.

## Phase 2 - Public Stdlib (`irrev_std@1`)

Design constraint: stdlib must be **protocol primitives**, not ontology.

- Include:
  - stable module + namespace conventions
  - generic query helpers (e.g., `query witness`, `query lint fail_on ...`)
  - generic evaluation primitives used by many packs
- Exclude:
  - vault-specific invariants as prescriptive prose
  - private rule IDs and private policy narratives
- Add 2-3 example `.adm` programs that run using only `irrev_std@1`.

## Phase 3 - Packs as First-Class Artifacts

- Define the pack interface in docs:
  - how `.adm` modules are located/loaded
  - how pack content is hashed / referenced (content-addressed)
  - how dependency resolution works (`module:*@<major>`)
- Make it explicit: "vault owns policy; tool enforces it."
- Plan separate repos (optional):
  - `admitc` (engine)
  - `admitc-packs` (community packs)
  - private repo (vault + private packs)

## Phase 4 - Vault Lint (Separate Repo: `admitc-vault`)

Objective: keep the core engine vault-free and ship vault lint as a separate, optional repo.

`admitc-vault` contains:
- `vault_ingest` (filesystem scan -> deterministic vault scan/snapshot)
- `pred_vault_lint` (implements `vault_rule(rule_id)` -> findings)
- `packs/vault_lint_pack@1/` (the ADM ruleset)
- golden fixtures (snapshot + witness hashes)

Dependencies:
- only public `admitc` crates + snapshot schema
- no vault content committed

Guardrails (v0):
- No dynamic plugins.
- Provider IDs are versioned and registered at compile time.
- Unknown predicate IDs are hard errors.
- Provider outputs are canonicalized into deterministic witness facts.

See `mechanism-protocol-v0.md` and `scope-authority-protocol-v0.md` for the runtime/mechanism and scope-capability context that keeps this split governable.

## Phase 5 - CI + Release Hygiene

- Add GitHub Actions:
  - `cargo fmt --check`
  - `cargo clippy --all-targets` (and `--all-features` if features are stable)
  - `cargo test`
- Add repo hygiene docs:
  - `CODE_OF_CONDUCT.md`
  - `CONTRIBUTING.md`
  - `SECURITY.md`
  - `CHANGELOG.md`
- Versioning:
  - semver for crates
  - schema IDs are immutable once published (`@<major>` implies breaking changes only)

## Phase 6 - Licensing + Distribution

- License core engine under MIT or Apache-2.0 (or dual MIT/Apache-2.0).
- Document that packs may have different licenses (including private/internal).
- Decide distribution:
  - publish crates to crates.io when stable, or
  - keep as git dependency until interface stabilizes

## Phase 7 - Public Documentation (Minimum Viable)

- `docs/overview.md`: what `admitc` is / is not
- `docs/adm-language.md`: language surface + stability guarantees
- `docs/witness.md`: witness schema + determinism rules
- `docs/packs.md`: how to author + load packs

## Immediate Next Step (Concrete)

Pick where vault lint lives (in-tree feature vs separate repo). Then:
- finalize the minimal public stdlib layout
- add CI (fmt/clippy/test)
- verify the build is clean from a fresh clone with no private assets
