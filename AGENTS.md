# AGENTS.md (irrev-compiler)

This folder is the Rust workspace for the Irreversibility compiler/runtime.

## Repo layout

- `crates/`: Rust crates (compiler core, DSL, CLI, bundles, vault utilities).
- `meta/`: design notes and governance docs for the compiler/runtime.
- `meta/design/`: implementation designs and concrete plans.
- `meta/design/compiler/`: compiler plans, IR specs, and schema/registry designs.
- `meta/protocols/`: binding process and authority protocols.
- `meta/oss/`: open-source release and packaging notes.
- `testdata/`: fixtures and sample inputs used by tests or experiments.
- `out/`: generated outputs; treat as build artifacts unless a task says otherwise.
- `target/`: Cargo build output.

## Working guidelines

- Prefer editing sources in `crates/` and keep `out/` as generated output.
- Use `meta/` documents for architectural intent and protocol constraints.
- Keep changes minimal and localized; avoid cross-crate refactors unless requested.
- When you need product intent or scope, start in `meta/README.md`.
- For plan-contract workflows, generate and update tracked artifacts under `.admit/plan/` (not `out/`).
- Preferred command for scaffolding is:
  - `admit plan autogen --root . --out-plan .admit/plan/plan-artifact.json --out-manifest .admit/plan/proposal-manifest.json`

## Plans and specs (start here)

- Architecture and primitives: `meta/Architecture.md`, `meta/Scope Primitives & Algebras.md`.
- Compiler status: `meta/compiler-progress-summary.md`.
- Compiler plan and kernel specs: `meta/design/compiler/`.
- Runtime loop and boundaries: `meta/Compiler Runtime Loop.md`, `meta/Boundary Events & DB Scope.md`.
- Registry and deadlock discipline: `meta/Registry Scope Architecture.md`, `meta/Semantic Deadlock & Scope Registry.md`.

## Crate hints

- `crates/admit_core`: core data types, validation, and compiler rules.
- `crates/admit_dsl`: DSL parsing and related helpers.
- `crates/admit_cli`: CLI entrypoints and commands.
- `crates/vault_snapshot` and `crates/vault_ingest`: vault IO, snapshot schema, and ingest paths.
- `crates/program_bundle` and `crates/facts_bundle`: bundle formats and serialization.

## Local commands (PowerShell)

- Build workspace: `cargo build`
- Run tests: `cargo test`
- Run a specific crate: `cargo run -p admit_cli -- --help`

## Encoding

- Keep files UTF-8. Use standard ASCII punctuation when editing instructions or docs.
