# Refactor Plan: UX + Core/Adapter Separation

## 1. Objective

Make the compiler usable with a clear default flow:

1. install
2. init
3. ingest
4. query
5. iterate

At the same time, enforce a hard architecture split:

- core compiler remains substrate-agnostic
- vault/obsidian behavior moves to optional scope packs

---

## 2. Product Shape

Target command flow:

```bash
admit init
admit ingest .
admit status
admit lint vault
admit lint rust
```

Secondary commands:

```bash
admit project
admit runs
admit db ensure-schemas
admit db query 'SELECT count() FROM doc_chunk GROUP ALL;'
admit verify-ledger
```

---

## 3. Architecture Boundary

### Core (`admit_core`)

- canonical hashing and identity primitives
- witness types and encoding
- scope/runtime contracts
- deterministic ordering helpers

Must not contain:

- obsidian-specific parsing rules
- vault prefix assumptions
- database-specific projection behavior

### CLI (`admit_cli`)

- command surface and config loading
- artifact and ledger orchestration
- scope selection and execution

### Projection Backend (`admit_surrealdb`)

- projection store implementation only
- schema ensure and projection run/event persistence

Must not contain:

- obsidian-specific business rules

### Scope Packs

- `admit_scope_fs` (generic filesystem)
- `admit_scope_rust` (rust irreversibility rules)
- `admit_scope_markdown` (generic markdown)
- `admit_scope_obsidian` (optional adapter layer)

---

## 4. `admit init` Contract

`admit init` should be idempotent and scaffold:

- `admit.toml`
- `out/.gitignore`
- optional `meta/rules/` starter files
- optional `meta/fixtures/mini_vault/`

Default `admit.toml` must include:

- project paths
- ingest include/exclude patterns
- projection defaults
- surrealdb mode (`off | auto | on`)

---

## 5. Execution Modes

Projection mode policy:

- `auto`: use db if configured and reachable
- `off`: court-only run
- `on`: require db and fail if unavailable

Expected behavior after ingest:

- always emit ledger + artifacts
- print short deterministic summary
- project when mode allows it

---

## 6. Scope Enablement Model

`admit.toml` controls enabled scopes:

```toml
[scopes]
enabled = ["rust.ir_lint", "markdown.chunk"]
```

Personal/local usage can opt in:

```toml
[scopes]
enabled = ["rust.ir_lint", "markdown.chunk", "obsidian.links", "vault.ir_lint"]
```

---

## 7. Refactor Work Plan

### Phase 1: UX baseline

- implement/finish `admit init`
- unify config loading from `admit.toml`
- make `ingest -> status` the default first-time path

### Phase 2: Boundary extraction

- move obsidian-specific logic behind scope interfaces
- keep generic markdown logic in non-obsidian scope pack
- remove direct obsidian coupling from core crates

### Phase 3: Pluginized scope packs

- register built-in generic scopes
- allow optional scope pack loading at runtime/build time
- keep personal adapters separate from compiler core

### Phase 4: Governance hardening

- add compiler self-lint for architecture coupling (IR-RS-13)
- gate CI on boundary rules

---

## 8. Enforcement Rules

Add rule `IR-RS-13`:

- no obsidian/vault coupling in:
  - `admit_core`
  - `admit_surrealdb`
  - `admit_cli` (except explicit optional-scope wiring)

Signals:

- forbidden identifiers/patterns in protected crates
- CI fails on violations

---

## 9. Data Model Policy

Keep projection tables grouped by scope family:

- generic tables stay generic (`doc_file`, `doc_chunk`, etc.)
- obsidian-specific tables stay adapter-scoped (`obsidian_*`)

This enables non-obsidian users to run the system without creating adapter-specific tables.

---

## 10. Acceptance Criteria

Done when all are true:

1. Fresh user can run `init -> ingest -> status` with no manual setup.
2. Core crates compile and test without obsidian-specific assumptions.
3. Scope packs cleanly separate generic and adapter behavior.
4. CI enforces IR-RS-13.
5. Ledger and witness outputs remain deterministic across runs.

---

## 11. Risks

- Hidden coupling may still exist in projection paths.
- Existing tests may encode obsidian assumptions in generic crates.
- Config migration may break existing local workflows.

Mitigations:

- incremental extraction with fixture coverage
- golden tests for ingest/projection outputs
- compatibility layer for old config keys during migration

---

## 12. Immediate Next Actions

1. Add/verify `admit init` scaffolding behavior and tests.
2. Create a coupling-audit checklist per crate.
3. Land IR-RS-13 lint and enable in CI as warn first, then error.
4. Split current obsidian-specific code paths into an adapter scope module.
