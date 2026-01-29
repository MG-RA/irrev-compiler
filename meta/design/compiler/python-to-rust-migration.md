# Python → Rust Migration Plan (Semantics Authority)

Status date: 2026-01-29
Owner: mg

## Principle

Python is a **structure extractor** only. Rust is the **semantic authority** (invariants, admissibility, witnesses, ledger binding).

**Mantra:** Vault dreams. Rust judges. `.adm` travels. The witness remembers.

## Phase 0 — Freeze authority (now)

- Declare Rust as the sole authority for invariants/admissibility.
- Python may export structure but must not emit verdicts or witnesses.
- Block any Python “lint” or “admissibility” paths from being treated as authoritative.

**Deliverables**
- Note in protocols: Python is non‑authoritative for semantics.
- CI guard: reject Python‑produced verdict/witness artifacts.

## Schema IDs (declare early)

- `VaultScan@1` — scanner output (structural IR)
- `VaultLintWitness@1` — lint witness artifact
- `ProgramBundle@1` — projection output

## Phase 1 — Rust vault scanner (structural IR)

Build a Rust `vault scan` that parses the vault into a deterministic IR:
- files, roles, layers, frontmatter
- wikilinks + span mapping
- adjacency list of links
- stable hashes per file and per scan

**Deliverables**
- Rust scanner crate + canonical JSON output + hash
- Golden fixtures for a minimal vault sample

## Phase 2 — Rust vault lint (structural invariants)

Implement structural invariants in Rust and emit witness artifacts:
- missing roles
- broken links
- layer violations
- dependency cycles
- registry/alias drift

**Deliverables**
- `vault lint` command in Rust
- `vault.lint_witness@1` schema (CBOR identity + JSON projection)
- Ledger event for `vault.lint.checked`

## Phase 3 — `.adm` projection in Rust

Add `vault project adm`:
- deterministic `.adm` pack from vault scan IR
- canonical ProgramBundle output + hash
- no semantic evaluation (projection only)

**Deliverables**
- ProgramBundle emitted by Rust
- Optional projection witness (recommended)

## Phase 4 — Decommission Python semantics

Remove Python checks/predicates that overlap with Rust:
- Python keeps only data extraction or optional utilities
- Any Python linting becomes export‑only or is removed

**Deliverables**
- Python CLI only exposes export utilities
- Deprecation notice for legacy Python lint paths

## Phase 5 — Rust as the unified CLI (`irrev`)

Rename or alias Rust CLI to `irrev`:
- `irrev vault scan`
- `irrev vault lint`
- `irrev vault project adm`
- `irrev admit check|declare-cost|execute`

**Deliverables**
- Unified CLI docs
- One authoritative path for users

## Risk controls

- **Hash provenance:** always include snapshot + bundle + facts refs in ledger events.
- **No dual truths:** do not allow Python to emit verdicts or witnesses.
- **Parity tests:** run Rust lint/admissibility against fixtures on every change.
