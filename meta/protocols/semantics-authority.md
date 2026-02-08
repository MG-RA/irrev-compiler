# Semantics Authority Protocol

Status date: 2026-01-29

## Purpose

Define a single authoritative semantics engine for admissibility and vault governance.

## Rule (binding)

**Rust is the sole semantic authority.**

- Python may extract structure (frontmatter, links, spans, file lists).
- Python must not emit verdicts, witnesses, or ledger events.
- Any Python‑produced diagnostics are non‑authoritative inputs and must be re‑validated in Rust.

## Enforcement mechanism

**Current enforcement:** Review discipline — witnesses and ledger events are manually verified to originate from Rust tooling during PR review.

**Planned enforcement:** CI guard rejects witness/ledger artifacts not produced by Rust tooling. Detection mechanism: witness artifacts include `engine_version` field populated only by the Rust compiler; artifacts from other tooling lack this field or use different schema versions.

**Violation detection:** Schema registry enforces that only Rust-emitted schema versions are accepted in ledger ingestion. Violations produce `meta-registry-missing-schema/0` rejection witness.

## Enforcement (v0)

- Tooling and docs must treat Rust outputs as the only valid source of admissibility.
- Ledger events are emitted only by Rust tooling.
- CI guard (planned): reject any witness/ledger artifacts produced by Python tooling.
