# Semantics Authority Protocol

Status date: 2026-01-29

## Purpose

Define a single authoritative semantics engine for admissibility and vault governance.

## Rule (binding)

**Rust is the sole semantic authority.**

- Python may extract structure (frontmatter, links, spans, file lists).
- Python must not emit verdicts, witnesses, or ledger events.
- Any Python‑produced diagnostics are non‑authoritative inputs and must be re‑validated in Rust.

## Enforcement (v0)

- Tooling and docs must treat Rust outputs as the only valid source of admissibility.
- Ledger events are emitted only by Rust tooling.
- CI guard (planned): reject any witness/ledger artifacts produced by Python tooling.
