# Schema Registry (Compiler + Vault)

Status date: 2026-01-29

This registry tracks active and planned schema IDs. Use these IDs in artifacts
and ledger events to keep provenance deterministic and auditable.

## Active schema IDs (in use)

- `admissibility-witness/1` — compiler witness output
- `vault-snapshot/0` — vault snapshot JSON
- `program-bundle/0` — ProgramBundle JSON
- `facts-bundle/0` — FactsBundle JSON

## Planned schema IDs (migration)

- `VaultScan@1` — vault scanner output (structural IR)
- `VaultLintWitness@1` — vault lint witness artifact
- `ProgramBundle@1` — projection output (future canonical name)

## Notes

- Planned IDs are part of the Python → Rust migration plan and are not yet enforced.
- If/when `ProgramBundle@1` becomes active, align the emitted `schema_id` in the
  ProgramBundle artifact and keep a compatibility note for `program-bundle/0`.
