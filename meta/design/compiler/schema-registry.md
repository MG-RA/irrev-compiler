# Schema Registry (Compiler + Vault)

Status date: 2026-01-29

This registry tracks active and planned schema IDs. Use these IDs in artifacts
and ledger events to keep provenance deterministic and auditable.

## Naming convention

**Canonical format:** `schema-name/version` (slash notation).

Examples: `admissibility-witness/1`, `vault-snapshot/0`, `engine-query/1`.

Planned schemas using @-notation (`VaultScan@1`, `VaultLintWitness@1`, `ProgramBundle@1`) are flagged for normalization to slash notation before activation. The @-notation is transitional only.

## Active schema IDs (in use)

- `admissibility-witness/1` — compiler witness output
- `vault-snapshot/0` — vault snapshot JSON
- `program-bundle/0` — ProgramBundle JSON
- `facts-bundle/0` — FactsBundle JSON
- `plan-witness/1` — plan witness artifact (diagnostic questions + answers + derived risks)
- `meta-registry/0` — meta registry allowlist (schema_id and scope_id gates)

## Planned schema IDs (migration)

- `ledger-projection-updated/0` — witness: DB projection updated for a ledger range
- `ledger-projection-drift/0` — witness: DB projection drift/mismatch detected
- `meta-registry/1` — meta registry with scope contracts (phase/determinism/deps)
- `meta-registry-missing-schema/0` — rejection witness (unknown schema_id)
- `meta-registry-missing-scope/0` — rejection witness (unknown scope_id)

- `VaultScan@1` — vault scanner output (structural IR)
- `VaultLintWitness@1` — vault lint witness artifact
- `ProgramBundle@1` — projection output (future canonical name)

## Notes

- Planned IDs are part of the Python → Rust migration plan and are not yet enforced.
- If/when `ProgramBundle@1` becomes active, align the emitted `schema_id` in the
  ProgramBundle artifact and keep a compatibility note for `program-bundle/0`.
