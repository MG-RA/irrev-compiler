# Documentation Contract

This directory separates binding rules from design discussion.

## Structure

- `docs/spec/`: normative contracts. These files may use `MUST`, `SHALL`, `MUST NOT`, and `SHALL NOT`.
- `docs/arch/`: architecture notes and implementation rationale (non-normative).
- `docs/ideas/`: proposed or future designs (non-normative).
- `docs/status/`: audits, progress snapshots, and migration status.

## Authoring Rule

Only `docs/spec/*` may define binding behavior.
All other directories are explanatory and may not redefine normative requirements.

