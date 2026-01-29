# .adm Well-Formedness Checklist (Lowering Rules)

Status date: 2026-01-29

This document lists the semantic checks enforced during lowering and evaluation.
Parsing accepts a superset; lowering enforces well-formedness.

## Lowering well-formedness rules (static)

- WF001: Namespace prefixes are valid and resolvable (`difference:*`, `transform:*`, `bucket:*`, `constraint:*`, `scope:*`, `module:*`).
- WF002: `module` declaration is present and well-formed (`module:<name>@<major>`).
- WF003: `depends` includes required core dependency `module:irrev_std@1` (or `irrev_std@1`).
- WF003a: Core dependency version pinning is strict (must match `@1` exactly; no minor/patch syntax in v0).
- WF004: `allow_erase <diff>` requires a matching `erasure_rule <diff>`.
- WF005: Conflicting permissions (`allow_erase` and `deny_erase` for the same diff) are rejected.
- WF006: `scope_change` modes are limited to `widen|narrow|translate` and have no default; omission is an error.
- WF007: `allow_scope_change <from> -> <to>` requires a matching `scope_change_rule <from> -> <to>`.
- WF008: `scope_change_rule` buckets must be declared and valid (`bucket:*`).
- WF011: Duplicate identical declarations are idempotent; conflicting duplicates are rejected (same symbol, different unit/cost/bucket/etc.).

## Evaluation well-formedness rules (semantic)

- WF009: Canonicalization rules apply (deterministic ordering + stable predicate strings + stable witness ordering).
- WF010: Quantity/unit comparisons are only allowed when units match exactly (v0 has no conversion table).

## Notes

- These rules are deterministic and decidable; they are not encoded in the grammar.
- WF failures include `{wf_id, span}` in errors (and a short, non-prescriptive message).
- Rule IDs are stable and should be referenced in tests and error messages where practical.
