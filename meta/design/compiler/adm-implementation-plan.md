# Implementation Plan: Chumsky Determinism + .adm Well-Formedness

Status date: 2026-01-29
Inputs:
- `meta/design/compiler/chomsky-features-comparison.md`
- `meta/design/compiler/adm-wellformedness.md`

## Current delta (what exists today)

- Parser: `.adm` grammar implemented in Chumsky; precedence for `not/and/or`; spans and structured parse errors.
- Lowering: namespace validation, dependency enforcement, erasure-rule checks, deterministic ordering, and scope-change checks.
- Tests: parsing fixtures + some parse-error tests; lowering error tests; golden witness fixtures.
- Determinism: canonical predicate strings and deterministic witness ordering; canonical CBOR encoding for witness identity.
- Docs: Chomsky analysis and well-formedness checklist exist, but WF IDs are not wired into error types.

## Desired new state (targets)

1. **Parser determinism contract enforced**
   - Parsing is referentially transparent (no side effects; no interning; no counters).
   - Any parser feature usage remains deterministic and isolated from semantic artifacts.
2. **Well-formedness rules enforced with IDs**
   - Lowering and evaluation failures carry `{wf_id, span, message}`.
   - WF rules split into static (lowering) and semantic (evaluation) concerns in code paths.
3. **Unit compatibility and duplicate declaration policy**
   - Unit mismatch errors are explicit and deterministic.
   - Duplicate declarations are idempotent if identical; conflicting duplicates are rejected.
4. **Unambiguity regression coverage**
   - Tests guard prefix collisions (`scope_change`, `allow_scope_change`, `scope_change_rule`) and parse errors.
5. **Docs aligned with behavior**
   - `adm-wellformedness.md` reflects actual enforcement locations and error IDs.
   - Chumsky determinism note is enforced by code review checklist and tests.
6. **Syntactic sugar additions (deterministic + desugared)**
   - Block form for `scope_change` desugars to explicit `allow_scope_change` and
     `scope_change_rule` without semantic changes.
   - Predicate call syntax (`displaced_total(bucket)`, `commit(diff)`) desugars to
     existing predicate forms with stable spans.
   - `@inadmissible_if` attribute form desugars to `inadmissible_if`.

## Plan (phased, minimal change set)

### Phase A — Error surface + WF IDs

- Define a compact error type for lowering/eval WF violations:
  - `struct BuildError { wf_id: String, span: Span, message: String }`
  - Keep messages short, non-prescriptive.
- Update lowering to emit WF IDs for:
  - WF001–WF008 + WF011 (static checks).
- Update evaluation to emit WF IDs for:
  - WF009 (canonicalization guarantees, if enforced explicitly),
  - WF010 (unit compatibility).
- Add unit tests that assert `wf_id` values (not full message text).

### Phase B — Duplicate declarations + unit compatibility

- Add deterministic resolution for duplicate declarations:
  - identical → idempotent,
  - conflicting → WF011 error with both spans if available.
- Enforce WF010 in evaluation where quantity comparisons occur
  (`commit_cmp`, `displaced_total`).
- Add fixtures:
  - duplicate identical declaration (accept),
  - duplicate conflicting declaration (reject),
  - unit mismatch in `commit_cmp` or `displaced_total` (reject).

### Phase C — Chumsky determinism guardrails

- Add a short “parser invariants” comment block in `admit_dsl` (one place),
  describing the no-side-effects rule.
- Add parse error fixtures for unclosed parens / bad keywords (already added)
  and ensure they remain part of CI.
- Add an unambiguity regression test for prefix collisions
  (ensure `allow_scope_change` does not parse as `scope_change`).

### Phase D — Sugar additions (block form, predicate calls, attributes)

- **Block form for `scope_change`**
  - Grammar: allow `{ allow; cost <n> "<unit>" -> <bucket> }` block after
    `scope_change <from> -> <to> <mode>`.
  - Desugaring: emit `scope_change`, and if present, expand to
    `allow_scope_change` + `scope_change_rule`.
  - Spans: keep the block span for the desugared statements, and preserve
    token spans for `allow` and `cost` inner statements.
  - Tests: fixture with block form + expected IR statements; ambiguity test with
    existing `scope_change_rule` syntax.

- **Predicate call syntax**
  - Grammar: allow `predicate_name("(" ident ")")` for predicates that take a
    single symbol (`displaced_total`, `commit`, `erase_allowed`, `has_commit`).
  - Desugaring: map to existing predicate variants with stable spans.
  - Tests: equivalence fixtures between call form and legacy form.

- **`@inadmissible_if` attribute form**
  - Grammar: allow `@inadmissible_if <expr>` as a statement.
  - Desugaring: map to `inadmissible_if <expr>` with the attribute span.
  - Tests: parse fixture + lowering equivalence.

### Phase E — Documentation sync

- Add or update a short “WF enforcement locations” section in
  `adm-wellformedness.md` (lowering vs evaluation).
- Add a “WF IDs are part of the public semantic API” note.
- Optionally add `adm-grammar.md` if you want a stable EBNF reference.

## Acceptance criteria

- All WF checks that can fail include `{wf_id, span}` in errors.
- Unit mismatch and duplicate declaration policy are enforced and tested.
- Parser determinism contract is documented and has at least one regression test.
- `cargo test -p admit_dsl` and `cargo test -p admit_core` pass.

## Risks / notes

- Avoid introducing parse-time side effects; keep interning in lowering/eval.
- If `wf_id` becomes public API, keep the list stable and versioned.
