# Chomsky Hierarchy Features vs Current .adm Implementation

Status date: 2026-01-29
Source for phase status: meta/protocols/compiler-progress-tracking.md
Parser library: chumsky

## Current status snapshot (from progress tracking)

- Phases 0-5.6: Complete (workspace, IR, parser/lowering, evaluator, cost protocol, snapshot, program bundle, facts bundle)
- Phases 6-7: Not started (ledger+witness integration; parity testing + replacement path)

## Current implementation summary (what exists today)

- Lexer + parser live in `execution/compiler-rs/crates/admit_dsl/src` and use `chumsky`.
- Tokens are produced by a regular lexer and fed into a parser combinator grammar.
- Boolean expressions use explicit precedence (`not` > `and` > `or`) with parentheses.
- The parser builds a statement list; semantic checks occur in lowering and later phases
  (namespaces, dependency enforcement, erasure rule requirements, spans, deterministic ordering).

## Chomsky features that fit this context (positive effect candidates)

The table below maps formal-language features to the current compiler surface and highlights
where they could add value without breaking the admissibility design constraints.

| Feature (Chomsky lens) | Current state | Potential positive effect | How it could be used here |
| --- | --- | --- | --- |
| Type-3 (regular) lexical layer | Implemented via lexer tokens | Keeps syntax fast and deterministic; improves error spans | Continue separating tokenization from parsing; add token-level fixtures for edge cases (numbers, units, prefixes) |
| Type-2 (context-free) grammar | Implemented in chumsky parser | Clear, deterministic syntax with precedence; supports nested constructs | Write an explicit BNF/EBNF doc for `.adm` that mirrors the parser to lock expectations |
| Unambiguous grammar / ambiguity tests | Implicit in current parser | Prevents drift in parser surface and error UX | Add ambiguity regression tests around keyword prefixes (e.g., `scope_change`, `allow_scope_change`, `scope_change_rule`) |
| Deterministic CFG (LL/LR-style) | Implicit in parser combinators | Predictable parse results and easier diagnostics | Add ambiguity tests and grammar notes when adding new keywords or statement forms |
| Precedence + associativity constraints | Implemented for `not/and/or` | Avoids ambiguous boolean expression parsing | Extend precedence rules if new operators are added; add golden parse tests for precedence |
| Grammar factoring / left-factoring | Partial (manual in parser) | Better error recovery and clearer parse errors | Refactor new statement forms to minimize prefix ambiguity (e.g., `scope_change` vs `allow_scope_change`) |
| Attribute grammar (context-sensitive checks after parse) | Implemented in lowering/validation | Enforces namespace rules, dependency constraints, and erasure invariants | Formalize semantic checks as "attributes" in design docs to keep grammar + validation aligned |
| Type-1 (context-sensitive) constraints | Implemented outside grammar | Keeps parsing simple while allowing deterministic static semantics | Keep context-sensitive rules in lowering/eval (not in grammar) to preserve determinism and modularity |

## Notes on applicability

- **Chomsky Normal Form** or other formal normalizations are not needed for this DSL.
  The parser is small and human-focused; normal forms would add complexity without
  obvious benefit.
- **Context-sensitive features** (Type-1) are already the domain of admissibility
  semantics. Keeping them out of syntax preserves the "policy-as-data" structure and
  keeps parsing deterministic.
- **Two-phase language**: parsing accepts a superset; lowering enforces well-formedness.
  This keeps grammar growth constrained and pushes semantics into explicit checks.
- **Chumsky determinism contract**: parsing must be referentially transparent.
  Avoid parser-side interning, counting, or side effects that could change outputs or
  hashes; keep semantics in lowering/eval where determinism is tested.

## Recommended next docs/tests (small, concrete wins)

1. Add a short grammar reference (EBNF) in `meta/design/compiler/adm-grammar.md`
   that mirrors `execution/compiler-rs/crates/admit_dsl/src/parser.rs`.
2. Add 3-5 parsing fixtures covering precedence, parentheses, and scope-change
   ambiguity in `execution/compiler-rs/testdata/programs`.
3. Add a "semantic attribute" section to `meta/design/compiler/compiler-rs-plan.md`
   to document which checks are semantic (not grammatical) and why.
4. Add a one-page well-formedness checklist in `meta/design/compiler/adm-wellformedness.md`
   with stable IDs for lowering-time rules.
5. Add golden parse-error fixtures to stabilize error UX as the grammar grows.
