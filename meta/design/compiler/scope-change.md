# Scope Change (Compiler Boundary Primitive)

Status date: 2026-01-29

This note introduces **scope-change** as a first-class operation in the Rust
admissibility compiler. Scope change is not a UX feature. It is an
admissibility/irreversibility boundary primitive with deterministic, witnessable
semantics.

Related concepts:

- [[irreversibility]]
- [[erasure-cost]]
- [[displacement]]
- [[admissibility]]
- [[feasible-set]]
- [[persistence]]
- [[transformation-space]]

## Intent (structural)

A scope change crosses a boundary where distinctions may be lost and commitments may
persist across domains. The compiler treats this boundary crossing as an implicit
erasure surface unless explicit accounting exists.

## Vocabulary (minimal)

- Boundary: a crossing between scopes/domains.
- Scope change: a boundary event recorded in the program IR.
- Boundary loss: distinctions that may not survive the crossing (mode-dependent).
- Accounting requirement: widen/translate boundary loss is inadmissible unless it is
  explicitly allowed and cost-routed.

## IR shape

The kernel IR introduces a statement:

- `Stmt::ScopeChange { from, to, mode, span }`

Where `mode` is one of:

- `widen`: increases scope / blast radius
- `narrow`: reduces scope (still witnessed)
- `translate`: cross-domain reinterpretation

All scope-change statements carry a Span for attribution.

## v0 semantics (deterministic)

Scope change is evaluated as a boundary event.

1. A `ScopeChangeUsed` fact is emitted for every scope-change statement.
2. For `mode in {widen, translate}` the program is inadmissible unless explicit
   accounting exists for the boundary loss.

Accounting mechanism (minimal primitives, v0):

- Model boundary loss as a synthetic difference:
  `difference:boundary_loss:<from>-><to>`
- Accounting exists if and only if:
  - `AllowErase(boundary_loss_diff)` is present, and
  - `ErasureRule(boundary_loss_diff)` is present and routes to a bucket.

Boundary-loss naming convention (compiler-owned):

- `boundary_loss_diff_name(from: &ScopeId, to: &ScopeId) -> String`
- `boundary_loss_diff(from: &ScopeId, to: &ScopeId) -> SymbolRef`

If accounting is missing, the witness records an `UnaccountedBoundaryChange` fact and
the verdict becomes inadmissible.

For `mode == narrow`, the boundary change is still witnessed but does not require
additional accounting in v0.

## Witness + identity

Witnesses are proof objects:

- canonical CBOR (RFC 8949) defines artifact identity bytes
- SHA256 over canonical CBOR defines the witness hash

Scope change contributes deterministic facts:

- `Fact::ScopeChangeUsed { from, to, mode, span }`
- `Fact::UnaccountedBoundaryChange { from, to, mode, span }` (only when accounting is
  missing for widen/translate)

Facts are ordered deterministically by type rank then span fields.
