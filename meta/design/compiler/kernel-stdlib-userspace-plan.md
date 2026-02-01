# Kernel vs Stdlib vs User Space (Ship boundaries)

Status date: 2026-01-31

## Purpose

Clarify what belongs in:

1. the **kernel** (Rust authority; “the court”),
2. the **stdlib** (shipped defaults; “the law books”), and
3. **user space** (vault/packs/plugins; “commentary and jurisdictions”),

so the system remains governable while still being useful on day 1.

## Layer 1 — Kernel (Rust, non‑negotiable authority)

The kernel is the minimal machinery required to:

- parse/lower/check admissibility programs
- request/accept witnesses
- encode witnesses deterministically (canonical encoding + hashing)
- append/query the ledger (append‑only integrity)
- enforce “unknown IDs are inadmissible” once meta registry exists
- enforce phase/authority boundaries and deadlock‑class invariants

Kernel rule: keep it small, boring, and hard to change.

What belongs here:

- admissibility IR + evaluator
- canonical witness encoding (CBOR) + hashing rules
- ledger integrity + artifact references
- registry gating (schema_id/scope_id) per `meta-registry-gate-plan.md`
- constitutional checks that must not be bypassable (phase discipline, deadlock class)

What does *not* belong here:

- domain‑specific logic (vault, db, kubectl, git…)
- vault rule IDs / project doctrine
- “convenient defaults” that are policy

## Layer 2 — Stdlib (shipped defaults, not the kernel)

Stdlib is “official” but:

- versioned
- declared in the registry
- replaceable
- auditable like everything else

Stdlib rule: if it can’t be expressed as artifacts the system can govern, it probably doesn’t belong in stdlib (and might be kernel).

### What stdlib should contain (minimal, strong)

The goal is a default set that makes the system immediately composable:

**A) `meta` domain (needed early)**

- `meta.schema` (schema IDs + validation rules as artifacts)
- `meta.scope` (scope contracts as artifacts)
- `meta.registry.core` (authoritative registry artifact)
- `meta.registry.verify` (drift checks; may exist as a tool surface too)

**B) Foundational substrate scopes (“physics primitives”)**

- `file.observe`
- `hash.content`
- `calc.eval` (exact, deterministic)
- `time.now` (explicit oracle)
- `binary.identity` (derived from bytes+hash; no oracles)

**C) Workflow governance scopes**

- `plan.declare`, `plan.bind`, `plan.check`
- `boundary.declare`, `boundary.check` (or boundary facts emitted by runtime)
- `artifact.store` (content‑addressed storage surface; file‑backed is fine)

**D) Ledger surfaces**

- `ledger.append` (kernel-enforced integrity, but surfaced as a scope boundary)
- `ledger.query`

### Current state of `irrev_std@1` (implementation reality check)

In the current Rust compiler implementation, `module:irrev_std@1` is required by lowering, but the repo does not yet contain a shipped stdlib module directory (the docs mention future layouts like `adm-pack/irrev_std@1/core.adm`).

So the “stdlib” currently exists as a *required name*, not yet as a concrete, governed artifact set.

## Layer 3 — User space (vault, packs, plugins)

Everything that is:

- opinionated
- dataset-specific (the irreversibility vault)
- experimental/fast‑changing
- per team / per project policy

Examples:

- vault lint packs (patterns/projections/diagnostics)
- DB projections and indexes tuned to workflow
- domain DSL plugins (later)

User space rule: it must be possible to delete user space without breaking the court.

## Where irreversibility “lives”

Split irreversibility into three forms:

1. **Kernel invariants (constitutional, non-bypassable)**
   - “effects must be logged”
   - “authority cannot be emitted by non-authoritative components”
   - “unknown schema/scope IDs are inadmissible” (meta-governance)
   - “no scope may require its own verdict to produce required witnesses” (deadlock class)
   - “oracle usage must be declared or claims downgraded”

2. **Stdlib domains/scopes (default governance languages)**
   - `meta.*`, `plan.*`, `boundary.*`, `artifact.*`, `ledger.*`

3. **Vault content (doctrine / diagnostics / pattern catalogs)**
   - valuable, but must not be fused to compiler authority

## Inclusion tests (decide what goes where)

When deciding whether something belongs in kernel:

1. **Bypass test:** can a malicious/buggy plugin bypass it? If yes → kernel.
2. **Authority test:** does it define authority or only produce evidence?
   - authority boundaries → kernel/meta
   - evidence production → scopes/stdlib
3. **Bootstrap test:** required to load/verify IDs from zero? If yes → kernel+stdlib(meta).

