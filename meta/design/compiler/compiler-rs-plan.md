# Rust Admissibility Compiler Plan (Parallel, Replaceable)

This plan implements the **admissibility compiler** in Rust as a **parallel** tool that can eventually replace the current Python constraints engine. It applies the **Cost Declaration Protocol** and the vault **invariants** (governance, irreversibility, decomposition, attribution) as first-class constraints on the compiler itself, and aligns with `meta/design/compiler/admissibility-ir.md` as the kernel IR + witness spec.

Status date: 2026-01-29

---

## Design commitments (protocol + invariants)

**Cost Declaration Protocol (binding):**

1. **Declare cost before action**: no transformation is admissible unless its irreversible costs are declared **before** execution.
2. **Default deny**: erasure, scope expansion, and overrides are denied unless explicitly permitted.
3. **Cost routing**: every declared cost must be routed to an explicit sink (`bucket:*`).
4. **Witness-first**: all inadmissibility outcomes must emit structured witnesses with spans.
5. **Irreversible declarations**: cost declarations are ledgered and **never retracted**.

**Vault invariants (compiler-owned constraints):**

- **Governance**: rulesets and IR schemas are validated and versioned; ruleset changes are auditable.
- **Irreversibility**: default deny erasure + mandatory erasure accounting.
- **Decomposition**: scopes/modules prevent global soup; dependencies are explicit and validated.
- **Attribution**: every rule, permission, and cost declaration is source-attributed with spans + module IDs.

---

## Scope (explicit)

- **Parallel** Rust compiler that consumes the vault state and emits witnesses.
- **New syntax**: `.adm` (deprecate TOML rulesets over time).
- **Compatibility**: provide a temporary TOML-to-IR lowering path for parity with `epistemics/vault/meta/rulesets/*.toml`.
- **Extensible**: designed for eventual replacement of Python constraints engine (`execution/irrev/irrev/constraints/*`).

### TOML deprecation irreversibility cost

Deprecating TOML rulesets is an irreversible migration:

- **Preserved:** Lowering path from TOML to IR (compatibility for existing rulesets maintained)
- **Lost:** Native TOML authoring support, TOML-specific tooling
- **Migration ceremony:** Convert existing TOML rulesets to .adm, emit conversion witness artifacts, maintain TOML reader for legacy artifact replay

This cost is accepted because .adm provides first-class support for admissibility semantics that TOML cannot express.

Out of scope for v0:

- Full rewrite of Python constraints predicates.
- Full replacement of vault loader (we will bridge via a snapshot export).

## Repo location + crate layout (recommended)

Place the Rust compiler as a **peer surface**, not a new core:

```
execution/compiler-rs/
  Cargo.toml
  crates/
    admit_core/        # kernel IR + eval + witness emit (pure, deterministic)
    admit_dsl/         # .adm parser + lowering to kernel
    vault_snapshot/    # snapshot schema + loader + hashing
    ledger_emit/       # JSONL/event emission + artifact packaging
    facts_bundle/      # facts bundle schema + observation helpers
  bin/
    compiler.rs        # CLI front-end wiring the crates
  testdata/
    snapshots/
    programs/
    golden_witness/
```

Key constraint: `admit_core` stays pure; all effects live in `ledger_emit` or the CLI.

## Witness artifact type (recommended)

Use a **new artifact type** named `witness` as the canonical payload.
Treat `lint_report` as a rendered view, not the truth object.

If the registry requires versioning:

- `witness@1` (or `witness.v1`)
- `schema_id: "admissibility-witness/1"`

## Schema registry

See `meta/design/compiler/schema-registry.md` for the active and planned schema IDs
used by artifacts and ledger events.

## Artifact model + ledger spine (for `.adm`)

The ledger continues as an **append-only witness spine**. It records irreversible declarations/outcomes and points at immutable artifacts; it does not become a second database.

Artifacts (minimal set, v0):

- `adm_source`: human-authored `.adm` module (diffable input)
- `vault_snapshot`: normalized snapshot of vault state used as compiler input (hashable provenance)
- `witness`: proof output (verdict + facts + displacement trace + spans)

Artifacts (optional, staged):

- `admit_ir`: normalized kernel IR (canonical JSON/CBOR) for caching/diffing
- `admit_obj` (`.admc`): sealed compiled encoding (CBOR/MessagePack); must preserve spans (or carry a span table)

Ledger events (small + boring; always reference artifacts):

- `admit.compiled`: refs `adm_source` -> `admit_ir`/`admit_obj` and `vault_snapshot`
- `cost.declared`: refs `witness` with `kind="cost_declared"` (never retracted)
- `admit.checked`: refs `witness` with `kind="admissibility_checked"`
- `admit.executed` (future): refs execution artifacts and backrefs `cost.declared` + `admit.checked`

Hard rule:

> No ledger event without an artifact reference.

## Artifact encoding (identity vs projection)

Canonical encoding is part of artifact semantics:

- **Identity encoding:** CBOR with RFC 8949 canonical encoding rules (deterministic bytes).
- **Projection encoding:** JSON for human review and diffing (non-authoritative).
- **Content hash:** computed over the canonical CBOR bytes only (not over parsed JSON).

Float policy (v0):

- Prefer integer or fixed-point quantities.
- If floats are present, they must be finite; NaN/inf are forbidden.
- Encoders must normalize `-0.0` to `0.0` in the canonical stream.

## Alignment notes (with adjacent design docs)

- **Kernel IR + witness**: follows `meta/design/compiler/admissibility-ir.md` (8 primitives, default deny erasure, witness schema).
- **Current policy-as-data**: TOML rulesets remain canonical in `epistemics/vault/meta/rulesets/*.toml` during the transition.
- **Syntax naming**: `.adm` is the chosen file extension; existing mentions of `.admit` in earlier notes should be treated as legacy naming.
- **Artifact type**: `witness` is the canonical output; `lint_report` is a rendering.

--- 

## Canonical CBOR primer (for humans)

CBOR is “JSON engineered for machines that care about exact bytes.” The key reminders:

- CBOR encodes the same primitives as JSON (maps, arrays, numbers, strings) yet has smaller size, explicit types, and **RFC 8949 canonical rules**.
- Canonical CBOR enforces shortest integers, sorted map keys (by length then byte order), and no redundant representations, so “same data = same bytes.”
- This fixes your requirements: `hash = identity`, ledger verifiability, and deterministic `.adm → IR → witness` pipelines.
- Store the canonical CBOR in the ledger and optionally render JSON projections for humans; never hash the JSON.
- Ban floats (or normalize them) to avoid canonical pitfalls (no NaN/Inf, normalize `-0.0`).

## Admissibility lattice + path finding (future, non-prescriptive)

Treat admissibility as a **lattice of states** ordered by “has at least these commitments/constraints/permissions.”
This provides a geometry of constraint space without prescribing action.

State (v0 summary for search):

- permissions (allow/deny per difference)
- erasure rules (routing + cost per difference)
- commits (diff -> value)
- constraints (inadmissible_if predicates)
- derived totals (bucket accumulations)

Ordering:

- A <= B if B contains all facts/constraints/permissions in A plus more.
- Join (⊔) composes modules; meet (⊓) captures common subsets.

Path finding:

- **Edges** are typed deltas (small IR patches), e.g. add `Commit`, add `Constraint`,
  add `AllowErase` + required `ErasureRule`.
- **Weights** are displacement costs and governance friction (permissions/overrides/scope expansion),
  allowing multi-criteria (Pareto) search instead of a single scalar.
- **Targets** are structural predicates (e.g., “admissible and constraint X not triggered”),
  never desirability goals.

Witness integration:

- Each node yields a standard `Witness`.
- Each edge can emit a delta witness (permission uses, displacement contributions).
- Path output is a sequence of (delta, witness) pairs as an artifact (future `path_witness`).

Guardrail:

- Path finding is a query; it must not be framed as a recommendation engine.

Potential v1 IR extension:

- `Query PathFind(target_predicate, cost_vector, k)` with a `path_witness` schema.

---

## Milestones (phased implementation)

### Phase 0 — Project skeleton + IO contract (week 1)

**Goal:** establish the Rust compiler surface and stable IO contract.

- Create `execution/compiler-rs/` (or `execution/irrev-rs/`) with a `compiler` binary.
- Define **input contracts**:
  - Vault snapshot JSON (exported by existing Python loader).
  - `.adm` source files (new syntax).
  - Optional: TOML ruleset import for parity.
- Define **output contract**:
  - Witness JSON (stable schema, versioned) per `admissibility-ir.md`.
  - Optional IR dump (debug).
- Establish versioned schema IDs for:
  - `Admissibility IR`
  - `Witness`
  - `Cost Declaration`

**Protocol application:**

- No admissibility check without cost declaration output.
- Output always includes a `Witness` object, even for admissible cases (verdict + trace).

### Phase 1 — Kernel IR + Witness schema (week 1–2)

**Goal:** encode the minimal admissibility kernel and witness format in Rust.

Implement the IR types (8 primitives from `admissibility-ir.md`):

- `DeclareDifference`
- `DeclareTransform`
- `Persist`
- `ErasureRule`
- `AllowErase` / `DenyErase`
- `Constraint`
- `Commit`
- `Query`

Implement the witness format (verdict + facts + displacement trace):

- `verdict`, `reason`, `facts[]`, `displacement_trace`
- typed facts with `Span` + module attribution

Add identity hashes to the witness header:

- `program_hash` (normalized IR hash)
- `snapshot_hash`
- `ruleset_hash` (only when TOML lowering is used)

For v0, **witness minimization is a non-goal**; prioritize determinism and completeness.

**Protocol application:**

- Add invariant checks: any `AllowErase` must have `ErasureRule` and `displaced_to`.
- Require `Span` on all IR nodes to satisfy attribution invariant.

### Phase 2 — `.adm` parser + lowering (week 2–3)

**Goal:** introduce the new `.adm` syntax and lower it into the kernel IR.

- Define `.adm` grammar (explicit scope blocks, namespaces, declarations).
- Implement parser with recoverable spans.
- Lower parsed AST into kernel IR.
- Reserve namespaces: `difference:*`, `transform:*`, `bucket:*`, `constraint:*`, `scope:*`, `module:*`.
- Mirror the front-end location described in `compiler-idea-context.md` by wiring a Rust-backed front-end under `execution/irrev/irrev/frontends/admit_dsl` (thin adapter or CLI bridge).

Grammar outline (v0):

```
module <name>@<major>            # or module:<name>@<major>
depends [<name>@<major>, ...]    # or module:<name>@<major>
scope  <name>                    # or scope:<name>

difference <name> [unit "<unit>"]   # or difference:<name>
transform  <name>                   # or transform:<name>
bucket     <name>                   # or bucket:<name>
constraint <name>                   # or constraint:<name>

persist <difference> under [<transform>, <transform>]

deny_erase  <difference>
allow_erase <difference>
erasure_rule <difference> cost <number> "<unit>" -> <bucket>

commit <difference> = <bool|string|number ["<unit>"]>

inadmissible_if <bool-expr>

query admissible
query witness
query delta
```

Dependency rule (v0):

- Every module must declare explicit dependencies and include the core irreversibility stdlib
  (proposed: `module:irrev_std@1`).
- The compiler rejects programs missing required dependencies or with undeclared cross-module references.

Erasure note (v0):

- `erase` is a builtin transform concept; it does not require a `transform` declaration.

Determinism rules (v0):

- declarations are order-insensitive; serialize sorted by namespace+name
- constraints evaluate in file order
- witness facts sorted stably by type then span

**Protocol application:**

- Enforce default deny erasure at parse-time if no explicit permission is declared.
- Require `ErasureRule` for any declared `AllowErase`.

### Phase 3 — Constraint engine + predicate evaluation (week 3–4)

**Goal:** evaluate IR deterministically with bounded boolean algebra.

  - Implement boolean algebra + predicates (as in `admissibility-ir.md`):
    - `EraseAllowed`, `DisplacedTotal`, `HasCommit`, `CommitEquals`, `CommitCmp`
  - Deterministic evaluation with monotonic facts inside a scope.
  - Enforce unit compatibility for comparisons.

  **Phase 3 checklist:** refer to `meta/design/compiler/compiler-rs-phase3-checklist.md` for the ordered tasks that ensure deterministic semantics, predicate tracing, and canonical witness readiness.

  **Protocol application:**
  
- Default deny erasure is enforced in the evaluator.
- All predicate evaluations emit witness facts.
- Displacement trace explicitly marks `mode: "potential"` in v0 (no explicit erasure actions yet).

### Phase 4 — Cost Declaration Protocol (week 4–5)

**Goal:** implement the protocol phases as explicit compiler commands backed by canonical witness commitments.

**Commands:**

1. `compiler propose` (Phase 0)
2. `compiler declare-cost` (Phase 1)
3. `compiler check` (Phase 2)
4. `compiler execute` (Phase 3 — optional/gated)

**Outputs:**

- `cost.declared` event that includes the canonical witness bytes, witness SHA256, witness schema ID, compiler build hash (or version + commit), and displacement trace.
- `admissibility.checked` witness (structured) that references the same hash.

**Protocol application:**

- Cost declaration is ledgered and immutable (cannot be retracted or replaced).
- A `cost.declared` event is valid only if `sha256(canonical_cbor(witness_json)) == witness_sha256` and those bytes are RFC 8949 canonical, which makes the verifier rule mechanized.
- The `execute` command requires a prior `cost.declared` event ID. Enforcement: the CLI gate verifies the event exists in the ledger before proceeding. Bypass path: direct ledger file write (mitigated by file permissions and CI schema validation).

**Leveraging Phase 3 deliverables (improvements):**

- Canonical witness artifacts from Phase 3 become the *input contract* for Phase 4: `declare-cost` must seal and emit the RFC 8949 bytes + SHA256 hash that were captured in the golden fixtures.
- `cost.declared` events must include the displacement trace, canonical witness hash, witness schema ID, compiler build hash (or version + commit), and optional snapshot hash so downstream ledger consumers can verify provenance before any `check` or `execute` command.
- The command surface accepts explicit artifact references (`witness_id`, `content_hash`) so the ledger can enforce immutability (`cost.declared` cannot run unless the witness hash matches the canonical bytes produced in Phase 3).
- Introduce a lightweight `witness-verifier` subcommand that reruns the canonical CBOR serializer on the stored witness (optionally by loading the JSON projection + reserializing) to guard against drift before ledger emission.

### Phase 5 — Vault snapshot bridge (week 5)

**Goal:** connect Rust compiler to real vault state.

- Add a Python exporter (temporary) that writes a normalized vault snapshot JSON:
  - concepts, diagnostics, domains, projections, invariants
  - graph dependencies
  - ruleset metadata
- Rust consumes snapshot as the canonical vault input.

**Protocol application:**

- Snapshot is hashed and included in witness metadata (traceable provenance).

### Phase 5.5 — Program bundle bridge (week 5)

**Goal:** introduce a canonical ProgramBundle contract so the compiler can accept
either vault-projected `.adm` or stabilized ADM packs without changing evaluation
logic.

- Define `program-bundle/0` schema (canonical JSON, stable ordering rules).
- Implement vault projection: extract explicit ` ```adm ` blocks from notes with
  `surface: adm` into module files and a ProgramBundle.
- Implement `program_bundle` loader in Rust and verify bundle hash.
- Add `--bundle <path>` to compiler CLI (or `admit_cli check`) as the canonical
  program input.

**Protocol application:**

- Bundle hash is a first-class identity input (content-addressed).
- Bundle provenance is carried into witness metadata.

### Phase 5.6 — Facts bundle + observation runner (week 5–6)

**Goal:** introduce a canonical facts bundle and a minimal observation pipeline
so text sources can contribute witnessable, deterministic facts without changing
the kernel IR.

- Define `facts-bundle/0` schema (canonical JSON, stable ordering rules).
- Implement a minimal observation provider: regex scanner over markdown/text.
- Add `admit observe` CLI to emit a facts bundle + hash.
- Wire `admit check` to accept `--facts-bundle` (or `FACTS_BUNDLE_PATH`) and
  include the bundle hash in witness metadata.
- Add golden fixtures: facts bundle + input text → stable witness hash.

**Protocol application:**

- Facts bundles are content-addressed and immutable.
- Observation output is deterministic and witnessable (no prescriptive output).

**Related note:**

- `meta/design/compiler/semantics-instrumentation-ritual-binding.md`

### Phase 6 — Ledger + witness integration (week 6)

**Goal:** emit artifacts compatible with existing ledger/event infrastructure.

- Emit `constraint.evaluated` / `invariant.checked`-like events using Rust ledger output.
- Add a `witness` artifact type (or reuse `lint_report` with witness payload).
- Store full witness payload as content and reference it by artifact_id.

**Protocol application:**

- Witness artifacts are immutable and addressable.
- Ledger records are append-only, enforcing irreversibility.

### Phase 7 — Parity testing + replacement path (week 6–7)

**Goal:** compare Rust output with current Python lint and create a replacement strategy.

- Add a comparison harness:
  - Same inputs → compare verdict + witness facts.
- Document gaps in predicates and scope mapping.
- Create a transition plan:
  - Python as fallback; Rust as primary once parity reached.

**Protocol application:**

- Differences in admissibility must be witnessable (no silent divergence).

---

## Workstreams (parallelizable)

1. **Syntax + parser** (.adm grammar + spans)
2. **Kernel IR + evaluation**
3. **Witness schema + ledger integration**
4. **Vault snapshot exporter (Python)**
5. **Parity testing harness**

---

## Risks + guardrails

- **Risk:** `.adm` syntax not aligned with vault semantics.
  - **Guardrail:** require concept-locked identifiers; reserve namespaces; fail early.
- **Risk:** erasure rules are bypassed via implicit predicates.
  - **Guardrail:** default deny + hard invariant: allow erase implies erasure rule.
- **Risk:** witness drift (non-deterministic output).
  - **Guardrail:** deterministic ordering; stable serialization; content hashing.

---

## Definition of done (v0)

- `.adm` parser + kernel IR implemented in Rust (kernel aligned with `admissibility-ir.md`).
- Deterministic admissibility evaluation with default deny erasure.
- Structured witness JSON with spans and displacement trace.
- Ledger-compatible witness artifact emitted.
- Snapshot bridge to vault data.
- Parallel CLI runnable without breaking Python workflow.
- TOML parity path available for diffing (even if deprecated).

---

## Next steps (execution-ready)

1. Confirm repo location for Rust compiler crate.
2. Decide witness artifact type ID (new or `lint_report`).
3. Draft `.adm` grammar outline for review.
