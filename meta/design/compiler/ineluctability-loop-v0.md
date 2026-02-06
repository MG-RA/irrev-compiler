# Ineluctability Loop v0 (Operational Plan)

Date: 2026-02-06

This plan turns the "Ineluctability Loop" into a repeatable, auditable engine.

Core principle: SurrealDB is memory/microscope; the Rust court is the authority. Every lap is a court artifact with stable identity.

## Goals

- Make "running the loop" a deliberate, repeatable workflow.
- Ensure every loop lap is pointable (identity), replayable (inputs), and comparable (pressure metrics).
- Require a plan artifact for every idea before operationalization.
- Keep semantic tooling (embeddings, suggestions) strictly propositional; acceptance requires governance.

## Non-goals (v0)

- Do not auto-apply link repairs, merges, renames, or governance changes.
- Do not make SurrealDB authoritative for identity or admissibility.
- Do not require cryptographic signatures for approvals (can be added later).

## Current substrate (already implemented)

- Content-addressed artifacts in `out/artifacts/` (canonical CBOR + sha256).
- Append-only ledger in `out/ledger.jsonl` (court event chain).
- SurrealDB projections for:
  - DAG traces (`dag_trace`, `node`, `edge`)
  - vault docs (`doc_file`, `doc_chunk`, `doc_heading`, `doc_stats`)
  - vault graph (`obsidian_link`, `obsidian_file_link`, `doc_link_unresolved`)
  - embeddings (`embed_run`, `doc_embedding`, `doc_embedding_doc`, `doc_title_embedding`)
  - unresolved-link suggestions (`unresolved_link_suggestion`)

v0 builds on these without changing their "court vs memory" roles.

## The Loop (operational form)

Each lap is: Idea -> Plan -> Implementation/Projection -> Diagnostics/Pressure -> Refinement -> Lap record

### Stage 1: Idea / Framing

- Artifact: a markdown note (often in the vault) capturing 1-3 sentences.
- Success: the idea is pointable (doc_path + optional chunk reference).

### Stage 2: Plan (required)

Every idea MUST have a plan artifact before operationalization.

- Artifact: `plan/*` artifact (existing plan machinery).
- Success: plan exists, with explicit scope and prompts (if relevant).

### Stage 3: Implementation

- Artifacts: code changes, projection additions, DSL stubs, queries, indices.
- Success: tool/projection runs without manual curation and emits machine-produced outputs.

### Stage 4: Diagnostic pressure

- Artifacts: diagnostics outputs as projections and/or court artifacts (see pressure schema below).
- Success: results can surprise (awkward output is evidence of real pressure).

### Stage 5: Refinement under pressure

- Artifacts: updated definition, narrower scope, new invariant, new guardrail, explicit non-goal.
- Success: degrees of freedom decrease; misuse becomes harder; exceptions become explicit.

### Lap record (court artifact)

After diagnostics and refinement, record the lap as a court artifact: `loop_run/0`.

## Court artifact: `loop_run/0` schema

Encoding: canonical CBOR map (Rust-minted), content-addressed by sha256 of canonical bytes.

Recommended minimal payload (v0):

```json
{
  "schema_id": "loop-run/0",
  "schema_version": 0,
  "run_id": "<sha256 of canonical bytes>",
  "created_at_utc": "2026-02-06T01:23:45Z",

  "idea": {
    "doc_path": "irrev-vault/meta/Ineluctability under Irreversibility.md",
    "chunk_sha256": "optional",
    "start_line": 0
  },

  "plan": {
    "plan_id": "required",
    "plan_artifact_sha256": "required"
  },

  "inputs": {
    "root": "\\\\?\\C:\\\\Users\\\\user\\\\code\\\\Irreversibility",
    "snapshot_sha256": "optional",
    "parse_sha256": "optional",
    "dag_trace_sha256": "optional",
    "embed_run_id": "optional",
    "compiler_build_id": "optional"
  },

  "pressure_summary": {
    "structural": { "items": 0 },
    "hygiene": { "missing": 0, "heading_missing": 0, "ambiguous": 0 },
    "semantic": { "items": 0 },
    "quantitative": { "items": 0 }
  },

  "pressure_items": [
    {
      "kind": "hygiene.unresolved_links",
      "severity": "warn",
      "evidence": { "query": "optional", "table": "doc_link_unresolved" },
      "metrics": { "missing": 8, "heading_missing": 2, "ambiguous": 0 }
    }
  ],

  "refinement": {
    "git_commit": "optional",
    "refs": [
      { "kind": "doc_edit", "doc_path": "..." },
      { "kind": "rule_change", "rule_id": "..." }
    ]
  },

  "notes": "short optional text"
}
```

Notes:
- `run_id` is redundant but useful for cross-system referencing; it MUST match the canonical hash.
- The schema intentionally allows optional inputs; a lap can be "docs-only" early on.
- The plan reference is required; this enforces "ideas must operationalize intentionally."

## Pressure taxonomy (v0)

Pressure is a measurement, not a truth oracle. v0 keeps four lanes:

1) structural
- DAG validity: cycles, scope boundary violations, authority reachability, missing witnesses for risk classes

2) hygiene
- unresolved links, ambiguous targets, missing headings, orphaned facets

3) semantic
- embedding-based surprises: nearest neighbors that contradict expected neighborhoods, cluster collisions, drift across runs

4) quantitative
- counts, deltas, rates (trend lines across laps)

Ranking rule:
- Structural pressure dominates refinement. If refinement is not responding to structural pressure, the loop is stalling.

## CLI surface (proposed)

Add a new CLI group: `admit_cli loop ...`

### `loop new`

Creates a `loop_run/0` artifact in "draft" mode pointing at:
- idea doc reference
- required plan reference

### `loop lap`

Generates a lap record from current projections:
- reads latest ingest inputs (snapshot/parse/dag trace) if available
- reads latest `embed_run` for the same parse (or user-provided)
- computes pressure summary (queries SurrealDB if enabled; else uses artifacts-only heuristics)
- writes `loop_run/0` artifact

### `loop show`

Renders a human-friendly view of a lap record.

## SurrealDB projection (optional, recommended)

Project `loop_run/0` artifacts to SurrealDB for browsing.

Tables:
- `loop_run` (one per run_id)
- `loop_pressure` (one per pressure_item)

Relations (optional but useful):
- `RELATE loop_run -> about -> doc_file`
- `RELATE loop_run -> uses_plan -> plan` (if/when plan becomes a projected table)
- `RELATE loop_run -> uses_embed_run -> embed_run`

Design constraint:
- SurrealDB stores and indexes; it does not mint identities. The court artifact remains the source of truth.

## Governance: suggestions are propositional

Embedding-backed outputs (e.g. `unresolved_link_suggestion`) are:
- allowed as projections
- allowed as pressure evidence
- NOT allowed to directly mutate notes or rules

Acceptance requires:
- a plan artifact reference
- (later) an approval artifact + witness bundle for risky mutations

## Milestones

M0 (small): Lap artifact and doc-only laps
- Define `loop_run/0` schema and artifact writer/reader.
- CLI: `loop new`, `loop show` (artifacts-only).

M1 (medium): Pressure extraction from current projections
- CLI: `loop lap` computes hygiene pressure from `doc_link_unresolved` (SurrealDB optional).
- Include `embed_run` and unresolved-link suggestion counts as semantic pressure evidence when available.

M2 (medium): SurrealDB projection for loop runs
- Add `loop_run` and `loop_pressure` tables and projection functions.
- Add Surrealist query templates (trend views).

M3 (later): Ledger integration (ceremony)
- Append a ledger event `LoopRunRecorded` referencing `loop_run` artifact sha256 + inputs.
- Add `ledger_event` time-series projection to SurrealDB.

## Success criteria (v0)

- You can "mark a lap" with a single command and get a stable identity back.
- Every lap references a plan artifact (no unplanned operationalization).
- Pressure summaries are queryable and comparable across laps.
- Suggested actions remain propositional and require governance to apply.

