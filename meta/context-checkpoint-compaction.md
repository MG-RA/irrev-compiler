---
role: support
type: design-note
canonical: true
facets:
  - governance
  - protocols
---

# Context Checkpoint Compaction

## Purpose

Capture the habit of "paying for clarity before doing work" so that context checkpoints stay compact, shareable, and auditable. This note is the record of the meta-algorithm you surfaced: do the irreversible thinking up front and treat each scope as a checkpoint.

## Key ideas (summary)

- **Scope-first design**: break goals into implied scopes, identify primitives, and formalize the foundational layers before adding higher-level capabilities.
- **Irreversible cost accounting**: treat ambiguity as a latent cost; record boundary claims, primitives, and witness shapes so you can later verify that work was built on a solid checkpoint.
- **Context compaction**: each checkpoint is a small, canonical artifact (boundary statement, snapshot schema, predicate family, witness shape, gold fixture) that can be hashed and referenced instead of long-running prose.
- **Procedure as artifact**: encode the procedure itself (scope addition, meta-extension) as a pack or `.adm` module so the system can reason about when it’s time to expand core.
- **Pattern literacy**: once the scaffolding is explicit, pattern-based diagnostics become the social contract—scope patterns, boundary facts, and witness registries keep context compressed.

## Next actions

1. Keep every new scope launch documented with the checkpoint artifacts above so later audits can reconstruct the decision without re-reading long narratives.
2. Use the `Context Checkpoint Compaction` note as a reference for future docs; link it from the architecture map so it becomes part of the narrative scaffolding.
3. When expanding scope catalogs, rely on this note to decide whether a new scope needs a dedicated `.scope` manifest or can be treated as a derived projection.
