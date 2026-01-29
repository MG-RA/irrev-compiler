# Semantic Providers Plan (Vault + ADM Packs)

Status date: 2026-01-29

This plan defines a pluggable architecture where the compiler consumes a **canonical
ProgramBundle**, regardless of whether the source is the vault or a stabilized ADM
pack. The compiler evaluates bundles and emits witnesses; providers only supply
canonical inputs and provenance.

## Goal

Enable two interoperable sources of meaning:

- **Vault provider**: human-legible notes + projection blocks produce `.adm` modules.
- **ADM pack provider**: stabilized `.adm` modules stored as production inputs.

Both providers emit **the same ProgramBundle schema**, so the compiler consumes a
single canonical input contract.

## Non-goals

- No free-form prose compilation.
- No LLM interpretation of note content.
- No server or async orchestration.

## Core contract: ProgramBundle

### Identity rule

`bundle_hash = sha256(canonical_json_bytes(program_bundle))`

Canonical JSON rules follow the snapshot rules: UTF-8, sorted object keys,
no extra whitespace, arrays already deterministically ordered.

### ProgramBundle v0 (JSON)

```
{
  "schema_id": "program-bundle/0",
  "schema_version": 0,
  "programs": [
    {
      "module_id": "module:irrev_std@1",
      "path": "adm-pack/irrev_std@1/core.adm",
      "sha256": "<file hash>",
      "content": "<optional inline text>"
    }
  ],
  "dependencies": [
    ["module:domain@1", "module:irrev_std@1"]
  ],
  "provenance": {
    "source": "vault|adm-pack",
    "generator_id": "vault-projection/0",
    "generator_hash": "<hash>",
    "snapshot_hash": "<hash>"
  }
}
```

### Ordering rules

- `programs` sorted by `module_id`, then `path`
- `dependencies` sorted lexicographically by `(from, to)`
- `provenance` fields fixed by schema order

### Provenance requirements

- `snapshot_hash` is required for the vault provider
- `generator_id` + `generator_hash` identify the projection tool or pack version

## Provider interface (conceptual)

```
trait SemanticProvider {
  fn build_bundle(input: ProviderInput) -> ProgramBundleWithHash
}
```

### Provider A: VaultProvider

Input: vault path or snapshot

Output:

- ProgramBundle with `source = "vault"`
- Bundle hash
- Generator metadata

### Provider B: AdmPackProvider

Input: folder of `.adm` modules

Output:

- ProgramBundle with `source = "adm-pack"`
- Bundle hash
- Generator metadata (git commit or manifest hash)

## Projection convention (vault → adm)

Projection blocks are explicit and deterministic. Notes that participate include:

- frontmatter keys:
  - `surface: adm`
  - `module: module:<name>@<ver>`
- fenced ` ```adm ` blocks that define module content

The exporter concatenates blocks for the same module in file order and preserves
source spans for traceability.

## Pipeline (canonical chain)

```
Vault files -> snapshot.json -> ProgramBundle.json -> witness -> ledger
```

Each hop produces a hash over canonical bytes. Provenance is embedded in the bundle
and carried into the witness metadata.

## P0 implementation plan

### P0.1 — ProgramBundle schema

- Add schema doc (this note).
- Add canonical JSON rules (done here).
- Add `program-bundle/0` id.

### P0.2 — Vault projection extractor (Python)

- Walk vault and collect projection blocks.
- Emit `.adm` files (one per module) plus ProgramBundle JSON.
- Compute canonical bundle hash and write `bundle.json.sha256`.

### P0.3 — Rust bundle loader

- Add `program_bundle` crate with schema + canonical hashing.
- Provide `load_bundle_with_hash(path)` API.
- Verify canonical hash matches provided `.sha256` (if present).

### P0.4 — Compiler integration

- Add CLI option or subcommand to load/verify `program-bundle.json`.
- Use bundle hash as program provenance in witness metadata (Phase 6).

### P0.5 — Golden test

- Tiny vault fixture containing 1 module and 1 `.adm` block.
- Generated bundle hash is deterministic.
- Bundle feeds compiler and produces stable witness hash.

## P1 stabilization plan

- Add `adm-pack/` layout with manifest.
- Add `verify-pack --from-vault` to diff generated vs committed packs.
- Add bundle-to-IR cache keyed by bundle hash.

## P2 ergonomics plan

- Emit provenance map (source spans) as a separate artifact.
- Add JSON report of projection differences.

## File layout (proposed)

```
execution/compiler-rs/
  crates/program_bundle/
  testdata/bundles/
execution/irrev/irrev/commands/
  projection.py
adm-pack/
  irrev_std@1/*.adm
```

## Acceptance criteria

- Bundle hash is deterministic and stable across machines.
- Compiler consumes bundles from both providers without code changes.
- Witnesses carry bundle provenance.
