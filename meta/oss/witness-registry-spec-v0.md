# Witness Registry Spec v0

Status date: 2026-01-30
Owner: mg

## Purpose

Capture the missing piece: once you have plan bundles, witnesses, and evidence bundles, you need a governance-friendly registry to store, index, fetch, and verify those proof objects across scopes.

## Key Concepts

### PlanBundle

Intended effect (what would change). Content-addressed canonical CBOR + hash.

### Witness

Verdict + evidence trace (why admissible/inadmissible, costs, findings, spans).

### EvidenceBundle

Sealed envelope that ties everything together for third-party verification. Recommended contents:

- `bundle_manifest.json` (hashes, schema IDs, dependencies)
- `plan.cbor` + hash
- `witness.cbor` + hash
- `inputs/` references (snapshot hash, repo state hash, tool versions)
- Optional: `result.cbor` + result witness (if executed)
- Optional rendered views (JSON/HTML)

## Registry Responsibilities

1. **Content-addressed storage** – Blobs stored/served by hash (e.g., `sha256(canonical_cbor)`). Immutability becomes natural.
2. **Indexing & discovery** – Index by `scope_id`, `rule_id`, `artifact_type`, `time`, `producer`, `schema_id`. Answer queries like “show all prod executions last week” or “show all `broken-link` findings in vault scope.”
3. **Verification** – Each fetch is verified locally: hash matches bytes, schema IDs match, witness references align with plan + snapshot hashes. Registry is untrusted storage; clients verify proof objects themselves.

## Ledger vs Registry

- Ledger = append-only event spine (“this happened”). Small, chronological, auditable.
- Registry = content store for blobs (“here are the proofs”). Big, deduplicated, indexed.

Ledger entries reference registry hashes. Registry never interprets meaning.

## Agent-Safe Workflow

LLMs/agents become non-authoritative planners:

1. Agent generates candidate `.adm` programs or manipulations.
2. Compiler produces `PlanBundle` + `Witness` for each.
3. Bundle + witness packaged into `EvidenceBundle`.
4. Human/policy chooses one path.
5. Execution runs `execute(plan_hash)` only.
6. Result witness stored in registry.

Agents are option generators; decisions rest with policy/humans.

## EvidenceBundle Manifest

Treat `evidence_bundle/1` as an artifact type:

- Manifest fields: `bundle_id`, `plan_hash`, `witness_hash`, `snapshot_hash`, optional `result_hash`, `inputs`, `schema_ids`, `producer`, `timestamp`.
- Each member referenced by role (`plan`, `witness`, `snapshot`, `result`).
- Manifest hash becomes the shareable bundle id: “share evidence = share one hash.”

## Registry CLI (v0)

Local-first interface:

- `registry put <file>` – validate canonical encoding, store by hash.
- `registry get <hash>` – fetch and verify bytes against schema/hash.
- `registry query --scope ... --rule ...` – indexed discovery.

Optional HTTP layer may be added later without changing identity semantics.

## Evidence Sharing

Sharing evidence is sharing a manifest hash. Consumers fetch each referenced artifact, verify canonical bytes/hashes, and then trust the proof object.
