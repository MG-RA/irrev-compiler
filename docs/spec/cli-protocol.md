# CLI Ceremony Protocol (Normative)

Version: 0.1  
Status date: 2026-02-11

## Scope

This spec defines binding CLI ceremony for admissibility-related effects.

## Primary Chain

The canonical chain is:

1. `declare-cost`
2. `check`
3. `execute`

Normative requirements:

1. `declare-cost` MUST bind witness hash, snapshot hash, and program reference.
2. `check` MUST validate the declared event and artifact hashes before emitting `admissibility.checked`.
3. `execute` MUST require a prior checked event id and MUST re-verify referenced hashes before emitting `admissibility.executed`.

## Binding Rules

## C-010 - Ledger-bound identities

`event_id` values MUST be derived from canonical payload bytes and re-checkable during verification.

Enforced by:

- `crates/admit_cli/src/witness.rs` (`payload_hash` checks)
- `crates/admit_cli/src/verify.rs`

## C-020 - No execute without checked event

Execute MUST fail if the referenced checked event is missing or invalid.

Enforced by:

- `crates/admit_cli/src/witness.rs` (`execute_checked`)

## C-030 - Registry-aware artifact admission

When a meta registry is present, artifact schema ids and scope ids MUST be registry-valid.

Enforced by:

- `crates/admit_cli/src/artifact.rs`
- `crates/admit_cli/src/registry.rs`
- `crates/admit_cli/src/verify.rs`

## C-040 - Append-only event discipline

Ledger writes SHALL be append-only and duplicate event ids MUST be rejected.

Enforced by:

- `crates/admit_cli/src/ledger.rs`
- `crates/admit_cli/src/rust_ir_lint.rs` (duplicate guard on append path)

## Effect Classes

This protocol applies strictly to irreversible execute/apply operations.
Observation-oriented commands may emit witnesses and artifacts without passing through execute, but MUST remain verifiable and content-addressed.

## Ruleset Observation Loop

The CLI supports the executable ruleset observation loop:

1. `observe --scope <scope_id> --root <path> --out <facts.json>`
2. `check --ruleset <ruleset.json> --inputs <facts.json>`

Copy/paste multi-scope guardrail example:

```bash
admit observe --scope git.working_tree --root . --out out/git.facts.json
admit observe --scope deps.manifest --root . --out out/deps.facts.json

admit check --ruleset testdata/rulesets/git-deps-guardrails.ruleset.json \
  --inputs out/git.facts.json,out/deps.facts.json
```

Normative requirements:

1. Scope observation mode MUST remain read-only and emit a facts bundle artifact.
2. Ruleset check mode MUST route predicate dispatch through `ProviderRegistry`.
3. Ruleset witnesses MUST include rule and predicate evaluation trace facts.

## Visualization Surface

The CLI provides a Git-like visualization surface over governance artifacts:

1. `status` renders governance/repo/evidence state from ledger + artifact metadata.
1. `show <target>` renders decoded artifacts (`path` or `sha256:<hash>`).
2. `explain <target>` renders witness verdict explanations from witness facts.
3. `log --source ledger|artifacts` renders event/artifact rows.

Normative requirements:

1. `show --quiet` MUST print canonical payload hash as `sha256:<hash>`.
2. `show` and `explain` hash resolution MUST be schema-first (decode then detect).
3. `explain` ordering MUST be deterministic for rules, predicate trace, and findings.
4. `status --json` MUST emit stable top-level sections: `repo`, `ledger`, `governance`, `scopes`.
5. `log --source ledger` MUST support deterministic filtering for `--since`, `--scope`, and `--verdict`.
6. Pretty output for `status`, `show`, `explain`, and `log` SHOULD use section headers + key=value rows.

## Status V2 Contract

`status` is governance-focused and reports:

1. Repo context (`root`, `branch`, `head`) where derivable.
2. Ledger overview (`path`, total events, latest event).
3. Latest governance transitions (`admissibility.checked`, `admissibility.executed`).
4. Evidence freshness state (`fresh` | `pending_apply` | `missing`) with reason.
5. Ruleset hash visibility from latest check witness when present.

`status --json` envelope:

```json
{
  "command": "status",
  "repo": {},
  "ledger": {},
  "governance": {},
  "scopes": {}
}
```
