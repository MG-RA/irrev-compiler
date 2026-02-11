# Compiler Self-Audit (Ruleset Run)

Date: 2026-02-11  
Repository: `c:\Users\user\code\Irreversibility\irrev-compiler`  
Audit artifacts root: `c:\Users\user\code\Irreversibility\out\compiler-self-audit-2026-02-11`

## Scope

This audit runs the available example rulesets against the compiler repository itself (not a demo repo), captures witness hashes, and records all `rule_result` outputs.

Rulesets audited:

- `docs/spec/ruleset-git-working-tree.example.json`
- `docs/spec/ruleset-deps-manifest.example.json`
- `docs/spec/ruleset-git-deps-guardrails.example.json`
- `docs/spec/ruleset-text-metrics.example.json`

## Baseline Repo State

- `HEAD`: `a3104773bf40a60d9f4ce0fa8d3ddcee6ca980ed`
- `git status --porcelain` entries: `18`

Status snapshot:

```text
 M Cargo.lock
 M Cargo.toml
 M README.md
 M crates/admit_cli/Cargo.toml
 M crates/admit_cli/src/commands/mod.rs
 M crates/admit_cli/src/main.rs
 M crates/admit_cli/tests/ruleset_check.rs
 M docs/spec/cli-protocol.md
 M docs/spec/rules.md
?? crates/admit_cli/src/commands/visualize.rs
?? crates/admit_cli/tests/visualize.rs
?? crates/admit_scope_deps/
?? crates/admit_scope_git/
?? crates/admit_scope_text/
?? docs/spec/ruleset-deps-manifest.example.json
?? docs/spec/ruleset-git-deps-guardrails.example.json
?? docs/spec/ruleset-git-working-tree.example.json
?? docs/spec/ruleset-text-metrics.example.json
```

## Commands Used

```powershell
$repo='c:\Users\user\code\Irreversibility\irrev-compiler'
$cli='c:\Users\user\code\Irreversibility\irrev-compiler\target\debug\admit_cli.exe'
$audit='c:\Users\user\code\Irreversibility\out\compiler-self-audit-2026-02-11'

& $cli observe --scope git.working_tree --root $repo --out "$audit\facts\git.facts.json"
& $cli observe --scope deps.manifest --root $repo --out "$audit\facts\deps.facts.json"
& $cli observe --scope text.metrics --root $repo --out "$audit\facts\text.facts.json"

& $cli check --ruleset "$repo\docs\spec\ruleset-git-working-tree.example.json" `
  --inputs "$audit\facts\git.facts.json" --artifacts-dir "$audit\artifacts"

& $cli check --ruleset "$repo\docs\spec\ruleset-deps-manifest.example.json" `
  --inputs "$audit\facts\deps.facts.json" --artifacts-dir "$audit\artifacts"

& $cli check --ruleset "$repo\docs\spec\ruleset-git-deps-guardrails.example.json" `
  --inputs "$audit\facts\git.facts.json,$audit\facts\deps.facts.json" --artifacts-dir "$audit\artifacts"

& $cli check --ruleset "$repo\docs\spec\ruleset-text-metrics.example.json" `
  --inputs "$audit\facts\text.facts.json" --artifacts-dir "$audit\artifacts"
```

## Observed Fact Bundles

| scope_id | snapshot_hash | bundle_hash |
|---|---|---|
| `git.working_tree` | `f38b3f41097141e2f28f08b8d2c4c8d1ceac71343f7388999104c7985d98b0b1` | `ea0e01fd5f08cbecaec6e4f6fa4ff579d76e48c84b3b55e32bf3df1d5a2c9081` |
| `deps.manifest` | `db2564854760b533483c9dfc083ef27578af31b71a4138ed7eede9582bd99280` | `527ff93ce055fe01063961ac4bbd91a475426b26e188c078174fb4c62ba97ea8` |
| `text.metrics` | `796eaeb8780a59bd1c9aa9994955e6909aee858817640c1187cb14064d95491d` | `493defc7f4e9f8827390ea10250090ea3607310393d013ad521ab6fb21c1dc90` |

## Ruleset Results

### `deps-manifest-default`

- verdict: `admissible`
- ruleset_sha256: `9e8f58dc393de354cf5610ff79fa980990820c267cc8e9dce05307eb2defcb48`
- witness_sha256: `076a33d74093a855c5f116041852e37357e2667e79f0888994e164d7f0067274`

| rule_id | severity | triggered | findings | scope | predicate |
|---|---|---:|---:|---|---|
| `R-400` | `error` | `false` | `0` | `deps.manifest` | `git_dependency_present` |
| `R-410` | `error` | `false` | `0` | `deps.manifest` | `wildcard_version_present` |
| `R-420` | `error` | `false` | `0` | `deps.manifest` | `lockfile_missing` |

### `git-working-tree-default`

- verdict: `inadmissible`
- ruleset_sha256: `bfb5dc55a622567de64c376b9eb72699393e73466eece151a464d8dce9c57abd`
- witness_sha256: `fa6191b0591b3224c6e27e363c9780297275cb98052bcf00f0fafa62d88d2cc0`

| rule_id | severity | triggered | findings | scope | predicate |
|---|---|---:|---:|---|---|
| `R-200` | `error` | `true` | `27` | `git.working_tree` | `dirty_state` |
| `R-210` | `error` | `true` | `18` | `git.working_tree` | `untracked_file` |

### `git-deps-guardrails`

- verdict: `inadmissible`
- ruleset_sha256: `e9b541ea6d1a9c994bdafadb3e098985809b0f80ddbc82e15e4191003a70e1c9`
- witness_sha256: `744fdac76260d68450e22b19ba80763be73045f1215785c84488eb898132e9e6`

| rule_id | severity | triggered | findings | scope | predicate |
|---|---|---:|---:|---|---|
| `R-200` | `error` | `true` | `27` | `git.working_tree` | `dirty_state` |
| `R-210` | `error` | `true` | `18` | `git.working_tree` | `untracked_file` |
| `R-400` | `error` | `false` | `0` | `deps.manifest` | `git_dependency_present` |
| `R-410` | `error` | `false` | `0` | `deps.manifest` | `wildcard_version_present` |
| `R-420` | `error` | `false` | `0` | `deps.manifest` | `lockfile_missing` |

### `text-metrics-default`

- verdict: `inadmissible`
- ruleset_sha256: `31b1a5de977c369129a2e46529ac72accb19a0a68a9db1669cbab05ab66ac610`
- witness_sha256: `e5cfe8082d6be0970a3bf9f44bb5492261645868a3b16055c07941bb02e3b21b`

| rule_id | severity | triggered | findings | scope | predicate |
|---|---|---:|---:|---|---|
| `R-300` | `error` | `true` | `53` | `text.metrics` | `lines_exceed` |
| `R-310` | `error` | `true` | `104` | `text.metrics` | `line_length_exceed` |
| `R-320` | `warning` | `true` | `3` | `text.metrics` | `todo_present` |

## Aggregate Rule Coverage From This Run

Unique rules evaluated in this self-audit:

- `R-200`
- `R-210`
- `R-300`
- `R-310`
- `R-320`
- `R-400`
- `R-410`
- `R-420`

## Raw Output Files

- `c:\Users\user\code\Irreversibility\out\compiler-self-audit-2026-02-11\checks\ruleset-git-working-tree.example.txt`
- `c:\Users\user\code\Irreversibility\out\compiler-self-audit-2026-02-11\checks\ruleset-deps-manifest.example.txt`
- `c:\Users\user\code\Irreversibility\out\compiler-self-audit-2026-02-11\checks\ruleset-git-deps-guardrails.example.txt`
- `c:\Users\user\code\Irreversibility\out\compiler-self-audit-2026-02-11\checks\ruleset-text-metrics.example.txt`
