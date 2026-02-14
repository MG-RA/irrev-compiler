# CIv3: CI as a Witnessed Constraint Runtime

## Context

V2 (adjudicator transition) is complete. The next step from CIv3.md is making the repo's CI produce admissibility witnesses — turning CI from "tests pass/fail" into "every merge boundary crossing is witnessed under a declared lens." Self-hosting first: the repo governs itself with its own tooling.

## Implementation Plan

### Step 1: `git/changed_paths` stable fact + `sensitive_path_touched` predicate

**File**: [provider_impl.rs](irrev-compiler/crates/admit_scope_git/src/provider_impl.rs)

**1a. New `git/changed_paths` summary fact** — emitted at end of `status_to_facts()` as a single `LintFinding` containing a sorted array of all changed paths. Decouples cross-scope consumers from `DIRTY_RULE_IDS` internals.

```rust
const RULE_CHANGED_PATHS: &str = "git/changed_paths";
// evidence: { "paths": ["Cargo.toml", "src/main.rs", ...], "count": N }
```

Collect paths from all existing entries (modified/added/deleted/renamed/staged/untracked), sort, deduplicate, emit as single fact.

**1b. `sensitive_path_touched` predicate** — reads `params.patterns` (glob strings), matches against `git/changed_paths` fact paths.

- Add `globset` dependency to [admit_scope_git/Cargo.toml](irrev-compiler/crates/admit_scope_git/Cargo.toml) for proper `**`/`*` semantics
- Compile patterns into `GlobSet`, match each changed path
- Emit `LintFinding` per match with `rule_id: "scope:git.working_tree/predicate:sensitive_path_touched"`
- Evidence: `{ "matched_pattern": "...", "path": "..." }`
- Add `PredicateDescriptor` to `describe()` predicates vec

**1c. Tests**: synthetic `git/changed_paths` fact -> predicate eval -> assert triggered/findings. Follow existing pattern in the file's `#[cfg(test)]` module.

### Step 2: `manifest_changed_without_lockfile` predicate on deps scope

**File**: [provider_impl.rs](irrev-compiler/crates/admit_scope_deps/src/provider_impl.rs)

- New predicate accepts `params.changed_paths` (array of strings) — injected at runtime by `admit ci`, NOT persisted in ruleset JSON
- Checks if any manifest file (Cargo.toml, package.json) appears in `changed_paths` without its corresponding lockfile also in `changed_paths`
- Uses manifest-to-lockfile pairing: `Cargo.toml` <-> `Cargo.lock`, `package.json` <-> `package-lock.json`/`yarn.lock`/`pnpm-lock.yaml` (same directory)
- Finding `rule_id: "scope:deps.manifest/predicate:manifest_changed_without_lockfile"`
- Add `PredicateDescriptor` to `describe()` predicates vec
- Unit tests with synthetic inputs

### Step 3: Runtime param overlay for cross-scope injection

**File**: [rules.rs](irrev-compiler/crates/admit_core/src/rules.rs) — `evaluate_ruleset_with_inputs()`

Add a new optional parameter `runtime_overlays: Option<&BTreeMap<String, Value>>` to `evaluate_ruleset_with_inputs()`. These are key-value pairs merged into `effective_params` **after** per-scope facts injection but **before** predicate evaluation. Critically:

- Overlays are keyed by rule_id (e.g., `"R-CI-200"`) so injection is targeted
- Ruleset JSON stays untouched — `ruleset_hash` remains stable across runs
- The overlay values are merged into the binding's `effective_params` object
- New signature:

```rust
pub fn evaluate_ruleset_with_inputs(
    ruleset: &RuleSet,
    registry: &ProviderRegistry,
    input_bundles: Option<&BTreeMap<ScopeId, FactsBundle>>,
    runtime_overlays: Option<&BTreeMap<String, Value>>,  // NEW: keyed by rule_id
) -> Result<RuleEvaluationOutcome, EvalError>
```

At [rules.rs:169](irrev-compiler/crates/admit_core/src/rules.rs#L169), after existing per-scope facts injection, add:

```rust
if let Some(overlays) = runtime_overlays {
    if let Some(overlay) = overlays.get(&binding.rule_id) {
        if let Value::Object(overlay_obj) = overlay {
            let obj = effective_params.as_object_mut().unwrap_or(/* ... */);
            for (k, v) in overlay_obj {
                obj.insert(k.clone(), v.clone());
            }
        }
    }
}
```

Update `evaluate_ruleset()` wrapper to pass `None` for the new param. Update all callers (search for `evaluate_ruleset_with_inputs` in `admit_cli`).

### Step 4: `admit ci` subcommand

**New file**: [ci_check.rs](irrev-compiler/crates/admit_cli/src/commands/ci_check.rs)
**Modified**: [mod.rs](irrev-compiler/crates/admit_cli/src/commands/mod.rs) — add `pub mod ci_check;`
**Modified**: [main.rs](irrev-compiler/crates/admit_cli/src/main.rs) — register `Ci` subcommand in clap enum + dispatch

```
admit ci [--config PATH] [--root PATH] [--json] [--artifacts-dir PATH] [--mode observe|audit|enforce]
```

**Three modes** (clear semantics):

- `observe`: always exit 0, emit witness artifacts + summary
- `audit`: exit 1 only on **integrity failures** (missing lens_id, empty snapshot_hash, non-deterministic witness hash). Determinism check: run eval twice, compare witness hash only (not ledger timestamps).
- `enforce`: exit 1 if verdict is `Inadmissible`. Policy gate.

**Behavior**:

1. Load `.admit/config.toml` from `--root` (or cwd)
2. Load ruleset from config path (relative to `.admit/`)
3. Auto-snapshot `git.working_tree` scope (pass `root` param) -> `FactsBundle`
4. Auto-snapshot `deps.manifest` scope (pass `root` param) -> `FactsBundle`
5. Extract `changed_paths` from git `FactsBundle` (find `git/changed_paths` fact, read `evidence.paths`)
6. Build `runtime_overlays`: `{ "R-CI-200": { "changed_paths": [...] } }` (sorted paths for determinism)
7. Call `evaluate_ruleset_with_inputs(ruleset, registry, input_bundles, runtime_overlays)`
8. Set `outcome.witness.input_id = Some(sha256(canonical sorted changed_paths))` — existing field on `Witness`
9. Set `outcome.witness.config_hash = Some(sha256(canonical config.toml + ruleset_ref))` — existing field on `Witness`
10. Store witness artifact, append `lens.activated` to ledger
11. Print JSON summary to stdout:
    - `verdict`, `top_warnings` (top N triggered), `fail_threshold` (e.g., "error (none present)")
    - `witness_hash`, `artifact_path`
12. Exit code per mode

**Ledger handling**: default to `<artifacts_dir>/ledger.jsonl` (per existing `run_ruleset_check` pattern). In CI, ledger lives inside the artifact bundle.

### Step 5: `.admit/` configuration directory

**`.admit/config.toml`** (new at repo root):

```toml
[ci]
default_ruleset = "rulesets/software-lens-v0.json"
mode = "observe"
```

**`.admit/rulesets/software-lens-v0.json`** (new — compiled lens, not mutated at runtime):

```json
{
  "schema_id": "ruleset/admit@1",
  "ruleset_id": "software-lens-v0",
  "enabled_rules": ["R-CI-100", "R-CI-110", "R-CI-120", "R-CI-130", "R-CI-200"],
  "bindings": [
    { "rule_id": "R-CI-100", "severity": "warning",
      "when": { "scope_id": "deps.manifest", "predicate": "lockfile_missing", "params": {} } },
    { "rule_id": "R-CI-110", "severity": "warning",
      "when": { "scope_id": "deps.manifest", "predicate": "git_dependency_present", "params": {} } },
    { "rule_id": "R-CI-120", "severity": "warning",
      "when": { "scope_id": "deps.manifest", "predicate": "wildcard_version_present", "params": {} } },
    { "rule_id": "R-CI-130", "severity": "info",
      "when": { "scope_id": "git.working_tree", "predicate": "sensitive_path_touched",
               "params": { "patterns": ["**/.env", "**/.env.*", "**/*.pem", "**/*.key", "**/secrets/**", ".github/workflows/**"] } } },
    { "rule_id": "R-CI-200", "severity": "warning",
      "when": { "scope_id": "deps.manifest", "predicate": "manifest_changed_without_lockfile",
               "params": {} } }
  ],
  "fail_on": "error"
}
```

Phase 0: all severities `warning`/`info`, `fail_on: "error"` — verdict always Admissible. `R-CI-200.params.changed_paths` injected at runtime via overlay (ruleset JSON stays pristine). Glob patterns use `**/` prefix for repo-wide matching.

Note: treat this JSON as "compiled lens" — future authoring surface will be ADM.

### Step 6: CI workflow integration (Phase 0)

**File**: [ci.yml](.github/workflows/ci.yml)

Build once, run binary (faster than `cargo run`):

```yaml
    - name: Build admit CLI
      working-directory: irrev-compiler
      run: cargo build -p admit_cli --release

    - name: Admissibility witness (observe)
      run: |
        mkdir -p out/artifacts
        irrev-compiler/target/release/admit ci --root . --json --artifacts-dir out/artifacts > out/ci-witness.json
        echo "## Admissibility Witness" >> $GITHUB_STEP_SUMMARY
        echo '```json' >> $GITHUB_STEP_SUMMARY
        jq . out/ci-witness.json >> $GITHUB_STEP_SUMMARY || cat out/ci-witness.json >> $GITHUB_STEP_SUMMARY
        echo '```' >> $GITHUB_STEP_SUMMARY

    - name: Upload witness artifacts
      if: always()
      uses: actions/upload-artifact@v4
      with:
        name: admissibility-witness
        path: out/
        retention-days: 90
```

Cargo cache already configured via `Swatinem/rust-cache@v2`.

### Step 7: GitHub Action (`action.yml`)

**New file**: [action.yml](action.yml) at repo root — composite action.

Inputs: `mode` (observe|audit|enforce), `config-path`, `comment` (true/false, best-effort)
Outputs: `verdict`, `witness-hash`, `witness-path`

Two output paths:

- **Always**: write to `$GITHUB_STEP_SUMMARY` (no extra perms needed)
- **Best-effort**: PR comment via `gh pr comment` if `comment=true` AND token has write perms (catch failures gracefully, don't block on missing perms)

Self-hosting: update CI workflow to use `uses: ./` with `mode: observe`.

### Step 8: Rule ID convention

New predicates use `scope:<scope_id>/predicate:<predicate_name>`:

- `scope:git.working_tree/predicate:sensitive_path_touched`
- `scope:deps.manifest/predicate:manifest_changed_without_lockfile`

Existing predicates keep their current `git/*` / `deps/*` convention for backward compat.

### Step 9: Update tracking doc

**File**: [adjudicator-transition.md](irrev-compiler/meta/design/v2/adjudicator-transition.md) — add CIv3 implementation state section.

## Files to Create/Modify

| File | Action |
| ---- | ------ |
| `irrev-compiler/crates/admit_scope_git/Cargo.toml` | Add `globset` dependency |
| `irrev-compiler/crates/admit_scope_git/src/provider_impl.rs` | Add `git/changed_paths` fact + `sensitive_path_touched` predicate |
| `irrev-compiler/crates/admit_scope_deps/src/provider_impl.rs` | Add `manifest_changed_without_lockfile` predicate |
| `irrev-compiler/crates/admit_core/src/rules.rs` | Add `runtime_overlays` param to `evaluate_ruleset_with_inputs` |
| `irrev-compiler/crates/admit_cli/src/commands/mod.rs` | Add `pub mod ci_check;` |
| `irrev-compiler/crates/admit_cli/src/commands/ci_check.rs` | New — `admit ci` command module |
| `irrev-compiler/crates/admit_cli/src/main.rs` | Register `ci` subcommand, update `evaluate_ruleset_with_inputs` callers |
| `.admit/config.toml` | New — repo CI config |
| `.admit/rulesets/software-lens-v0.json` | New — default software lens |
| `.github/workflows/ci.yml` | Add build + witness step + artifact upload |
| `action.yml` | New — reusable GitHub Action |
| `irrev-compiler/meta/design/v2/adjudicator-transition.md` | Update state |

## Key Reuse Points

- `evaluate_ruleset_with_inputs()` in [rules.rs:119](irrev-compiler/crates/admit_core/src/rules.rs#L119)
- `build_ruleset_provider_registry()` pattern in [main.rs:2489](irrev-compiler/crates/admit_cli/src/main.rs#L2489)
- `store_value_artifact()` for content-addressed witness storage
- `append_lens_activated_event()` for ledger
- `Witness.input_id` / `Witness.config_hash` — existing fields at [witness.rs:27-29](irrev-compiler/crates/admit_core/src/witness.rs#L27)
- `decode_facts()`, `findings_for_rule()`, `sort_findings()` helpers in both scope providers

---

## CIv3.1: `scope:github@0` (after baseline lands)

### Context

GitHub is the ceremony layer on top of git — PRs, reviews, checks, branch protection. `scope:github@0` extends the witness runtime to cover merge ceremony facts, completing the "governed change" story from CIv3.md.

**Prerequisite**: CIv3 baseline (Steps 1-9 above) must land first. `gh` CLI is not available locally (Windows PATH), so this scope is CI-environment-only for now.

### Step 10: New crate `admit_scope_github`

**New crate**: `irrev-compiler/crates/admit_scope_github/`

Scope ID: `github.ceremony`
Schema ID: `facts-bundle/github.ceremony@1`
Requires: `gh` CLI on PATH + `GITHUB_TOKEN` auth

**Snapshot facts** (extracted via `gh api`/`gh pr view --json`):

| Fact rule_id | Source | Evidence fields |
| --- | --- | --- |
| `github/pr_state` | `gh pr view --json state,baseRefName,headRefName,headRefOid,number,title,labels` | state, base, head, sha, number, labels |
| `github/review_summary` | `gh pr view --json reviews,reviewDecision` | total_reviews, approvals, changes_requested, review_decision |
| `github/checks_summary` | `gh pr view --json statusCheckRollup` | total_checks, passed, failed, pending, check_names |
| `github/changed_files` | `gh pr view --json files` | files list, additions, deletions, count |

**Predicates**:

- `required_checks_green` — triggers when any required check is not `SUCCESS`. Params: `{ "required": ["CI", "lint"] }` (optional filter; empty = all must pass)
- `min_approvals_met` — triggers when approval count < `params.min` (default 1)
- `workflow_change_requires_extra_approval` — triggers when `github/changed_files` includes `.github/workflows/**` AND approval count < `params.min_for_workflow` (default 2)

Finding rule_ids follow new convention: `scope:github.ceremony/predicate:<name>`

**Snapshot determinism**: capture raw JSON payloads from `gh`, hash them as `snapshot_hash`. Witness binds to `pr_number + head_sha + captured_payload_hash` — "I judged this PR at head SHA X with check status Y."

### Step 11: Wire into CLI provider registry

**File**: [main.rs](irrev-compiler/crates/admit_cli/src/main.rs) — `build_ruleset_provider_registry()`

Add match arm:
```rust
"github.ceremony" => registry.register(Arc::new(GithubCeremonyProvider::new()))?,
```

Add `admit_scope_github` dependency to [admit_cli/Cargo.toml](irrev-compiler/crates/admit_cli/Cargo.toml).

### Step 12: Extend software lens with GitHub bindings

**File**: [software-lens-v0.json](.admit/rulesets/software-lens-v0.json)

Add new rules (Phase 0 severities):

```json
{ "rule_id": "R-CI-300", "severity": "info",
  "when": { "scope_id": "github.ceremony", "predicate": "required_checks_green", "params": {} } },
{ "rule_id": "R-CI-310", "severity": "info",
  "when": { "scope_id": "github.ceremony", "predicate": "min_approvals_met", "params": { "min": 1 } } },
{ "rule_id": "R-CI-320", "severity": "info",
  "when": { "scope_id": "github.ceremony", "predicate": "workflow_change_requires_extra_approval",
           "params": { "min_for_workflow": 2 } } }
```

### Step 13: `admit ci` graceful degradation for GitHub scope

**File**: [ci_check.rs](irrev-compiler/crates/admit_cli/src/commands/ci_check.rs)

When `github.ceremony` scope is referenced in the ruleset but `gh` is not available (local dev, no token):

- Skip the scope with a warning fact: `Fact::LintFinding { rule_id: "github/scope_unavailable", severity: Info, message: "gh CLI not available; github.ceremony scope skipped" }`
- Do NOT fail the evaluation — graceful degradation
- This means the scope works in CI (where `gh` + `GITHUB_TOKEN` exist) but silently skips locally

### CIv3.1 Files

| File | Action |
| --- | --- |
| `irrev-compiler/crates/admit_scope_github/Cargo.toml` | New crate |
| `irrev-compiler/crates/admit_scope_github/src/lib.rs` | New — exports |
| `irrev-compiler/crates/admit_scope_github/src/backend.rs` | New — scope/schema constants |
| `irrev-compiler/crates/admit_scope_github/src/provider_impl.rs` | New — provider + predicates |
| `irrev-compiler/crates/admit_cli/Cargo.toml` | Add `admit_scope_github` dep |
| `irrev-compiler/crates/admit_cli/src/main.rs` | Wire provider in registry builder |
| `irrev-compiler/crates/admit_cli/src/commands/ci_check.rs` | Graceful degradation for missing `gh` |
| `.admit/rulesets/software-lens-v0.json` | Add R-CI-300/310/320 bindings |
| `irrev-compiler/Cargo.toml` | Add workspace member |

---

## Verification

1. **Unit tests**: `cargo test -p admit_scope_git -p admit_scope_deps` — new predicate tests
2. **Core tests**: `cargo test -p admit_core` — runtime overlay doesn't break existing eval paths
3. **Determinism golden test**: run `admit ci` twice on same snapshot, assert witness hash identical (exclude ledger timestamps from assertion)
4. **CLI smoke**: `cargo run -p admit_cli -- ci --root . --json` from repo root — valid witness JSON with summary fields
5. **Full regression**: `cargo test -p admit_core -p admit_cli --no-fail-fast`
6. **CI dry-run**: push branch, verify witness in GitHub Actions step summary + uploaded artifact
