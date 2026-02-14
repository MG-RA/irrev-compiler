# CI Self-Hosting Hardening (CIv3)

## Scope

This document captures the hardening slice where `irrev-compiler` enforces its own
admissibility policy in CI, including GitHub ceremony checks and protected branch flow.

## Implemented Changes

1. `admit ci` strictness controls
- `--mode observe|audit|enforce`
- `--require-github` CLI flag
- `[ci].require_github_scope` config toggle in `.admit/config.toml`

2. GitHub ceremony provider (`scope: github.ceremony`)
- Crate: `crates/admit_scope_github`
- Snapshot facts:
  - `github/pr_state`
  - `github/review_summary`
  - `github/checks_summary`
  - `github/changed_files`
- Predicates:
  - `required_checks_green`
  - `min_approvals_met`
  - `workflow_change_requires_extra_approval`
  - `protected_branch_flow`

3. Review counting hardening
- Approval counts are derived from latest state per reviewer, not raw review-event counts.

4. Witness binding hardening
- When GitHub facts are available, witness binds PR identity via:
  - `program.content_id = github-pr:<pr_number>:<head_sha>:<payload_hash>`

5. Graceful degradation and strict mode
- Default behavior when `github.ceremony` is unavailable:
  - inject fallback facts bundle with `github/scope_unavailable`
  - continue evaluation
- Strict mode (`--require-github` or config) fails immediately when GitHub scope cannot be loaded.

6. Self-hosting CI workflow
- `.github/workflows/ci.yml`:
  - runs `enforce` on `pull_request`
  - runs `observe` on `push`
- `action.yml` supports input `require-github`.

7. Branch flow policy
- Ruleset `.admit/rulesets/software-lens-v0.json` includes `R-CI-330`:
  - predicate: `protected_branch_flow`
  - protected bases: `main`, `master`
  - allowed heads: `dev`, `dev/*`
  - severity: `error`

## Operational Guidance

1. Local development
- Use observe/audit mode without strict GitHub requirement:
  - `admit ci --root . --mode observe --json`

2. CI for pull requests
- Use enforce mode with GitHub requirement:
  - `admit ci --root . --mode enforce --require-github --json`

3. Branch protection
- Configure GitHub branch protection on `main`/`master` to require the CI workflow status check.
- Without branch protection, CI enforcement is advisory rather than merge-blocking.

## Known Constraints

1. `gh` availability/auth
- `github.ceremony` needs `gh` on PATH and working `GITHUB_TOKEN` in CI.

2. Dynamic required checks
- Current `required_checks_green` uses PR status rollup data; branch-protection-derived required
  check discovery is a future hardening item.

3. API/runtime variability
- GitHub ceremony data is time-dependent. Snapshot hashing is used to bind judgments to captured
  payloads.

## Follow-up Hardening Candidates

1. Discover required checks directly from branch protection rules.
2. Add pagination-safe handling for large PR file/check sets.
3. Add fixture tests for `gh` JSON schema drift and fork-PR permission edge cases.
4. Add optional strict failure when `github/scope_unavailable` appears in any required scope.
