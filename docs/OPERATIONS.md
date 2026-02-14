# Operations Runbook

This runbook is non-normative and intended for maintainers operating `irrev-compiler` in local development and GitHub CI.

## 1. Local Environment

### Rust/Cargo PATH (Windows)

Ensure Cargo is durable in user PATH:

```powershell
$cargoBin = "$HOME\\.cargo\\bin"
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (($userPath -split ';') -notcontains $cargoBin) {
  [Environment]::SetEnvironmentVariable("Path", "$userPath;$cargoBin", "User")
}
```

Restart terminal and verify:

```powershell
cargo --version
where cargo
```

## 2. CI Command Modes

Run from repository root:

```bash
# Observe: always exits 0, emits witness artifacts
admit ci --root . --mode observe --json --artifacts-dir out/artifacts

# Audit: fails on integrity issues (missing metadata, nondeterministic witness hash)
admit ci --root . --mode audit --json --artifacts-dir out/artifacts

# Enforce: fails when verdict is inadmissible
admit ci --root . --mode enforce --json --artifacts-dir out/artifacts
```

Require GitHub ceremony scope:

```bash
admit ci --root . --mode enforce --require-github --json --artifacts-dir out/artifacts
```

Equivalent config (`.admit/config.toml`):

```toml
[ci]
default_ruleset = "rulesets/software-lens-v0.json"
mode = "observe"
require_github_scope = false
```

## 3. Current Self-Hosting Policy

Ruleset: `.admit/rulesets/software-lens-v0.json`

Key enforced policy:
- `R-CI-330` (`protected_branch_flow`)
- protected bases: `main`, `master`
- allowed heads: `dev`, `dev/*`

Effect:
- PRs into `main|master` from non-`dev` heads are inadmissible in enforce mode.

## 4. GitHub Actions Behavior

Workflow: `.github/workflows/ci.yml`

Current behavior:
- `pull_request`: runs admissibility in `enforce` mode with `require-github=true`
- `pull_request`: updates a sticky PR comment with witness summary/details
- `push`: runs admissibility in `observe` mode

Composite action: `action.yml`
- builds `admit_cli`
- runs `admit ci`
- publishes witness summary
- posts/updates PR witness comment when running on pull requests
- uploads artifacts in workflow

## 5. Branch Protection (Required for Real Enforcement)

Configure branch protection on `main` and/or `master`:

1. Require status checks to pass before merge
2. Select the CI workflow check from `.github/workflows/ci.yml`
3. Restrict direct pushes to protected branches
4. (Optional) Require pull request reviews

Without branch protection, CI is advisory only.

## 6. Witness and Artifact Triage

When a PR fails admissibility:

1. Open CI step summary (`Admissibility Witness`)
2. Inspect:
   - `verdict`
   - `top_warnings`
   - `scope_warnings`
   - `witness_hash`
3. Download artifact bundle (`out/`) from workflow run
4. Use `witness_hash` to locate witness under `witness/<hash>.cbor`

If failure is `ci require-github failed`:
- verify `gh` availability in runner
- verify `GITHUB_TOKEN` permissions
- verify API/network reachability

## 7. Useful Local Checks Before Push

```bash
cargo check -p admit_scope_github
cargo check -p admit_cli
cargo test -p admit_scope_github
cargo test -p admit_cli --test ci_command
admit ci --root . --mode audit --json --artifacts-dir out/artifacts-local
```

## 8. Change Management Notes

When editing CI governance:
- update `.admit/rulesets/software-lens-v0.json`
- update `README.md` CI section if behavior changed
- update `meta/design/v2/ci-self-hosting-hardening.md` state notes
- keep deterministic behavior (same inputs => same witness hash)
