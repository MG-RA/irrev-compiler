---
role: support
type: compiler-runtime
canonical: true
facets:
  - governance
  - protocols
---

# Compiler + Runtime Loop

## Purpose

Capture the explicit execution loop where the compiler remains pure and the runtime applies admissibility law to world facts. This makes scopes, providers, artifacts, and ceremonies visible.

## 1. Two loops

### Compiler loop (pure)

Input: `.adm` modules + stdlib packs (no world state)  
Output: IR + compile witness (parse/lower/type diagnostics)  

This is court logic: no mutations, just law.

### Runtime loop (governed effects)

Input: compiled program + scope snapshot(s)  
Output: findings, plans, cost declarations, results, witnesses  

Effects only happen after the runtime enforces plan → witness → execute.

## 2. Runtime as composition

Runtime isn't one monolith. It is:

* a **scope resolver** (what scopes exist, where they live)
* a **provider registry** (predicates + mechanisms per scope)
* an **artifact store** (witness registry + ledger)
* an **execution harness** (plan → check → execute)

Scopes host packs + providers, runtime hosts scopes, and the harness enforces boundaries.

## 3. User workflow

1. **Compile**

```bash
admit compile --bundle ./packs --program program.adm --out program.air
```

Outputs: `program.air` (IR + hash) + compile witness.

2. **Snapshot**

```bash
admit snapshot --scope vault --out vault.snap
```

Outputs: deterministic `vault.snap` + snapshot witness.

3. **Evaluate**

```bash
admit eval --program program.air --input vault.snap --witness out.wit
```

Outputs: `out.wit` (findings + admissibility) + optional plan bundle.

4. **Execute**

```bash
admit exec --plan plan.bundle --require-witness out.wit
```

Outputs: result witness/artifact, ledger event, registry entries.

This is the ceremony: plan → witness → execute.

## 4. Runtime scope

Name a meta-scope `scope:runtime` that governs:

* provider registration rules
* pack loading rules
* artifact identity rules
* execution ceremony expectations

Each runtime instance (local / CI / prod) claims its own governance via this scope.

## 5. Providers + scopes

Each scope needs:

1. Snapshot mechanism (pure fact capture)
2. Predicate/mechanism provider (interpreter)

Example `scope:vault`:

* mechanism: `vault.snapshot`
* predicate: `vault_rule(rule_id)`
* optional: `vault.autofix.plan`

Runtime wiring: resolve provider, snapshot world, run program, collect witness.

## 6. Packs as law

Law binds to a scope. Two approaches:

### A) Runtime config (preferred)

`runtime.toml` example:

```toml
[scopes.vault]
packs = ["vault_lint_pack@1#<hash>"]
fail_on = "warning"
```

### B) Program-declared packs (flexible; risk: program can override runtime governance if pack selection is not constrained by meta-scope gates)

Program states which packs govern. Prefer runtime config in v0 for clarity.

## 7. Minimal CLI surface

* `admit compile`
* `admit snapshot --scope <id>`
* `admit eval --program --input`
* `admit exec --plan`
* `admit registry put/get/query`
* `admit ledger tail/audit`

Enough to run the certificate-producing runtime.

## 8. JSON-RPC providers

Providers may be in-process or external adapters. Runtime only requires:

* `describe`
* `snapshot`
* `plan`
* `execute(plan_hash)`
* `verify`

This keeps core agnostic while enabling pluggable scope providers.

## See also

- [[Scope Patterns]]
- [[Boundary Events & DB Scope]]
- [[Pattern Evidence Pipeline]]
