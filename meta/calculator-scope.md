---
role: support
type: scope-note
canonical: true
facets:
  - governance
  - protocols
---

# Calculator Scope

## Purpose

Document the `scope:calc` idea—the smallest "effect" scope that still produces meaningful governance because its outputs are provably correct and deterministically reproducible. If this scope behaves, all the higher-cost reasoning (budgets, cost routing, thresholds, agent math) inherits credibility.

## What it guards

* Primitives: exact numerics (`Int`, `Nat`, `Rational`, `Bool`, `Unit` labels).
* Operations: parsing, normalization, canonical formatting, comparisons, additive/compositional arithmetic.
* Witnesses: audited equation traces, normalized results, bucket totals, threshold checks.
* Determinism: only exact math in the foundational layer; any floating point lives in a higher scope flagged as nondeterministic.

## Why this scope matters

1. **Truth anchor.** Other scopes can reference cost totals, bucket sums, and risk scores as long as they cite a `calc` witness instead of trusting ad-hoc numbers.
2. **Budget routing.** The scope can emit findings like `total(bucket:incident_hours) = 200` and `exceeds(bucket:incident_hours, 150)` so `admit` rules can gate on verified sums without embedding arithmetic.
3. **Perfect planning.** When admissibility depends on numeric constraints, the scope can enumerate feasible allocations, show the binding constraints, and compute minimal deltas.
4. **Mechanism server.** Implement `mechanism.calc.eval` over stdio JSON-RPC so plans can ask for canonical math results and receive witnesses that include the expression AST + inputs + output.
5. **Unit/dimension checking.** Costs attach units (engineer_hours, usd, risk_points); the scope enforces compatibility and requires explicit conversions.
6. **Safe AI math.** LLMs submit a plan (expression tree); calculator scope returns an attested result witness instead of trusting the agent's numeric claim.

## Example artifact sketch

*PlanArtifact:* expression AST + referenced inputs + unit policy + expected output type.
*Witness:* inputs + normalized AST + canonical output + optional trace steps.
*Constraint example:* `total(bucket:incident_hours) <= bucket_limit` where both sides cite calculator witnesses.

## Next steps

* Implement a minimal `calc` mechanism (plan + execute returning deterministic witness).
* Ship `scope:calc` in the default standard library so packs can depend on it for gating budgets and costs.
* Use it as a reference implementation for future scope designs (any scope needing deterministic assertions can first prove the math inside `calc`).
