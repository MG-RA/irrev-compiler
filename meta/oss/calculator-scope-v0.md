# Calculator Domain v0 (`calc.*`)

Status date: 2026-01-30
Owner: mg

## Purpose

This note was drafted while “domain” and “scope” were sometimes used interchangeably. In the current framing:

- **Calc is a domain**: the semantic universe of expressions, values, and unit discipline.
- **`calc.*` are scopes**: admissible interfaces into that universe.

Define a minimal, perfectly checkable domain that serves as a truth anchor for numeric computation, unit discipline, and budget gating across other scopes.

The calculator domain is intentionally "small but strict": if the system cannot make `calc.eval` behave deterministically with plan hashes and witnesses, larger scopes will leak.

## Why it matters

`calc` is useful beyond a toy:

- **Truth anchor** for arithmetic used in witnesses (totals, thresholds, risk scoring).
- **Budget routing** across buckets becomes mechanical (sum, compare, gate).
- **Feasible-region mapping** for bounded planning (enumerate allocations, identify binding constraints).
- **Reference mechanism server** that validates the mechanism protocol surface (plan/execute/witness).
- **Unit-and-dimension checker** that prevents silent nonsense (no implicit conversions).
- **Agent-safe computation**: LLMs propose computations; calculator produces attested results.

## Scope + Mechanism

- Example scope id: `scope:calc.eval` (domain: `calc`, scope: `eval`)
- Example mechanism id: `mechanism.calc.eval`

Transport: stdio JSON-RPC (same rationale as other mechanisms).

## Protocol shape

The calculator mechanism follows the mechanism protocol:

- `describe`
- `plan`
- `execute`
- Optional: `status`

## PlanArtifact (minimum)

Calculator plans must be explicit and content-addressed:

- `mechanism_id` + version
- expression AST (typed)
- referenced inputs (hashes or inline literals)
- unit rules (explicit conversions only)
- expected output unit
- declared touched scope: `scope:calc.eval`

## Witness (minimum)

Calculator witness is an attested computation:

- input values (or input hashes + resolver)
- normalized expression (canonical form)
- output value + unit
- optional bounded trace (step-by-step) for audit

## Unit discipline (v0)

- Only compatible units may be added/compared.
- Conversions must be explicit.
- Unknown units are errors (or warnings if policy chooses).

## Integration patterns

### Attested computation

Other scopes can reference:

- input hash
- calculator witness hash
- output value

This removes "trust my arithmetic" from governance flows.

### Budget gating

Compute totals per bucket and gate execution via lint thresholds:

- sum declared costs into bucket totals
- compare against thresholds
- emit findings ("exceeds budget")

### Agent-safe math

Agents submit a computation plan and receive a witness; they do not assert numbers as authority.

## When it becomes load-bearing

`calc.eval` is essential once you have:

- budget gating
- multi-bucket cost routing
- threshold-based approvals (e.g., prod changes above X)
- Pareto/path exploration under numeric constraints

In this naming scheme, those integrations typically depend on `calc.eval` (and often also `units.*`).
