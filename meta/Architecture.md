---
role: support
type: architecture-map
canonical: true
facets:
  - meta
  - governance
---

# Architecture Map

Ledger is not "history". Ledger is "history of effects". Git is "history of meaning".

**Status:** living map
**Purpose:** stabilize the mental model of the Quartz/irrev system: what exists, what runs, what changes state, what gets tracked, and why.

## See also

* [[Irreversibility-First Design]]
* [[Scope Patterns]]
* [[Scope Wiki]]

## 0) One-sentence model

**Vault = interpretive space** (claims and structure)
**Engine = diagnostic machinery** (parsing, checks, rule evaluation)
**Execution = effectful operations** (state changes, external side effects)
**Projections = views** (regenerable representations)
**Ledger = proof spine** (append-only provenance for effectful things)

> Vault says. Engine checks. Execution does. Projections show. Ledger proves.

---

## 1) Vault layer

### What it is

A graph of editorial artifacts extracted from and extending Irreversibility Accounting:

* concepts (canonical definitions + dependencies)
* invariants (kernel constraints)
* diagnostics (how to apply the lens)
* domains (repeatable application patterns)
* projections (re-readings of external work through the lens)
* papers/registries/meta docs (compilations, inventories, indexes)
* rulesets/configs (vault-owned policy)

### What it is not

* not an execution substrate
* not a source of “truth by authority”
* not required to be internally consistent at all times (but inconsistency becomes discoverable)

### Governance

* Governed by **lint + constraint rulesets**
* Source-of-truth for editorial changes is **git**, not ledger

### Failure modes

* drift (frontmatter/structure deviates from intended contract)
* ambiguous types (domain vs projection)
* hidden prescriptions (content tries to act like authority)

---

## 2) Engine layer

### What it is

Deterministic tooling that reads the vault and produces diagnostics:

* parsing notes/frontmatter
* building the concept graph
* running invariant checks
* computing violations and evidence
* generating reports and structured outputs

### What it is not

* not allowed to “fix” things by itself (unless routed through execution gates)
* not allowed to treat intent as evidence (effect > claim)

### Core components

* Parser/loader: reads vault
* Graph builder: builds dependency graph
* Rule evaluation: evaluates rulesets/predicates
* Lint runner: collects violations + evidence
* Self-audit: evaluates the tool against the invariants (meta-governance)

---

## 3) Execution layer

### What “execution” means here

Execution = **any operation that changes state** outside “pure analysis”.

That includes:

* writing files (exports, registry rebuilds, in-place edits)
* mutating external systems (Neo4j writes, DB wipes/rebuilds)
* appending ledger/audit entries (yes, even logging is an effect)
* applying automated fixes to vault content (if/when you add that)

### What execution is for

* producing projections that improve analysis (Neo4j, HTML graphs)
* applying planned changes safely (future: plan-driven edits)
* enforcing governance for anything that can’t be undone cheaply

### Execution chokepoint

All effectful operations should eventually run through the **Harness**:

* plan (pure)
* validate (rulesets + invariants)
* gate (approval if required)
* execute (impure)
* emit bundle (proof pack)
* log audit trail

---

## 4) Projection layer

### What projections are

Regenerable representations of vault state:

* Neo4j graph projection
* HTML/SVG/DOT graph exports
* CSV audits
* dashboards / views
* Quartz site output

### What projections are not

* not canon
* not policy
* not authoritative evidence unless tied to a reproducibility header (hashes)

### Governance

* should be reproducible
* should be marked ephemeral when appropriate
* ideally gitignored when generated

---

## 5) Ledger layer (proof spine)

### What the ledger is

Append-only event stream for **governance-relevant artifacts**:

* plans
* approvals
* execution results
* bundles (plan + approval + result + repro header)
* optionally: lint reports, self-audit reports, constraint evaluation events

### Ledger as a spine (one log)

One canonical append-only event log (e.g. `.irrev/ledger.jsonl`) with envelopes and content-addressed payloads.

This stays boring on purpose:

* append-only is auditable
* ordering exists
* indexes are rebuildable views

### Streams (logical sub-ledgers)

"Multiple ledgers" show up as typed streams within the spine (by `event_type` / `artifact_type`), not as multiple files.

Examples:

* execution stream: plan/approval/result/bundle lifecycle
* governance stream: approvals, force-acks, denials
* constraint stream: constraint evaluation and invariant checks
* diagnostic stream: lint/self-audit reports (when treated as artifacts)
* domain stream: observations and promotions (see below)

### Stream indexes (rebuildable)

Examples of rebuildable index projections:

* `.irrev/index/by_artifact_type/...`
* `.irrev/index/by_event_type/...`
* `.irrev/index/by_operation/...`
* `.irrev/index/by_ruleset_hash/...`

### What it is not

* not a mirror of every file change
* not a replacement for git history
* not where "all thinking" lives

### What gets tracked and why

Tracked in ledger when one or more is true:

* operation is effectful (irreversibility risk)
* operation requires approval
* operation must be independently checkable later
* operation creates a proof pack for external audit

Not tracked in ledger:

* manual editorial edits in vault (use git)
* ordinary code edits (use git)
* interpretive changes (use git + review discipline)

---

## 6) Surfaces and interface invariance

### Surfaces

Ways the system can be invoked:

* CLI
* LSP/VSCode
* MCP server
* CI
* (future) web dashboard

### Interface invariance (derived constraint)

If the same effect can be produced through multiple surfaces, then:

* the same gating rules apply
* the same attribution fields appear
* the same ledger artifacts are emitted
* no surface becomes a bypass channel

> Same action, same trail, regardless of interface.

---

## 7) Domains vs projections

### Projection (interpretive)

* anchored to a specific external object
* can remain a one-off re-reading
* does not need to stabilize into a procedure

### Domain (repeatable)

* anchored to a class of systems
* expected to become runnable as a diagnostic protocol
* likely to have: scope, boundary, transformations, failure signatures, stress tests

**Rule of thumb:** If someone else could “run it” as a checklist, it’s a domain. Otherwise it’s a projection.

---

## 8) Self-governance loop

### Loop A: Vault governs Vault (content lint)

* rulesets/invariants define constraints for vault structure
* lint evaluates vault against those constraints
* outputs violations (diagnostic artifacts, usually git-tracked)

### Loop B: Vault governs Engine (self-audit)

* invariants also apply to the tool
* self-audit finds structural leaks in the tool (e.g., prescriptive language, bypass paths)
* remediation happens in code (git-tracked)
* but governance-critical fixes can be executed through harness if they are effectful

### Loop C: Execution governed by itself (harness + ledger)

* harness is the chokepoint
* ledger proves what happened under what rulesets and vault state

---

## 9) Practical workflows

### Workflow 1: Editorial work (typical day)

* edit vault notes manually
* run lint (pure analysis)
* fix violations manually
* commit to git

### Workflow 2: Projection refresh (graph/neo4j)

* propose plan (pure)
* validate and gate
* execute (writes to external systems / files)
* emit bundle with repro header
* commit generated outputs only if they’re declared non-ephemeral

### Workflow 3: Self-audit remediation

* run self-audit (pure)
* create issues/backlog items
* implement fixes in code
* run tests + self-audit again
* commit to git

---

## 10) “What is being governed?”

**Anything that can cause irreversible costs**:

* external mutations (Neo4j, DB wipes)
* destructive rebuilds
* automated edits to vault
* actions that could be misattributed later

The system’s purpose is to make those actions:

* attributable
* reproducible
* gated
* auditable without trust

---

# End

---
