## Irreversibility-First Plan Design Prompt (Refactor Idea)

### 1. Action Definition

Prompt ID: `action_definition`

Answer:

Refactor compiler UX and architecture so the default experience is install -> init -> ingest -> status -> iterate, while enforcing a hard separation between substrate-agnostic compiler core and optional vault/obsidian adapters.

---

### 2. Boundary Declaration

Prompt ID: `boundary_declaration`

Answer:

In scope: `admit_cli` UX commands/config flow, `admit_core` boundary hardening, optional scope-pack wiring, and docs/templates for initialization. Out of scope: changing core DSL semantics unrelated to this flow, and forcing SurrealDB as a mandatory runtime dependency.

---

### 3. Persistence Analysis

Prompt ID: `persistence_analysis`

Answer:

Persistent changes include command surface additions (`init`, `status`, lint flow), `admit.toml` conventions, scope-pack boundaries, and new enforcement checks for core/adapter coupling. These will affect CI, user workflows, and long-term plugin compatibility.

---

### 4. Erasure Cost

Prompt ID: `erasure_cost`

Answer:

Grade 2: reversing this would require undoing command UX contracts, config expectations, scope/package boundaries, and governance checks. Existing artifacts and ledger history produced by the new flow remain part of project evidence.

---

### 5. Displacement & Ownership

Prompt ID: `displacement_ownership`

Answer:

Primary ownership is compiler maintainers (core boundary + CLI UX). Secondary ownership is adapter/scope-pack maintainers (obsidian/vault integration). CI owners absorb enforcement burden for boundary checks and rollout gating.

---

### 6. Preconditions

Prompt ID: `preconditions`

Answer:

Need: stable command spec for `init/ingest/status/lint`, agreed core-vs-adapter boundaries per crate, baseline tests for deterministic outputs, and migration notes for existing local configs. Must have a clear definition for optional projection modes (`off|auto|on`) before rollout.

---

### 7. Execution Constraints

Prompt ID: `execution_constraints`

Answer:

Must preserve deterministic witness/ledger behavior. Must not introduce obsidian-specific coupling into `admit_core` and generic backends. Must keep court-only execution viable without SurrealDB. Roll out in phases: UX baseline, boundary extraction, scope-pack pluginization, enforcement.

---

### 8. Postconditions

Prompt ID: `postconditions`

Answer:

After completion, a fresh user can run `admit init`, then `admit ingest .`, then `admit status` with minimal setup. Core crates are substrate-agnostic, optional adapter scopes are explicit, and CI enforces boundary rules with deterministic tests.

---

### 9. Accountability

Prompt ID: `accountability`

Answer:

Acting entity is the compiler maintainers through repository-controlled CLI/CI workflows. Accountability anchors are commit SHA, plan witness hash, and ledger event IDs for refactor milestones and enforcement changes.

---

### 10. Acceptance Criteria

Prompt ID: `acceptance_criteria`

Answer:

Accepted when: (1) `init -> ingest -> status` works out of the box, (2) core/adapter split is structurally enforced, (3) optional scope packs work without contaminating core crates, (4) projection remains optional, and (5) all relevant tests and ledger verification pass.

---

### 11. Refusal Conditions

Prompt ID: `refusal_conditions`

Answer:

Do not proceed if boundaries are not explicitly defined, if deterministic tests are missing, if adapter-specific behavior cannot be isolated, or if rollout would break existing users without migration guidance.

---

### 12. Final Check

Prompt ID: `final_check`

Answer:

Yes: irreversible effects are bounded to explicit UX contracts and architecture boundaries; erasure cost is declared and accepted; ownership is explicit; and a future reader can reconstruct rationale from plan witness, code boundaries, and CI policy artifacts.

---
