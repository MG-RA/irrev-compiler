<!-- plan-projection
plan_id: 1edc010f6a9c2072ddfb3bda9cb591d325f48926c60db9f5d29b2516698be8bb
witness_created_at: 2026-02-07T11:35:17Z
witness_hash: 1edc010f6a9c2072ddfb3bda9cb591d325f48926c60db9f5d29b2516698be8bb
identity: plan_id == sha256(canonical_cbor(plan_witness))
repro: plan_witness includes created_at; to reproduce plan_id, pass the same created_at and identical answers bytes.
template_id: plan:diagnostic@1
source: plan_witness artifact (canonical CBOR)
NOTE: This is a projection. The CBOR artifact is the source of truth.
-->

## Irreversibility-First Plan Design Prompt

### 1. Action Definition

Establish compiler self-application as the baseline court loop: run admit over the compiler itself and require stable witness identity across repeated executions with identical inputs.

---

### 2. Boundary Declaration

In scope: admit CLI flow, deterministic ingest/lint/check execution paths, witness identity reproducibility checks, and CI gates for fixed-point stability. Out of scope: new DSL features and non-deterministic experimental adapters.

---

### 3. Persistence Analysis

Persistent effects include new reproducibility contracts, additional CI assertions, ledger evidence from self-runs, and workflow expectations for contributors. These effects alter governance posture and release criteria.

---

### 4. Erasure Cost

Grade 3: reversing this would require removing fixed-point guarantees, changing CI policy, and invalidating trust assumptions built from published reproducible witnesses.

---

### 5. Displacement & Ownership

Compiler maintainers and CI owners carry primary cost for enforcing determinism; contributors carry secondary cost by adapting code to strict reproducibility boundaries.

---

### 6. Preconditions

Canonical input ordering, normalized paths, explicit time/provenance contracts, stable batch/hash rules, and zero hidden entropy from env/random/CWD before enforcement is enabled.

---

### 7. Execution Constraints

Must preserve existing witness schemas, keep ordering deterministic in all court paths, avoid weakening rules to force green status, and ensure failures report exact non-deterministic source.

---

### 8. Postconditions

Repeated self-application runs on identical source trees produce identical witness hashes, identical event identities, and auditable ledger proof of reproducibility.

---

### 9. Accountability

Accountability anchor is repository commit SHA plus emitted plan/lint/check witness hashes and corresponding ledger event IDs from self-application runs.

---

### 10. Acceptance Criteria

Accepted when clean-room reruns of admit lint rust . and compiler check paths produce identical witness IDs across at least two fresh executions, and CI enforces this invariant.

---

### 11. Refusal Conditions

Do not proceed if canonical ordering is incomplete, required provenance fields are ambiguous, or enforcement would pass by suppressing non-determinism instead of fixing it.

---

### 12. Final Check

Yes: effects and ownership are explicit, erasure cost is declared, and the fixed-point self-application loop is testable and reconstructable from witnesses.

---

