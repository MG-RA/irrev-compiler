# Structural Audit: Compiler Documentation

**Audit date:** 2026-02-07  
**Scope:** Documentation only (README, architecture notes, design docs, protocols)  
**Documents reviewed:** Architecture.md, Scope_Primitives___Algebras.md, Irreversibility-First_Design.md, Compiler_Runtime_Loop.md, Meta_Scope_Governance.md, Boundary_Events___DB_Scope.md, Semantic_Deadlock___Scope_Registry.md, Pattern_Evidence_Pipeline.md, compiler-rs-plan.md, admissibility-ir.md, cost-declaration.md, kernel-stdlib-userspace-plan.md, semantics-authority.md, schema-registry.md, semantic-providers-plan.md, meta-registry-gate-plan.md, ledger-export-and-db-projection.md, vault-snapshot-schema-v0.md, witness-format.md, self_governance.md, selfgovernancebootstrap.md, compiler-progress-summary.md, context-checkpoint-compaction.md, runtime-genesis-implementation-plan.md, ineluctability-loop-v0.md, DAG.md, Ingestion_Protocol.md, compiler-self-application-fixed-point_plan.md, README.md

---

## 1. Concept Fidelity

### F-01. "Court" metaphor functions as an undeclared primitive

**Issue:** The term "court" appears across multiple canonical docs as a structural analogy for the compiler/kernel authority layer, but it is never formally defined or bounded.

**Location:** Compiler_Runtime_Loop.md L22 ("court logic: no mutations, just law"), Ingestion_Protocol.md L14 ("Court (authoritative)"), kernel-stdlib-userspace-plan.md L9 ("the court"), runtime-genesis-implementation-plan.md L178 ("constitutional machine"), ineluctability-loop-v0.md L7, DAG.md passim.

**Why it matters:** "Court" carries connotations of judgment, sentencing, and finality that extend beyond what the compiler does (diagnostic admissibility checking). If it remains informal, different docs will project different meanings onto it. If it becomes structural, it should be subject to the same vocabulary discipline as other concepts.

**Classification:** Concept drift

**Minimal correction:** Either (a) add a single definition note declaring "court" as a working metaphor with explicit boundaries (what it means, what it does not mean), or (b) replace its structural uses with defined terms ("kernel authority," "admissibility engine") and reserve "court" for narrative/pedagogical contexts only.

---

### F-02. "Ceremony" used structurally without definition

**Issue:** "Ceremony" appears as a near-technical term across docs — "plan → witness → execute ceremony," "bridge ceremony," "stronger ceremonies as irreversibility rises" — but is never defined. It serves as an informal synonym for "gated effectful operation with required witnesses" but could mean different things in different contexts.

**Location:** Compiler_Runtime_Loop.md L77, Scope_Primitives___Algebras.md L148 ("bridge ceremonies"), Meta_Scope_Governance.md L65, runtime-genesis-implementation-plan.md L59 ("minimum ceremony"), DAG.md L496 ("Risk-class ceremony").

**Why it matters:** Without a definition, it is ambiguous whether "ceremony" requires specific structural components (plan hash, approval, witness) or whether it is a loose descriptor. The DAG doc's "risk-class ceremony" policy depends on this term being precise.

**Classification:** Concept drift

**Minimal correction:** Add a brief definition in Architecture.md or Scope_Primitives___Algebras.md specifying what constitutes a ceremony (required inputs, required outputs, required witnessing) and reference it from other docs.

---

### F-03. "Witness" is overloaded across three structural roles

**Issue:** "Witness" is used as (1) a specific artifact type (the proof object defined in admissibility-ir.md), (2) a scope role category ("Witness scopes produce evidence" — Meta_Scope_Governance.md L56-58), and (3) a general verb/adjective ("witnessed," "witnessable," "witness-first").

**Location:** admissibility-ir.md (artifact schema), Meta_Scope_Governance.md L56-58 (scope role), selfgovernancebootstrap.md L107 ("witness-first governance"), Semantic_Deadlock___Scope_Registry.md L58 (scope kind enum).

**Why it matters:** A reader encountering "witness" in context must determine which sense applies. This is especially confusing when a "witness scope" emits a "witness artifact" — the nesting makes it difficult to reason about what is evidence and what is the producer of evidence.

**Classification:** Concept drift

**Minimal correction:** In Scope_Primitives___Algebras.md or a terminology note, distinguish "witness (artifact)" from "witness (scope role)" from "witnessing (property of being evidenced)." Consider whether the scope role needs a more specific name (e.g., "evidence scope" or "observation scope") to avoid collision with the artifact type.

---

### F-04. "Provider" operates as an undeclared primitive

**Issue:** "Provider" appears extensively as a structural concept (Compiler_Runtime_Loop.md L38 "provider registry," semantic-providers-plan.md passim, Pattern_Evidence_Pipeline.md L19, DAG.md L411) but is not anchored to any vault concept and has no formal definition.

**Location:** Multiple documents (see above).

**Why it matters:** The system now relies on providers as a key extensibility mechanism (fact providers, semantic providers, mechanism providers) but the concept has no definition contract, no admissibility properties, and no declared failure modes.

**Classification:** Concept drift (de facto new primitive)

**Minimal correction:** Add a definition block for "provider" — what it is, what it must produce, what invariants apply — either in Scope_Primitives___Algebras.md or Compiler_Runtime_Loop.md. Alternatively, explicitly acknowledge it as a new operational concept not derived from the vault vocabulary.

---

### F-05. Schema naming convention inconsistency

**Issue:** Active schemas use slash notation (`admissibility-witness/1`, `vault-snapshot/0`). Planned schemas mix slash notation with @-notation (`VaultScan@1`, `VaultLintWitness@1`, `ProgramBundle@1`). This makes it ambiguous which convention is canonical.

**Location:** schema-registry.md L8-28.

**Why it matters:** Schema identity is a governance surface — inconsistent naming makes registry gates harder to enforce and introduces potential for silent misreference.

**Classification:** Concept drift

**Minimal correction:** Add a note in schema-registry.md declaring which naming convention is authoritative and flag the planned schemas as needing name normalization before activation.

---

## 2. Layer Discipline

### F-06. Boundary Events doc grants DB "authority" status

**Issue:** Boundary_Events___DB_Scope.md L53-54 states: "The DB becomes a self-governing authority, issuing capabilities tied to namespaces and verifying witnesses for writes."

This directly contradicts:
- Architecture.md: vault layer is "not a source of 'truth by authority'"
- ledger-export-and-db-projection.md L11: "DB may accelerate queries, but it must not be required to decide admissibility verdicts"
- semantics-authority.md L11: "Rust is the sole semantic authority"

**Location:** Boundary_Events___DB_Scope.md L53-54.

**Why it matters:** If the DB is described as an "authority" in a canonical doc, this creates a structural license for future implementations to treat DB outputs as admissibility inputs, violating the authority boundary.

**Classification:** Boundary leak

**Minimal correction:** Rewrite the sentence to clarify the DB's role as a governed projection scope, not an authority. E.g., "The DB scope provides governed access to persistent state. Write operations require witnesses verified by the admissibility kernel; the DB does not issue verdicts."

---

### F-07. Self-governance docs blur protocol and tutorial

**Issue:** selfgovernancebootstrap.md and self_governance.md are written in an instructional second-person voice ("If you want one rule…", "You stop trusting humans to remember…", "Once that works, you've lit the first self-governing candle"). Their `role` frontmatter is absent or not clearly distinguished from canonical protocol docs.

**Location:** selfgovernancebootstrap.md passim, self_governance.md passim.

**Why it matters:** A reader cannot determine whether these docs declare binding governance procedures or provide advisory guidance. The instructional voice makes diagnostic claims ("that's the vault pattern") look like personal coaching, obscuring their structural status.

**Classification:** Boundary leak (doc layer ambiguity)

**Minimal correction:** Add frontmatter declaring `role: support` and `type: implementation-guide` (or similar) to both docs, clearly separating them from `role: meta, type: design-procedure` docs like Irreversibility-First_Design.md.

---

### F-08. Compiler progress summary embeds prescriptive instructions

**Issue:** compiler-progress-summary.md L35 states: "Resolve the `registry-drift` error by re-running `irrev -v <vault> registry build --in-place`…" This is a prescriptive remediation instruction in what is nominally a status summary document.

**Location:** compiler-progress-summary.md L35-37.

**Why it matters:** Status documents should report state, not prescribe action. Mixing status with instructions makes it unclear whether the prescribed action has been governance-approved or is merely a suggestion.

**Classification:** Normative creep

**Minimal correction:** Move the remediation instructions to a separate section headed "Proposed next actions" or "Remediation (not yet executed)," making the diagnostic/prescriptive boundary explicit.

---

### F-09. Execution layer definition inconsistently enforced

**Issue:** Architecture.md L99 defines execution as "any operation that changes state." Compiler_Runtime_Loop.md L30 says "Effects only happen after the runtime enforces plan → witness → execute." But the genesis bootstrap (runtime-genesis-implementation-plan.md L166-172) permits one "unwitnessed" transition, and current ledger appends happen through CLI commands without the full ceremony described in the architecture.

**Location:** Architecture.md L99, Compiler_Runtime_Loop.md L30, runtime-genesis-implementation-plan.md L166-172.

**Why it matters:** If the execution boundary is defined as universal ("any operation") but implemented with known exceptions, the boundary becomes ambiguous. Each exception should be declared, not assumed.

**Classification:** Boundary leak

**Minimal correction:** Add a section to Architecture.md (or a linked note) enumerating known exceptions to the execution ceremony requirement and their rationale — e.g., "genesis bootstrap is the sole unwitnessed transition; all post-genesis effects require ceremony."

---

## 3. Irreversibility Awareness

### F-10. TOML deprecation described with cost-free language

**Issue:** compiler-rs-plan.md L31 describes ".adm" as the new syntax and says "deprecate TOML rulesets over time." This is an irreversible migration — dropping a format — described without any erasure cost analysis, displacement accounting, or declaration of what is lost.

**Location:** compiler-rs-plan.md L31, L122.

**Why it matters:** By the system's own principles, format deprecation is an irreversible act that creates obligations (migration tooling, backward compatibility, knowledge loss). Describing it casually violates the irreversibility-first design procedure.

**Classification:** Irreversibility blind spot

**Minimal correction:** Add a note acknowledging the deprecation as an irreversible commitment with at minimum: (a) what must be preserved (the lowering path), (b) what is lost (native TOML authoring), (c) what the migration ceremony looks like.

---

### F-11. Genesis bootstrap exception not cost-declared

**Issue:** runtime-genesis-implementation-plan.md L166-172 states: "Kernel allows exactly one 'unwitnessed' transition: from empty → genesis authority state. After genesis, all rule/registry/authority transitions require governed ceremony." The erasure cost and displacement of this exception are not documented. If genesis is wrong, what is the rollback path?

**Location:** runtime-genesis-implementation-plan.md L166-172.

**Why it matters:** The genesis exception is a known irreversibility whose cost has been deliberately accepted but not declared. The docs should apply their own protocol to this decision.

**Classification:** Irreversibility blind spot

**Minimal correction:** Add a short cost-declaration note: "The genesis transition is irreversible. If the genesis ruleset or registry is incorrect, correction requires a full re-initialization (state wipe). This cost is accepted because…"

---

### F-12. "Upsert" in projection sink implies silent overwrite potential

**Issue:** ledger-export-and-db-projection.md L113: "upsert by `event_id` (idempotent)." While the intent is idempotent replay, "upsert" semantically permits overwriting existing records. For a system that emphasizes append-only discipline, the word choice introduces ambiguity about whether overwriting is acceptable in the projection layer.

**Location:** ledger-export-and-db-projection.md L113.

**Why it matters:** If projections silently overwrite records, the system could mask drift or corruption without generating a witness. The distinction between "idempotent insert" and "overwrite" is structurally meaningful.

**Classification:** Irreversibility blind spot

**Minimal correction:** Clarify: "Insert-if-absent by `event_id` (idempotent). If a row with the same `event_id` already exists, verify fields match; emit a drift witness if they do not."

---

### F-13. `irrev_std@1` required but not materialized

**Issue:** kernel-stdlib-userspace-plan.md L85-87: "In the current Rust compiler implementation, `module:irrev_std@1` is required by lowering, but the repo does not yet contain a shipped stdlib module directory."

**Location:** kernel-stdlib-userspace-plan.md L85-87.

**Why it matters:** The compiler requires a module name that has no corresponding governed artifact — a reference without a provenance anchor. Until the stdlib is materialized as a content-addressed artifact, the "required" dependency is a trust assumption, not a witnessed dependency.

**Classification:** Witness/provenance gap combined with Irreversibility blind spot (the name is committed without the artifact being committed)

**Minimal correction:** Add an explicit note: "`irrev_std@1` is currently a name-only dependency. Until a content-addressed stdlib artifact exists, this dependency is unwitnessed. Tracking: [issue/milestone reference]."

---

## 4. Witness & Provenance Clarity

### F-14. Compiler purity claim is asserted, not witnessed

**Issue:** Compiler_Runtime_Loop.md L22 declares: "This is court logic: no mutations, just law." The compiler loop is described as "pure" (no side effects), but no mechanism is documented for verifying or witnessing this purity. The claim is structural but the evidence is absent.

**Location:** Compiler_Runtime_Loop.md L20-22.

**Why it matters:** If the compiler loop is relied upon as pure, and a future change introduces a side effect (logging, caching, telemetry), there is no documented detection mechanism. The purity claim should be either (a) enforced by construction (e.g., type-level purity in Rust) or (b) tested and witnessed.

**Classification:** Witness/provenance gap

**Minimal correction:** Add a note describing how purity is maintained — e.g., "Purity is enforced by crate isolation: `admit_core` has no IO dependencies. Integration tests verify no file/network access during evaluation."

---

### F-15. Semantics Authority Protocol declares authority without a witness trail

**Issue:** semantics-authority.md L11 states: "Rust is the sole semantic authority." This is a binding governance declaration, but the document does not cite what mechanism enforces it, how violations are detected, or what witness would be emitted if Python code attempted to produce verdicts.

**Location:** semantics-authority.md L11-22.

**Why it matters:** A governance declaration without an enforcement mechanism is a policy document, not a protocol. The doc's own framing as "Rule (binding)" implies enforcement that is not yet documented.

**Classification:** Witness/provenance gap

**Minimal correction:** Add an enforcement section: "Enforcement mechanism: CI guard (planned) rejects witness/ledger artifacts not produced by Rust tooling. Until CI guard is active, enforcement is by review discipline. Violations are detectable by…"

---

### F-16. Projections described as "not authoritative" without verification witness

**Issue:** Architecture.md L142-143: projections are "not authoritative evidence unless tied to a reproducibility header (hashes)." But no document specifies who verifies the hashes, where the verification result is witnessed, or what happens if the hash does not match.

**Location:** Architecture.md L142-143.

**Why it matters:** The authority boundary between projections and canonical artifacts depends on hash verification. If verification is assumed but not witnessed, the boundary is aspirational rather than structural.

**Classification:** Witness/provenance gap

**Minimal correction:** Add a note specifying the verification point — e.g., "The compiler verifies projection hashes at load time and emits a witness fact (hash_verified/hash_mismatch) before using projection content as input."

---

### F-17. Concept definitions referenced but not inlined or summarized

**Issue:** admissibility-ir.md L17-22 lists concept anchors (`[[difference]]`, `[[persistence]]`, `[[constraint]]`, etc.) pointing to vault concept files. For a reader of the compiler docs without vault access, these anchors are opaque references.

**Location:** admissibility-ir.md L17-22.

**Why it matters:** Provenance of meaning depends on the vault definitions being accessible. If the compiler docs are read standalone (as they will be for OSS contributors), the concept anchors provide no semantic content — they are references without payloads.

**Classification:** Witness/provenance gap

**Minimal correction:** Add a one-sentence summary for each concept anchor in admissibility-ir.md, or add a linked glossary document within the compiler meta directory that reproduces the minimal definitions needed to read the compiler docs.

---

## 5. Failure Mode Coverage

### F-18. "Structurally impossible" claim without witness

**Issue:** compiler-rs-plan.md L332: "Action is **structurally impossible** without a prior `cost.declared`." This is a strong claim about system behavior that, if true, should be trivially demonstrable. But the docs do not cite the enforcement mechanism (is it a type-level constraint? a runtime check? a CLI gate?).

**Location:** compiler-rs-plan.md L332.

**Why it matters:** "Structurally impossible" is the strongest claim a system can make. If it is achieved by a runtime check that can be bypassed (e.g., direct ledger write), the claim is false. If it is achieved by type-level enforcement, it should say so. Self-sealing explanation risk: the claim may discourage investigation of bypass paths.

**Classification:** Normative creep + potential self-sealing

**Minimal correction:** Replace with: "The `execute` command requires a prior `cost.declared` event ID. Enforcement: the CLI gate verifies the event exists in the ledger before proceeding. [If bypass paths exist, name them.]"

---

### F-19. "Pressure" taxonomy introduced without vault anchoring

**Issue:** ineluctability-loop-v0.md L137-153 introduces a "Pressure taxonomy" with four lanes (structural, hygiene, semantic, quantitative) and a ranking rule ("Structural pressure dominates refinement"). This functions as a new analytical vocabulary layered on top of the system without anchoring to vault concepts.

**Location:** ineluctability-loop-v0.md L137-153.

**Why it matters:** "Pressure" risks becoming a reified bookkeeping term — the system optimizes for "reducing pressure" rather than for the underlying structural properties that pressure is supposed to measure. The disclaimer "Pressure is a measurement, not a truth oracle" (L139) is good but insufficient if the ranking rule ("dominates refinement") introduces a normative hierarchy.

**Classification:** Concept drift (potential reification of bookkeeping term)

**Minimal correction:** Add a note anchoring each pressure lane to existing vault concepts (e.g., structural pressure maps to constraint-load and feasible-set reduction; hygiene maps to witness completeness). Add the system's own failure mode warning: "Pressure lanes are diagnostic projections. Optimizing for pressure reduction rather than addressing underlying structural conditions is a known failure mode."

---

### F-20. "Packs as law" section contains hidden prescription

**Issue:** Compiler_Runtime_Loop.md L119 heading reads "B) Program-declared packs (flexible but risky)." The parenthetical "risky" is an undeclared value judgment. The text does not specify what risk is introduced, who bears it, or what the displacement cost would be.

**Location:** Compiler_Runtime_Loop.md L106-121.

**Why it matters:** Labeling an approach as "risky" without analysis is a hidden prescription — it steers readers toward Option A without declaring the reasoning as a governance decision. By the system's own standards, this should be a declared cost comparison, not an adjective.

**Classification:** Normative creep

**Minimal correction:** Replace "risky" with a specific characterization: e.g., "B) Program-declared packs (flexible; risk: program can override runtime governance if pack selection is not constrained)."

---

### F-21. Self-audit failure path not documented

**Issue:** Architecture.md L269-275 describes "Loop B: Vault governs Engine (self-audit)" and selfgovernancebootstrap.md describes the self-governance loop. But neither document addresses what happens when self-audit fails — when the compiler finds itself inadmissible under its own invariants. The remediation path, the authority to override, and the witness requirements for override are all absent.

**Location:** Architecture.md L269-275, selfgovernancebootstrap.md passim.

**Why it matters:** This is the "compiler exempting itself from its own rules" failure mode. Without an explicit protocol for self-audit failure, the system may silently suppress or ignore its own findings, creating a self-sealing loop where the compiler's authority is never meaningfully constrained.

**Classification:** Failure mode (self-exemption)

**Minimal correction:** Add a documented protocol for self-audit failure: "When self-audit produces an inadmissible verdict for compiler artifacts, the following procedure applies: [witness the failure, require explicit override with witnessed rationale, block merge until resolved or overridden]."

---

### F-22. Architecture.md execution chokepoint uses aspirational language

**Issue:** Architecture.md L116: "All effectful operations **should eventually** run through the Harness." The phrasing "should eventually" makes it ambiguous whether this is a current invariant, a design goal, or a future aspiration.

**Location:** Architecture.md L116.

**Why it matters:** If this is an invariant, "should eventually" weakens it. If it is aspirational, calling it a "chokepoint" overstates the current state. The gap between claimed architecture and actual enforcement is itself an irreversibility risk — implementations built assuming the chokepoint exists may be unsound if it does not.

**Classification:** Normative creep

**Minimal correction:** Replace with either: "All effectful operations run through the Harness" (if true) or "Design target: all effectful operations will run through the Harness. Current exceptions: [list]. Tracking: [reference]."

---

### F-23. Meta_Scope_Governance uses emoji in canonical doc

**Issue:** Meta_Scope_Governance.md L102 ends with: "enabling the compiler to remain the judge 📜🧾."

**Location:** Meta_Scope_Governance.md L102.

**Why it matters:** Minor, but the document has `canonical: true` in its frontmatter. Emoji in canonical governance docs introduces informal register that could be cited as precedent for looser documentation standards.

**Classification:** (Minor) Normative creep

**Minimal correction:** Remove the emoji from the canonical document.

---

## Potential Extractions (Not Applied)

The following issues suggest concepts that *may* need formal treatment but cannot be resolved by rewording alone. They are listed here for awareness; no changes are proposed.

**PE-01. "Ceremony" as a first-class concept.**
If ceremony is defined (required inputs, outputs, witnessing), it becomes a composition primitive — "this operation requires ceremony level X." This may be valuable but would constitute a new primitive.

**PE-02. "Provider" as a formal interface contract.**
If providers are formally defined with admissibility properties (determinism grade, witness obligations, failure modes), they become a governed extensibility boundary. This is likely needed but exceeds doc-only correction scope.

**PE-03. "Pressure" as a diagnostic projection type.**
If pressure lanes are anchored to vault concepts and governed as projections, they become a formal diagnostic vocabulary. This requires design work beyond rewording.

**PE-04. "Purity enforcement" as a witnessed property.**
If compiler purity is enforced and witnessed (not just claimed), a "purity witness" or "effect-freedom certificate" would be a new artifact type. This is a feature, not a doc fix.

---

## Summary Statistics

| Classification | Count |
|---|---|
| Concept drift | 5 (F-01, F-02, F-03, F-04, F-05) |
| Boundary leak | 3 (F-06, F-07, F-09) |
| Irreversibility blind spot | 4 (F-10, F-11, F-12, F-13) |
| Witness/provenance gap | 4 (F-14, F-15, F-16, F-17) |
| Normative creep | 4 (F-08, F-18, F-20, F-22) |
| Failure mode (self-exemption) | 1 (F-21) |
| Failure mode (reification risk) | 1 (F-19) |
| Minor | 1 (F-23) |

**Total findings:** 23

---

## Positive Observations (structural strengths)

For completeness, the following practices demonstrate strong alignment with the system's own principles:

- **cost-declaration.md "Non-claims" section** (L44-47) is a model of diagnostic discipline — explicitly declaring what the artifact does *not* assert.
- **Ingestion_Protocol.md coverage model** (L61) — "the system is forced to admit what it could not see" — is an exemplary application of irreversibility-aware design to blind spots.
- **admissibility-ir.md epistemic constraints section** (L7-15) correctly front-loads anti-reification and anti-prescription warnings as design constraints, not afterthoughts.
- **kernel-stdlib-userspace-plan.md inclusion tests** (L125-132) provide mechanical decision criteria (bypass test, authority test, bootstrap test) that prevent layer violations by construction.
- **runtime-genesis-implementation-plan.md "Law governs claims" section** (L177-191) makes the deny-on-fail vs record-as-violation distinction explicit, preventing a common conflation.
