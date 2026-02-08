---
role: meta
type: protocol
canonical: true
audit_ref: compiler-docs-audit F-21
---

# Self-Audit Failure Protocol

## Purpose

Define the remediation procedure when the compiler finds itself inadmissible under its own invariants. Without this protocol, the system may silently suppress or ignore its own findings, creating a self-sealing loop.

## Protocol

When self-audit produces an inadmissible verdict for compiler artifacts:

1. **Witness the failure.** Emit a standard inadmissibility witness with full fact trail, treating compiler artifacts exactly as it would treat any other input.

2. **Block merge.** CI gate prevents merge of inadmissible compiler changes. The inadmissibility finding is not advisory — it has the same blocking force as any other inadmissible verdict.

3. **Remediation paths:**
   - (a) Fix the violation and re-audit (preferred path).
   - (b) Explicit override with witnessed rationale (requires manual approval gate).

4. **Override requirements:**
   - Emit an override witness artifact (`self-audit-override/0`) containing:
     - The original inadmissibility witness hash (what is being overridden)
     - Rationale for override (why the violation is accepted)
     - Cost declaration (what invariant is being suspended and what is displaced)
   - Require approval from designated authority (initially: maintainer review)
   - Override is recorded in ledger — it cannot be silent

## Non-exemption principle

The compiler cannot silently exempt itself from its own rules. Override is permitted but must be explicit, witnessed, and approved. If self-audit findings are routinely overridden without structural correction, this is itself a self-governance failure that should be flagged by the next audit cycle.

## Current state

Self-audit is not yet automated as a CI gate. Current enforcement is by review discipline. This protocol documents the target behavior for when self-audit becomes mechanized.
