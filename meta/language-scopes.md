---
role: support
type: scope-note
canonical: true
facets:
  - governance
  - protocols
---

# Language Scopes

## Purpose

Capture the observation that language itself fractures cleanly into hierarchical scopes (characters ? alphabets ? tokens ? grammar ? semantics ? domain-specific English). Each layer is a governable space described by admissibility rules, boundary facts, and explicit failure modes.

## The stack of language scopes

1. **`scope:char` (binary/encoding foundation)**
   * Governs: character sets (ASCII, Unicode 15.1), normalization form (NFC/NFD), allowed codepoint ranges.
   * Witnesses: encoding declarations, normalization results, repro hashes.
   * Why: text identity needs a proof object before any higher scope can safely rely on it.

2. **`scope:alphabet:latin` (alphabet restrictions)**
   * Governs: allowed symbols (`a-z`), case folding, collation.
   * Use: identifier vocab, token whitelists, preventing invisible Unicode trickery.

3. **`scope:token` (word/n-gram metadata)**
   * Governs: tokenization rules, delimiters, whitespace policy, classification.
   * Use: decide if `foo-bar` is one token, whether punctuation counts as semantics, etc.

4. **`scope:grammar` (syntax integrity)**
   * Governs: parse trees, well-formedness under a grammar spec (BNF/PEG), ambiguity handling.
   * Witnesses: parse-proof artifacts, span references to reject malformed input.

5. **`scope:semantics` (meaning layer)**
   * Governs: binding, reference resolution, consistency of role assignments (subject/object), type-level constraints.
   * Use: subject-verb agreement, referent coherence in governance prose.

6. **`scope:language:english` (meta bundle)**
   * Bundles: orthography, morphology, syntax, semantics, pragmatics.
   * Not all layers shipped; treat them as composable sub-scopes.

7. **Controlled English scopes** (operational boundaries)
   * Examples: `scope:english:controlled:technical`, `scope:english:controlled:diagnostic`.
   * Rules: forbid ambiguity, enforce explicit agents/causality, ban metaphor and hedging.
   * Outcome: statements can be declared admissible or rejected with deterministic witnesses.

## Why this matters

* Languages become analyzable like code: parse, check, witness, and gate actions.
* AI output can be forced through these scopes: e.g., `scope:english:controlled:diagnostic` lints can run on LLM responses and emit witness facts when compliance fails.
* Controlled English plus scope facts turns translation, explanation, and governance language into proof-carrying artifacts.

## Practical next steps

* Treat language scope packs as part of the default distribution (like the standard library). Ship baseline `scope:char`, `scope:alphabet`, `scope:token`, `scope:grammar`, and a sample `scope:english:controlled:diagnostic`.
* Define snapshot schemas (e.g., allowed alphabet sets, grammar versions) and witness schemas for parsing + semantics outcomes.
* Connect these scopes to VS Code + CLI so that boundary/pattern checks can reference explicit language failures in the ledger.
