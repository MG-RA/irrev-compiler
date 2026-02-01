# Language Scopes v0 (Text as Layered Scopes)

Status date: 2026-01-30
Owner: mg

## Purpose

Capture the idea that "language" fractures cleanly into layered scopes once we stop treating text as a blob. These scopes make text identity, parsing, and (parts of) meaning checkable and witnessable.

## Core Stack (bottom-up)

### 1) `scope:char` (ASCII/Unicode)

Ground floor for text identity.

Governs:
- character set version (ASCII, Unicode version)
- normalization rules (NFC/NFD)
- allowed codepoint ranges

Why it matters:
- hashing/diffing/identity are only reliable if text identity is provable.

### 2) `scope:alphabet:*` (restricted character sets)

Restriction over `scope:char`.

Governs:
- allowed symbol subsets (e.g., latin lowercase `a-z`)
- ordering/collation rules

Use cases:
- identifiers/token sets
- defenses against invisible Unicode attacks
- “identifiers must be latin_lower” as an admissibility rule

### 3) `scope:token` (word/tokenization)

Where symbol streams become units.

Governs:
- tokenization rules and delimiters
- whitespace policy
- case-folding/case sensitivity

Why it matters:
- defines what counts as a “word” and what boundaries mean (e.g. `foo-bar`).

### 4) `scope:grammar` (syntax)

Where tokens become structure.

Governs:
- grammar definition (BNF/PEG/etc.) + version/hash
- ambiguity rules
- parse trees with spans

Why it matters:
- syntax errors become first-class evidence, not just messages.

### 5) `scope:semantics` (meaning constraints)

Where structure becomes meaning (in the checkable sense).

Governs:
- binding / reference resolution
- role consistency and typing-like checks
- interpretation constraints for constructs

Note: “semantics” can be layered; not all meaning is tractable.

### 6) `scope:language:english` (bundle of scopes)

English is not one scope. It decomposes into layers such as:

- `scope:english:orthography`
- `scope:english:morphology`
- `scope:english:syntax`
- `scope:english:core_semantics`
- `scope:english:pragmatics` (possible, but high-risk for v0)

Key point: systems can adopt only the layers they can prove.

## Controlled English (sweet spot)

Define controlled subsets that are powerful and safe to verify:

- `scope:english:controlled:technical`
- `scope:english:controlled:spec`
- `scope:english:controlled:diagnostic`

Controlled scopes can enforce:
- explicit agents and causality
- reduced ambiguity
- restrictions on tense/voice
- bans on metaphor or hedging

This enables statements like:

"This document is admissible under `english:controlled:diagnostic@1`."

...and the claim can be proven with a witness (findings + spans).

## Composition (why this scales)

These scopes compose orthogonally:

- `char x alphabet x token x grammar x semantics`
- language scopes combine with other domains (vault, math proofs, governance)

This yields useful distinctions:

- syntactically valid text that is semantically inadmissible
- parsed claims that violate causal/agent constraints
- valid English that fails controlled-diagnostic rules

## Programs Enabled

- explanation linters (prescriptive language, hidden agency, unstated assumptions)
- AI output admissibility filters (violations produce witnesses, not vibes)
- translation as proof (witness shows what meaning survived)
- language-aware governance (policies written in controlled English; enforcement is mechanical)

## Suggested Defaults (eventual)

- `scope:char`
- `scope:alphabet`
- `scope:token`
- `scope:grammar` (generic)
- an example controlled pack (not “law”): `scope:english:controlled:diagnostic`

## Principle

This does not assert “what English means.” It asserts:

"What English admits under declared constraints."

