The “git scope” idea: why it’s so useful

A scope:git.* is basically a superpower because Git is already a universal coordination substrate. If your admissibility system can speak Git, you get adoption leverage.

Here are three Git-shaped scopes that are actually worth doing, in increasing complexity:

A) scope:git.snapshot@0 (high ROI, low complexity)

Produces a deterministic snapshot witness of a repo state:

HEAD commit hash

status clean/dirty

list of tracked files with blob hashes

optionally: submodule commits

optionally: .gitignore-filtered working tree manifest

Uses encode.canonical to serialize the snapshot deterministically.

What it enables: rules like “admissible only if built from a clean tree at commit X,” or “this witness corresponds exactly to this repo state.”

B) scope:git.diff@0 (pairs naturally with diff.struct)

Git’s diff is line-oriented text diff; your diff.struct is structural diff. A Git scope can produce:

changed files list

hunks (as evidence)

plus a structural diff for structured files (JSON/CBOR/your witnesses)

What it enables: review automation that is evidence-grade, not “trust the UI.”

C) scope:git.provenance@0 (harder, but civilization-flavored)

Witness chain like:

which commits introduced which registry entries

signatures (if using signed commits/tags)

mapping from artifact hashes to commits that produced them

What it enables: “who authorized what,” without turning into a ticketing system.