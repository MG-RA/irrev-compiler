A docs plan that will actually help users

If you’re anticipating “a lot of docs for user guides”, I’d structure them like a staircase:

1) Concepts (short, non-technical)

What is a witness?

What is a scope?

What is a registry hash?

What does “admissible” mean in practice?

2) User workflows (job-to-be-done)

“Is this PR admissible?”

“Can I deploy this artifact?”

“Can I train on this dataset?”

“Can I run this migration?”

Each guide should show:

input

preflight output

how to satisfy missing evidence

commit output (witnesses and verdict)

3) Scope cookbook (per substrate)

Git scope: snapshots, diffs, provenance

Files scope: input declarations, directory snapshots

CI scope: execution witnesses, artifact hashes

DB scope: schema snapshots, migrations, invariants

4) Policy authoring guide

how to write a policy program

how to declare constraints

how waivers work

how to version policies without breaking history

5) Operator guide

registry updates

meta.scope gating

fixtures

troubleshooting drift

If you want the docs to land, write 3 “hero flows” first (PR gate, deploy gate, dataset gate). Users learn systems by walking paths, not by reading ontology.