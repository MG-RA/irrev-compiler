Yeah — parsing Rust AST + ingesting Git into the DB is a *killer* combo for analysis. Same governance rule as before: **Rust + git are authorities; DB is a projection.** You get powerful queries without letting the DB “decide meaning.”

## 1) Rust AST in the DB: what you actually want to store

Storing *full* AST nodes for everything is usually overkill. The high-value projection is:

* **Symbol inventory**: crates, modules, types, traits, fns, impl blocks
* **Edges**: `defines`, `references`, `calls`, `imports`, `implements`, `uses_trait`, `type_depends`
* **Spans**: file path + byte range (or line/col) so you can jump back to source
* **Hashes**:

  * `file_hash` (content-address)
  * `item_hash` (stable identity for a def’s “shape,” optional)
  * `extractor_version` (so projections are reproducible)

This gives you graph queries like:

* “what depends on this type?”
* “who calls this function transitively?”
* “what changed in public API between commits?”
* “what code touches ledger/projection boundaries?”

### Tooling choices (practical)

* **`syn`**: great for parsing files into syntax trees (works without type info).
* **`rust-analyzer` / `ra_ap_*` crates**: heavier, but unlocks *semantic* info (name resolution, types).
* **`cargo metadata`**: authoritative crate graph + workspace layout.
* **`tree-sitter-rust`**: fast and forgiving for shallow extraction (great if you only need symbol outlines and spans).

A sane progression:

1. start with `cargo metadata` + light parse (`syn` or tree-sitter) → defs + spans + import edges
2. later, optionally add rust-analyzer powered passes for “real” reference edges

## 2) Git in the DB: don’t store “all history,” store **events + snapshots**

Git already *is* your history-of-meaning. In the DB you want a projection that makes questions cheap:

### Minimal Git projection tables

* `git_commit { oid, parents[], author_time, message_summary }`
* `git_tree_entry { commit_oid, path, blob_oid }`
* `git_diff_file { base_oid, head_oid, path, change_kind, stats }` (optional)
* `git_tag/release` (optional)

Then join that with your file hash world:

* `doc_file` / `code_file` record should include:

  * `path`
  * `blob_oid` (git identity)
  * `content_hash` (your canonical hash, often equals sha256 not git’s sha1/sha256)
  * `commit_oid` or `run_id`

This lets you ask:

* “show me all files whose content_hash changed between commit A and B”
* “which concept notes changed in the last N commits”
* “what code changes correlate with DAG structure changes”

## 3) The really fun bit: unify them with **run_id** + **commit_oid**

You want one consistent “view identity”:

* `ingest_run` references a particular checkout (commit) + root + hashing config.
* `projection_run` references the ingest_run.
* Rust AST projection is tied to the same ingest_run (or a sibling run type).

So every derived row carries either:

* `run_id` (preferred), and run_id links to `commit_oid`
  or
* directly `commit_oid` (works, but run_id is cleaner when you have non-git sources)

Then your DB becomes a time machine you can query like:

* “At commit X, what was the dependency DAG?”
* “Between commit X and Y, which nodes gained edges?”
* “Which Rust symbols changed that are upstream of a broken vault invariant?”

## 4) Incremental ingestion becomes trivial

If you do:

* Git blob OID per file (cheap to compare)
* your own `content_hash` per file (strong identity)

Then “diff ingest” is literally:

* if `blob_oid` unchanged → skip read + skip parse + skip chunk + skip embed
* if changed → recompute only that file’s derived objects

For AST extraction you can do the same:

* if `blob_oid` unchanged → keep previous extracted symbol/edge rows for that file (or just don’t emit new ones for this run)

## 5) One important warning: determinism under parallel parsing

If you parse Rust files in parallel and emit edges, the *set* of edges will be stable but the *order* won’t be unless you canonicalize. So:

* collect per-file results in parallel
* then **sort by stable keys** (path, span start, symbol name, etc.)
* then write batches

That keeps “same input → same projection bytes/hashes,” which matters for your whole irreversibility vibe.

---

If you implement just the minimal projections (symbols + edges + spans + commit linkage), you’ll get 80% of the analytic power with 20% of the complexity. After that, you can decide if you want semantic resolution (rust-analyzer) or keep it syntactic and fast.
