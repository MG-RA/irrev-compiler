# Text Metrics Deep Dive

Date: 2026-02-11  
Repo: `irrev-compiler`  
HEAD: `92450cc64c7d2ff962a7b324e520fa22e7472336`

## Run Inputs

- Ruleset: `docs/spec/ruleset-text-metrics.example.json`
- Scope: `text.metrics`
- Thresholds:
  - `R-300` `max_lines=400`
  - `R-310` `max_line_len=120`
  - `R-320` TODO markers present

Artifacts:

- Facts bundle: `c:\Users\user\code\Irreversibility\out\text-metrics-detail-2026-02-11\facts\text.facts.json`
- Witness: `c:\Users\user\code\Irreversibility\out\text-metrics-detail-2026-02-11\artifacts\witness\02a24243ad97995c5606a70a703d2b98e5e544621edc7bc0fdb9e1457f378262.json`

## Summary

- verdict: `inadmissible`
- witness_sha256: `02a24243ad97995c5606a70a703d2b98e5e544621edc7bc0fdb9e1457f378262`
- total findings: `161`

Findings by rule:

| rule_id | findings |
|---|---:|
| `text/line_length_exceed` | 105 |
| `text/lines_exceed` | 53 |
| `text/todo_present` | 3 |

## Distribution By Path Class

| path class | findings |
|---|---:|
| `meta/*` | 84 |
| `crates/*` | 58 |
| `testdata/*` | 10 |
| root files | 6 |
| `docs/*` | 3 |

Code-focused subset:

- `crates/*` only: `58`
- `crates/*` + `docs/*`: `61`

## Top Offenders By Max Line Length

| file | max_line_len | lines |
|---|---:|---:|
| `history.txt` | 1008502 | 101 |
| `testdata/ledger/ledger.jsonl` | 1622 | 6 |
| `testdata/ledger/admissibility.executed.json` | 1622 | 1 |
| `testdata/ledger/admissibility.checked.json` | 1521 | 1 |
| `testdata/ledger/cost.declared.json` | 1077 | 1 |
| `testdata/artifacts/witness/5429b6067c816d04251ae8c2f5e3e9d0e838d8a2501b99ed91dcdf6448019151.cbor` | 920 | 1 |
| `compiler-docs-audit.md` | 804 | 389 |
| `crates/admit_surrealdb/src/lib.rs` | 625 | 3073 |
| `meta/design/compiler/rust-ir-derived-rules-plan.md` | 555 | 121 |
| `testdata/artifacts/facts_bundle/93ce09f87063d42e8809331c92b14c170d6b9092c443c5fc340117020ab36a12.json` | 520 | 1 |

## Top Offenders By File Length

| file | lines | max_line_len |
|---|---:|---:|
| `crates/admit_cli/src/main.rs` | 4561 | 174 |
| `crates/admit_surrealdb/src/lib.rs` | 3073 | 625 |
| `crates/admit_cli/src/ingest_dir.rs` | 1888 | 100 |
| `meta/performance.md` | 1851 | 312 |
| `crates/admit_cli/src/commands/visualize.rs` | 1753 | 138 |
| `meta/buzzing-giggling-snail.md` | 1407 | 491 |
| `crates/admit_scope_obsidian/src/projection.rs` | 1381 | 426 |
| `crates/admit_cli/src/verify.rs` | 1293 | 115 |
| `crates/admit_scope_deps/src/provider_impl.rs` | 1290 | 105 |
| `crates/admit_scope_ingest/src/lib.rs` | 1240 | 104 |

## TODO Findings (`R-320`)

| file | todo_count | lines |
|---|---:|---:|
| `crates/admit_scope_text/src/provider_impl.rs` | 11 | 722 |
| `crates/admit_surrealdb/src/lib.rs` | 1 | 3073 |
| `crates/admit_scope_text/src/lib.rs` | 1 | 10 |

## Delta Vs Previous Self-Audit Witness

Compared against witness `e5cfe8082d6be0970a3bf9f44bb5492261645868a3b16055c07941bb02e3b21b`:

- added findings: `1`
- removed findings: `0`
- added entry:
  - `text/line_length_exceed | docs/status/self-audit-2026-02-11.md | max line length 168 exceeds 120`

## Notes

- Most failures come from `meta/*` and large generated/fixture-style files rather than runtime code.
- If this ruleset is intended as a release gate, a narrower target (for example `crates/**` and selected docs) will significantly reduce noise.
