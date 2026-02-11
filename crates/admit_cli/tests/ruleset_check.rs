use std::process::Command;

use admit_core::{Fact, Provider, ScopeId};
use admit_core::provider_types::SnapshotRequest;
use admit_scope_rust::backend::RUST_SCOPE_ID;
use admit_scope_rust::provider_impl::RustStructureProvider;

#[test]
fn check_ruleset_with_inputs_emits_rule_and_predicate_trace() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("repo");
    let src = root.join("src");
    std::fs::create_dir_all(&src).expect("create src");
    std::fs::write(
        src.join("lib.rs"),
        r#"
pub fn do_unsafe() {
    unsafe {
        let p = core::ptr::null::<u8>();
        let _ = p.read();
    }
}
"#,
    )
    .expect("write fixture");

    let provider = RustStructureProvider::new();
    let snapshot = provider
        .snapshot(&SnapshotRequest {
            scope_id: ScopeId(RUST_SCOPE_ID.to_string()),
            params: serde_json::json!({ "root": root.to_string_lossy() }),
        })
        .expect("snapshot");

    let facts_path = temp.path().join("rust.facts.json");
    let facts_bytes = serde_json::to_vec(&snapshot.facts_bundle).expect("encode facts bundle");
    std::fs::write(&facts_path, facts_bytes).expect("write facts bundle");

    let ruleset_path = temp.path().join("ruleset.json");
    let ruleset = serde_json::json!({
        "schema_id": "ruleset/admit@1",
        "ruleset_id": "default",
        "enabled_rules": ["R-060"],
        "bindings": [{
            "rule_id": "R-060",
            "severity": "error",
            "when": {
                "scope_id": "rust.structure",
                "predicate": "unsafe_without_justification",
                "params": {}
            }
        }],
        "fail_on": "error"
    });
    std::fs::write(
        &ruleset_path,
        serde_json::to_vec(&ruleset).expect("encode ruleset"),
    )
    .expect("write ruleset");

    let artifacts_dir = temp.path().join("artifacts");
    let bin = std::env::var("CARGO_BIN_EXE_admit_cli").expect("admit_cli binary path");
    let output = Command::new(bin)
        .args([
            "check",
            "--ruleset",
            ruleset_path.to_str().expect("ruleset path"),
            "--inputs",
            facts_path.to_str().expect("facts path"),
            "--artifacts-dir",
            artifacts_dir.to_str().expect("artifacts path"),
        ])
        .output()
        .expect("run admit_cli check --ruleset");

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    assert!(stdout.contains("mode=ruleset"), "stdout:\n{}", stdout);
    assert!(stdout.contains("verdict=inadmissible"), "stdout:\n{}", stdout);

    let witness_sha = stdout
        .lines()
        .find_map(|line| line.strip_prefix("witness_sha256="))
        .expect("witness_sha256 line");
    let witness_path = artifacts_dir.join("witness").join(format!("{}.json", witness_sha));
    assert!(witness_path.exists(), "missing witness artifact");

    let witness_bytes = std::fs::read(&witness_path).expect("read witness json");
    let witness: admit_core::Witness =
        serde_json::from_slice(&witness_bytes).expect("decode witness");

    assert_eq!(
        witness.program.snapshot_hash.as_deref(),
        Some(snapshot.facts_bundle.snapshot_hash.as_str())
    );
    assert!(
        witness.facts.iter().any(|fact| matches!(
            fact,
            Fact::RuleEvaluated {
                rule_id,
                triggered,
                ..
            } if rule_id == "R-060" && *triggered
        )),
        "expected rule_evaluated fact"
    );
    assert!(
        witness.facts.iter().any(|fact| matches!(
            fact,
            Fact::PredicateEvaluated {
                predicate,
                result,
                ..
            } if predicate.contains("rust.structure::unsafe_without_justification") && *result
        )),
        "expected predicate_evaluated fact"
    );
    assert!(
        witness.facts.iter().any(|fact| matches!(
            fact,
            Fact::LintFinding { rule_id, .. } if rule_id == "rust/unsafe_without_justification"
        )),
        "expected lint finding from rule predicate"
    );
}
