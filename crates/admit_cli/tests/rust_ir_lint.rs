use std::path::PathBuf;

use admit_cli::{append_rust_ir_lint_event, run_rust_ir_lint, verify_ledger, RustIrLintInput};

fn temp_dir(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("admit-rust-ir-lint-{}-{}", label, nanos))
}

#[test]
fn rust_ir_lint_emits_witness_event_and_verifies_ledger() {
    let dir = temp_dir("emit");
    let src_dir = dir.join("src");
    let artifacts_dir = dir.join("artifacts");
    let ledger = dir.join("ledger.jsonl");
    std::fs::create_dir_all(&src_dir).expect("create src dir");

    std::fs::write(
        src_dir.join("projection_writer.rs"),
        r#"
pub fn write_projection_batch(batch_hash: &str, batch_index: usize) -> String {
    let q = format!("DELETE FROM doc_chunk WHERE batch='{}'", batch_hash);
    let _identity = format!("{}:{}", batch_hash, batch_index);
    q
}
"#,
    )
    .expect("write fixture");

    let output = run_rust_ir_lint(RustIrLintInput {
        root: dir.clone(),
        timestamp: "2026-02-07T00:00:00Z".to_string(),
        tool_version: "admit-cli test".to_string(),
        artifacts_root: Some(artifacts_dir.clone()),
        meta_registry_path: None,
    })
    .expect("run rust ir lint");

    assert_eq!(output.event.event_type, "rust.ir_lint.completed");
    assert_eq!(output.event.witness.schema_id, "rust-ir-lint-witness/1");
    assert!(
        output.event.violations > 0,
        "fixture should produce at least one violation"
    );

    append_rust_ir_lint_event(&ledger, &output.event).expect("append lint event");

    let report = verify_ledger(&ledger, Some(artifacts_dir.as_path())).expect("verify ledger");
    assert!(
        report.issues.is_empty(),
        "rust ir lint event should verify cleanly, got {:?}",
        report.issues
    );

    let cbor_path = artifacts_dir
        .join("rust_ir_lint_witness")
        .join(format!("{}.cbor", output.event.witness.sha256));
    let json_path = artifacts_dir
        .join("rust_ir_lint_witness")
        .join(format!("{}.json", output.event.witness.sha256));
    assert!(cbor_path.exists(), "missing witness cbor");
    assert!(json_path.exists(), "missing witness json");
}

#[test]
fn rust_ir_lint_clean_tree_passes() {
    let dir = temp_dir("clean");
    let src_dir = dir.join("src");
    let artifacts_dir = dir.join("artifacts");
    std::fs::create_dir_all(&src_dir).expect("create src dir");

    std::fs::write(
        src_dir.join("lib.rs"),
        r#"
pub fn identity(x: i64) -> i64 {
    x
}
"#,
    )
    .expect("write fixture");

    let output = run_rust_ir_lint(RustIrLintInput {
        root: dir,
        timestamp: "2026-02-07T00:00:00Z".to_string(),
        tool_version: "admit-cli test".to_string(),
        artifacts_root: Some(artifacts_dir),
        meta_registry_path: None,
    })
    .expect("run rust ir lint");

    assert!(output.event.passed, "clean tree should pass");
    assert_eq!(output.event.violations, 0);
    assert!(output.witness.violations.is_empty());
}

#[test]
fn rust_ir_lint_ir_rs_13_detects_adapter_coupling_in_protected_modules() {
    let dir = temp_dir("ir-rs-13-detect");
    let core_src = dir.join("crates").join("admit_core").join("src");
    let artifacts_dir = dir.join("artifacts");
    std::fs::create_dir_all(&core_src).expect("create core src");

    std::fs::write(
        core_src.join("leak.rs"),
        r#"
use admit_scope_obsidian::normalize_target;

pub fn leak_target(input: &str) -> String {
    normalize_target(input)
}
"#,
    )
    .expect("write fixture");

    let output = run_rust_ir_lint(RustIrLintInput {
        root: dir,
        timestamp: "2026-02-07T00:00:00Z".to_string(),
        tool_version: "admit-cli test".to_string(),
        artifacts_root: Some(artifacts_dir),
        meta_registry_path: None,
    })
    .expect("run rust ir lint");

    assert!(
        output
            .witness
            .violations
            .iter()
            .any(|v| v.rule_id == "IR-RS-13"),
        "expected IR-RS-13 violation"
    );
}

#[test]
fn rust_ir_lint_ir_rs_13_allows_explicit_adapter_wiring_paths() {
    let dir = temp_dir("ir-rs-13-allow");
    let adapter_src = dir.join("crates").join("admit_cli").join("src");
    let artifacts_dir = dir.join("artifacts");
    std::fs::create_dir_all(&adapter_src).expect("create cli src");

    std::fs::write(
        adapter_src.join("obsidian_adapter.rs"),
        r#"
use admit_scope_obsidian::normalize_target;

pub fn adapter_target(input: &str) -> String {
    normalize_target(input)
}
"#,
    )
    .expect("write fixture");

    let output = run_rust_ir_lint(RustIrLintInput {
        root: dir,
        timestamp: "2026-02-07T00:00:00Z".to_string(),
        tool_version: "admit-cli test".to_string(),
        artifacts_root: Some(artifacts_dir),
        meta_registry_path: None,
    })
    .expect("run rust ir lint");

    assert!(
        output
            .witness
            .violations
            .iter()
            .all(|v| v.rule_id != "IR-RS-13"),
        "explicit adapter wiring path should not trigger IR-RS-13"
    );
}

#[test]
fn rust_ir_lint_ir_rs_13_ignores_comment_only_mentions() {
    let dir = temp_dir("ir-rs-13-comments");
    let core_src = dir.join("crates").join("admit_core").join("src");
    let artifacts_dir = dir.join("artifacts");
    std::fs::create_dir_all(&core_src).expect("create core src");

    std::fs::write(
        core_src.join("notes.rs"),
        r#"
// use admit_scope_obsidian::normalize_target;
// obsidian_adapter::normalize_obsidian_vault_links_phase("vault_links");
pub fn comment_only() {}
"#,
    )
    .expect("write fixture");

    let output = run_rust_ir_lint(RustIrLintInput {
        root: dir,
        timestamp: "2026-02-07T00:00:00Z".to_string(),
        tool_version: "admit-cli test".to_string(),
        artifacts_root: Some(artifacts_dir),
        meta_registry_path: None,
    })
    .expect("run rust ir lint");

    assert!(
        output
            .witness
            .violations
            .iter()
            .all(|v| v.rule_id != "IR-RS-13"),
        "comment-only mentions should not trigger IR-RS-13"
    );
}
