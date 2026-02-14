use std::path::PathBuf;
use std::process::Command;

use admit_core::provider_types::SnapshotRequest;
use admit_core::{Provider, ScopeId};
use admit_scope_rust::backend::RUST_SCOPE_ID;
use admit_scope_rust::provider_impl::RustStructureProvider;
use sha2::Digest;

fn find_admit_cli_bin() -> PathBuf {
    for key in ["CARGO_BIN_EXE_admit_cli", "CARGO_BIN_EXE_admit-cli"] {
        if let Ok(path) = std::env::var(key) {
            return PathBuf::from(path);
        }
    }

    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root");
    let target_debug = workspace_root.join("target").join("debug");
    let candidates = if cfg!(windows) {
        vec!["admit_cli.exe", "admit-cli.exe"]
    } else {
        vec!["admit_cli", "admit-cli"]
    };
    for candidate in candidates {
        let path = target_debug.join(candidate);
        if path.exists() {
            return path;
        }
    }
    panic!("admit_cli binary path not found");
}

fn run_cmd(args: &[&str]) -> std::process::Output {
    Command::new(find_admit_cli_bin())
        .args(args)
        .output()
        .expect("run admit_cli command")
}

fn derive_to_lens_hash(from_lens_hash: &str, kind: &str, payload_ref: &str) -> String {
    let payload = serde_json::json!({
        "from_lens_hash": from_lens_hash,
        "kind": kind,
        "payload_ref": payload_ref,
    });
    hex::encode(sha2::Sha256::digest(payload.to_string().as_bytes()))
}

fn parse_stdout_line<'a>(stdout: &'a str, key: &str) -> &'a str {
    stdout
        .lines()
        .find_map(|line| line.strip_prefix(&format!("{}=", key)))
        .unwrap_or_else(|| panic!("missing {} in stdout:\n{}", key, stdout))
}

fn read_ledger_lines(path: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(path)
        .expect("read ledger")
        .lines()
        .map(|line| line.to_string())
        .collect()
}

#[test]
fn v2_lineage_check_delta_update_is_append_only() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo_root = temp.path().join("repo");
    let src = repo_root.join("src");
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
    .expect("write source fixture");

    let provider = RustStructureProvider::new();
    let snapshot = provider
        .snapshot(&SnapshotRequest {
            scope_id: ScopeId(RUST_SCOPE_ID.to_string()),
            params: serde_json::json!({ "root": repo_root.to_string_lossy() }),
        })
        .expect("snapshot");

    let facts_path = temp.path().join("rust.facts.json");
    std::fs::write(
        &facts_path,
        serde_json::to_vec(&snapshot.facts_bundle).expect("encode facts"),
    )
    .expect("write facts");

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

    let registry_path = temp.path().join("meta-registry.json");
    admit_cli::registry_init(&registry_path).expect("registry init");
    let mut registry: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&registry_path).expect("read initialized registry"))
            .expect("decode registry");

    let default_lens_hash = registry["default_lens"]["lens_hash"]
        .as_str()
        .expect("default lens hash")
        .to_string();
    let kind = "constraint_tuning";
    let payload_ref = "payload:lineage@1";
    let lens_v1_hash = derive_to_lens_hash(&default_lens_hash, kind, payload_ref);
    registry["lenses"]
        .as_array_mut()
        .expect("lenses array")
        .push(serde_json::json!({
            "lens_id": "lens:v1@1",
            "lens_hash": lens_v1_hash
        }));
    std::fs::write(
        &registry_path,
        serde_json::to_vec_pretty(&registry).expect("encode registry"),
    )
    .expect("write registry");

    let artifacts_dir = temp.path().join("artifacts");
    let ledger_path = temp.path().join("ledger.jsonl");

    let check = run_cmd(&[
        "check",
        "--ruleset",
        ruleset_path.to_str().expect("ruleset path"),
        "--inputs",
        facts_path.to_str().expect("facts path"),
        "--meta-registry",
        registry_path.to_str().expect("registry path"),
        "--ledger",
        ledger_path.to_str().expect("ledger path"),
        "--artifacts-dir",
        artifacts_dir.to_str().expect("artifacts path"),
    ]);
    let check_stdout = String::from_utf8(check.stdout).expect("check stdout utf8");
    let check_stderr = String::from_utf8(check.stderr).expect("check stderr utf8");
    assert!(
        check.status.success(),
        "check failed\nstdout:\n{}\nstderr:\n{}",
        check_stdout,
        check_stderr
    );

    let witness_sha = parse_stdout_line(&check_stdout, "witness_sha256");
    let baseline_path = artifacts_dir
        .join("witness")
        .join(format!("{}.json", witness_sha));
    assert!(baseline_path.exists(), "missing baseline witness artifact");

    let baseline: admit_core::Witness =
        serde_json::from_slice(&std::fs::read(&baseline_path).expect("read baseline witness"))
            .expect("decode baseline witness");
    assert_eq!(
        baseline.schema_id.as_deref(),
        Some(admit_core::DEFAULT_WITNESS_SCHEMA_ID)
    );
    assert_eq!(baseline.lens_id, "lens:default@0");

    let snapshot_hash = baseline
        .program
        .snapshot_hash
        .clone()
        .expect("snapshot hash in baseline witness");

    let mut candidate = baseline.clone();
    candidate.lens_id = "lens:v1@1".to_string();
    candidate.lens_hash = lens_v1_hash;
    let candidate_path = temp.path().join("candidate-witness.json");
    std::fs::write(
        &candidate_path,
        serde_json::to_vec_pretty(&candidate).expect("encode candidate witness"),
    )
    .expect("write candidate witness");

    let ledger_after_check = read_ledger_lines(&ledger_path);
    assert!(
        ledger_after_check
            .iter()
            .any(|line| line.contains("\"event_type\":\"lens.activated\"")),
        "expected lens.activated event in ledger"
    );

    let delta = run_cmd(&[
        "lens",
        "delta",
        "--baseline",
        baseline_path.to_str().expect("baseline path"),
        "--candidate",
        candidate_path.to_str().expect("candidate path"),
        "--snapshot-hash",
        &snapshot_hash,
        "--meta-registry",
        registry_path.to_str().expect("registry path"),
        "--ledger",
        ledger_path.to_str().expect("ledger path"),
        "--artifacts-dir",
        artifacts_dir.to_str().expect("artifacts path"),
        "--json",
    ]);
    let delta_stdout = String::from_utf8(delta.stdout).expect("delta stdout utf8");
    let delta_stderr = String::from_utf8(delta.stderr).expect("delta stderr utf8");
    assert!(
        delta.status.success(),
        "lens delta failed\nstdout:\n{}\nstderr:\n{}",
        delta_stdout,
        delta_stderr
    );
    let delta_json: serde_json::Value =
        serde_json::from_str(delta_stdout.trim()).expect("decode delta json");
    assert_eq!(
        delta_json
            .get("meta_interpretation_delta_event")
            .and_then(|v| v.get("event_type"))
            .and_then(|v| v.as_str()),
        Some("meta.interpretation.delta")
    );

    let ledger_after_delta = read_ledger_lines(&ledger_path);
    assert_eq!(ledger_after_delta.len(), ledger_after_check.len() + 1);
    assert_eq!(
        &ledger_after_delta[..ledger_after_check.len()],
        ledger_after_check.as_slice(),
        "ledger prefix changed after delta append"
    );

    let update = run_cmd(&[
        "lens",
        "update",
        "--from-lens",
        "lens:default@0",
        "--kind",
        kind,
        "--payload-ref",
        payload_ref,
        "--to-lens",
        "lens:v1@1",
        "--route",
        "bucket:trust_debt=1:risk_points",
        "--change-constraints",
        "--meta-registry",
        registry_path.to_str().expect("registry path"),
        "--ledger",
        ledger_path.to_str().expect("ledger path"),
        "--json",
    ]);
    let update_stdout = String::from_utf8(update.stdout).expect("update stdout utf8");
    let update_stderr = String::from_utf8(update.stderr).expect("update stderr utf8");
    assert!(
        update.status.success(),
        "lens update failed\nstdout:\n{}\nstderr:\n{}",
        update_stdout,
        update_stderr
    );
    let update_json: serde_json::Value =
        serde_json::from_str(update_stdout.trim()).expect("decode update json");
    assert_eq!(
        update_json
            .get("meta_change_checked_event")
            .and_then(|v| v.get("event_type"))
            .and_then(|v| v.as_str()),
        Some("meta.change.checked")
    );

    let ledger_after_update = read_ledger_lines(&ledger_path);
    assert_eq!(ledger_after_update.len(), ledger_after_delta.len() + 1);
    assert_eq!(
        &ledger_after_update[..ledger_after_delta.len()],
        ledger_after_delta.as_slice(),
        "ledger prefix changed after meta-change append"
    );
    assert!(
        ledger_after_update
            .last()
            .is_some_and(|line| line.contains("\"event_type\":\"meta.change.checked\"")),
        "expected final event to be meta.change.checked"
    );
}
