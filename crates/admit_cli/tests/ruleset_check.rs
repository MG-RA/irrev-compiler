use std::collections::BTreeSet;
use std::process::Command;

use admit_core::provider_types::{FactsBundle, SnapshotRequest};
use admit_core::{Fact, Provider, ScopeId};
use admit_scope_deps::backend::DEPS_MANIFEST_SCOPE_ID;
use admit_scope_deps::provider_impl::DepsManifestProvider;
use admit_scope_git::backend::GIT_WORKING_TREE_SCOPE_ID;
use admit_scope_git::provider_impl::GitWorkingTreeProvider;
use admit_scope_rust::backend::RUST_SCOPE_ID;
use admit_scope_rust::provider_impl::RustStructureProvider;
use admit_scope_text::backend::TEXT_METRICS_SCOPE_ID;
use admit_scope_text::provider_impl::TextMetricsProvider;

fn find_admit_cli_bin() -> std::path::PathBuf {
    for key in ["CARGO_BIN_EXE_admit_cli", "CARGO_BIN_EXE_admit-cli"] {
        if let Ok(path) = std::env::var(key) {
            return std::path::PathBuf::from(path);
        }
    }

    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
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

    panic!(
        "admit_cli binary path not found via CARGO_BIN_EXE_* or {}",
        target_debug.display()
    );
}

fn git_available() -> bool {
    Command::new("git").arg("--version").output().is_ok()
}

fn run_git(root: &std::path::Path, args: &[&str]) {
    let status = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .status()
        .expect("run git");
    assert!(
        status.success(),
        "git command failed: git -C {:?} {:?}",
        root,
        args
    );
}

fn combined_git_deps_guardrails_ruleset() -> serde_json::Value {
    serde_json::json!({
        "schema_id": "ruleset/admit@1",
        "ruleset_id": "git-deps-guardrails",
        "enabled_rules": ["R-200", "R-210", "R-400", "R-410", "R-420"],
        "bindings": [
            {
                "rule_id": "R-200",
                "severity": "error",
                "when": {
                    "scope_id": "git.working_tree",
                    "predicate": "dirty_state",
                    "params": {}
                }
            },
            {
                "rule_id": "R-210",
                "severity": "error",
                "when": {
                    "scope_id": "git.working_tree",
                    "predicate": "untracked_file",
                    "params": {}
                }
            },
            {
                "rule_id": "R-400",
                "severity": "error",
                "when": {
                    "scope_id": "deps.manifest",
                    "predicate": "git_dependency_present",
                    "params": {}
                }
            },
            {
                "rule_id": "R-410",
                "severity": "error",
                "when": {
                    "scope_id": "deps.manifest",
                    "predicate": "wildcard_version_present",
                    "params": {}
                }
            },
            {
                "rule_id": "R-420",
                "severity": "error",
                "when": {
                    "scope_id": "deps.manifest",
                    "predicate": "lockfile_missing",
                    "params": {}
                }
            }
        ],
        "fail_on": "error"
    })
}

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
    let bin = find_admit_cli_bin();
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
    assert!(
        stdout.contains("verdict=inadmissible"),
        "stdout:\n{}",
        stdout
    );

    let witness_sha = stdout
        .lines()
        .find_map(|line| line.strip_prefix("witness_sha256="))
        .expect("witness_sha256 line");
    let witness_path = artifacts_dir
        .join("witness")
        .join(format!("{}.json", witness_sha));
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

#[test]
fn check_ruleset_git_scope_detects_dirty_tree_from_inputs() {
    if !git_available() {
        return;
    }

    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("repo");
    std::fs::create_dir_all(&root).expect("create repo dir");
    run_git(&root, &["init", "-q"]);
    std::fs::write(root.join("tracked.txt"), "v1\n").expect("write tracked");
    run_git(&root, &["add", "tracked.txt"]);
    run_git(
        &root,
        &[
            "-c",
            "user.email=test@example.com",
            "-c",
            "user.name=Test",
            "commit",
            "-m",
            "init",
            "-q",
        ],
    );
    std::fs::write(root.join("tracked.txt"), "v2\n").expect("modify tracked");
    std::fs::write(root.join("new.txt"), "new\n").expect("write untracked");

    let provider = GitWorkingTreeProvider::new();
    let snapshot = provider
        .snapshot(&SnapshotRequest {
            scope_id: ScopeId(GIT_WORKING_TREE_SCOPE_ID.to_string()),
            params: serde_json::json!({ "root": root.to_string_lossy() }),
        })
        .expect("snapshot");

    let facts_path = temp.path().join("git.facts.json");
    std::fs::write(
        &facts_path,
        serde_json::to_vec(&snapshot.facts_bundle).expect("encode facts bundle"),
    )
    .expect("write facts bundle");

    let ruleset_path = temp.path().join("ruleset-git.json");
    let ruleset = serde_json::json!({
        "schema_id": "ruleset/admit@1",
        "ruleset_id": "git-default",
        "enabled_rules": ["R-200"],
        "bindings": [{
            "rule_id": "R-200",
            "severity": "error",
            "when": {
                "scope_id": "git.working_tree",
                "predicate": "dirty_state",
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
    let bin = find_admit_cli_bin();
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
    assert!(
        stdout.contains("verdict=inadmissible"),
        "stdout:\n{}",
        stdout
    );
    assert!(
        stdout.contains("rule_result id=R-200"),
        "missing R-200 rule output\n{}",
        stdout
    );

    let witness_sha = stdout
        .lines()
        .find_map(|line| line.strip_prefix("witness_sha256="))
        .expect("witness_sha256 line");
    let witness_path = artifacts_dir
        .join("witness")
        .join(format!("{}.json", witness_sha));
    let witness_bytes = std::fs::read(&witness_path).expect("read witness");
    let witness: admit_core::Witness = serde_json::from_slice(&witness_bytes).expect("witness");
    assert!(
        witness.facts.iter().any(|fact| matches!(
            fact,
            Fact::PredicateEvaluated { predicate, result, .. }
                if predicate.contains("git.working_tree::dirty_state") && *result
        )),
        "expected predicate trace for git dirty_state"
    );
}

#[test]
fn check_ruleset_text_metrics_detects_line_limit_violation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("repo");
    std::fs::create_dir_all(&root).expect("create repo dir");
    std::fs::write(
        root.join("large.txt"),
        "line1\nline2\nline3\nline4\nline5\nline6\n",
    )
    .expect("write fixture");

    let provider = TextMetricsProvider::new();
    let snapshot = provider
        .snapshot(&SnapshotRequest {
            scope_id: ScopeId(TEXT_METRICS_SCOPE_ID.to_string()),
            params: serde_json::json!({ "root": root.to_string_lossy() }),
        })
        .expect("snapshot");

    let facts_path = temp.path().join("text.facts.json");
    std::fs::write(
        &facts_path,
        serde_json::to_vec(&snapshot.facts_bundle).expect("encode facts bundle"),
    )
    .expect("write facts bundle");

    let ruleset_path = temp.path().join("ruleset-text.json");
    let ruleset = serde_json::json!({
        "schema_id": "ruleset/admit@1",
        "ruleset_id": "text-default",
        "enabled_rules": ["R-300"],
        "bindings": [{
            "rule_id": "R-300",
            "severity": "error",
            "when": {
                "scope_id": "text.metrics",
                "predicate": "lines_exceed",
                "params": { "max_lines": 4 }
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
    let bin = find_admit_cli_bin();
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
    assert!(
        stdout.contains("verdict=inadmissible"),
        "stdout:\n{}",
        stdout
    );
    assert!(
        stdout.contains("rule_result id=R-300"),
        "missing R-300 rule output\n{}",
        stdout
    );

    let witness_sha = stdout
        .lines()
        .find_map(|line| line.strip_prefix("witness_sha256="))
        .expect("witness_sha256 line");
    let witness_path = artifacts_dir
        .join("witness")
        .join(format!("{}.json", witness_sha));
    let witness_bytes = std::fs::read(&witness_path).expect("read witness");
    let witness: admit_core::Witness = serde_json::from_slice(&witness_bytes).expect("witness");
    assert!(
        witness.facts.iter().any(|fact| matches!(
            fact,
            Fact::PredicateEvaluated { predicate, result, .. }
                if predicate.contains("text.metrics::lines_exceed") && *result
        )),
        "expected predicate trace for text.metrics lines_exceed"
    );
}

#[test]
fn check_ruleset_deps_manifest_detects_git_dependency() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("repo");
    std::fs::create_dir_all(&root).expect("create repo dir");
    std::fs::write(
        root.join("Cargo.toml"),
        r#"
[package]
name = "fixture"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0"
git_dep = { git = "https://example.com/repo.git" }
"#,
    )
    .expect("write fixture");

    let provider = DepsManifestProvider::new();
    let snapshot = provider
        .snapshot(&SnapshotRequest {
            scope_id: ScopeId(DEPS_MANIFEST_SCOPE_ID.to_string()),
            params: serde_json::json!({ "root": root.to_string_lossy() }),
        })
        .expect("snapshot");

    let facts_path = temp.path().join("deps.facts.json");
    std::fs::write(
        &facts_path,
        serde_json::to_vec(&snapshot.facts_bundle).expect("encode facts bundle"),
    )
    .expect("write facts bundle");

    let ruleset_path = temp.path().join("ruleset-deps.json");
    let ruleset = serde_json::json!({
        "schema_id": "ruleset/admit@1",
        "ruleset_id": "deps-default",
        "enabled_rules": ["R-400"],
        "bindings": [{
            "rule_id": "R-400",
            "severity": "error",
            "when": {
                "scope_id": "deps.manifest",
                "predicate": "git_dependency_present",
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
    let bin = find_admit_cli_bin();
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
    assert!(
        stdout.contains("verdict=inadmissible"),
        "stdout:\n{}",
        stdout
    );
    assert!(
        stdout.contains("rule_result id=R-400"),
        "missing R-400 rule output\n{}",
        stdout
    );

    let witness_sha = stdout
        .lines()
        .find_map(|line| line.strip_prefix("witness_sha256="))
        .expect("witness_sha256 line");
    let witness_path = artifacts_dir
        .join("witness")
        .join(format!("{}.json", witness_sha));
    let witness_bytes = std::fs::read(&witness_path).expect("read witness");
    let witness: admit_core::Witness = serde_json::from_slice(&witness_bytes).expect("witness");
    assert!(
        witness.facts.iter().any(|fact| matches!(
            fact,
            Fact::PredicateEvaluated { predicate, result, .. }
                if predicate.contains("deps.manifest::git_dependency_present") && *result
        )),
        "expected predicate trace for deps.manifest git_dependency_present"
    );
}

#[test]
fn check_ruleset_git_deps_combined_detects_violations() {
    if !git_available() {
        return;
    }

    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("repo");
    std::fs::create_dir_all(&root).expect("create repo dir");
    run_git(&root, &["init", "-q"]);
    std::fs::write(root.join("tracked.txt"), "v1\n").expect("write tracked");
    run_git(&root, &["add", "tracked.txt"]);
    run_git(
        &root,
        &[
            "-c",
            "user.email=test@example.com",
            "-c",
            "user.name=Test",
            "commit",
            "-m",
            "init",
            "-q",
        ],
    );
    std::fs::write(root.join("tracked.txt"), "v2\n").expect("modify tracked");
    std::fs::write(root.join("untracked.txt"), "new\n").expect("write untracked");
    std::fs::write(
        root.join("Cargo.toml"),
        r#"
[package]
name = "fixture"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "*"
git_dep = { git = "https://example.com/repo.git" }
"#,
    )
    .expect("write Cargo.toml");

    let git_provider = GitWorkingTreeProvider::new();
    let git_snapshot = git_provider
        .snapshot(&SnapshotRequest {
            scope_id: ScopeId(GIT_WORKING_TREE_SCOPE_ID.to_string()),
            params: serde_json::json!({ "root": root.to_string_lossy() }),
        })
        .expect("git snapshot");

    let deps_provider = DepsManifestProvider::new();
    let deps_snapshot = deps_provider
        .snapshot(&SnapshotRequest {
            scope_id: ScopeId(DEPS_MANIFEST_SCOPE_ID.to_string()),
            params: serde_json::json!({ "root": root.to_string_lossy() }),
        })
        .expect("deps snapshot");

    let git_facts_path = temp.path().join("git.facts.json");
    std::fs::write(
        &git_facts_path,
        serde_json::to_vec(&git_snapshot.facts_bundle).expect("encode git facts bundle"),
    )
    .expect("write git facts bundle");
    let deps_facts_path = temp.path().join("deps.facts.json");
    std::fs::write(
        &deps_facts_path,
        serde_json::to_vec(&deps_snapshot.facts_bundle).expect("encode deps facts bundle"),
    )
    .expect("write deps facts bundle");

    let ruleset_path = temp.path().join("ruleset-git-deps.json");
    std::fs::write(
        &ruleset_path,
        serde_json::to_vec(&combined_git_deps_guardrails_ruleset()).expect("encode ruleset"),
    )
    .expect("write ruleset");

    let inputs_arg = format!(
        "{},{}",
        git_facts_path.to_str().expect("git facts path"),
        deps_facts_path.to_str().expect("deps facts path")
    );
    let artifacts_dir = temp.path().join("artifacts");
    let bin = find_admit_cli_bin();
    let output = Command::new(bin)
        .args([
            "check",
            "--ruleset",
            ruleset_path.to_str().expect("ruleset path"),
            "--inputs",
            inputs_arg.as_str(),
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
    assert!(
        stdout.contains("verdict=inadmissible"),
        "stdout:\n{}",
        stdout
    );

    let witness_sha = stdout
        .lines()
        .find_map(|line| line.strip_prefix("witness_sha256="))
        .expect("witness_sha256 line");
    let witness_path = artifacts_dir
        .join("witness")
        .join(format!("{}.json", witness_sha));
    let witness_bytes = std::fs::read(&witness_path).expect("read witness");
    let witness: admit_core::Witness = serde_json::from_slice(&witness_bytes).expect("witness");

    let mut git_triggered = false;
    let mut deps_triggered = false;
    for fact in &witness.facts {
        if let Fact::PredicateEvaluated {
            predicate, result, ..
        } = fact
        {
            if *result && predicate.contains("git.working_tree::") {
                git_triggered = true;
            }
            if *result && predicate.contains("deps.manifest::") {
                deps_triggered = true;
            }
        }
    }
    assert!(
        git_triggered,
        "expected at least one triggered git predicate in combined witness"
    );
    assert!(
        deps_triggered,
        "expected at least one triggered deps predicate in combined witness"
    );
}

#[test]
fn check_ruleset_git_deps_combined_passes_clean_inputs() {
    if !git_available() {
        return;
    }

    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("repo");
    std::fs::create_dir_all(&root).expect("create repo dir");
    run_git(&root, &["init", "-q"]);

    std::fs::write(root.join("tracked.txt"), "v1\n").expect("write tracked");
    std::fs::write(
        root.join("Cargo.toml"),
        r#"
[package]
name = "fixture"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0.0"
"#,
    )
    .expect("write Cargo.toml");
    std::fs::write(
        root.join("Cargo.lock"),
        r#"
version = 3

[[package]]
name = "fixture"
version = "0.1.0"

[[package]]
name = "serde"
version = "1.0.0"
"#,
    )
    .expect("write Cargo.lock");

    run_git(&root, &["add", "."]);
    run_git(
        &root,
        &[
            "-c",
            "user.email=test@example.com",
            "-c",
            "user.name=Test",
            "commit",
            "-m",
            "clean baseline",
            "-q",
        ],
    );

    let git_provider = GitWorkingTreeProvider::new();
    let git_snapshot = git_provider
        .snapshot(&SnapshotRequest {
            scope_id: ScopeId(GIT_WORKING_TREE_SCOPE_ID.to_string()),
            params: serde_json::json!({ "root": root.to_string_lossy() }),
        })
        .expect("git snapshot");

    let deps_provider = DepsManifestProvider::new();
    let deps_snapshot = deps_provider
        .snapshot(&SnapshotRequest {
            scope_id: ScopeId(DEPS_MANIFEST_SCOPE_ID.to_string()),
            params: serde_json::json!({ "root": root.to_string_lossy() }),
        })
        .expect("deps snapshot");

    let git_facts_path = temp.path().join("git.facts.json");
    std::fs::write(
        &git_facts_path,
        serde_json::to_vec(&git_snapshot.facts_bundle).expect("encode git facts bundle"),
    )
    .expect("write git facts bundle");
    let deps_facts_path = temp.path().join("deps.facts.json");
    std::fs::write(
        &deps_facts_path,
        serde_json::to_vec(&deps_snapshot.facts_bundle).expect("encode deps facts bundle"),
    )
    .expect("write deps facts bundle");

    let ruleset_path = temp.path().join("ruleset-git-deps.json");
    std::fs::write(
        &ruleset_path,
        serde_json::to_vec(&combined_git_deps_guardrails_ruleset()).expect("encode ruleset"),
    )
    .expect("write ruleset");

    let inputs_arg = format!(
        "{},{}",
        git_facts_path.to_str().expect("git facts path"),
        deps_facts_path.to_str().expect("deps facts path")
    );
    let artifacts_dir = temp.path().join("artifacts");
    let bin = find_admit_cli_bin();
    let output = Command::new(bin)
        .args([
            "check",
            "--ruleset",
            ruleset_path.to_str().expect("ruleset path"),
            "--inputs",
            inputs_arg.as_str(),
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
    assert!(stdout.contains("verdict=admissible"), "stdout:\n{}", stdout);

    let witness_sha = stdout
        .lines()
        .find_map(|line| line.strip_prefix("witness_sha256="))
        .expect("witness_sha256 line");
    let witness_path = artifacts_dir
        .join("witness")
        .join(format!("{}.json", witness_sha));
    let witness_bytes = std::fs::read(&witness_path).expect("read witness");
    let witness: admit_core::Witness = serde_json::from_slice(&witness_bytes).expect("witness");

    let target_rules = ["R-200", "R-210", "R-400", "R-410", "R-420"];
    let mut seen_rules = BTreeSet::new();
    let mut triggered_rules = Vec::new();
    for fact in &witness.facts {
        if let Fact::RuleEvaluated {
            rule_id, triggered, ..
        } = fact
        {
            if target_rules.contains(&rule_id.as_str()) {
                seen_rules.insert(rule_id.clone());
                if *triggered {
                    triggered_rules.push(rule_id.clone());
                }
            }
        }
    }
    assert_eq!(
        seen_rules.len(),
        target_rules.len(),
        "expected all combined rules to be evaluated, saw: {:?}",
        seen_rules
    );
    assert!(
        triggered_rules.is_empty(),
        "expected no triggered rules in clean scenario, got: {:?}",
        triggered_rules
    );
}

#[test]
fn observe_scope_git_working_tree_writes_facts_bundle() {
    if !git_available() {
        return;
    }

    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("repo");
    std::fs::create_dir_all(&root).expect("create repo dir");
    run_git(&root, &["init", "-q"]);
    std::fs::write(root.join("tracked.txt"), "v1\n").expect("write tracked");
    run_git(&root, &["add", "tracked.txt"]);
    run_git(
        &root,
        &[
            "-c",
            "user.email=test@example.com",
            "-c",
            "user.name=Test",
            "commit",
            "-m",
            "init",
            "-q",
        ],
    );

    let out_path = temp.path().join("git.observe.facts.json");
    let bin = find_admit_cli_bin();
    let output = Command::new(bin)
        .args([
            "observe",
            "--scope",
            "git.working_tree",
            "--root",
            root.to_str().expect("repo path"),
            "--out",
            out_path.to_str().expect("out path"),
        ])
        .output()
        .expect("run admit_cli observe --scope");

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    assert!(stdout.contains("mode=scope"), "stdout:\n{}", stdout);
    assert!(
        stdout.contains("scope_id=git.working_tree"),
        "stdout:\n{}",
        stdout
    );
    assert!(out_path.exists(), "missing observe output bundle");

    let bundle_bytes = std::fs::read(&out_path).expect("read observe bundle");
    let bundle: FactsBundle = serde_json::from_slice(&bundle_bytes).expect("decode observe bundle");
    assert_eq!(bundle.scope_id.0, "git.working_tree");
    assert_eq!(bundle.schema_id, "facts-bundle/git.working_tree@1");
    assert!(
        bundle.facts.iter().any(
            |fact| matches!(fact, Fact::LintFinding { rule_id, .. } if rule_id == "git/branch")
        ),
        "expected git/branch fact"
    );
}

#[test]
fn observe_scope_deps_manifest_writes_facts_bundle() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("repo");
    std::fs::create_dir_all(&root).expect("create repo dir");
    std::fs::write(
        root.join("Cargo.toml"),
        r#"
[package]
name = "fixture"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0"
"#,
    )
    .expect("write fixture");

    let out_path = temp.path().join("deps.observe.facts.json");
    let bin = find_admit_cli_bin();
    let output = Command::new(bin)
        .args([
            "observe",
            "--scope",
            "deps.manifest",
            "--root",
            root.to_str().expect("repo path"),
            "--out",
            out_path.to_str().expect("out path"),
        ])
        .output()
        .expect("run admit_cli observe --scope deps.manifest");

    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    assert!(stdout.contains("mode=scope"), "stdout:\n{}", stdout);
    assert!(
        stdout.contains("scope_id=deps.manifest"),
        "stdout:\n{}",
        stdout
    );
    assert!(out_path.exists(), "missing observe output bundle");

    let bundle_bytes = std::fs::read(&out_path).expect("read observe bundle");
    let bundle: FactsBundle = serde_json::from_slice(&bundle_bytes).expect("decode observe bundle");
    assert_eq!(bundle.scope_id.0, "deps.manifest");
    assert_eq!(bundle.schema_id, "facts-bundle/deps.manifest@1");
    assert!(
        bundle.facts.iter().any(|fact| matches!(
            fact,
            Fact::LintFinding { rule_id, .. } if rule_id == "deps/manifest_file"
        )),
        "expected deps/manifest_file fact"
    );
}
