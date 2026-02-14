use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

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

fn write_ci_files(root: &std::path::Path) {
    let admit_dir = root.join(".admit");
    let rules_dir = admit_dir.join("rulesets");
    std::fs::create_dir_all(&rules_dir).expect("create rules dir");

    std::fs::write(
        admit_dir.join("config.toml"),
        "[ci]\ndefault_ruleset = \"rulesets/software-lens-v0.json\"\nmode = \"observe\"\n",
    )
    .expect("write config");

    std::fs::write(
        rules_dir.join("software-lens-v0.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_id": "ruleset/admit@1",
            "ruleset_id": "software-lens-v0",
            "enabled_rules": ["R-CI-200"],
            "bindings": [{
                "rule_id": "R-CI-200",
                "severity": "warning",
                "when": {
                    "scope_id": "deps.manifest",
                    "predicate": "manifest_changed_without_lockfile",
                    "params": {}
                }
            }],
            "fail_on": "error"
        }))
        .expect("encode ruleset"),
    )
    .expect("write ruleset");
}

#[test]
fn ci_command_is_deterministic_and_ledger_is_append_only() {
    if !git_available() {
        return;
    }

    let temp = tempfile::tempdir().expect("tempdir");
    let repo = temp.path().join("repo");
    std::fs::create_dir_all(&repo).expect("create repo");

    write_ci_files(&repo);
    std::fs::write(
        repo.join("Cargo.toml"),
        "[package]\nname = \"ci-fixture\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    )
    .expect("write Cargo.toml");
    std::fs::write(
        repo.join("Cargo.lock"),
        "version = 3\n\n[[package]]\nname = \"ci-fixture\"\nversion = \"0.1.0\"\n",
    )
    .expect("write Cargo.lock");

    run_git(&repo, &["init", "-q"]);
    run_git(&repo, &["add", "."]);
    run_git(
        &repo,
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

    let artifacts = temp.path().join("artifacts");
    std::fs::create_dir_all(&artifacts).expect("create artifacts dir");

    let run_once = || {
        let output = Command::new(find_admit_cli_bin())
            .args([
                "ci",
                "--root",
                repo.to_str().expect("repo path"),
                "--mode",
                "audit",
                "--json",
                "--artifacts-dir",
                artifacts.to_str().expect("artifacts path"),
            ])
            .output()
            .expect("run admit ci");
        let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
        let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
        assert!(
            output.status.success(),
            "ci command failed\nstdout:\n{}\nstderr:\n{}",
            stdout,
            stderr
        );
        serde_json::from_str::<serde_json::Value>(stdout.trim()).expect("decode ci json")
    };

    let first = run_once();
    let first_hash = first
        .get("witness_hash")
        .and_then(|v| v.as_str())
        .expect("witness_hash")
        .to_string();
    let ledger_path = artifacts.join("ledger.jsonl");
    let ledger_after_first: Vec<String> = std::fs::read_to_string(&ledger_path)
        .expect("read first ledger")
        .lines()
        .map(|line| line.to_string())
        .collect();

    std::thread::sleep(Duration::from_millis(2));

    let second = run_once();
    let second_hash = second
        .get("witness_hash")
        .and_then(|v| v.as_str())
        .expect("witness_hash")
        .to_string();
    let ledger_after_second: Vec<String> = std::fs::read_to_string(&ledger_path)
        .expect("read second ledger")
        .lines()
        .map(|line| line.to_string())
        .collect();

    assert_eq!(
        first_hash, second_hash,
        "witness hash should be deterministic"
    );
    assert_eq!(
        ledger_after_second.len(),
        ledger_after_first.len() + 1,
        "second run should append exactly one ledger event"
    );
    assert_eq!(
        &ledger_after_second[..ledger_after_first.len()],
        ledger_after_first.as_slice(),
        "ledger must remain append-only (prefix invariant)"
    );
}
