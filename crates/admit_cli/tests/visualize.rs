use std::path::PathBuf;
use std::process::Command;

const WITNESS_SHA: &str = "5429b6067c816d04251ae8c2f5e3e9d0e838d8a2501b99ed91dcdf6448019151";

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

fn testdata_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("testdata")
}

fn artifacts_root() -> PathBuf {
    testdata_root().join("artifacts")
}

fn ledger_path() -> PathBuf {
    testdata_root().join("ledger").join("ledger.jsonl")
}

fn witness_json_path() -> PathBuf {
    artifacts_root()
        .join("witness")
        .join(format!("{}.json", WITNESS_SHA))
}

fn witness_cbor_path() -> PathBuf {
    artifacts_root()
        .join("witness")
        .join(format!("{}.cbor", WITNESS_SHA))
}

fn run_admit(args: &[&str]) -> std::process::Output {
    Command::new(find_admit_cli_bin())
        .args(args)
        .output()
        .expect("run admit_cli")
}

#[test]
fn show_path_witness_pretty_prints_header() {
    let output = run_admit(&["show", witness_json_path().to_str().expect("path")]);
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains("Witness  admissibility-witness/1"),
        "{}",
        stdout
    );
    assert!(
        stdout.contains(&format!("hash: sha256:{}", WITNESS_SHA)),
        "{}",
        stdout
    );
}

#[test]
fn show_path_cbor_is_supported() {
    let output = run_admit(&["show", witness_cbor_path().to_str().expect("path")]);
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains("Witness  admissibility-witness/1"),
        "{}",
        stdout
    );
}

#[test]
fn show_sha256_resolves_from_store() {
    let output = run_admit(&[
        "show",
        &format!("sha256:{}", WITNESS_SHA),
        "--artifacts-dir",
        artifacts_root().to_str().expect("path"),
    ]);
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    assert!(
        stdout.contains(&format!("hash: sha256:{}", WITNESS_SHA)),
        "{}",
        stdout
    );
}

#[test]
fn status_json_v2_emits_repo_ledger_and_governance_sections() {
    let output = run_admit(&[
        "status",
        "--ledger",
        ledger_path().to_str().expect("path"),
        "--artifacts-dir",
        artifacts_root().to_str().expect("path"),
        "--json",
    ]);
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("decode json");
    assert_eq!(
        value.get("command").and_then(|v| v.as_str()),
        Some("status")
    );
    assert!(value.get("repo").is_some());
    assert!(value.get("ledger").is_some());
    assert!(value.get("governance").is_some());
    assert!(
        value
            .get("governance")
            .and_then(|v| v.get("latest_check"))
            .and_then(|v| v.get("event_type"))
            .and_then(|v| v.as_str())
            == Some("admissibility.checked")
    );
}

#[test]
fn show_json_envelope_contains_required_keys() {
    let output = run_admit(&[
        "show",
        witness_json_path().to_str().expect("path"),
        "--json",
    ]);
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("decode json");
    assert_eq!(value.get("command").and_then(|v| v.as_str()), Some("show"));
    assert_eq!(
        value.get("detected_type").and_then(|v| v.as_str()),
        Some("witness")
    );
    assert!(value.get("artifact").is_some());
    assert!(value.get("header").is_some());
    assert!(value.get("sections").is_some());
}

#[test]
fn explain_json_emits_verdict_rules_and_findings() {
    let output = run_admit(&[
        "explain",
        witness_json_path().to_str().expect("path"),
        "--json",
    ]);
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("decode json");
    assert_eq!(
        value.get("command").and_then(|v| v.as_str()),
        Some("explain")
    );
    assert_eq!(
        value.get("verdict").and_then(|v| v.as_str()),
        Some("inadmissible")
    );
    assert!(value.get("rules").and_then(|v| v.as_array()).is_some());
    assert!(value.get("findings").and_then(|v| v.as_array()).is_some());
    assert!(value
        .get("grouped_by_file")
        .and_then(|v| v.as_array())
        .is_some());
}

#[test]
fn log_artifacts_json_replaces_list_artifacts() {
    let output = run_admit(&[
        "log",
        "--source",
        "artifacts",
        "--artifacts-dir",
        artifacts_root().to_str().expect("path"),
        "--json",
    ]);
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("decode json");
    assert_eq!(value.get("command").and_then(|v| v.as_str()), Some("log"));
    assert_eq!(
        value.get("source").and_then(|v| v.as_str()),
        Some("artifacts")
    );
    let rows = value
        .get("rows")
        .and_then(|v| v.as_array())
        .expect("rows array");
    assert!(!rows.is_empty());
}

#[test]
fn log_ledger_json_reads_event_rows() {
    let output = run_admit(&[
        "log",
        "--source",
        "ledger",
        "--ledger",
        ledger_path().to_str().expect("path"),
        "--json",
    ]);
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("decode json");
    assert_eq!(value.get("source").and_then(|v| v.as_str()), Some("ledger"));
    let rows = value
        .get("rows")
        .and_then(|v| v.as_array())
        .expect("rows array");
    assert!(!rows.is_empty());
    assert!(rows
        .iter()
        .any(|row| row.get("event_type").and_then(|v| v.as_str()) == Some("cost.declared")));
}

#[test]
fn log_ledger_filters_by_scope_and_verdict() {
    let output = run_admit(&[
        "log",
        "--source",
        "ledger",
        "--ledger",
        ledger_path().to_str().expect("path"),
        "--artifacts-dir",
        artifacts_root().to_str().expect("path"),
        "--scope",
        "scope:main",
        "--verdict",
        "inadmissible",
        "--json",
    ]);
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("decode json");
    let rows = value
        .get("rows")
        .and_then(|v| v.as_array())
        .expect("rows array");
    assert!(!rows.is_empty());
    assert!(rows.iter().all(|row| {
        row.get("scope").and_then(|v| v.as_str()) == Some("scope:main")
            && row.get("verdict").and_then(|v| v.as_str()) == Some("inadmissible")
    }));
}

#[test]
fn log_ledger_since_filter_can_return_empty_set() {
    let output = run_admit(&[
        "log",
        "--source",
        "ledger",
        "--ledger",
        ledger_path().to_str().expect("path"),
        "--artifacts-dir",
        artifacts_root().to_str().expect("path"),
        "--since",
        "2099-01-01T00:00:00Z",
        "--json",
    ]);
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(
        output.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        stdout,
        stderr
    );
    let value: serde_json::Value = serde_json::from_str(stdout.trim()).expect("decode json");
    let rows = value
        .get("rows")
        .and_then(|v| v.as_array())
        .expect("rows array");
    assert!(rows.is_empty());
}

#[test]
fn show_hash_ambiguous_without_kind_and_disambiguates_with_kind() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path();
    let witness_dir = root.join("witness");
    let mirror_dir = root.join("mirror");
    std::fs::create_dir_all(&witness_dir).expect("mkdir witness");
    std::fs::create_dir_all(&mirror_dir).expect("mkdir mirror");

    let src = witness_json_path();
    std::fs::copy(&src, witness_dir.join(format!("{}.json", WITNESS_SHA))).expect("copy 1");
    std::fs::copy(&src, mirror_dir.join(format!("{}.json", WITNESS_SHA))).expect("copy 2");

    let bad = run_admit(&[
        "show",
        &format!("sha256:{}", WITNESS_SHA),
        "--artifacts-dir",
        root.to_str().expect("path"),
    ]);
    let bad_stderr = String::from_utf8(bad.stderr).expect("stderr utf8");
    assert!(!bad.status.success());
    assert!(
        bad_stderr.contains("ambiguous target"),
        "stderr:\n{}",
        bad_stderr
    );

    let ok = run_admit(&[
        "show",
        &format!("sha256:{}", WITNESS_SHA),
        "--artifacts-dir",
        root.to_str().expect("path"),
        "--kind",
        "witness",
    ]);
    let ok_stdout = String::from_utf8(ok.stdout).expect("stdout utf8");
    let ok_stderr = String::from_utf8(ok.stderr).expect("stderr utf8");
    assert!(
        ok.status.success(),
        "command failed\nstdout:\n{}\nstderr:\n{}",
        ok_stdout,
        ok_stderr
    );
    assert!(ok_stdout.contains("Witness  admissibility-witness/1"));
}

#[test]
fn removed_legacy_commands_fail() {
    for cmd in ["list-artifacts", "show-artifact"] {
        let output = run_admit(&[cmd]);
        let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
        assert!(!output.status.success(), "expected failure for {}", cmd);
        assert!(
            stderr.contains("unrecognized subcommand"),
            "stderr for {}:\n{}",
            cmd,
            stderr
        );
    }
}
