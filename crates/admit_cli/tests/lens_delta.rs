use std::path::PathBuf;
use std::process::Command;

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

#[test]
fn lens_delta_emits_artifact_and_ledger_event() {
    let temp = tempfile::tempdir().expect("tempdir");
    let artifacts_dir = temp.path().join("artifacts");
    let ledger_path = temp.path().join("ledger.jsonl");
    let baseline = testdata_root()
        .join("golden-witness")
        .join("allow-erasure-trigger.json");
    let candidate = testdata_root()
        .join("golden-witness")
        .join("scope-widen-accounted.json");

    let output = Command::new(find_admit_cli_bin())
        .args([
            "lens",
            "delta",
            "--baseline",
            baseline.to_str().expect("baseline path"),
            "--candidate",
            candidate.to_str().expect("candidate path"),
            "--snapshot-hash",
            "snapshot:test@1",
            "--artifacts-dir",
            artifacts_dir.to_str().expect("artifacts path"),
            "--ledger",
            ledger_path.to_str().expect("ledger path"),
            "--json",
        ])
        .output()
        .expect("run lens delta");

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
        Some("lens_delta")
    );
    assert_eq!(
        value
            .get("witness_artifact")
            .and_then(|v| v.get("schema_id"))
            .and_then(|v| v.as_str()),
        Some("lens-delta-witness/0")
    );
    assert_eq!(
        value
            .get("witness_artifact")
            .and_then(|v| v.get("sha256"))
            .and_then(|v| v.as_str()),
        Some("8aead4c97613c1f2ab8956b062b80b85593162c21ef4dee9f1241fc076d7a805")
    );
    assert_eq!(
        value
            .get("meta_interpretation_delta_event")
            .and_then(|v| v.get("event_type"))
            .and_then(|v| v.as_str()),
        Some("meta.interpretation.delta")
    );

    let ledger = std::fs::read_to_string(&ledger_path).expect("read ledger");
    assert!(
        ledger.contains("\"event_type\":\"meta.interpretation.delta\""),
        "ledger missing meta.interpretation.delta event:\n{}",
        ledger
    );
}

#[test]
fn lens_delta_rejects_legacy_witness_without_lens_metadata() {
    let temp = tempfile::tempdir().expect("tempdir");
    let artifacts_dir = temp.path().join("artifacts");
    let baseline = testdata_root()
        .join("artifacts")
        .join("witness")
        .join("5429b6067c816d04251ae8c2f5e3e9d0e838d8a2501b99ed91dcdf6448019151.json");
    let candidate = testdata_root()
        .join("golden-witness")
        .join("scope-widen-accounted.json");

    let output = Command::new(find_admit_cli_bin())
        .args([
            "lens",
            "delta",
            "--baseline",
            baseline.to_str().expect("baseline path"),
            "--candidate",
            candidate.to_str().expect("candidate path"),
            "--snapshot-hash",
            "snapshot:test@1",
            "--artifacts-dir",
            artifacts_dir.to_str().expect("artifacts path"),
        ])
        .output()
        .expect("run lens delta");

    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(!output.status.success(), "expected command to fail");
    assert!(
        stderr.contains("missing lens metadata"),
        "stderr:\n{}",
        stderr
    );
}
