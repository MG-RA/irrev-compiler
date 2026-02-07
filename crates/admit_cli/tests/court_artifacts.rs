use std::path::PathBuf;

use tempfile::TempDir;

use admit_cli::{
    append_court_event, build_court_event, register_function_artifact, register_query_artifact,
    verify_ledger,
};

fn temp_path(dir: &TempDir, name: &str) -> PathBuf {
    dir.path().join(name)
}

#[test]
fn court_artifact_event_verifies_cleanly() {
    let dir = TempDir::new().expect("tempdir");
    let artifacts_dir = temp_path(&dir, "artifacts");
    let ledger_path = temp_path(&dir, "ledger.jsonl");

    let query = register_query_artifact(
        &artifacts_dir,
        "audit_counts",
        "surql",
        "SELECT count() AS n FROM doc_file GROUP ALL;",
        vec!["audit".to_string(), "diagnostic".to_string()],
        None,
    )
    .expect("register query artifact");

    let fn_def = register_function_artifact(
        &artifacts_dir,
        "audit_unresolved",
        "surql",
        "RETURN (SELECT resolution_kind, count() AS n FROM doc_link_unresolved GROUP BY resolution_kind);",
        vec!["audit".to_string()],
        None,
    )
    .expect("register function artifact");

    let ts = "2026-02-06T00:00:00Z".to_string();
    let q_event = build_court_event(
        "court.query.registered",
        ts.clone(),
        "query",
        query,
        Some("audit_counts".to_string()),
        Some("surql".to_string()),
        Some(vec!["audit".to_string(), "diagnostic".to_string()]),
    )
    .expect("build query event");
    append_court_event(&ledger_path, &q_event).expect("append query event");

    let f_event = build_court_event(
        "court.function.registered",
        ts,
        "function",
        fn_def,
        Some("audit_unresolved".to_string()),
        Some("surql".to_string()),
        Some(vec!["audit".to_string()]),
    )
    .expect("build function event");
    append_court_event(&ledger_path, &f_event).expect("append function event");

    let report = verify_ledger(&ledger_path, Some(&artifacts_dir)).expect("verify ledger");
    assert_eq!(report.issues.len(), 0, "ledger issues: {:?}", report.issues);
}
