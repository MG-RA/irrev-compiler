use std::path::PathBuf;

use admit_cli::summarize_ledger;

fn temp_path(label: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    std::env::temp_dir().join(format!("admit-status-{}-{}.jsonl", label, nanos))
}

#[test]
fn summarize_ledger_returns_empty_for_missing_file() {
    let path = temp_path("missing");
    let summary = summarize_ledger(&path).expect("summarize");
    assert_eq!(summary.events_total, 0);
    assert!(summary.latest_event_type.is_none());
    assert!(summary.latest_ingest.is_none());
}

#[test]
fn summarize_ledger_tracks_latest_key_event_types() {
    let path = temp_path("latest");
    let lines = [
        serde_json::json!({
            "event_type": "ingest.completed",
            "event_id": "evt-1",
            "timestamp": "2026-02-07T00:00:01Z",
            "ingest_run_id": "ing-1",
            "status": "complete"
        }),
        serde_json::json!({
            "event_type": "plan.created",
            "event_id": "evt-2",
            "timestamp": "2026-02-07T00:00:02Z"
        }),
        serde_json::json!({
            "event_type": "projection.completed",
            "event_id": "evt-3",
            "timestamp": "2026-02-07T00:00:03Z",
            "projection_run_id": "proj-1",
            "status": "complete"
        }),
        serde_json::json!({
            "event_type": "rust.ir_lint.completed",
            "event_id": "evt-4",
            "timestamp": "2026-02-07T00:00:04Z",
            "violations": 3,
            "passed": false
        }),
    ];

    let mut text = String::new();
    for line in &lines {
        text.push_str(&serde_json::to_string(line).expect("serialize line"));
        text.push('\n');
    }
    std::fs::write(&path, text).expect("write ledger");

    let summary = summarize_ledger(&path).expect("summarize");
    assert_eq!(summary.events_total, 4);
    assert_eq!(summary.latest_event_id.as_deref(), Some("evt-4"));
    assert_eq!(
        summary
            .latest_ingest
            .as_ref()
            .and_then(|e| e.run_id.as_deref()),
        Some("ing-1")
    );
    assert_eq!(
        summary
            .latest_projection
            .as_ref()
            .and_then(|e| e.run_id.as_deref()),
        Some("proj-1")
    );
    assert_eq!(
        summary.latest_rust_lint.as_ref().and_then(|e| e.violations),
        Some(3)
    );
}
