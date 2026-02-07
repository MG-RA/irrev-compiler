use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::types::DeclareCostError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusEventSummary {
    pub event_type: String,
    pub event_id: String,
    pub timestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub violations: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusSummary {
    pub ledger_path: PathBuf,
    pub events_total: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_event_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_ingest: Option<StatusEventSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_projection: Option<StatusEventSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_plan: Option<StatusEventSummary>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latest_rust_lint: Option<StatusEventSummary>,
}

pub fn summarize_ledger(ledger_path: &Path) -> Result<StatusSummary, DeclareCostError> {
    if !ledger_path.exists() {
        return Ok(StatusSummary {
            ledger_path: ledger_path.to_path_buf(),
            events_total: 0,
            latest_event_type: None,
            latest_event_id: None,
            latest_ingest: None,
            latest_projection: None,
            latest_plan: None,
            latest_rust_lint: None,
        });
    }

    let contents =
        fs::read_to_string(ledger_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    let mut events_total = 0usize;
    let mut latest_event_type = None;
    let mut latest_event_id = None;
    let mut latest_ingest = None;
    let mut latest_projection = None;
    let mut latest_plan = None;
    let mut latest_rust_lint = None;

    for line in contents.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|err| DeclareCostError::Json(err.to_string()))?;
        events_total += 1;
        let event_type = value
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let event_id = value
            .get("event_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let timestamp = value
            .get("timestamp")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        if event_type.is_empty() || event_id.is_empty() {
            continue;
        }

        latest_event_type = Some(event_type.clone());
        latest_event_id = Some(event_id.clone());

        let summary = StatusEventSummary {
            event_type: event_type.clone(),
            event_id,
            timestamp,
            status: value
                .get("status")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            run_id: value
                .get("ingest_run_id")
                .or_else(|| value.get("projection_run_id"))
                .or_else(|| value.get("run_id"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            violations: value.get("violations").and_then(|v| v.as_u64()),
            passed: value.get("passed").and_then(|v| v.as_bool()),
        };

        if event_type.starts_with("ingest.") {
            latest_ingest = Some(summary);
        } else if event_type.starts_with("projection.") {
            latest_projection = Some(summary);
        } else if event_type == "plan.created" {
            latest_plan = Some(summary);
        } else if event_type == "rust.ir_lint.completed" {
            latest_rust_lint = Some(summary);
        }
    }

    Ok(StatusSummary {
        ledger_path: ledger_path.to_path_buf(),
        events_total,
        latest_event_type,
        latest_event_id,
        latest_ingest,
        latest_projection,
        latest_plan,
        latest_rust_lint,
    })
}
