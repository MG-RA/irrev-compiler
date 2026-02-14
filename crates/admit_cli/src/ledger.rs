use std::fs;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::internal::payload_hash;
use super::types::{
    AdmissibilityCheckedEvent, AdmissibilityExecutedEvent, CostDeclaredEvent, DeclareCostError,
    EngineEvent, EngineEventPayload, IngestEvent, IngestEventPayload, ProjectionEvent,
    ProjectionEventPayload,
};

pub fn default_ledger_path() -> PathBuf {
    PathBuf::from("out/ledger.jsonl")
}

pub fn read_file_bytes(path: &Path) -> Result<Vec<u8>, DeclareCostError> {
    fs::read(path).map_err(|err| DeclareCostError::Io(err.to_string()))
}

pub fn build_projection_event(
    event_type: &str,
    projection_run_id: &str,
    timestamp: String,
    trace_sha256: Option<String>,
    phase: Option<String>,
    status: Option<String>,
    duration_ms: Option<u64>,
    error: Option<String>,
    config_hash: Option<String>,
    projector_version: Option<String>,
    meta: Option<serde_json::Value>,
) -> Result<ProjectionEvent, DeclareCostError> {
    let payload = ProjectionEventPayload {
        event_type: event_type.to_string(),
        timestamp: timestamp.clone(),
        projection_run_id: projection_run_id.to_string(),
        trace_sha256: trace_sha256.clone(),
        phase: phase.clone(),
        status: status.clone(),
        duration_ms,
        error: error.clone(),
        config_hash: config_hash.clone(),
        projector_version: projector_version.clone(),
        meta: meta.clone(),
    };
    let event_id = payload_hash(&payload)?;

    Ok(ProjectionEvent {
        event_type: payload.event_type,
        event_id,
        timestamp,
        projection_run_id: projection_run_id.to_string(),
        trace_sha256,
        phase,
        status,
        duration_ms,
        error,
        config_hash,
        projector_version,
        meta,
    })
}

pub fn build_ingest_event(
    event_type: &str,
    ingest_run_id: &str,
    timestamp: String,
    root: Option<String>,
    status: Option<String>,
    duration_ms: Option<u64>,
    error: Option<String>,
    config: Option<super::types::ArtifactRef>,
    coverage: Option<super::types::ArtifactRef>,
    ingest_run: Option<super::types::ArtifactRef>,
    snapshot_sha256: Option<String>,
    parse_sha256: Option<String>,
    files: Option<u64>,
    chunks: Option<u64>,
    total_bytes: Option<u64>,
) -> Result<IngestEvent, DeclareCostError> {
    let payload = IngestEventPayload {
        event_type: event_type.to_string(),
        timestamp: timestamp.clone(),
        ingest_run_id: ingest_run_id.to_string(),
        root: root.clone(),
        status: status.clone(),
        duration_ms,
        error: error.clone(),
        config: config.clone(),
        coverage: coverage.clone(),
        ingest_run: ingest_run.clone(),
        snapshot_sha256: snapshot_sha256.clone(),
        parse_sha256: parse_sha256.clone(),
        files,
        chunks,
        total_bytes,
    };
    let event_id = payload_hash(&payload)?;

    Ok(IngestEvent {
        event_type: payload.event_type,
        event_id,
        timestamp,
        ingest_run_id: ingest_run_id.to_string(),
        root,
        status,
        duration_ms,
        error,
        config,
        coverage,
        ingest_run,
        snapshot_sha256,
        parse_sha256,
        files,
        chunks,
        total_bytes,
    })
}

pub fn build_engine_event(
    event_type: &str,
    timestamp: String,
    artifact_kind: &str,
    artifact: super::types::ArtifactRef,
    name: Option<String>,
    lang: Option<String>,
    tags: Option<Vec<String>>,
) -> Result<EngineEvent, DeclareCostError> {
    let payload = EngineEventPayload {
        event_type: event_type.to_string(),
        timestamp: timestamp.clone(),
        artifact_kind: artifact_kind.to_string(),
        artifact: artifact.clone(),
        name: name.clone(),
        lang: lang.clone(),
        tags: tags.clone(),
    };
    let event_id = payload_hash(&payload)?;

    Ok(EngineEvent {
        event_type: payload.event_type,
        event_id,
        timestamp,
        artifact_kind: artifact_kind.to_string(),
        artifact,
        name,
        lang,
        tags,
    })
}

fn append_serialized_event<T: Serialize>(
    ledger_path: &Path,
    event_id: &str,
    event: &T,
) -> Result<(), DeclareCostError> {
    if let Some(parent) = ledger_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        }
    }

    if ledger_path.exists() {
        let contents =
            fs::read_to_string(ledger_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        for line in contents.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let value: serde_json::Value = serde_json::from_str(line)
                .map_err(|err| DeclareCostError::Json(err.to_string()))?;
            if value
                .get("event_id")
                .and_then(|v| v.as_str())
                .is_some_and(|id| id == event_id)
            {
                return Err(DeclareCostError::DuplicateEventId(event_id.to_string()));
            }
        }
    }

    let line =
        serde_json::to_string(event).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(ledger_path)
        .and_then(|mut file| {
            use std::io::Write;
            writeln!(file, "{}", line)
        })
        .map_err(|err| DeclareCostError::Io(err.to_string()))?;

    Ok(())
}

pub fn append_event(ledger_path: &Path, event: &CostDeclaredEvent) -> Result<(), DeclareCostError> {
    append_serialized_event(ledger_path, &event.event_id, event)
}

pub fn append_checked_event(
    ledger_path: &Path,
    event: &AdmissibilityCheckedEvent,
) -> Result<(), DeclareCostError> {
    append_serialized_event(ledger_path, &event.event_id, event)
}

pub fn append_executed_event(
    ledger_path: &Path,
    event: &AdmissibilityExecutedEvent,
) -> Result<(), DeclareCostError> {
    append_serialized_event(ledger_path, &event.event_id, event)
}

pub fn append_projection_event(
    ledger_path: &Path,
    event: &ProjectionEvent,
) -> Result<(), DeclareCostError> {
    append_serialized_event(ledger_path, &event.event_id, event)
}

pub fn append_ingest_event(
    ledger_path: &Path,
    event: &IngestEvent,
) -> Result<(), DeclareCostError> {
    append_serialized_event(ledger_path, &event.event_id, event)
}

pub fn append_engine_event(
    ledger_path: &Path,
    event: &EngineEvent,
) -> Result<(), DeclareCostError> {
    append_serialized_event(ledger_path, &event.event_id, event)
}

pub fn read_cost_declared_event(
    ledger_path: &Path,
    event_id: &str,
) -> Result<CostDeclaredEvent, DeclareCostError> {
    let contents =
        fs::read_to_string(ledger_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    for line in contents.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|err| DeclareCostError::Json(err.to_string()))?;
        let found_id = value.get("event_id").and_then(|v| v.as_str());
        if found_id.is_some_and(|id| id == event_id) {
            let found_type = value
                .get("event_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            if found_type != "cost.declared" {
                return Err(DeclareCostError::LedgerEventTypeMismatch {
                    event_id: event_id.to_string(),
                    found: found_type.to_string(),
                });
            }
            return serde_json::from_value::<CostDeclaredEvent>(value)
                .map_err(|err| DeclareCostError::Json(err.to_string()));
        }
    }
    Err(DeclareCostError::LedgerEventNotFound(event_id.to_string()))
}

pub fn read_checked_event(
    ledger_path: &Path,
    event_id: &str,
) -> Result<AdmissibilityCheckedEvent, DeclareCostError> {
    let contents =
        fs::read_to_string(ledger_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    for line in contents.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|err| DeclareCostError::Json(err.to_string()))?;
        let found_id = value.get("event_id").and_then(|v| v.as_str());
        if found_id.is_some_and(|id| id == event_id) {
            let found_type = value
                .get("event_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            if found_type != "admissibility.checked" {
                return Err(DeclareCostError::CheckedEventTypeMismatch {
                    event_id: event_id.to_string(),
                    found: found_type.to_string(),
                });
            }
            return serde_json::from_value::<AdmissibilityCheckedEvent>(value)
                .map_err(|err| DeclareCostError::Json(err.to_string()));
        }
    }
    Err(DeclareCostError::CheckedEventNotFound(event_id.to_string()))
}
