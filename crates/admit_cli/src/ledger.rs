use std::fs;
use std::path::{Path, PathBuf};

use super::types::{
    AdmissibilityCheckedEvent, AdmissibilityExecutedEvent, CostDeclaredEvent, DeclareCostError,
};

pub fn default_ledger_path() -> PathBuf {
    PathBuf::from("out/ledger.jsonl")
}

pub fn read_file_bytes(path: &Path) -> Result<Vec<u8>, DeclareCostError> {
    fs::read(path).map_err(|err| DeclareCostError::Io(err.to_string()))
}

pub fn append_event(
    ledger_path: &Path,
    event: &CostDeclaredEvent,
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
            let value: serde_json::Value =
                serde_json::from_str(line).map_err(|err| DeclareCostError::Json(err.to_string()))?;
            if value
                .get("event_id")
                .and_then(|v| v.as_str())
                .is_some_and(|id| id == event.event_id)
            {
                return Err(DeclareCostError::DuplicateEventId(event.event_id.clone()));
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

pub fn append_checked_event(
    ledger_path: &Path,
    event: &AdmissibilityCheckedEvent,
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
            let value: serde_json::Value =
                serde_json::from_str(line).map_err(|err| DeclareCostError::Json(err.to_string()))?;
            if value
                .get("event_id")
                .and_then(|v| v.as_str())
                .is_some_and(|id| id == event.event_id)
            {
                return Err(DeclareCostError::DuplicateEventId(event.event_id.clone()));
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

pub fn append_executed_event(
    ledger_path: &Path,
    event: &AdmissibilityExecutedEvent,
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
            let value: serde_json::Value =
                serde_json::from_str(line).map_err(|err| DeclareCostError::Json(err.to_string()))?;
            if value
                .get("event_id")
                .and_then(|v| v.as_str())
                .is_some_and(|id| id == event.event_id)
            {
                return Err(DeclareCostError::DuplicateEventId(event.event_id.clone()));
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
    Err(DeclareCostError::CheckedEventNotFound(
        event_id.to_string(),
    ))
}
