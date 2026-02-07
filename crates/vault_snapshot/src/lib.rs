use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub enum SnapshotError {
    Io(String),
    Json(String),
    Canonical(String),
}

impl std::fmt::Display for SnapshotError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SnapshotError::Io(err) => write!(f, "io error: {}", err),
            SnapshotError::Json(err) => write!(f, "json error: {}", err),
            SnapshotError::Canonical(err) => write!(f, "canonical json error: {}", err),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Snapshot {
    pub schema_id: String,
    pub schema_version: i64,
    pub concepts: Vec<SnapshotConcept>,
    pub diagnostics: Vec<SnapshotNote>,
    pub domains: Vec<SnapshotNote>,
    pub projections: Vec<SnapshotNote>,
    pub papers: Vec<SnapshotNote>,
    pub meta: Vec<SnapshotNote>,
    pub support: Vec<SnapshotNote>,
    pub rulesets: Vec<SnapshotRuleset>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotConcept {
    pub name: String,
    pub layer: String,
    pub role: String,
    pub canonical: bool,
    pub aliases: Vec<String>,
    pub depends_on: Vec<String>,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotNote {
    pub name: String,
    pub role: String,
    pub canonical: bool,
    #[serde(default)]
    pub depends_on: Vec<String>,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRuleset {
    pub path: String,
    pub sha256: String,
}

#[derive(Debug, Clone)]
pub struct SnapshotWithHash {
    pub snapshot: Snapshot,
    pub sha256: String,
    pub canonical_bytes: Vec<u8>,
}

pub fn load_snapshot_with_hash(path: &Path) -> Result<SnapshotWithHash, SnapshotError> {
    let bytes = fs::read(path).map_err(|err| SnapshotError::Io(err.to_string()))?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|err| SnapshotError::Json(err.to_string()))?;
    let canonical_bytes = canonical_json_bytes(&value)?;
    let sha256 = sha256_hex(&canonical_bytes);
    let snapshot: Snapshot =
        serde_json::from_value(value).map_err(|err| SnapshotError::Json(err.to_string()))?;
    Ok(SnapshotWithHash {
        snapshot,
        sha256,
        canonical_bytes,
    })
}

pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, SnapshotError> {
    let mut out = String::new();
    write_canonical_json(value, &mut out)?;
    Ok(out.into_bytes())
}

fn write_canonical_json(value: &Value, out: &mut String) -> Result<(), SnapshotError> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            let s = serde_json::to_string(value)
                .map_err(|err| SnapshotError::Canonical(err.to_string()))?;
            out.push_str(&s);
            Ok(())
        }
        Value::Array(items) => {
            out.push('[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_canonical_json(item, out)?;
            }
            out.push(']');
            Ok(())
        }
        Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<_> = map.keys().collect();
            keys.sort();
            for (idx, key) in keys.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                let key_json = serde_json::to_string(key)
                    .map_err(|err| SnapshotError::Canonical(err.to_string()))?;
                out.push_str(&key_json);
                out.push(':');
                if let Some(val) = map.get(*key) {
                    write_canonical_json(val, out)?;
                }
            }
            out.push('}');
            Ok(())
        }
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}
