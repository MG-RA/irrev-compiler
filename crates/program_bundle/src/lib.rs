use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub enum BundleError {
    Io(String),
    Json(String),
    Canonical(String),
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BundleError::Io(err) => write!(f, "io error: {}", err),
            BundleError::Json(err) => write!(f, "json error: {}", err),
            BundleError::Canonical(err) => write!(f, "canonical json error: {}", err),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramBundle {
    pub schema_id: String,
    pub schema_version: i64,
    pub programs: Vec<BundleProgram>,
    pub dependencies: Vec<BundleDependency>,
    pub provenance: BundleProvenance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleProgram {
    pub module_id: String,
    pub path: String,
    pub sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleDependency {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundleProvenance {
    pub source: String,
    pub generator_id: String,
    pub generator_hash: String,
    pub snapshot_hash: String,
}

#[derive(Debug, Clone)]
pub struct BundleWithHash {
    pub bundle: ProgramBundle,
    pub sha256: String,
    pub canonical_bytes: Vec<u8>,
}

pub fn load_bundle_with_hash(path: &Path) -> Result<BundleWithHash, BundleError> {
    let bytes = fs::read(path).map_err(|err| BundleError::Io(err.to_string()))?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|err| BundleError::Json(err.to_string()))?;
    let canonical_bytes = canonical_json_bytes(&value)?;
    let sha256 = sha256_hex(&canonical_bytes);
    let bundle: ProgramBundle =
        serde_json::from_value(value).map_err(|err| BundleError::Json(err.to_string()))?;
    Ok(BundleWithHash {
        bundle,
        sha256,
        canonical_bytes,
    })
}

pub fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, BundleError> {
    let mut out = String::new();
    write_canonical_json(value, &mut out)?;
    Ok(out.into_bytes())
}

fn write_canonical_json(value: &Value, out: &mut String) -> Result<(), BundleError> {
    match value {
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {
            let s = serde_json::to_string(value)
                .map_err(|err| BundleError::Canonical(err.to_string()))?;
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
                    .map_err(|err| BundleError::Canonical(err.to_string()))?;
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
