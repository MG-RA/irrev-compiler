use std::path::{Path, PathBuf};

use serde::Serialize;
use sha2::{Digest, Sha256};

use super::types::{ArtifactRef, DeclareCostError};

// ---------------------------------------------------------------------------
// Shared constants
// ---------------------------------------------------------------------------

pub(crate) const DEFAULT_WITNESS_SCHEMA_ID: &str = "admissibility-witness/2";
pub(crate) const DEFAULT_ARTIFACT_ROOT: &str = "out/artifacts";
pub(crate) const META_REGISTRY_SCHEMA_ID: &str = "meta-registry/1";
pub(crate) const META_REGISTRY_KIND: &str = "meta_registry";
pub(crate) const META_REGISTRY_ENV: &str = "ADMIT_META_REGISTRY";
pub(crate) const LENS_DELTA_WITNESS_SCHEMA_ID: &str = "lens-delta-witness/0";
pub(crate) const PLAN_WITNESS_SCHEMA_ID: &str = "plan-witness/2";
pub(crate) const PLAN_WITNESS_SCHEMA_ID_V1: &str = "plan-witness/1";
pub(crate) const PLAN_WITNESS_SCHEMA_IDS: [&str; 2] =
    [PLAN_WITNESS_SCHEMA_ID, PLAN_WITNESS_SCHEMA_ID_V1];
pub(crate) const PLAN_TEMPLATE_ID: &str = "plan:diagnostic@1";
pub(crate) const RUST_IR_LINT_WITNESS_SCHEMA_ID: &str = "rust-ir-lint-witness/1";

// ---------------------------------------------------------------------------
// Hashing & payload ID
// ---------------------------------------------------------------------------

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

pub(crate) fn payload_hash<T: Serialize>(payload: &T) -> Result<String, DeclareCostError> {
    let payload_bytes =
        serde_json::to_vec(payload).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    Ok(sha256_hex(&payload_bytes))
}

// ---------------------------------------------------------------------------
// Artifact path helpers
// ---------------------------------------------------------------------------

pub(crate) fn artifact_rel_path(kind: &str, sha256: &str, ext: &str) -> String {
    format!("{}/{}.{}", kind, sha256, ext)
}

pub(crate) fn artifact_disk_path(root: &Path, kind: &str, sha256: &str, ext: &str) -> PathBuf {
    root.join(kind).join(format!("{}.{}", sha256, ext))
}

pub(crate) fn artifact_path_from_ref(root: &Path, reference: &ArtifactRef) -> PathBuf {
    if let Some(path) = &reference.path {
        return root.join(path);
    }
    root.join(&reference.kind)
        .join(format!("{}.cbor", reference.sha256))
}

// ---------------------------------------------------------------------------
// CBOR decoder
// ---------------------------------------------------------------------------

pub(crate) fn decode_cbor_to_value(bytes: &[u8]) -> Result<serde_json::Value, DeclareCostError> {
    let mut idx = 0usize;
    let value = decode_cbor_value(bytes, &mut idx)?;
    if idx != bytes.len() {
        return Err(DeclareCostError::CborDecode(
            "trailing bytes after CBOR value".to_string(),
        ));
    }
    Ok(value)
}

fn decode_cbor_value(bytes: &[u8], idx: &mut usize) -> Result<serde_json::Value, DeclareCostError> {
    let byte = read_byte(bytes, idx)?;
    let major = byte >> 5;
    let ai = byte & 0x1f;

    let val = read_ai(bytes, idx, ai)?;
    match major {
        0 => Ok(serde_json::Value::Number(serde_json::Number::from(val))),
        1 => {
            let n = -1i64 - (val as i64);
            let num = serde_json::Number::from(n);
            Ok(serde_json::Value::Number(num))
        }
        3 => {
            let len = val as usize;
            let s = read_bytes(bytes, idx, len)?;
            let text = std::str::from_utf8(s)
                .map_err(|err| DeclareCostError::CborDecode(err.to_string()))?;
            Ok(serde_json::Value::String(text.to_string()))
        }
        4 => {
            let len = val as usize;
            let mut items = Vec::with_capacity(len);
            for _ in 0..len {
                items.push(decode_cbor_value(bytes, idx)?);
            }
            Ok(serde_json::Value::Array(items))
        }
        5 => {
            let len = val as usize;
            let mut map = serde_json::Map::new();
            for _ in 0..len {
                let key_val = decode_cbor_value(bytes, idx)?;
                let key = match key_val {
                    serde_json::Value::String(s) => s,
                    _ => {
                        return Err(DeclareCostError::CborDecode(
                            "map key is not a string".to_string(),
                        ))
                    }
                };
                let value = decode_cbor_value(bytes, idx)?;
                map.insert(key, value);
            }
            Ok(serde_json::Value::Object(map))
        }
        7 => match ai {
            20 => Ok(serde_json::Value::Bool(false)),
            21 => Ok(serde_json::Value::Bool(true)),
            22 => Ok(serde_json::Value::Null),
            _ => Err(DeclareCostError::CborDecode(
                "unsupported simple value".to_string(),
            )),
        },
        _ => Err(DeclareCostError::CborDecode(
            "unsupported CBOR major type".to_string(),
        )),
    }
}

fn read_ai(bytes: &[u8], idx: &mut usize, ai: u8) -> Result<u64, DeclareCostError> {
    match ai {
        0..=23 => Ok(ai as u64),
        24 => Ok(read_uint(bytes, idx, 1)?),
        25 => Ok(read_uint(bytes, idx, 2)?),
        26 => Ok(read_uint(bytes, idx, 4)?),
        27 => Ok(read_uint(bytes, idx, 8)?),
        _ => Err(DeclareCostError::CborDecode(
            "indefinite lengths not supported".to_string(),
        )),
    }
}

fn read_uint(bytes: &[u8], idx: &mut usize, len: usize) -> Result<u64, DeclareCostError> {
    let slice = read_bytes(bytes, idx, len)?;
    let mut value = 0u64;
    for &b in slice {
        value = (value << 8) | b as u64;
    }
    Ok(value)
}

fn read_byte(bytes: &[u8], idx: &mut usize) -> Result<u8, DeclareCostError> {
    if *idx >= bytes.len() {
        return Err(DeclareCostError::CborDecode(
            "unexpected end of input".to_string(),
        ));
    }
    let b = bytes[*idx];
    *idx += 1;
    Ok(b)
}

fn read_bytes<'a>(
    bytes: &'a [u8],
    idx: &mut usize,
    len: usize,
) -> Result<&'a [u8], DeclareCostError> {
    if *idx + len > bytes.len() {
        return Err(DeclareCostError::CborDecode(
            "unexpected end of input".to_string(),
        ));
    }
    let slice = &bytes[*idx..*idx + len];
    *idx += len;
    Ok(slice)
}
