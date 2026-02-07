use std::fs;
use std::path::{Path, PathBuf};

use super::internal::{artifact_disk_path, artifact_rel_path, sha256_hex, DEFAULT_ARTIFACT_ROOT};
use super::registry::registry_allows_schema;
use super::types::{ArtifactEntry, ArtifactRef, DeclareCostError, MetaRegistryV0};

pub fn default_artifacts_dir() -> PathBuf {
    PathBuf::from(DEFAULT_ARTIFACT_ROOT)
}

/// Store a JSON value as a content-addressed artifact.
///
/// The artifact bytes are the compiler's canonical CBOR encoding of `value`.
/// A JSON projection is also stored alongside the CBOR for convenient inspection.
pub fn store_value_artifact(
    root: &Path,
    kind: &str,
    schema_id: &str,
    value: &serde_json::Value,
) -> Result<ArtifactRef, DeclareCostError> {
    let cbor_bytes =
        admit_core::encode_canonical_value(value).map_err(|err| DeclareCostError::Json(err.0))?;
    let json_projection =
        serde_json::to_vec(value).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    store_artifact(
        root,
        kind,
        schema_id,
        &cbor_bytes,
        "cbor",
        Some(json_projection),
        None,
    )
}

fn write_bytes_if_missing(path: &Path, bytes: &[u8]) -> Result<(), DeclareCostError> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        }
    }
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, bytes).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    fs::rename(&tmp_path, path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    Ok(())
}

pub(crate) fn store_artifact(
    root: &Path,
    kind: &str,
    schema_id: &str,
    bytes: &[u8],
    ext: &str,
    json_projection: Option<Vec<u8>>,
    registry: Option<&MetaRegistryV0>,
) -> Result<ArtifactRef, DeclareCostError> {
    if let Some(registry) = registry {
        if !registry_allows_schema(registry, schema_id) {
            return Err(DeclareCostError::MetaRegistryMissingSchemaId(
                schema_id.to_string(),
            ));
        }
    }
    let sha256 = sha256_hex(bytes);
    let data_path = artifact_disk_path(root, kind, &sha256, ext);
    write_bytes_if_missing(&data_path, bytes)?;
    if let Some(json_bytes) = json_projection {
        let json_path = artifact_disk_path(root, kind, &sha256, "json");
        write_bytes_if_missing(&json_path, &json_bytes)?;
    }
    Ok(ArtifactRef {
        kind: kind.to_string(),
        schema_id: schema_id.to_string(),
        sha256: sha256.clone(),
        size_bytes: bytes.len() as u64,
        path: Some(artifact_rel_path(kind, &sha256, ext)),
    })
}

pub fn list_artifacts(root: &Path) -> Result<Vec<ArtifactEntry>, DeclareCostError> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for kind_entry in fs::read_dir(root).map_err(|err| DeclareCostError::Io(err.to_string()))? {
        let kind_entry = kind_entry.map_err(|err| DeclareCostError::Io(err.to_string()))?;
        if !kind_entry
            .file_type()
            .map_err(|err| DeclareCostError::Io(err.to_string()))?
            .is_dir()
        {
            continue;
        }
        let kind = kind_entry
            .file_name()
            .into_string()
            .unwrap_or_else(|_| "unknown".to_string());
        for file in
            fs::read_dir(kind_entry.path()).map_err(|err| DeclareCostError::Io(err.to_string()))?
        {
            let file = file.map_err(|err| DeclareCostError::Io(err.to_string()))?;
            let path = file.path();
            let ext = match path.extension().and_then(|e| e.to_str()) {
                Some(ext) => ext,
                None => continue,
            };
            if ext != "cbor" && ext != "json" {
                continue;
            }
            let metadata =
                fs::metadata(&path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
            let sha256 = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            if sha256.is_empty() {
                continue;
            }
            let rel_path = artifact_rel_path(&kind, &sha256, ext);
            entries.push(ArtifactEntry {
                kind: kind.clone(),
                sha256,
                size_bytes: metadata.len(),
                path: rel_path,
            });
        }
    }
    entries.sort_by(|a, b| a.kind.cmp(&b.kind).then(a.sha256.cmp(&b.sha256)));
    Ok(entries)
}

pub fn read_artifact_projection(
    root: &Path,
    kind: &str,
    sha256: &str,
) -> Result<Option<Vec<u8>>, DeclareCostError> {
    let json_path = artifact_disk_path(root, kind, sha256, "json");
    if !json_path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&json_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    Ok(Some(bytes))
}
