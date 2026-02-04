use std::fs;
use std::path::{Path, PathBuf};

use super::artifact::store_artifact;
use super::internal::{
    artifact_disk_path, decode_cbor_to_value, sha256_hex, META_REGISTRY_ENV,
    META_REGISTRY_KIND, META_REGISTRY_SCHEMA_ID,
};
use super::types::{
    ArtifactRef, DeclareCostError, MetaRegistrySchema, MetaRegistryScope, MetaRegistryStdlib,
    MetaRegistryV0, ScopeGateMode,
};

// ---------------------------------------------------------------------------
// Internal resolved registry (hash cached alongside the parsed value)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub(crate) struct MetaRegistryResolved {
    pub registry: MetaRegistryV0,
    pub hash: String,
}

// ---------------------------------------------------------------------------
// Schema / scope query helpers
// ---------------------------------------------------------------------------

pub(crate) fn registry_allows_schema(registry: &MetaRegistryV0, schema_id: &str) -> bool {
    registry.schemas.iter().any(|entry| entry.id == schema_id)
}

pub(crate) fn registry_allows_scope(registry: &MetaRegistryV0, scope_id: &str) -> bool {
    registry.scopes.iter().any(|entry| entry.id == scope_id)
}

pub(crate) fn enforce_scope_gate(
    registry: Option<&MetaRegistryV0>,
    scope_id: &str,
    mode: ScopeGateMode,
) -> Result<(), DeclareCostError> {
    if let Some(registry) = registry {
        if !registry_allows_scope(registry, scope_id) {
            if mode == ScopeGateMode::Error {
                return Err(DeclareCostError::MetaRegistryMissingScopeId(
                    scope_id.to_string(),
                ));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Registry resolution (from path or env)
// ---------------------------------------------------------------------------

pub(crate) fn resolve_meta_registry(
    path: Option<&Path>,
) -> Result<Option<MetaRegistryResolved>, DeclareCostError> {
    let resolved_path = match path {
        Some(path) => Some(path.to_path_buf()),
        None => std::env::var(META_REGISTRY_ENV).ok().map(PathBuf::from),
    };
    let path = match resolved_path {
        Some(path) => path,
        None => return Ok(None),
    };
    if !path.exists() {
        return Err(DeclareCostError::MetaRegistryMissing(path.display().to_string()));
    }
    let bytes = fs::read(&path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    let registry_raw: MetaRegistryV0 =
        serde_json::from_slice(&bytes).map_err(|err| DeclareCostError::MetaRegistryDecode(err.to_string()))?;
    if registry_raw.schema_id != META_REGISTRY_SCHEMA_ID {
        return Err(DeclareCostError::MetaRegistrySchemaMismatch {
            expected: META_REGISTRY_SCHEMA_ID.to_string(),
            found: registry_raw.schema_id.clone(),
        });
    }
    let registry = normalize_meta_registry(registry_raw)?;
    let value =
        serde_json::to_value(&registry).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    let cbor_bytes = admit_core::encode_canonical_value(&value)
        .map_err(|err| DeclareCostError::CanonicalEncode(err.0))?;
    let hash = sha256_hex(&cbor_bytes);
    Ok(Some(MetaRegistryResolved {
        registry,
        hash,
    }))
}

// ---------------------------------------------------------------------------
// Registry loading by artifact hash (for verify_ledger)
// ---------------------------------------------------------------------------

fn load_meta_registry_by_hash(
    artifacts_root: &Path,
    hash: &str,
) -> Result<MetaRegistryV0, DeclareCostError> {
    let cbor_path = artifact_disk_path(artifacts_root, META_REGISTRY_KIND, hash, "cbor");
    if !cbor_path.exists() {
        return Err(DeclareCostError::ArtifactMissing {
            kind: META_REGISTRY_KIND.to_string(),
            sha256: hash.to_string(),
        });
    }
    let bytes = fs::read(&cbor_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    let value = decode_cbor_to_value(&bytes)?;
    let registry_raw = serde_json::from_value::<MetaRegistryV0>(value)
        .map_err(|err| DeclareCostError::MetaRegistryDecode(err.to_string()))?;
    if registry_raw.schema_id != META_REGISTRY_SCHEMA_ID {
        return Err(DeclareCostError::MetaRegistrySchemaMismatch {
            expected: META_REGISTRY_SCHEMA_ID.to_string(),
            found: registry_raw.schema_id,
        });
    }
    normalize_meta_registry(registry_raw)
}

pub(crate) fn load_registry_cached(
    cache: &mut std::collections::HashMap<String, MetaRegistryV0>,
    artifacts_root: &Path,
    hash: &str,
) -> Result<MetaRegistryV0, DeclareCostError> {
    if let Some(existing) = cache.get(hash) {
        return Ok(existing.clone());
    }
    let registry = load_meta_registry_by_hash(artifacts_root, hash)?;
    cache.insert(hash.to_string(), registry.clone());
    Ok(registry)
}

// ---------------------------------------------------------------------------
// Registry init & build (public CLI operations)
// ---------------------------------------------------------------------------

pub fn registry_init(out_path: &Path) -> Result<(), DeclareCostError> {
    if let Some(parent) = out_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        }
    }

    let registry = MetaRegistryV0 {
        schema_id: META_REGISTRY_SCHEMA_ID.to_string(),
        schema_version: 0,
        registry_version: 0,
        generated_at: None,
        stdlib: vec![MetaRegistryStdlib {
            module_id: "module:irrev_std@1".to_string(),
        }],
        schemas: vec![
            MetaRegistrySchema {
                id: META_REGISTRY_SCHEMA_ID.to_string(),
                schema_version: 0,
                kind: META_REGISTRY_KIND.to_string(),
                canonical_encoding: "canonical-cbor".to_string(),
            },
            MetaRegistrySchema {
                id: "admissibility-witness/1".to_string(),
                schema_version: 1,
                kind: "witness".to_string(),
                canonical_encoding: "canonical-cbor".to_string(),
            },
            MetaRegistrySchema {
                id: "vault-snapshot/0".to_string(),
                schema_version: 0,
                kind: "snapshot".to_string(),
                canonical_encoding: "canonical-json".to_string(),
            },
            MetaRegistrySchema {
                id: "program-bundle/0".to_string(),
                schema_version: 0,
                kind: "program_bundle".to_string(),
                canonical_encoding: "canonical-json".to_string(),
            },
            MetaRegistrySchema {
                id: "facts-bundle/0".to_string(),
                schema_version: 0,
                kind: "facts_bundle".to_string(),
                canonical_encoding: "canonical-json".to_string(),
            },
            MetaRegistrySchema {
                id: "plan-witness/1".to_string(),
                schema_version: 1,
                kind: "plan_witness".to_string(),
                canonical_encoding: "canonical-cbor".to_string(),
            },
        ],
        scopes: vec![
            MetaRegistryScope {
                id: "scope:meta.registry".to_string(),
                version: 0,
                snapshot_schema_id: None,
                phase: None,
                deterministic: None,
                foundational: None,
                emits: None,
                consumes: None,
                deps: None,
                role: None,
                contract_ref: None,
            },
            MetaRegistryScope {
                id: "scope:main".to_string(),
                version: 0,
                snapshot_schema_id: None,
                phase: None,
                deterministic: None,
                foundational: None,
                emits: None,
                consumes: None,
                deps: None,
                role: None,
                contract_ref: None,
            },
        ],
    };

    let json =
        serde_json::to_string_pretty(&registry).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    fs::write(out_path, json).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    Ok(())
}

pub fn registry_build(
    input_path: &Path,
    artifacts_root: &Path,
) -> Result<ArtifactRef, DeclareCostError> {
    let bytes = fs::read(input_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    let registry_raw: MetaRegistryV0 =
        serde_json::from_slice(&bytes).map_err(|err| DeclareCostError::MetaRegistryDecode(err.to_string()))?;
    if registry_raw.schema_id != META_REGISTRY_SCHEMA_ID {
        return Err(DeclareCostError::MetaRegistrySchemaMismatch {
            expected: META_REGISTRY_SCHEMA_ID.to_string(),
            found: registry_raw.schema_id.clone(),
        });
    }
    let registry = normalize_meta_registry(registry_raw)?;

    let value =
        serde_json::to_value(&registry).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    let cbor_bytes = admit_core::encode_canonical_value(&value)
        .map_err(|err| DeclareCostError::CanonicalEncode(err.0))?;
    let json_projection =
        serde_json::to_vec(&registry).map_err(|err| DeclareCostError::Json(err.to_string()))?;

    store_artifact(
        artifacts_root,
        META_REGISTRY_KIND,
        META_REGISTRY_SCHEMA_ID,
        &cbor_bytes,
        "cbor",
        Some(json_projection),
        Some(&registry),
    )
}

// ---------------------------------------------------------------------------
// Normalization & validation
// ---------------------------------------------------------------------------

pub fn normalize_meta_registry(
    mut registry: MetaRegistryV0,
) -> Result<MetaRegistryV0, DeclareCostError> {
    let mut stdlib_ids = std::collections::HashSet::new();
    for entry in &registry.stdlib {
        if !stdlib_ids.insert(entry.module_id.as_str()) {
            return Err(DeclareCostError::MetaRegistryDuplicateStdlibModule(
                entry.module_id.clone(),
            ));
        }
    }
    registry
        .stdlib
        .sort_by(|a, b| a.module_id.cmp(&b.module_id));

    let mut schema_ids = std::collections::HashSet::new();
    let mut has_self_schema = false;
    for entry in &registry.schemas {
        if !schema_ids.insert(entry.id.as_str()) {
            return Err(DeclareCostError::MetaRegistryDuplicateSchemaId(
                entry.id.clone(),
            ));
        }
        if entry.canonical_encoding != "canonical-cbor"
            && entry.canonical_encoding != "canonical-json"
        {
            return Err(DeclareCostError::MetaRegistryInvalidCanonicalEncoding(
                entry.canonical_encoding.clone(),
            ));
        }
        if entry.id == registry.schema_id {
            has_self_schema = true;
            if entry.schema_version != registry.schema_version {
                return Err(DeclareCostError::MetaRegistrySchemaVersionMismatch {
                    expected: registry.schema_version,
                    found: entry.schema_version,
                });
            }
        }
    }
    if !has_self_schema {
        return Err(DeclareCostError::MetaRegistryMissingSelfSchema);
    }
    registry.schemas.sort_by(|a, b| a.id.cmp(&b.id));

    let mut scope_ids = std::collections::HashSet::new();
    for entry in &registry.scopes {
        if !scope_ids.insert(entry.id.as_str()) {
            return Err(DeclareCostError::MetaRegistryDuplicateScopeId(
                entry.id.clone(),
            ));
        }
    }
    registry.scopes.sort_by(|a, b| a.id.cmp(&b.id));

    Ok(registry)
}
