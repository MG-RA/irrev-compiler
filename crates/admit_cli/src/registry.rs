use std::fs;
use std::path::{Path, PathBuf};

use admit_core::Provider;

use super::artifact::store_artifact;
use super::internal::{
    artifact_disk_path, decode_cbor_to_value, sha256_hex, META_REGISTRY_ENV, META_REGISTRY_KIND,
    META_REGISTRY_SCHEMA_ID,
};
use super::types::{
    ArtifactRef, DeclareCostError, MetaRegistryDefaultLens, MetaRegistryMetaBucket,
    MetaRegistryMetaChangeKind, MetaRegistrySchema, MetaRegistryScope, MetaRegistryScopePack,
    MetaRegistryStdlib, MetaRegistryV0, ScopeGateMode,
};

const META_REGISTRY_SCHEMA_ID_V0: &str = "meta-registry/0";

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
        return Err(DeclareCostError::MetaRegistryMissing(
            path.display().to_string(),
        ));
    }
    let bytes = fs::read(&path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    let registry_raw: MetaRegistryV0 = serde_json::from_slice(&bytes)
        .map_err(|err| DeclareCostError::MetaRegistryDecode(err.to_string()))?;
    if registry_raw.schema_id != META_REGISTRY_SCHEMA_ID
        && registry_raw.schema_id != META_REGISTRY_SCHEMA_ID_V0
    {
        return Err(DeclareCostError::MetaRegistrySchemaMismatch {
            expected: format!("{}/{}", META_REGISTRY_SCHEMA_ID, META_REGISTRY_SCHEMA_ID_V0),
            found: registry_raw.schema_id.clone(),
        });
    }
    let registry = normalize_meta_registry(registry_raw)?;
    let value =
        serde_json::to_value(&registry).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    let cbor_bytes = admit_core::encode_canonical_value(&value)
        .map_err(|err| DeclareCostError::CanonicalEncode(err.0))?;
    let hash = sha256_hex(&cbor_bytes);
    Ok(Some(MetaRegistryResolved { registry, hash }))
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
    if registry_raw.schema_id != META_REGISTRY_SCHEMA_ID
        && registry_raw.schema_id != META_REGISTRY_SCHEMA_ID_V0
    {
        return Err(DeclareCostError::MetaRegistrySchemaMismatch {
            expected: format!("{}/{}", META_REGISTRY_SCHEMA_ID, META_REGISTRY_SCHEMA_ID_V0),
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
        schema_version: 1,
        registry_version: 0,
        generated_at: None,
        default_lens: MetaRegistryDefaultLens {
            lens_id: "lens:default@0".to_string(),
            lens_hash: default_lens_hash(),
        },
        lenses: vec![super::types::MetaRegistryLens {
            lens_id: "lens:default@0".to_string(),
            lens_hash: default_lens_hash(),
            description: Some("Deterministic fallback lens declaration".to_string()),
        }],
        meta_change_kinds: vec![
            MetaRegistryMetaChangeKind {
                kind_id: "lens_amendment".to_string(),
                may_change_transform_space: true,
                may_change_constraints: true,
                may_change_accounting_routes: true,
                may_change_permissions: true,
                requires_manual_approval: false,
            },
            MetaRegistryMetaChangeKind {
                kind_id: "constraint_tuning".to_string(),
                may_change_transform_space: false,
                may_change_constraints: true,
                may_change_accounting_routes: false,
                may_change_permissions: false,
                requires_manual_approval: false,
            },
            MetaRegistryMetaChangeKind {
                kind_id: "accounting_route_update".to_string(),
                may_change_transform_space: false,
                may_change_constraints: false,
                may_change_accounting_routes: true,
                may_change_permissions: false,
                requires_manual_approval: false,
            },
            MetaRegistryMetaChangeKind {
                kind_id: "permission_policy_update".to_string(),
                may_change_transform_space: false,
                may_change_constraints: false,
                may_change_accounting_routes: false,
                may_change_permissions: true,
                requires_manual_approval: true,
            },
        ],
        meta_buckets: vec![
            MetaRegistryMetaBucket {
                bucket_id: "bucket:trust_debt".to_string(),
                unit: Some("risk_points".to_string()),
                description: Some("Debt caused by trust displacement".to_string()),
            },
            MetaRegistryMetaBucket {
                bucket_id: "bucket:compatibility_debt".to_string(),
                unit: Some("risk_points".to_string()),
                description: Some("Debt caused by compatibility displacement".to_string()),
            },
            MetaRegistryMetaBucket {
                bucket_id: "bucket:explanation_debt".to_string(),
                unit: Some("risk_points".to_string()),
                description: Some("Debt caused by explanation displacement".to_string()),
            },
        ],
        stdlib: vec![MetaRegistryStdlib {
            module_id: "module:irrev_std@1".to_string(),
        }],
        schemas: vec![
            MetaRegistrySchema {
                id: META_REGISTRY_SCHEMA_ID.to_string(),
                schema_version: 1,
                kind: META_REGISTRY_KIND.to_string(),
                canonical_encoding: "canonical-cbor".to_string(),
            },
            MetaRegistrySchema {
                id: "admissibility-witness/2".to_string(),
                schema_version: 2,
                kind: "witness".to_string(),
                canonical_encoding: "canonical-cbor".to_string(),
            },
            MetaRegistrySchema {
                id: "admissibility-witness/1".to_string(),
                schema_version: 1,
                kind: "witness".to_string(),
                canonical_encoding: "canonical-cbor".to_string(),
            },
            MetaRegistrySchema {
                id: "lens-delta-witness/0".to_string(),
                schema_version: 0,
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
                id: "plan-witness/2".to_string(),
                schema_version: 2,
                kind: "plan_witness".to_string(),
                canonical_encoding: "canonical-cbor".to_string(),
            },
            MetaRegistrySchema {
                id: "plan-witness/1".to_string(),
                schema_version: 1,
                kind: "plan_witness".to_string(),
                canonical_encoding: "canonical-cbor".to_string(),
            },
            MetaRegistrySchema {
                id: "rust-ir-lint-witness/1".to_string(),
                schema_version: 1,
                kind: "rust_ir_lint_witness".to_string(),
                canonical_encoding: "canonical-cbor".to_string(),
            },
            MetaRegistrySchema {
                id: "identity-witness/0".to_string(),
                schema_version: 0,
                kind: "witness".to_string(),
                canonical_encoding: "canonical-cbor".to_string(),
            },
            MetaRegistrySchema {
                id: "git-snapshot-witness/0".to_string(),
                schema_version: 0,
                kind: "witness".to_string(),
                canonical_encoding: "canonical-cbor".to_string(),
            },
            MetaRegistrySchema {
                id: "git-diff-witness/0".to_string(),
                schema_version: 0,
                kind: "witness".to_string(),
                canonical_encoding: "canonical-cbor".to_string(),
            },
            MetaRegistrySchema {
                id: "git-provenance-witness/0".to_string(),
                schema_version: 0,
                kind: "witness".to_string(),
                canonical_encoding: "canonical-cbor".to_string(),
            },
            MetaRegistrySchema {
                id: "engine-query/1".to_string(),
                schema_version: 1,
                kind: "query_artifact".to_string(),
                canonical_encoding: "canonical-cbor".to_string(),
            },
            MetaRegistrySchema {
                id: "engine-function/1".to_string(),
                schema_version: 1,
                kind: "fn_artifact".to_string(),
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
                id: "scope:hash.verify".to_string(),
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
                id: "scope:identity.delegate".to_string(),
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
                id: "scope:git.snapshot".to_string(),
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
                id: "scope:git.diff".to_string(),
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
                id: "scope:git.provenance".to_string(),
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
                id: "scope:identity.verify".to_string(),
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
            MetaRegistryScope {
                id: "scope:patch.plan".to_string(),
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
                id: "scope:rust.ir_lint".to_string(),
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
        scope_packs: vec![],
    };

    let json = serde_json::to_string_pretty(&registry)
        .map_err(|err| DeclareCostError::Json(err.to_string()))?;
    fs::write(out_path, json).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    Ok(())
}

/// Load and normalize a meta registry from `--meta-registry` or `ADMIT_META_REGISTRY`.
///
/// Returns `(registry, registry_hash)` when present.
pub fn load_meta_registry(
    path: Option<&Path>,
) -> Result<Option<(MetaRegistryV0, String)>, DeclareCostError> {
    Ok(resolve_meta_registry(path)?.map(|resolved| (resolved.registry, resolved.hash)))
}

pub fn registry_build(
    input_path: &Path,
    artifacts_root: &Path,
) -> Result<ArtifactRef, DeclareCostError> {
    let bytes = fs::read(input_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    let registry_raw: MetaRegistryV0 = serde_json::from_slice(&bytes)
        .map_err(|err| DeclareCostError::MetaRegistryDecode(err.to_string()))?;
    if registry_raw.schema_id != META_REGISTRY_SCHEMA_ID
        && registry_raw.schema_id != META_REGISTRY_SCHEMA_ID_V0
    {
        return Err(DeclareCostError::MetaRegistrySchemaMismatch {
            expected: format!("{}/{}", META_REGISTRY_SCHEMA_ID, META_REGISTRY_SCHEMA_ID_V0),
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

pub fn registry_scope_pack_sync(
    input_path: &Path,
    out_path: &Path,
) -> Result<(), DeclareCostError> {
    let bytes = fs::read(input_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    let registry_raw: MetaRegistryV0 = serde_json::from_slice(&bytes)
        .map_err(|err| DeclareCostError::MetaRegistryDecode(err.to_string()))?;
    if registry_raw.schema_id != META_REGISTRY_SCHEMA_ID
        && registry_raw.schema_id != META_REGISTRY_SCHEMA_ID_V0
    {
        return Err(DeclareCostError::MetaRegistrySchemaMismatch {
            expected: format!("{}/{}", META_REGISTRY_SCHEMA_ID, META_REGISTRY_SCHEMA_ID_V0),
            found: registry_raw.schema_id.clone(),
        });
    }

    let mut registry = normalize_meta_registry(registry_raw)?;

    let mut by_key: std::collections::BTreeMap<(String, u32), MetaRegistryScopePack> = registry
        .scope_packs
        .into_iter()
        .map(|entry| ((entry.scope_id.clone(), entry.version), entry))
        .collect();
    for entry in builtin_scope_packs()? {
        by_key.insert((entry.scope_id.clone(), entry.version), entry);
    }
    registry.scope_packs = by_key.into_values().collect();
    registry.registry_version = registry.registry_version.saturating_add(1);
    registry = normalize_meta_registry(registry)?;

    if let Some(parent) = out_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        }
    }
    let json = serde_json::to_string_pretty(&registry)
        .map_err(|err| DeclareCostError::Json(err.to_string()))?;
    fs::write(out_path, json).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    Ok(())
}

pub fn registry_migrate_v0_v1(input_path: &Path, out_path: &Path) -> Result<(), DeclareCostError> {
    let bytes = fs::read(input_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    let mut value: serde_json::Value = serde_json::from_slice(&bytes)
        .map_err(|err| DeclareCostError::MetaRegistryDecode(err.to_string()))?;
    let obj = value.as_object_mut().ok_or_else(|| {
        DeclareCostError::MetaRegistryDecode("registry is not an object".to_string())
    })?;

    obj.insert(
        "schema_id".to_string(),
        serde_json::Value::String(META_REGISTRY_SCHEMA_ID.to_string()),
    );
    obj.insert(
        "schema_version".to_string(),
        serde_json::Value::Number(serde_json::Number::from(1u64)),
    );

    let default_lens = serde_json::json!({
        "lens_id": "lens:default@0",
        "lens_hash": default_lens_hash(),
    });
    obj.entry("default_lens".to_string())
        .or_insert(default_lens.clone());
    obj.entry("lenses".to_string())
        .or_insert(serde_json::json!([default_lens]));
    obj.entry("meta_change_kinds".to_string())
        .or_insert(serde_json::json!([]));
    obj.entry("meta_buckets".to_string()).or_insert(serde_json::json!([
        { "bucket_id": "bucket:trust_debt", "unit": "risk_points", "description": "Debt caused by trust displacement" },
        { "bucket_id": "bucket:compatibility_debt", "unit": "risk_points", "description": "Debt caused by compatibility displacement" },
        { "bucket_id": "bucket:explanation_debt", "unit": "risk_points", "description": "Debt caused by explanation displacement" }
    ]));

    let mut registry: MetaRegistryV0 = serde_json::from_value(value)
        .map_err(|err| DeclareCostError::MetaRegistryDecode(err.to_string()))?;
    registry = normalize_meta_registry(registry)?;

    if let Some(parent) = out_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        }
    }
    let json = serde_json::to_string_pretty(&registry)
        .map_err(|err| DeclareCostError::Json(err.to_string()))?;
    fs::write(out_path, json).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Normalization & validation
// ---------------------------------------------------------------------------

pub fn normalize_meta_registry(
    mut registry: MetaRegistryV0,
) -> Result<MetaRegistryV0, DeclareCostError> {
    let had_v0_self_schema = registry
        .schemas
        .iter()
        .any(|entry| entry.id == META_REGISTRY_SCHEMA_ID_V0);
    if registry.schema_id == META_REGISTRY_SCHEMA_ID_V0 {
        registry.schema_id = META_REGISTRY_SCHEMA_ID.to_string();
        registry.schema_version = 1;
        if had_v0_self_schema
            && !registry
                .schemas
                .iter()
                .any(|entry| entry.id == META_REGISTRY_SCHEMA_ID)
        {
            registry.schemas.push(MetaRegistrySchema {
                id: META_REGISTRY_SCHEMA_ID.to_string(),
                schema_version: 1,
                kind: META_REGISTRY_KIND.to_string(),
                canonical_encoding: "canonical-cbor".to_string(),
            });
        }
    }

    if registry.default_lens.lens_id.trim().is_empty() {
        registry.default_lens.lens_id = "lens:default@0".to_string();
    }
    if registry.default_lens.lens_hash.trim().is_empty() {
        registry.default_lens.lens_hash = default_lens_hash();
    }
    if registry.lenses.is_empty() {
        registry.lenses.push(super::types::MetaRegistryLens {
            lens_id: registry.default_lens.lens_id.clone(),
            lens_hash: registry.default_lens.lens_hash.clone(),
            description: Some("Injected during v0->v1 normalization".to_string()),
        });
    }
    if registry.meta_buckets.is_empty() {
        registry.meta_buckets = vec![
            MetaRegistryMetaBucket {
                bucket_id: "bucket:trust_debt".to_string(),
                unit: Some("risk_points".to_string()),
                description: Some("Debt caused by trust displacement".to_string()),
            },
            MetaRegistryMetaBucket {
                bucket_id: "bucket:compatibility_debt".to_string(),
                unit: Some("risk_points".to_string()),
                description: Some("Debt caused by compatibility displacement".to_string()),
            },
            MetaRegistryMetaBucket {
                bucket_id: "bucket:explanation_debt".to_string(),
                unit: Some("risk_points".to_string()),
                description: Some("Debt caused by explanation displacement".to_string()),
            },
        ];
    }

    if registry.default_lens.lens_id.trim().is_empty()
        || registry.default_lens.lens_hash.trim().is_empty()
    {
        return Err(DeclareCostError::MetaRegistryMissingDefaultLens);
    }

    let mut lens_ids = std::collections::HashSet::new();
    let mut lens_hashes = std::collections::HashSet::new();
    for lens in &registry.lenses {
        if !lens_ids.insert(lens.lens_id.as_str()) {
            return Err(DeclareCostError::MetaRegistryDuplicateLensId(
                lens.lens_id.clone(),
            ));
        }
        if !lens_hashes.insert(lens.lens_hash.as_str()) {
            return Err(DeclareCostError::MetaRegistryDuplicateLensHash(
                lens.lens_hash.clone(),
            ));
        }
    }
    if !registry
        .lenses
        .iter()
        .any(|lens| lens.lens_id == registry.default_lens.lens_id)
    {
        return Err(DeclareCostError::MetaRegistryUnknownDefaultLens(
            registry.default_lens.lens_id.clone(),
        ));
    }
    registry.lenses.sort_by(|a, b| {
        a.lens_id
            .cmp(&b.lens_id)
            .then(a.lens_hash.cmp(&b.lens_hash))
    });

    let mut kind_ids = std::collections::HashSet::new();
    for entry in &registry.meta_change_kinds {
        if !kind_ids.insert(entry.kind_id.as_str()) {
            return Err(DeclareCostError::MetaRegistryDuplicateMetaChangeKind(
                entry.kind_id.clone(),
            ));
        }
    }
    registry
        .meta_change_kinds
        .sort_by(|a, b| a.kind_id.cmp(&b.kind_id));

    let mut bucket_ids = std::collections::HashSet::new();
    for entry in &registry.meta_buckets {
        if !bucket_ids.insert(entry.bucket_id.as_str()) {
            return Err(DeclareCostError::MetaRegistryDuplicateMetaBucket(
                entry.bucket_id.clone(),
            ));
        }
    }
    for core_bucket in [
        "bucket:trust_debt",
        "bucket:compatibility_debt",
        "bucket:explanation_debt",
    ] {
        if !bucket_ids.contains(core_bucket) {
            return Err(DeclareCostError::MetaRegistryMissingCoreBucket(
                core_bucket.to_string(),
            ));
        }
    }
    registry
        .meta_buckets
        .sort_by(|a, b| a.bucket_id.cmp(&b.bucket_id));

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

    let mut deduped_scope_packs: std::collections::BTreeMap<(String, u32), MetaRegistryScopePack> =
        std::collections::BTreeMap::new();
    for mut entry in std::mem::take(&mut registry.scope_packs) {
        if !is_sha256_hex(&entry.provider_pack_hash) {
            return Err(DeclareCostError::MetaRegistryInvalidScopePackHash {
                scope_id: entry.scope_id.clone(),
                version: entry.version,
                hash: entry.provider_pack_hash.clone(),
            });
        }

        let mut pred_ids = std::collections::HashSet::new();
        for predicate_id in &entry.predicate_ids {
            if !pred_ids.insert(predicate_id.as_str()) {
                return Err(DeclareCostError::MetaRegistryDuplicateScopePackPredicate {
                    scope_id: entry.scope_id.clone(),
                    version: entry.version,
                    predicate_id: predicate_id.clone(),
                });
            }
        }
        entry.predicate_ids.sort();

        let key = (entry.scope_id.clone(), entry.version);
        if let Some(existing) = deduped_scope_packs.get(&key) {
            if existing.provider_pack_hash == entry.provider_pack_hash
                && existing.deterministic == entry.deterministic
                && existing.predicate_ids == entry.predicate_ids
            {
                continue;
            }
            return Err(DeclareCostError::MetaRegistryDuplicateScopePack {
                scope_id: entry.scope_id,
                version: entry.version,
            });
        }
        deduped_scope_packs.insert(key, entry);
    }
    registry.scope_packs = deduped_scope_packs.into_values().collect();
    registry.scope_packs.sort_by(|a, b| {
        a.scope_id
            .cmp(&b.scope_id)
            .then(a.version.cmp(&b.version))
            .then(a.provider_pack_hash.cmp(&b.provider_pack_hash))
    });

    Ok(registry)
}

fn default_lens_hash() -> String {
    let lens_value = serde_json::json!({
        "lens_id": "lens:default@0",
        "version": 0,
        "kind": "default",
    });
    let bytes = admit_core::encode_canonical_value(&lens_value).unwrap_or_default();
    super::internal::sha256_hex(&bytes)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}

fn builtin_scope_packs() -> Result<Vec<MetaRegistryScopePack>, DeclareCostError> {
    let descriptors = vec![
        admit_scope_ingest::provider_impl::IngestDirProvider::new().describe(),
        admit_scope_rust::provider_impl::RustStructureProvider::new().describe(),
        admit_scope_git::provider_impl::GitWorkingTreeProvider::new().describe(),
        admit_scope_text::provider_impl::TextMetricsProvider::new().describe(),
        admit_scope_deps::provider_impl::DepsManifestProvider::new().describe(),
        admit_scope_github::provider_impl::GithubCeremonyProvider::new().describe(),
    ];

    descriptors
        .into_iter()
        .map(|desc| {
            let provider_pack_hash = admit_core::provider_pack_hash(&desc).map_err(|err| {
                DeclareCostError::CanonicalEncode(format!(
                    "provider_pack_hash {}: {}",
                    desc.scope_id.0, err
                ))
            })?;
            let mut predicate_ids = desc
                .predicates
                .iter()
                .map(|pred| normalize_predicate_id(&desc.scope_id.0, desc.version, pred))
                .collect::<Vec<_>>();
            predicate_ids.sort();
            Ok(MetaRegistryScopePack {
                scope_id: desc.scope_id.0,
                version: desc.version,
                provider_pack_hash,
                deterministic: desc.deterministic,
                predicate_ids,
            })
        })
        .collect()
}

fn normalize_predicate_id(
    scope_id: &str,
    version: u32,
    pred: &admit_core::PredicateDescriptor,
) -> String {
    if pred.predicate_id.trim().is_empty() {
        format!("{}/{}@{}", scope_id, pred.name, version)
    } else {
        pred.predicate_id.clone()
    }
}
