use std::fs;
use std::path::PathBuf;

use crate::registry::normalize_meta_registry;
use crate::scope_validation::{parse_scope_spec, ScopeValidationLevel, ScopeValidator};
use crate::types::{
    MetaRegistryScope, MetaRegistryV0, RegistryGateError, ScopeAdditionWitness, ScopePhase,
    ScopeRole, ScopeValidation, ScopeValidationSeverity,
};

// ---------------------------------------------------------------------------
// Command argument types (re-exported from main.rs)
// ---------------------------------------------------------------------------

pub struct ScopeAddArgs {
    pub scope: Option<String>,
    pub scope_id: Option<String>,
    pub version: Option<u32>,
    pub snapshot_schema_id: Option<String>,
    pub phase: Option<String>,
    pub deterministic: Option<bool>,
    pub foundational: Option<bool>,
    pub emits: Vec<String>,
    pub consumes: Vec<String>,
    pub deps: Vec<String>,
    pub role: Option<String>,
    pub contract_ref: Option<String>,
    pub registry: PathBuf,
    pub validation_level: String,
    pub dry_run: bool,
}

pub struct ScopeVerifyArgs {
    pub scope_id: String,
    pub registry: PathBuf,
    pub validation_level: String,
    pub json: bool,
}

pub struct ScopeListArgs {
    pub registry: PathBuf,
    pub phase: Option<String>,
    pub role: Option<String>,
    pub json: bool,
}

pub struct ScopeShowArgs {
    pub scope_id: String,
    pub registry: PathBuf,
    pub json: bool,
}

// ---------------------------------------------------------------------------
// Command implementations
// ---------------------------------------------------------------------------

pub fn scope_add(args: ScopeAddArgs) -> Result<ScopeAdditionWitness, RegistryGateError> {
    // Step 1: Load existing registry
    let registry_bytes =
        fs::read(&args.registry).map_err(|e| RegistryGateError::Io(e.to_string()))?;
    let mut registry: MetaRegistryV0 = serde_json::from_slice(&registry_bytes)
        .map_err(|e| RegistryGateError::Json(e.to_string()))?;

    // Step 2: Parse scope ID from args (handle both --scope and --scope-id/--version)
    let (scope_id, scope_version) = if let Some(spec) = &args.scope {
        parse_scope_spec(spec)?
    } else if let (Some(id), Some(ver)) = (&args.scope_id, args.version) {
        (id.clone(), ver)
    } else {
        return Err(RegistryGateError::ScopeIdMalformed {
            scope_id: String::new(),
            reason: "must provide either --scope or --scope-id with --version".to_string(),
        });
    };

    // Step 3: Validate ID format (no @version in id field)
    if scope_id.contains('@') {
        return Err(RegistryGateError::ScopeIdContainsVersion { scope_id });
    }

    // Step 4: Build new scope entry from CLI args
    let new_scope = MetaRegistryScope {
        id: scope_id.clone(),
        version: scope_version,
        snapshot_schema_id: args.snapshot_schema_id,
        phase: args.phase.as_ref().and_then(|p| parse_phase(p)),
        deterministic: args.deterministic,
        foundational: args.foundational,
        emits: if args.emits.is_empty() {
            None
        } else {
            Some(args.emits)
        },
        consumes: if args.consumes.is_empty() {
            None
        } else {
            Some(args.consumes)
        },
        deps: if args.deps.is_empty() {
            None
        } else {
            Some(args.deps)
        },
        role: args.role.as_ref().and_then(|r| parse_role(r)),
        contract_ref: args.contract_ref,
    };

    // Step 5: Hash registry BEFORE mutation (and clone for validation)
    let registry_hash_before = compute_registry_hash(&registry)?;
    let registry_version_before = registry.registry_version;
    let registry_for_validation = registry.clone();

    // Step 6: Validate using ScopeValidator
    let level = match args.validation_level.as_str() {
        "phase1" => ScopeValidationLevel::Phase1,
        "phase2" => ScopeValidationLevel::Phase2,
        _ => {
            return Err(RegistryGateError::InvalidValidationLevel(
                args.validation_level,
            ))
        }
    };

    let validator = ScopeValidator::new(registry_for_validation, level);
    let validations = validator.validate_scope_addition(&new_scope, None);

    // Step 7: Check all ERROR-severity validations passed
    let errors: Vec<String> = validations
        .iter()
        .filter(|v| !v.passed && v.severity == ScopeValidationSeverity::Error)
        .map(|v| format!("{}: {}", v.check, v.message.as_deref().unwrap_or("failed")))
        .collect();

    if !errors.is_empty() {
        return Err(RegistryGateError::ValidationFailed {
            scope_id: scope_id.clone(),
            errors,
        });
    }

    // Step 8: Add to registry, increment registry_version
    registry.scopes.push(new_scope);
    registry.registry_version += 1;

    // Step 9: Normalize registry (sort, dedup check)
    let normalized =
        normalize_meta_registry(registry).map_err(|e| RegistryGateError::Json(e.to_string()))?;

    // Step 10: Encode canonical CBOR and hash (registry_hash_after)
    let registry_hash_after = compute_registry_hash(&normalized)?;
    let registry_version_after = normalized.registry_version;

    // Step 11: Write back to disk (unless --dry-run)
    if !args.dry_run {
        let json = serde_json::to_string_pretty(&normalized)
            .map_err(|e| RegistryGateError::Json(e.to_string()))?;
        fs::write(&args.registry, json).map_err(|e| RegistryGateError::Io(e.to_string()))?;
    }

    // Step 12: Create ScopeAdditionWitness with both before/after hashes
    let witness = ScopeAdditionWitness {
        schema_id: "scope-addition-witness/0".to_string(),
        schema_version: 0,
        created_at: None,
        court_version: None,
        input_id: None,
        config_hash: None,
        scope_id: scope_id.clone(),
        scope_version,
        validation_timestamp: chrono::Utc::now().to_rfc3339(),
        validations,
        registry_version_before,
        registry_version_after,
        registry_hash_before,
        registry_hash_after,
    };

    // Step 13: Compute deterministic witness_id (implemented in validator)
    // let witness_id = ScopeValidator::compute_witness_id(&witness);

    Ok(witness)
}

pub fn scope_verify(args: ScopeVerifyArgs) -> Result<Vec<ScopeValidation>, RegistryGateError> {
    // Load registry
    let registry_bytes =
        fs::read(&args.registry).map_err(|e| RegistryGateError::Io(e.to_string()))?;
    let registry: MetaRegistryV0 = serde_json::from_slice(&registry_bytes)
        .map_err(|e| RegistryGateError::Json(e.to_string()))?;

    // Find scope (clone it to avoid borrow issues)
    let scope = registry
        .scopes
        .iter()
        .find(|s| s.id == args.scope_id)
        .cloned()
        .ok_or_else(|| RegistryGateError::ScopeIdMalformed {
            scope_id: args.scope_id.clone(),
            reason: "scope not found in registry".to_string(),
        })?;

    // Validate
    let level = match args.validation_level.as_str() {
        "phase1" => ScopeValidationLevel::Phase1,
        "phase2" => ScopeValidationLevel::Phase2,
        _ => {
            return Err(RegistryGateError::InvalidValidationLevel(
                args.validation_level,
            ))
        }
    };

    let validator = ScopeValidator::new(registry, level);
    // Use validate_scope_existing to skip duplicate check for existing scopes
    Ok(validator.validate_scope_existing(&scope, None))
}

pub fn scope_list(args: ScopeListArgs) -> Result<Vec<MetaRegistryScope>, RegistryGateError> {
    // Load registry
    let registry_bytes =
        fs::read(&args.registry).map_err(|e| RegistryGateError::Io(e.to_string()))?;
    let registry: MetaRegistryV0 = serde_json::from_slice(&registry_bytes)
        .map_err(|e| RegistryGateError::Json(e.to_string()))?;

    let mut scopes = registry.scopes.clone();

    // Apply filters
    if let Some(phase_filter) = args.phase {
        scopes.retain(|s| {
            s.phase.map(|p| format!("{:?}", p).to_lowercase()) == Some(phase_filter.to_lowercase())
        });
    }

    if let Some(role_filter) = args.role {
        scopes.retain(|s| {
            s.role.as_ref().map(|r| format!("{:?}", r).to_lowercase())
                == Some(role_filter.to_lowercase())
        });
    }

    Ok(scopes)
}

pub fn scope_show(args: ScopeShowArgs) -> Result<MetaRegistryScope, RegistryGateError> {
    // Load registry
    let registry_bytes =
        fs::read(&args.registry).map_err(|e| RegistryGateError::Io(e.to_string()))?;
    let registry: MetaRegistryV0 = serde_json::from_slice(&registry_bytes)
        .map_err(|e| RegistryGateError::Json(e.to_string()))?;

    // Find scope
    registry
        .scopes
        .into_iter()
        .find(|s| s.id == args.scope_id)
        .ok_or_else(|| RegistryGateError::ScopeIdMalformed {
            scope_id: args.scope_id.clone(),
            reason: "scope not found in registry".to_string(),
        })
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn parse_phase(s: &str) -> Option<ScopePhase> {
    match s.to_lowercase().as_str() {
        "p0" => Some(ScopePhase::P0),
        "p1" => Some(ScopePhase::P1),
        "p2" => Some(ScopePhase::P2),
        "p3" => Some(ScopePhase::P3),
        "p4" => Some(ScopePhase::P4),
        _ => None,
    }
}

fn parse_role(s: &str) -> Option<ScopeRole> {
    match s.to_lowercase().as_str() {
        "foundation" => Some(ScopeRole::Foundation),
        "transform" => Some(ScopeRole::Transform),
        "verification" => Some(ScopeRole::Verification),
        "governance" => Some(ScopeRole::Governance),
        "integration" => Some(ScopeRole::Integration),
        "application" => Some(ScopeRole::Application),
        _ => None,
    }
}

fn compute_registry_hash(registry: &MetaRegistryV0) -> Result<String, RegistryGateError> {
    // Convert to JSON value
    let value =
        serde_json::to_value(registry).map_err(|e| RegistryGateError::Json(e.to_string()))?;

    // Encode to canonical CBOR
    let cbor_bytes = admit_core::encode_canonical_value(&value)
        .map_err(|e| RegistryGateError::Json(format!("canonical CBOR encoding failed: {}", e)))?;

    // Hash
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(&cbor_bytes);
    let result = hasher.finalize();
    Ok(hex::encode(result))
}
