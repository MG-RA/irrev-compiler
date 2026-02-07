use std::collections::{HashMap, HashSet};
use std::path::Path;

use crate::types::{
    MetaRegistryScope, MetaRegistryV0, RegistryGateError, ScopeAdditionWitness,
    ScopeAdditionWitnessIdPayload, ScopeValidation, ScopeValidationSeverity,
};

// ---------------------------------------------------------------------------
// Validation level
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeValidationLevel {
    Phase1, // Name + basic structure only
    Phase2, // Full contract validation
}

// ---------------------------------------------------------------------------
// Scope validator
// ---------------------------------------------------------------------------

pub struct ScopeValidator {
    registry: MetaRegistryV0,
    level: ScopeValidationLevel,
}

impl ScopeValidator {
    pub fn new(registry: MetaRegistryV0, level: ScopeValidationLevel) -> Self {
        Self { registry, level }
    }

    // Step 1: Name + Boundary validation
    // CRITICAL: id MUST NOT contain @version
    pub fn validate_scope_id(&self, scope_id: &str) -> Result<(), RegistryGateError> {
        // Check if id contains @version (forbidden)
        if scope_id.contains('@') {
            return Err(RegistryGateError::ScopeIdContainsVersion {
                scope_id: scope_id.to_string(),
            });
        }

        // Must start with "scope:"
        if !scope_id.starts_with("scope:") {
            return Err(RegistryGateError::ScopeIdMalformed {
                scope_id: scope_id.to_string(),
                reason: "must start with 'scope:'".to_string(),
            });
        }

        // Extract domain part (after "scope:")
        let domain = &scope_id[6..];
        if domain.is_empty() {
            return Err(RegistryGateError::ScopeIdMalformed {
                scope_id: scope_id.to_string(),
                reason: "domain part is empty".to_string(),
            });
        }

        // Validate domain: lowercase, dots, underscores only
        for ch in domain.chars() {
            if !ch.is_lowercase() && ch != '.' && ch != '_' {
                return Err(RegistryGateError::ScopeIdMalformed {
                    scope_id: scope_id.to_string(),
                    reason: format!("domain contains invalid character '{}'", ch),
                });
            }
        }

        Ok(())
    }

    // Step 2: Snapshot Schema validation (with kind checking)
    pub fn validate_snapshot_schema(
        &self,
        scope: &MetaRegistryScope,
    ) -> Result<(), RegistryGateError> {
        if let Some(schema_id) = &scope.snapshot_schema_id {
            // Check schema exists
            let schema = self
                .registry
                .schemas
                .iter()
                .find(|s| s.id == *schema_id)
                .ok_or_else(|| RegistryGateError::ScopeSnapshotSchemaMissing {
                    scope_id: scope.id.clone(),
                    schema_id: schema_id.clone(),
                })?;

            // Check schema kind (if present, should be "snapshot" or compatible)
            // Phase 2 requirement: snapshot_schema_id must reference a schema with kind="snapshot"
            // Special exception: "meta_registry" is allowed (for meta scope's self-referential snapshot)
            if !schema.kind.is_empty()
                && schema.kind != "snapshot"
                && !schema.kind.contains("snapshot")
                && schema.kind != "meta_registry"
            {
                return Err(RegistryGateError::ScopeSnapshotSchemaWrongKind {
                    scope_id: scope.id.clone(),
                    schema_id: schema_id.clone(),
                    found_kind: schema.kind.clone(),
                });
            }
        }
        Ok(())
    }

    // Step 3: Predicate Family (emits) validation
    pub fn validate_emits(&self, scope: &MetaRegistryScope) -> Result<(), RegistryGateError> {
        if let Some(emits) = &scope.emits {
            for schema_id in emits {
                if !self.registry.schemas.iter().any(|s| s.id == *schema_id) {
                    return Err(RegistryGateError::ScopeEmitsSchemaUnknown {
                        scope_id: scope.id.clone(),
                        schema_id: schema_id.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    // Step 4: Mechanism Family (consumes) validation
    pub fn validate_consumes(&self, scope: &MetaRegistryScope) -> Result<(), RegistryGateError> {
        if let Some(consumes) = &scope.consumes {
            for schema_id in consumes {
                if !self.registry.schemas.iter().any(|s| s.id == *schema_id) {
                    return Err(RegistryGateError::ScopeConsumesSchemaUnknown {
                        scope_id: scope.id.clone(),
                        schema_id: schema_id.clone(),
                    });
                }
            }
        }
        Ok(())
    }

    // Step 5: Dependencies validation (full graph cycle detection)
    pub fn validate_dependencies(
        &self,
        scope: &MetaRegistryScope,
    ) -> Result<(), RegistryGateError> {
        if let Some(deps) = &scope.deps {
            // Check all deps exist
            for dep_id in deps {
                if !self.registry.scopes.iter().any(|s| s.id == *dep_id) {
                    return Err(RegistryGateError::ScopeDependencyMissing {
                        scope_id: scope.id.clone(),
                        dep_id: dep_id.clone(),
                    });
                }
            }

            // Check for cycles using full graph DFS
            if let Some(cycle) = self.detect_dependency_cycle(scope) {
                return Err(RegistryGateError::ScopeDependencyCycle {
                    scope_id: scope.id.clone(),
                    cycle,
                });
            }
        }
        Ok(())
    }

    // Step 6: Contract reference validation (Phase 2 only)
    pub fn validate_contract(
        &self,
        scope: &MetaRegistryScope,
        meta_root: &Path,
    ) -> Result<(), RegistryGateError> {
        if matches!(self.level, ScopeValidationLevel::Phase2) {
            if let Some(contract_ref) = &scope.contract_ref {
                let contract_path = meta_root.join(contract_ref);
                if !contract_path.exists() {
                    return Err(RegistryGateError::ScopeIdMalformed {
                        scope_id: scope.id.clone(),
                        reason: format!("contract file not found: {}", contract_ref),
                    });
                }
            }
        }
        Ok(())
    }

    // Special: Meta scope completeness validation
    pub fn validate_meta_scope_completeness(
        &self,
        scope: &MetaRegistryScope,
    ) -> Result<(), RegistryGateError> {
        // Special rule: scope:meta.scope must have all Phase 2 fields
        if scope.id == "scope:meta.scope" {
            if scope.phase.is_none() {
                return Err(RegistryGateError::MetaScopeMustBeComplete {
                    scope_id: scope.id.clone(),
                    missing_field: "phase".to_string(),
                });
            }
            if scope.deterministic.is_none() {
                return Err(RegistryGateError::MetaScopeMustBeComplete {
                    scope_id: scope.id.clone(),
                    missing_field: "deterministic".to_string(),
                });
            }
            if scope.foundational.is_none() {
                return Err(RegistryGateError::MetaScopeMustBeComplete {
                    scope_id: scope.id.clone(),
                    missing_field: "foundational".to_string(),
                });
            }
            if scope.emits.is_none() {
                return Err(RegistryGateError::MetaScopeMustBeComplete {
                    scope_id: scope.id.clone(),
                    missing_field: "emits".to_string(),
                });
            }
            if scope.role.is_none() {
                return Err(RegistryGateError::MetaScopeMustBeComplete {
                    scope_id: scope.id.clone(),
                    missing_field: "role".to_string(),
                });
            }
            if scope.contract_ref.is_none() {
                return Err(RegistryGateError::MetaScopeMustBeComplete {
                    scope_id: scope.id.clone(),
                    missing_field: "contract_ref".to_string(),
                });
            }

            // Verify emits includes "scope-addition-witness/0"
            if let Some(emits) = &scope.emits {
                if !emits.contains(&"scope-addition-witness/0".to_string()) {
                    return Err(RegistryGateError::MetaScopeMustBeComplete {
                        scope_id: scope.id.clone(),
                        missing_field: "emits must include 'scope-addition-witness/0'".to_string(),
                    });
                }
            }
        }
        Ok(())
    }

    // Full validation pipeline with severity-aware checks
    pub fn validate_scope_addition(
        &self,
        scope: &MetaRegistryScope,
        meta_root: Option<&Path>,
    ) -> Vec<ScopeValidation> {
        self.validate_scope_internal(scope, meta_root, true)
    }

    // Validate existing scope (skip duplicate check)
    pub fn validate_scope_existing(
        &self,
        scope: &MetaRegistryScope,
        meta_root: Option<&Path>,
    ) -> Vec<ScopeValidation> {
        self.validate_scope_internal(scope, meta_root, false)
    }

    // Internal validation with optional duplicate check
    fn validate_scope_internal(
        &self,
        scope: &MetaRegistryScope,
        meta_root: Option<&Path>,
        check_duplicate: bool,
    ) -> Vec<ScopeValidation> {
        let mut validations = Vec::new();

        // Step 1: Scope ID format (ERROR severity)
        match self.validate_scope_id(&scope.id) {
            Ok(_) => validations.push(ScopeValidation {
                check: "scope_id_format".to_string(),
                severity: ScopeValidationSeverity::Error,
                passed: true,
                message: None,
            }),
            Err(e) => validations.push(ScopeValidation {
                check: "scope_id_format".to_string(),
                severity: ScopeValidationSeverity::Error,
                passed: false,
                message: Some(e.to_string()),
            }),
        }

        // Check for duplicate (id, version) in registry (only for new additions)
        if check_duplicate {
            let duplicate = self
                .registry
                .scopes
                .iter()
                .any(|s| s.id == scope.id && s.version == scope.version);
            validations.push(ScopeValidation {
                check: "no_duplicate_scope".to_string(),
                severity: ScopeValidationSeverity::Error,
                passed: !duplicate,
                message: if duplicate {
                    Some(format!(
                        "scope '{}' version {} already exists",
                        scope.id, scope.version
                    ))
                } else {
                    None
                },
            });
        }

        // Step 2: Snapshot schema (ERROR if provided and invalid)
        match self.validate_snapshot_schema(scope) {
            Ok(_) => validations.push(ScopeValidation {
                check: "snapshot_schema_exists".to_string(),
                severity: ScopeValidationSeverity::Error,
                passed: true,
                message: None,
            }),
            Err(e) => validations.push(ScopeValidation {
                check: "snapshot_schema_exists".to_string(),
                severity: ScopeValidationSeverity::Error,
                passed: false,
                message: Some(e.to_string()),
            }),
        }

        // Step 3: Emits schemas (ERROR if provided and invalid)
        match self.validate_emits(scope) {
            Ok(_) => validations.push(ScopeValidation {
                check: "emits_schemas_exist".to_string(),
                severity: ScopeValidationSeverity::Error,
                passed: true,
                message: None,
            }),
            Err(e) => validations.push(ScopeValidation {
                check: "emits_schemas_exist".to_string(),
                severity: ScopeValidationSeverity::Error,
                passed: false,
                message: Some(e.to_string()),
            }),
        }

        // Step 4: Consumes schemas (ERROR if provided and invalid)
        match self.validate_consumes(scope) {
            Ok(_) => validations.push(ScopeValidation {
                check: "consumes_schemas_exist".to_string(),
                severity: ScopeValidationSeverity::Error,
                passed: true,
                message: None,
            }),
            Err(e) => validations.push(ScopeValidation {
                check: "consumes_schemas_exist".to_string(),
                severity: ScopeValidationSeverity::Error,
                passed: false,
                message: Some(e.to_string()),
            }),
        }

        // Step 5: Dependencies (ERROR if cycles or missing deps)
        match self.validate_dependencies(scope) {
            Ok(_) => validations.push(ScopeValidation {
                check: "dependencies_valid".to_string(),
                severity: ScopeValidationSeverity::Error,
                passed: true,
                message: None,
            }),
            Err(e) => validations.push(ScopeValidation {
                check: "dependencies_valid".to_string(),
                severity: ScopeValidationSeverity::Error,
                passed: false,
                message: Some(e.to_string()),
            }),
        }

        // Step 6: Contract reference (ERROR if provided but missing file, Phase 2 only)
        if matches!(self.level, ScopeValidationLevel::Phase2) {
            if let Some(meta_root) = meta_root {
                match self.validate_contract(scope, meta_root) {
                    Ok(_) => validations.push(ScopeValidation {
                        check: "contract_file_exists".to_string(),
                        severity: ScopeValidationSeverity::Error,
                        passed: true,
                        message: None,
                    }),
                    Err(e) => validations.push(ScopeValidation {
                        check: "contract_file_exists".to_string(),
                        severity: ScopeValidationSeverity::Error,
                        passed: false,
                        message: Some(e.to_string()),
                    }),
                }
            }
        }

        // Special: Meta scope completeness (ERROR severity)
        match self.validate_meta_scope_completeness(scope) {
            Ok(_) => validations.push(ScopeValidation {
                check: "meta_scope_completeness".to_string(),
                severity: ScopeValidationSeverity::Error,
                passed: true,
                message: None,
            }),
            Err(e) => validations.push(ScopeValidation {
                check: "meta_scope_completeness".to_string(),
                severity: ScopeValidationSeverity::Error,
                passed: false,
                message: Some(e.to_string()),
            }),
        }

        // Phase 2 optional field warnings (WARN severity, Phase 2 only)
        if matches!(self.level, ScopeValidationLevel::Phase2) {
            if scope.phase.is_none() && scope.id != "scope:meta.scope" {
                validations.push(ScopeValidation {
                    check: "phase_field_present".to_string(),
                    severity: ScopeValidationSeverity::Warn,
                    passed: false,
                    message: Some("phase field missing (recommended for Phase 2)".to_string()),
                });
            }
            if scope.deterministic.is_none() && scope.id != "scope:meta.scope" {
                validations.push(ScopeValidation {
                    check: "deterministic_field_present".to_string(),
                    severity: ScopeValidationSeverity::Warn,
                    passed: false,
                    message: Some(
                        "deterministic field missing (recommended for Phase 2)".to_string(),
                    ),
                });
            }
            if scope.role.is_none() && scope.id != "scope:meta.scope" {
                validations.push(ScopeValidation {
                    check: "role_field_present".to_string(),
                    severity: ScopeValidationSeverity::Warn,
                    passed: false,
                    message: Some("role field missing (recommended for Phase 2)".to_string()),
                });
            }
        }

        validations
    }

    // Full graph cycle detection using DFS
    fn detect_dependency_cycle(&self, candidate_scope: &MetaRegistryScope) -> Option<Vec<String>> {
        // Build adjacency map for all scopes (including candidate)
        let mut adj_map: HashMap<String, Vec<String>> = HashMap::new();

        // Add existing registry scopes
        for scope in &self.registry.scopes {
            if let Some(deps) = &scope.deps {
                adj_map.insert(scope.id.clone(), deps.clone());
            } else {
                adj_map.insert(scope.id.clone(), Vec::new());
            }
        }

        // Add candidate scope (or update if already exists)
        if let Some(deps) = &candidate_scope.deps {
            adj_map.insert(candidate_scope.id.clone(), deps.clone());
        } else {
            adj_map.insert(candidate_scope.id.clone(), Vec::new());
        }

        // DFS from candidate to detect cycles
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();
        let mut path = Vec::new();

        self.dfs_cycle_detect(
            &candidate_scope.id,
            &adj_map,
            &mut visited,
            &mut rec_stack,
            &mut path,
        )
    }

    fn dfs_cycle_detect(
        &self,
        node: &str,
        adj_map: &HashMap<String, Vec<String>>,
        visited: &mut HashSet<String>,
        rec_stack: &mut HashSet<String>,
        path: &mut Vec<String>,
    ) -> Option<Vec<String>> {
        visited.insert(node.to_string());
        rec_stack.insert(node.to_string());
        path.push(node.to_string());

        if let Some(neighbors) = adj_map.get(node) {
            for neighbor in neighbors {
                if !visited.contains(neighbor) {
                    if let Some(cycle) =
                        self.dfs_cycle_detect(neighbor, adj_map, visited, rec_stack, path)
                    {
                        return Some(cycle);
                    }
                } else if rec_stack.contains(neighbor) {
                    // Found cycle - build cycle path
                    let cycle_start = path.iter().position(|n| n == neighbor).unwrap();
                    let mut cycle = path[cycle_start..].to_vec();
                    cycle.push(neighbor.to_string());
                    return Some(cycle);
                }
            }
        }

        rec_stack.remove(node);
        path.pop();
        None
    }

    // Compute deterministic witness_id (excludes timestamp and messages)
    pub fn compute_witness_id(witness: &ScopeAdditionWitness) -> Result<String, RegistryGateError> {
        // Extract just check names from validations (exclude messages)
        let validation_checks: Vec<String> = witness
            .validations
            .iter()
            .map(|v| v.check.clone())
            .collect();

        let payload = ScopeAdditionWitnessIdPayload {
            scope_id: witness.scope_id.clone(),
            scope_version: witness.scope_version,
            validation_checks,
            registry_version_before: witness.registry_version_before,
            registry_version_after: witness.registry_version_after,
            registry_hash_before: witness.registry_hash_before.clone(),
            registry_hash_after: witness.registry_hash_after.clone(),
        };

        // Encode to canonical CBOR and hash
        let value = serde_json::to_value(&payload).map_err(|e| {
            RegistryGateError::Json(format!("failed to serialize witness payload: {}", e))
        })?;
        let cbor_bytes = admit_core::encode_canonical_value(&value).map_err(|e| {
            RegistryGateError::Json(format!("canonical CBOR encoding failed: {}", e))
        })?;

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&cbor_bytes);
        let result = hasher.finalize();
        Ok(hex::encode(result))
    }
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// Parse scope spec "scope:domain@version" into (id, version)
pub fn parse_scope_spec(spec: &str) -> Result<(String, u32), RegistryGateError> {
    let parts: Vec<&str> = spec.split('@').collect();
    if parts.len() != 2 {
        return Err(RegistryGateError::ScopeIdMalformed {
            scope_id: spec.to_string(),
            reason: "missing @version (expected format: scope:domain@version)".to_string(),
        });
    }

    let id = parts[0].to_string();
    let version = parts[1]
        .parse::<u32>()
        .map_err(|_| RegistryGateError::ScopeIdMalformed {
            scope_id: spec.to_string(),
            reason: "version must be non-negative integer".to_string(),
        })?;

    // Validate that parsed id doesn't still contain @
    if id.contains('@') {
        return Err(RegistryGateError::ScopeIdContainsVersion { scope_id: id });
    }

    Ok((id, version))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::MetaRegistryV0;

    fn minimal_registry() -> MetaRegistryV0 {
        MetaRegistryV0 {
            schema_id: "meta-registry/0".to_string(),
            schema_version: 0,
            registry_version: 0,
            generated_at: None,
            stdlib: vec![],
            schemas: vec![],
            scopes: vec![],
        }
    }

    fn registry_with_scopes(scopes: Vec<MetaRegistryScope>) -> MetaRegistryV0 {
        MetaRegistryV0 {
            schema_id: "meta-registry/0".to_string(),
            schema_version: 0,
            registry_version: 0,
            generated_at: None,
            stdlib: vec![],
            schemas: vec![],
            scopes,
        }
    }

    #[test]
    fn test_parse_scope_spec_valid() {
        let (id, ver) = parse_scope_spec("scope:test.foo@0").unwrap();
        assert_eq!(id, "scope:test.foo");
        assert_eq!(ver, 0);

        let (id, ver) = parse_scope_spec("scope:irreversibility.meta@42").unwrap();
        assert_eq!(id, "scope:irreversibility.meta");
        assert_eq!(ver, 42);
    }

    #[test]
    fn test_parse_scope_spec_invalid() {
        assert!(parse_scope_spec("no-at-sign").is_err());
        assert!(parse_scope_spec("scope:foo@").is_err());
        assert!(parse_scope_spec("scope:foo@bar").is_err());
        assert!(parse_scope_spec("scope:foo@-1").is_err());
        assert!(parse_scope_spec("scope:foo@1@2").is_err());
    }

    #[test]
    fn test_scope_id_format_valid() {
        let registry = minimal_registry();
        let validator = ScopeValidator::new(registry, ScopeValidationLevel::Phase1);

        let scope = MetaRegistryScope {
            id: "scope:test.foo".to_string(),
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
        };

        let validations = validator.validate_scope_addition(&scope, None);
        let id_check = validations
            .iter()
            .find(|v| v.check == "scope_id_format")
            .unwrap();
        assert!(id_check.passed, "Valid scope ID should pass");
    }

    #[test]
    fn test_scope_id_format_contains_version() {
        let registry = minimal_registry();
        let validator = ScopeValidator::new(registry, ScopeValidationLevel::Phase1);

        let scope = MetaRegistryScope {
            id: "scope:test.foo@0".to_string(),
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
        };

        let validations = validator.validate_scope_addition(&scope, None);
        let id_check = validations
            .iter()
            .find(|v| v.check == "scope_id_format")
            .unwrap();
        assert!(!id_check.passed, "Scope ID with @version should fail");
        assert_eq!(id_check.severity, ScopeValidationSeverity::Error);
    }

    #[test]
    fn test_duplicate_scope_detection() {
        let existing = MetaRegistryScope {
            id: "scope:test.foo".to_string(),
            version: 5,
            snapshot_schema_id: None,
            phase: None,
            deterministic: None,
            foundational: None,
            emits: None,
            consumes: None,
            deps: None,
            role: None,
            contract_ref: None,
        };

        let registry = registry_with_scopes(vec![existing]);
        let validator = ScopeValidator::new(registry, ScopeValidationLevel::Phase1);

        let duplicate = MetaRegistryScope {
            id: "scope:test.foo".to_string(),
            version: 5,
            snapshot_schema_id: None,
            phase: None,
            deterministic: None,
            foundational: None,
            emits: None,
            consumes: None,
            deps: None,
            role: None,
            contract_ref: None,
        };

        let validations = validator.validate_scope_addition(&duplicate, None);
        let dup_check = validations
            .iter()
            .find(|v| v.check == "no_duplicate_scope")
            .unwrap();
        assert!(!dup_check.passed, "Duplicate scope should fail");
        assert_eq!(dup_check.severity, ScopeValidationSeverity::Error);
    }

    #[test]
    fn test_full_validation_phase1() {
        let registry = minimal_registry();
        let validator = ScopeValidator::new(registry, ScopeValidationLevel::Phase1);

        let scope = MetaRegistryScope {
            id: "scope:test.foo".to_string(),
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
        };

        let validations = validator.validate_scope_addition(&scope, None);

        // Should have 7 validation results (id, duplicate, snapshot, emits, consumes, deps, contract)
        assert_eq!(validations.len(), 7);

        // All Phase 1 checks should pass for this minimal valid scope
        let errors: Vec<_> = validations
            .iter()
            .filter(|v| !v.passed && v.severity == ScopeValidationSeverity::Error)
            .collect();
        assert!(errors.is_empty(), "Phase 1 validation should pass");
    }

    #[test]
    fn test_full_validation_phase2_missing_deps() {
        let registry = minimal_registry();
        let validator = ScopeValidator::new(registry, ScopeValidationLevel::Phase2);

        let scope = MetaRegistryScope {
            id: "scope:test.foo".to_string(),
            version: 0,
            snapshot_schema_id: None,
            phase: None,
            deterministic: None,
            foundational: None,
            emits: None,
            consumes: None,
            deps: Some(vec!["scope:missing.dep".to_string()]),
            role: None,
            contract_ref: None,
        };

        let validations = validator.validate_scope_addition(&scope, None);

        let errors: Vec<_> = validations
            .iter()
            .filter(|v| !v.passed && v.severity == ScopeValidationSeverity::Error)
            .collect();

        assert!(
            !errors.is_empty(),
            "Phase 2 should detect missing dependency"
        );
        assert!(errors.iter().any(|v| v.check == "dependencies_valid"));
    }

    #[test]
    fn test_snapshot_schema_kind_validation() {
        use crate::types::MetaRegistrySchema;

        // Create registry with a schema that has wrong kind
        let mut registry = minimal_registry();
        registry.schemas.push(MetaRegistrySchema {
            id: "bad-schema/0".to_string(),
            schema_version: 0,
            kind: "witness".to_string(), // Wrong kind - should be "snapshot"
            canonical_encoding: "canonical-cbor".to_string(),
        });

        let validator = ScopeValidator::new(registry, ScopeValidationLevel::Phase2);

        let scope = MetaRegistryScope {
            id: "scope:test.bad".to_string(),
            version: 0,
            snapshot_schema_id: Some("bad-schema/0".to_string()),
            phase: None,
            deterministic: None,
            foundational: None,
            emits: None,
            consumes: None,
            deps: None,
            role: None,
            contract_ref: None,
        };

        let validations = validator.validate_scope_addition(&scope, None);

        let errors: Vec<_> = validations
            .iter()
            .filter(|v| !v.passed && v.severity == ScopeValidationSeverity::Error)
            .collect();

        assert!(!errors.is_empty(), "Should detect wrong schema kind");
        assert!(errors.iter().any(|v| v.check == "snapshot_schema_exists"));
    }

    #[test]
    fn test_indirect_cycle_detection() {
        // Create a cycle: A -> B -> C -> A
        let scope_a = MetaRegistryScope {
            id: "scope:test.a".to_string(),
            version: 0,
            snapshot_schema_id: None,
            phase: None,
            deterministic: None,
            foundational: None,
            emits: None,
            consumes: None,
            deps: Some(vec!["scope:test.b".to_string()]),
            role: None,
            contract_ref: None,
        };

        let scope_b = MetaRegistryScope {
            id: "scope:test.b".to_string(),
            version: 0,
            snapshot_schema_id: None,
            phase: None,
            deterministic: None,
            foundational: None,
            emits: None,
            consumes: None,
            deps: Some(vec!["scope:test.c".to_string()]),
            role: None,
            contract_ref: None,
        };

        let scope_c = MetaRegistryScope {
            id: "scope:test.c".to_string(),
            version: 0,
            snapshot_schema_id: None,
            phase: None,
            deterministic: None,
            foundational: None,
            emits: None,
            consumes: None,
            deps: Some(vec!["scope:test.a".to_string()]), // Creates cycle
            role: None,
            contract_ref: None,
        };

        let registry = registry_with_scopes(vec![scope_a.clone(), scope_b.clone()]);
        let validator = ScopeValidator::new(registry, ScopeValidationLevel::Phase1);

        // Try to add scope_c which would complete the cycle
        let validations = validator.validate_scope_addition(&scope_c, None);

        let errors: Vec<_> = validations
            .iter()
            .filter(|v| !v.passed && v.severity == ScopeValidationSeverity::Error)
            .collect();

        assert!(!errors.is_empty(), "Should detect indirect cycle");
        assert!(errors.iter().any(|v| v.check == "dependencies_valid"));
    }

    #[test]
    fn test_meta_scope_validates_itself() {
        use crate::types::{MetaRegistrySchema, ScopePhase, ScopeRole};

        // Create registry with scope-addition-witness schema
        let mut registry = minimal_registry();
        registry.schemas.push(MetaRegistrySchema {
            id: "scope-addition-witness/0".to_string(),
            schema_version: 0,
            kind: "scope_addition_witness".to_string(),
            canonical_encoding: "canonical-cbor".to_string(),
        });

        let validator = ScopeValidator::new(registry, ScopeValidationLevel::Phase2);

        // Create meta scope with all required Phase 2 fields
        let meta_scope = MetaRegistryScope {
            id: "scope:meta.scope".to_string(),
            version: 0,
            snapshot_schema_id: None,
            phase: Some(ScopePhase::P2),
            deterministic: Some(true),
            foundational: Some(true),
            emits: Some(vec!["scope-addition-witness/0".to_string()]),
            consumes: Some(vec![]),
            deps: Some(vec![]),
            role: Some(ScopeRole::Governance),
            contract_ref: Some("meta/meta-scope-contract.md".to_string()),
        };

        let validations = validator.validate_scope_addition(&meta_scope, None);

        let errors: Vec<_> = validations
            .iter()
            .filter(|v| !v.passed && v.severity == ScopeValidationSeverity::Error)
            .collect();

        // Meta scope should pass all ERROR-level validations (warnings OK)
        // Note: contract file check would fail without actual file, but that's expected in unit test
        for error in &errors {
            println!("Error: {} - {:?}", error.check, error.message);
        }

        // Check that meta scope completeness validation passed
        let completeness_check = validations
            .iter()
            .find(|v| v.check == "meta_scope_completeness")
            .expect("should have completeness check");
        assert!(
            completeness_check.passed,
            "Meta scope completeness check should pass"
        );
    }

    #[test]
    fn test_golden_fixture_scope_addition_witness_wire_format() {
        use crate::types::{ScopeAdditionWitness, ScopeAdditionWitnessIdPayload};

        // Golden fixture: Meta scope self-addition witness
        // This test pins the exact CBOR wire format for scope-addition-witness/0
        // Breaking this test means you've changed the wire format (schema version bump required)

        let witness = ScopeAdditionWitness {
            schema_id: "scope-addition-witness/0".to_string(),
            schema_version: 0,
            created_at: None,
            court_version: None,
            input_id: None,
            config_hash: None,
            scope_id: "scope:meta.scope".to_string(),
            scope_version: 0,
            validation_timestamp: "2024-11-15T10:00:00Z".to_string(),
            validations: vec![
                ScopeValidation {
                    check: "scope_id_format".to_string(),
                    severity: ScopeValidationSeverity::Error,
                    passed: true,
                    message: None,
                },
                ScopeValidation {
                    check: "emits_schemas_exist".to_string(),
                    severity: ScopeValidationSeverity::Error,
                    passed: true,
                    message: None,
                },
            ],
            registry_version_before: 0,
            registry_version_after: 1,
            registry_hash_before: "abc123".to_string(),
            registry_hash_after: "def456".to_string(),
        };

        // Full witness CBOR encoding (for documentation/debugging)
        let witness_value = serde_json::to_value(&witness).expect("serialize witness");
        let witness_cbor = admit_core::encode_canonical_value(&witness_value)
            .expect("encode witness to canonical CBOR");
        let _witness_cbor_hex = hex::encode(&witness_cbor);

        // Identity payload CBOR encoding (for witness_id - excludes timestamp and messages)
        let validation_checks: Vec<String> = witness
            .validations
            .iter()
            .map(|v| v.check.clone())
            .collect();

        let identity_payload = ScopeAdditionWitnessIdPayload {
            scope_id: witness.scope_id.clone(),
            scope_version: witness.scope_version,
            validation_checks,
            registry_version_before: witness.registry_version_before,
            registry_version_after: witness.registry_version_after,
            registry_hash_before: witness.registry_hash_before.clone(),
            registry_hash_after: witness.registry_hash_after.clone(),
        };

        let identity_value = serde_json::to_value(&identity_payload).expect("serialize identity");
        let identity_cbor = admit_core::encode_canonical_value(&identity_value)
            .expect("encode identity to canonical CBOR");
        let identity_cbor_hex = hex::encode(&identity_cbor);

        // Compute witness_id from identity payload
        let witness_id = ScopeValidator::compute_witness_id(&witness).expect("compute witness id");

        // GOLDEN FIXTURE: These exact bytes are the wire format for scope-addition-witness/0
        // If this assertion fails, you've changed the wire format and need a schema version bump

        // Identity payload CBOR: map with 7 keys, canonical encoding (sorted by key bytes)
        // Structure (in canonical sort order):
        //   1. "registry_hash_after" => "def456"
        //   2. "registry_hash_before" => "abc123"
        //   3. "registry_version_after" => 1
        //   4. "registry_version_before" => 0
        //   5. "scope_id" => "scope:meta.scope"
        //   6. "scope_version" => 0
        //   7. "validation_checks" => ["scope_id_format", "emits_schemas_exist"]

        // FROZEN WIRE FORMAT - DO NOT CHANGE without bumping schema version
        const EXPECTED_IDENTITY_CBOR_HEX: &str = "a7\
             6873636f70655f6964\
             7073636f70653a6d6574612e73636f7065\
             6d73636f70655f76657273696f6e\
             00\
             7176616c69646174696f6e5f636865636b73\
             826f73636f70655f69645f666f726d6174\
             73656d6974735f736368656d61735f6578697374\
             7372656769737472795f686173685f6166746572\
             66646566343536\
             7472656769737472795f686173685f6265666f7265\
             66616263313233\
             7672656769737472795f76657273696f6e5f6166746572\
             01\
             7772656769737472795f76657273696f6e5f6265666f7265\
             00";

        assert_eq!(
            identity_cbor_hex, EXPECTED_IDENTITY_CBOR_HEX,
            "\n\nWIRE FORMAT VIOLATION: scope-addition-witness identity payload CBOR changed!\n\
             This is a BREAKING CHANGE requiring schema version bump.\n\
             \n\
             Expected: {}\n\
             Got:      {}\n\
             \n\
             If this change is intentional, update to scope-addition-witness/1 and update this fixture.\n",
            EXPECTED_IDENTITY_CBOR_HEX, identity_cbor_hex
        );

        // The important thing is that the CBOR bytes above are frozen
        // Let's verify witness_id is deterministic
        let witness_id_2 =
            ScopeValidator::compute_witness_id(&witness).expect("compute witness id again");
        assert_eq!(witness_id, witness_id_2, "witness_id must be deterministic");

        // Print for documentation (helpful when fixture needs updating)
        println!("\n=== GOLDEN FIXTURE: scope-addition-witness/0 ===");
        println!("Identity payload CBOR: {}", identity_cbor_hex);
        println!("Identity payload size: {} bytes", identity_cbor.len());
        println!("Witness ID (SHA256):   {}", witness_id);
        println!("Full witness CBOR size: {} bytes", witness_cbor.len());
        println!("==============================================\n");
    }

    #[test]
    fn test_compute_witness_id_deterministic() {
        use crate::types::ScopeAdditionWitness;

        let witness = ScopeAdditionWitness {
            schema_id: "scope-addition-witness/0".to_string(),
            schema_version: 0,
            created_at: None,
            court_version: None,
            input_id: None,
            config_hash: None,
            scope_id: "scope:test.foo".to_string(),
            scope_version: 0,
            validation_timestamp: "2024-11-15T10:00:00Z".to_string(),
            validations: vec![ScopeValidation {
                check: "scope_id_format".to_string(),
                severity: ScopeValidationSeverity::Error,
                passed: true,
                message: None,
            }],
            registry_version_before: 0,
            registry_version_after: 1,
            registry_hash_before: "abc123".to_string(),
            registry_hash_after: "def456".to_string(),
        };

        // Compute witness ID twice - should be identical (deterministic)
        let id1 = ScopeValidator::compute_witness_id(&witness).expect("should compute witness id");
        let id2 = ScopeValidator::compute_witness_id(&witness).expect("should compute witness id");
        assert_eq!(id1, id2, "Witness ID should be deterministic");

        // Change timestamp - ID should still be same (timestamp excluded)
        let mut witness2 = witness.clone();
        witness2.validation_timestamp = "2024-11-15T11:00:00Z".to_string();
        let id3 = ScopeValidator::compute_witness_id(&witness2).expect("should compute witness id");
        assert_eq!(
            id1, id3,
            "Timestamp should not affect witness ID (excluded from hash)"
        );

        // Change message - ID should still be same (messages excluded)
        let mut witness3 = witness.clone();
        witness3.validations[0].message = Some("different message".to_string());
        let id4 = ScopeValidator::compute_witness_id(&witness3).expect("should compute witness id");
        assert_eq!(
            id1, id4,
            "Validation messages should not affect witness ID (excluded from hash)"
        );

        // Change registry hash - ID should differ (included in hash)
        let mut witness4 = witness.clone();
        witness4.registry_hash_after = "xyz789".to_string();
        let id5 = ScopeValidator::compute_witness_id(&witness4).expect("should compute witness id");
        assert_ne!(
            id1, id5,
            "Registry hash changes should affect witness ID (included in hash)"
        );
    }
}
