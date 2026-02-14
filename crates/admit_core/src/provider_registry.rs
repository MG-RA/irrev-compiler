//! Provider registry — maps scope IDs to provider instances.
//!
//! The CLI builds the registry at startup by querying scope enablement and
//! instantiating only enabled providers. The registry enforces uniqueness:
//! each scope ID maps to exactly one provider.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::provider_trait::Provider;
use crate::provider_types::*;
use crate::symbols::ScopeId;

/// Registry of providers keyed by scope ID.
pub struct ProviderRegistry {
    providers: BTreeMap<ScopeId, Arc<dyn Provider>>,
}

impl ProviderRegistry {
    pub fn new() -> Self {
        Self {
            providers: BTreeMap::new(),
        }
    }

    /// Register a provider. Fails if the scope ID is already taken.
    pub fn register(&mut self, provider: Arc<dyn Provider>) -> Result<(), ProviderError> {
        let desc = provider.describe();
        let scope_id = desc.scope_id.clone();
        if self.providers.contains_key(&scope_id) {
            return Err(ProviderError {
                scope: scope_id,
                phase: ProviderPhase::Describe,
                message: "provider already registered for this scope".into(),
            });
        }
        self.providers.insert(scope_id, provider);
        Ok(())
    }

    /// Look up a provider by scope ID.
    pub fn get(&self, scope_id: &ScopeId) -> Option<&Arc<dyn Provider>> {
        self.providers.get(scope_id)
    }

    /// All registered descriptors (sorted by scope ID via BTreeMap).
    pub fn all_descriptors(&self) -> Vec<ProviderDescriptor> {
        self.providers.values().map(|p| p.describe()).collect()
    }

    /// All registered scope IDs (sorted).
    pub fn scope_ids(&self) -> Vec<ScopeId> {
        self.providers.keys().cloned().collect()
    }

    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    pub fn len(&self) -> usize {
        self.providers.len()
    }
}

impl Default for ProviderRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider_types::ClosureRequirements;

    struct StubProvider {
        scope_id: ScopeId,
    }

    impl Provider for StubProvider {
        fn describe(&self) -> ProviderDescriptor {
            ProviderDescriptor {
                scope_id: self.scope_id.clone(),
                version: 1,
                schema_ids: vec![format!("facts-bundle/{}@1", self.scope_id.0)],
                supported_phases: vec![ProviderPhase::Describe, ProviderPhase::Snapshot],
                deterministic: true,
                closure: ClosureRequirements::default(),
                required_approvals: vec![],
                predicates: vec![],
            }
        }

        fn snapshot(&self, _req: &SnapshotRequest) -> Result<SnapshotResult, ProviderError> {
            Err(ProviderError {
                scope: self.scope_id.clone(),
                phase: ProviderPhase::Snapshot,
                message: "stub".into(),
            })
        }
    }

    #[test]
    fn register_and_get() {
        let mut reg = ProviderRegistry::new();
        let p = Arc::new(StubProvider {
            scope_id: ScopeId("test.scope".into()),
        });
        reg.register(p).unwrap();
        assert_eq!(reg.len(), 1);
        assert!(reg.get(&ScopeId("test.scope".into())).is_some());
        assert!(reg.get(&ScopeId("other.scope".into())).is_none());
    }

    #[test]
    fn duplicate_registration_fails() {
        let mut reg = ProviderRegistry::new();
        let p1 = Arc::new(StubProvider {
            scope_id: ScopeId("dup.scope".into()),
        });
        let p2 = Arc::new(StubProvider {
            scope_id: ScopeId("dup.scope".into()),
        });
        reg.register(p1).unwrap();
        let err = reg.register(p2).unwrap_err();
        assert_eq!(err.phase, ProviderPhase::Describe);
        assert!(err.message.contains("already registered"));
    }

    #[test]
    fn all_descriptors_sorted() {
        let mut reg = ProviderRegistry::new();
        reg.register(Arc::new(StubProvider {
            scope_id: ScopeId("z.scope".into()),
        }))
        .unwrap();
        reg.register(Arc::new(StubProvider {
            scope_id: ScopeId("a.scope".into()),
        }))
        .unwrap();
        let descs = reg.all_descriptors();
        assert_eq!(descs.len(), 2);
        assert_eq!(descs[0].scope_id.0, "a.scope");
        assert_eq!(descs[1].scope_id.0, "z.scope");
    }

    #[test]
    fn default_plan_execute_verify_return_errors() {
        let p = StubProvider {
            scope_id: ScopeId("test".into()),
        };
        let plan_err = p
            .plan(
                &PlanIntent {
                    scope_id: ScopeId("test".into()),
                    description: "test".into(),
                    params: serde_json::Value::Null,
                },
                &[],
            )
            .unwrap_err();
        assert_eq!(plan_err.phase, ProviderPhase::Plan);

        let exec_err = p
            .execute(&PlanRef {
                plan_hash: Sha256Hex::new("abc"),
                approval_witness_hash: None,
            })
            .unwrap_err();
        assert_eq!(exec_err.phase, ProviderPhase::Execute);

        let verify_err = p
            .verify(&VerifyRequest {
                artifact_hash: Sha256Hex::new("abc"),
                schema_id: "test".into(),
                scope_id: ScopeId("test".into()),
            })
            .unwrap_err();
        assert_eq!(verify_err.phase, ProviderPhase::Verify);
    }
}
