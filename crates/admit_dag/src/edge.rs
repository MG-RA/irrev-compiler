use serde::{Deserialize, Serialize};

use crate::node::NodeId;

/// Scope tag for scope-bounded evaluation
/// Maps directly to existing `MetaRegistryScope.id` format.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ScopeTag(pub String); // "scope:core.pure", "scope:obsidian.vault.read", "scope:fs.write", etc.

impl ScopeTag {
    pub fn new(s: impl Into<String>) -> Self {
        ScopeTag(s.into())
    }

    /// Create an Obsidian vault scope tag using the canonical namespaced form.
    /// Example: `ScopeTag::obsidian_vault("read")` -> `scope:obsidian.vault.read`.
    pub fn obsidian_vault(action: &str) -> Self {
        ScopeTag(format!("scope:obsidian.vault.{}", action))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Check if this scope matches a prefix pattern
    pub fn matches_prefix(&self, prefix: &str) -> bool {
        self.0.starts_with(prefix)
    }
}

impl std::fmt::Display for ScopeTag {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Mutation risk tiers — lint enforces witness/approval policy per tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MutationRiskClass {
    LocalReversible,     // cache writes — lowest ceremony
    LocalPersistent,     // exports, generated files
    ExternalDestructive, // DB wipes, external system mutations — highest ceremony
}

/// Step is scoped to a timeline, not global.
/// Prevents awkwardness with parallel executions or merged traces.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TimelineStep {
    pub timeline: String, // e.g., harness execution id, or "build" for pure computation
    pub seq: u64,         // monotonic within timeline
}

impl TimelineStep {
    pub fn new(timeline: impl Into<String>, seq: u64) -> Self {
        TimelineStep {
            timeline: timeline.into(),
            seq,
        }
    }
}

/// Five typed edges (\"time arrows\") with different acyclicity/governance rules
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EdgeType {
    BuildDepends,
    WitnessOf,

    /// Direction: AuthorityRoot → effectful_node (\"authority authorizes this result\").
    /// Reads like provenance. Reachability checks: \"can I reach this node from an authority root?\"
    AuthorityDepends {
        authority_id: String,   // stable identifier
        authority_hash: String, // content hash of the authority source
    },

    MutationCommitment {
        harness_id: String,
        risk_class: MutationRiskClass,
    },

    CostDisplacement {
        cost: String,
        displaced_to: String,
    },
}

/// Edge construction enforces witness requirements at type level.
/// MutationCommitment(LocalPersistent+) and AuthorityDepends (when scope rules require it)
/// MUST carry witness_ref. WitnessOf edges must NOT have witness_ref (they ARE the link).
/// This is enforced by DagEdge constructors, not by post-hoc lint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagEdge {
    pub from: NodeId,
    pub to: NodeId,
    pub edge_type: EdgeType,
    pub scope: ScopeTag,
    pub step: TimelineStep,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness_ref: Option<NodeId>,
}

impl DagEdge {
    /// Construct a BuildDepends edge
    pub fn build_depends(from: NodeId, to: NodeId, scope: ScopeTag, step: TimelineStep) -> Self {
        DagEdge {
            from,
            to,
            edge_type: EdgeType::BuildDepends,
            scope,
            step,
            witness_ref: None,
        }
    }

    /// Construct a WitnessOf edge. witness_ref must be None (this IS the witness link).
    pub fn witness_of(from: NodeId, to: NodeId, scope: ScopeTag, step: TimelineStep) -> Self {
        DagEdge {
            from,
            to,
            edge_type: EdgeType::WitnessOf,
            scope,
            step,
            witness_ref: None,
        }
    }

    /// Construct an AuthorityDepends edge
    pub fn authority_depends(
        from: NodeId,
        to: NodeId,
        authority_id: String,
        authority_hash: String,
        scope: ScopeTag,
        step: TimelineStep,
        witness_ref: Option<NodeId>,
    ) -> Self {
        DagEdge {
            from,
            to,
            edge_type: EdgeType::AuthorityDepends {
                authority_id,
                authority_hash,
            },
            scope,
            step,
            witness_ref,
        }
    }

    /// Construct a MutationCommitment edge. witness_ref required for LocalPersistent+.
    pub fn mutation(
        from: NodeId,
        to: NodeId,
        harness_id: String,
        risk_class: MutationRiskClass,
        scope: ScopeTag,
        step: TimelineStep,
        witness_ref: Option<NodeId>,
    ) -> Result<Self, String> {
        if matches!(
            risk_class,
            MutationRiskClass::LocalPersistent | MutationRiskClass::ExternalDestructive
        ) && witness_ref.is_none()
        {
            return Err("MutationCommitment(LocalPersistent+) requires witness_ref".to_string());
        }

        Ok(DagEdge {
            from,
            to,
            edge_type: EdgeType::MutationCommitment {
                harness_id,
                risk_class,
            },
            scope,
            step,
            witness_ref,
        })
    }

    /// Construct a CostDisplacement edge
    pub fn cost_displacement(
        from: NodeId,
        to: NodeId,
        cost: String,
        displaced_to: String,
        scope: ScopeTag,
        step: TimelineStep,
    ) -> Self {
        DagEdge {
            from,
            to,
            edge_type: EdgeType::CostDisplacement { cost, displaced_to },
            scope,
            step,
            witness_ref: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_edge_requires_witness_for_persistent() {
        let from = NodeId::from_hex(&"00".repeat(32)).unwrap();
        let to = NodeId::from_hex(&"11".repeat(32)).unwrap();
        let scope = ScopeTag::new("scope:test");
        let step = TimelineStep::new("test", 1);

        // LocalReversible doesn't require witness
        let result = DagEdge::mutation(
            from,
            to,
            "test_harness".to_string(),
            MutationRiskClass::LocalReversible,
            scope.clone(),
            step.clone(),
            None,
        );
        assert!(result.is_ok());

        // LocalPersistent requires witness
        let result = DagEdge::mutation(
            from,
            to,
            "test_harness".to_string(),
            MutationRiskClass::LocalPersistent,
            scope.clone(),
            step.clone(),
            None,
        );
        assert!(result.is_err());

        // LocalPersistent with witness is OK
        let witness = NodeId::from_hex(&"22".repeat(32)).unwrap();
        let result = DagEdge::mutation(
            from,
            to,
            "test_harness".to_string(),
            MutationRiskClass::LocalPersistent,
            scope,
            step,
            Some(witness),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn scope_tag_prefix_matching() {
        let scope = ScopeTag::new("scope:core.pure");
        assert!(scope.matches_prefix("scope:core"));
        assert!(scope.matches_prefix("scope:core."));
        assert!(!scope.matches_prefix("scope:external"));
    }

    #[test]
    fn scope_tag_obsidian_vault_namespace() {
        let scope = ScopeTag::obsidian_vault("read");
        assert_eq!(scope.as_str(), "scope:obsidian.vault.read");
        assert!(scope.matches_prefix("scope:obsidian.vault"));
    }
}
