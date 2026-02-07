use serde::{Deserialize, Serialize};

use crate::edge::{DagEdge, EdgeType, MutationRiskClass, ScopeTag};
use crate::graph::GovernedDag;
use crate::node::NodeId;

/// Severity of a scope boundary violation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Error => write!(f, "error"),
            Severity::Warning => write!(f, "warning"),
        }
    }
}

/// EdgeTypeMatch handles parameterized edge matching
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EdgeTypeMatch {
    Any,
    Exact(EdgeTypeTag),
    MutationWithMinRisk(MutationRiskClass),
    AuthorityWithPrefix(String),
}

/// Simplified edge type tag for matching
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EdgeTypeTag {
    BuildDepends,
    WitnessOf,
    AuthorityDepends,
    MutationCommitment,
    CostDisplacement,
}

impl EdgeTypeMatch {
    /// Check if an edge type matches this pattern
    pub fn matches(&self, edge_type: &EdgeType) -> bool {
        match self {
            EdgeTypeMatch::Any => true,
            EdgeTypeMatch::Exact(tag) => match (tag, edge_type) {
                (EdgeTypeTag::BuildDepends, EdgeType::BuildDepends) => true,
                (EdgeTypeTag::WitnessOf, EdgeType::WitnessOf) => true,
                (EdgeTypeTag::AuthorityDepends, EdgeType::AuthorityDepends { .. }) => true,
                (EdgeTypeTag::MutationCommitment, EdgeType::MutationCommitment { .. }) => true,
                (EdgeTypeTag::CostDisplacement, EdgeType::CostDisplacement { .. }) => true,
                _ => false,
            },
            EdgeTypeMatch::MutationWithMinRisk(min_risk) => {
                if let EdgeType::MutationCommitment { risk_class, .. } = edge_type {
                    risk_class >= min_risk
                } else {
                    false
                }
            }
            EdgeTypeMatch::AuthorityWithPrefix(prefix) => {
                if let EdgeType::AuthorityDepends { authority_id, .. } = edge_type {
                    authority_id.starts_with(prefix)
                } else {
                    false
                }
            }
        }
    }
}

/// Scope boundary rule
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeBoundaryRule {
    pub from_scope_prefix: String,
    pub to_scope_prefix: String,
    pub edge_type_match: EdgeTypeMatch,
    pub allowed: bool,
    pub requires_witness: bool,
    pub requires_authority: bool,
    pub severity: Severity,
}

impl ScopeBoundaryRule {
    /// Check if this rule applies to a given edge
    pub fn applies_to(&self, edge: &DagEdge, from_scope: &ScopeTag, to_scope: &ScopeTag) -> bool {
        from_scope.matches_prefix(&self.from_scope_prefix)
            && to_scope.matches_prefix(&self.to_scope_prefix)
            && self.edge_type_match.matches(&edge.edge_type)
    }
}

/// Default scope boundary rules
pub fn default_scope_rules() -> Vec<ScopeBoundaryRule> {
    vec![
        // Pure to pure: BuildDepends allowed, no ceremony
        ScopeBoundaryRule {
            from_scope_prefix: "scope:core.pure".to_string(),
            to_scope_prefix: "scope:core.pure".to_string(),
            edge_type_match: EdgeTypeMatch::Exact(EdgeTypeTag::BuildDepends),
            allowed: true,
            requires_witness: false,
            requires_authority: false,
            severity: Severity::Error,
        },
        // Pure to fs.write: Mutation(LocalPersistent+) requires witness
        ScopeBoundaryRule {
            from_scope_prefix: "scope:core.pure".to_string(),
            to_scope_prefix: "scope:fs.write".to_string(),
            edge_type_match: EdgeTypeMatch::MutationWithMinRisk(MutationRiskClass::LocalPersistent),
            allowed: true,
            requires_witness: true,
            requires_authority: false,
            severity: Severity::Error,
        },
        // fs.write to external: Any mutation requires witness + authority
        ScopeBoundaryRule {
            from_scope_prefix: "scope:fs.write".to_string(),
            to_scope_prefix: "scope:external.".to_string(),
            edge_type_match: EdgeTypeMatch::Exact(EdgeTypeTag::MutationCommitment),
            allowed: true,
            requires_witness: true,
            requires_authority: true,
            severity: Severity::Error,
        },
        // external to any: Any mutation requires witness + authority
        ScopeBoundaryRule {
            from_scope_prefix: "scope:external.".to_string(),
            to_scope_prefix: "scope:".to_string(), // matches any scope
            edge_type_match: EdgeTypeMatch::Exact(EdgeTypeTag::MutationCommitment),
            allowed: true,
            requires_witness: true,
            requires_authority: true,
            severity: Severity::Error,
        },
        // WitnessOf edges always allowed, no ceremony
        ScopeBoundaryRule {
            from_scope_prefix: "scope:".to_string(),
            to_scope_prefix: "scope:".to_string(),
            edge_type_match: EdgeTypeMatch::Exact(EdgeTypeTag::WitnessOf),
            allowed: true,
            requires_witness: false,
            requires_authority: false,
            severity: Severity::Error,
        },
        // CostDisplacement edges always allowed, no ceremony
        ScopeBoundaryRule {
            from_scope_prefix: "scope:".to_string(),
            to_scope_prefix: "scope:".to_string(),
            edge_type_match: EdgeTypeMatch::Exact(EdgeTypeTag::CostDisplacement),
            allowed: true,
            requires_witness: false,
            requires_authority: false,
            severity: Severity::Error,
        },
    ]
}

/// Violation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeViolation {
    pub edge_from: NodeId,
    pub edge_to: NodeId,
    pub from_scope: String,
    pub to_scope: String,
    pub edge_type: String,
    pub violation_type: ViolationType,
    pub severity: Severity,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViolationType {
    Forbidden,
    MissingWitness,
    MissingAuthority,
}

/// Scope enforcement checker
pub struct ScopeEnforcer {
    rules: Vec<ScopeBoundaryRule>,
}

impl ScopeEnforcer {
    pub fn new(rules: Vec<ScopeBoundaryRule>) -> Self {
        ScopeEnforcer { rules }
    }

    pub fn with_default_rules() -> Self {
        ScopeEnforcer::new(default_scope_rules())
    }

    /// Check all edges in the DAG against scope boundary rules
    pub fn check_dag(&self, dag: &GovernedDag) -> Vec<ScopeViolation> {
        let mut violations = Vec::new();

        for edge in dag.edges() {
            // Get scope tags for from and to nodes
            let from_node = dag.get_node(&edge.from);
            let to_node = dag.get_node(&edge.to);

            if let (Some(from_node), Some(to_node)) = (from_node, to_node) {
                if let Some(violation) = self.check_edge(edge, &from_node.scope, &to_node.scope) {
                    violations.push(violation);
                }
            }
        }

        violations
    }

    /// Check a single edge against the rules
    fn check_edge(
        &self,
        edge: &DagEdge,
        from_scope: &ScopeTag,
        to_scope: &ScopeTag,
    ) -> Option<ScopeViolation> {
        // Find the first matching rule (rules are evaluated in order)
        for rule in &self.rules {
            if rule.applies_to(edge, from_scope, to_scope) {
                // Check if edge is forbidden
                if !rule.allowed {
                    return Some(ScopeViolation {
                        edge_from: edge.from,
                        edge_to: edge.to,
                        from_scope: from_scope.to_string(),
                        to_scope: to_scope.to_string(),
                        edge_type: format!("{:?}", edge.edge_type),
                        violation_type: ViolationType::Forbidden,
                        severity: rule.severity,
                        message: format!(
                            "edge from {} to {} forbidden by scope boundary rules",
                            from_scope, to_scope
                        ),
                    });
                }

                // Check witness requirement
                if rule.requires_witness && edge.witness_ref.is_none() {
                    return Some(ScopeViolation {
                        edge_from: edge.from,
                        edge_to: edge.to,
                        from_scope: from_scope.to_string(),
                        to_scope: to_scope.to_string(),
                        edge_type: format!("{:?}", edge.edge_type),
                        violation_type: ViolationType::MissingWitness,
                        severity: rule.severity,
                        message: format!(
                            "edge from {} to {} requires witness",
                            from_scope, to_scope
                        ),
                    });
                }

                // Check authority requirement (we just check if the requirement exists here;
                // actual reachability is checked separately)
                if rule.requires_authority {
                    // For now, we'll check this in the authority reachability module
                    // This is just a marker that authority is required
                }

                // Rule matched and passed all checks
                return None;
            }
        }

        // No rule matched - this is a warning (undefined boundary crossing)
        Some(ScopeViolation {
            edge_from: edge.from,
            edge_to: edge.to,
            from_scope: from_scope.to_string(),
            to_scope: to_scope.to_string(),
            edge_type: format!("{:?}", edge.edge_type),
            violation_type: ViolationType::Forbidden,
            severity: Severity::Warning,
            message: format!(
                "no scope boundary rule defined for edge from {} to {} (type {:?})",
                from_scope, to_scope, edge.edge_type
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::TimelineStep;
    use crate::node::{DagNode, NodeKind};

    fn create_test_node(content_hash: &str, scope: &str) -> DagNode {
        DagNode::new(
            NodeKind::RulesetSource {
                content_hash: content_hash.to_string(),
            },
            ScopeTag::new(scope),
            vec![],
            vec![],
        )
        .unwrap()
    }

    #[test]
    fn pure_to_pure_build_depends_allowed() {
        let mut dag = GovernedDag::new();

        let n1 = create_test_node("n1", "scope:core.pure");
        let n2 = create_test_node("n2", "scope:core.pure");
        let id1 = n1.id;
        let id2 = n2.id;

        dag.ensure_node(n1);
        dag.ensure_node(n2);

        dag.add_edge(DagEdge::build_depends(
            id1,
            id2,
            ScopeTag::new("scope:core.pure"),
            TimelineStep::new("build", 1),
        ));

        let enforcer = ScopeEnforcer::with_default_rules();
        let violations = enforcer.check_dag(&dag);

        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn mutation_without_witness_fails() {
        let mut dag = GovernedDag::new();

        let n1 = create_test_node("n1", "scope:core.pure");
        let n2 = create_test_node("n2", "scope:fs.write");
        let id1 = n1.id;
        let id2 = n2.id;

        dag.ensure_node(n1);
        dag.ensure_node(n2);

        // Try to add mutation edge without witness
        let edge = DagEdge::mutation(
            id1,
            id2,
            "test".to_string(),
            MutationRiskClass::LocalPersistent,
            ScopeTag::new("scope:fs.write"),
            TimelineStep::new("build", 1),
            None,
        );

        // This should fail at construction time
        assert!(edge.is_err());
    }

    #[test]
    fn edge_type_match_works() {
        let build_match = EdgeTypeMatch::Exact(EdgeTypeTag::BuildDepends);
        assert!(build_match.matches(&EdgeType::BuildDepends));
        assert!(!build_match.matches(&EdgeType::WitnessOf));

        let mutation_match = EdgeTypeMatch::MutationWithMinRisk(MutationRiskClass::LocalPersistent);
        assert!(mutation_match.matches(&EdgeType::MutationCommitment {
            harness_id: "test".to_string(),
            risk_class: MutationRiskClass::LocalPersistent,
        }));
        assert!(mutation_match.matches(&EdgeType::MutationCommitment {
            harness_id: "test".to_string(),
            risk_class: MutationRiskClass::ExternalDestructive,
        }));
        assert!(!mutation_match.matches(&EdgeType::MutationCommitment {
            harness_id: "test".to_string(),
            risk_class: MutationRiskClass::LocalReversible,
        }));
    }
}
