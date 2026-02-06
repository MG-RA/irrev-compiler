use std::collections::{HashMap, HashSet, VecDeque};

use crate::edge::EdgeType;
use crate::graph::GovernedDag;
use crate::node::{NodeId, NodeKind};

/// Check authority reachability for all nodes in non-pure scopes
///
/// "No authority bypass" — every node in a non-pure scope must be reachable
/// (in the authority-order subgraph) from at least one AuthorityRoot node.
pub fn check_authority_reachability(dag: &GovernedDag) -> Vec<AuthorityViolation> {
    let mut violations = Vec::new();

    // Find all AuthorityRoot nodes
    let authority_roots: Vec<NodeId> = dag
        .iter_nodes()
        .filter(|(_, node)| matches!(node.kind, NodeKind::AuthorityRoot { .. }))
        .map(|(id, _)| *id)
        .collect();

    if authority_roots.is_empty() {
        // If there are no authority roots, check if any nodes require authority
        for (node_id, node) in dag.iter_nodes() {
            if requires_authority(&node.scope.as_str()) {
                violations.push(AuthorityViolation {
                    node_id: *node_id,
                    scope: node.scope.to_string(),
                    message: "node requires authority but no authority roots exist in DAG"
                        .to_string(),
                });
            }
        }
        return violations;
    }

    // Build forward reachability from authority roots via AuthorityDepends edges
    let reachable_from_authority = compute_authority_reachable(dag, &authority_roots);

    // Check each node that requires authority
    for (node_id, node) in dag.iter_nodes() {
        if requires_authority(&node.scope.as_str()) && !reachable_from_authority.contains(node_id)
        {
            violations.push(AuthorityViolation {
                node_id: *node_id,
                scope: node.scope.to_string(),
                message: format!(
                    "node in scope {} not reachable from any authority root",
                    node.scope
                ),
            });
        }
    }

    violations
}

/// Compute set of nodes reachable from authority roots via AuthorityDepends edges
fn compute_authority_reachable(dag: &GovernedDag, roots: &[NodeId]) -> HashSet<NodeId> {
    // Build adjacency list for AuthorityDepends edges
    let mut adj: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
    for edge in dag.authority_order_edges() {
        adj.entry(edge.from).or_default().push(edge.to);
    }

    // BFS from all authority roots
    let mut reachable = HashSet::new();
    let mut queue = VecDeque::new();

    for &root in roots {
        queue.push_back(root);
        reachable.insert(root);
    }

    while let Some(node) = queue.pop_front() {
        if let Some(neighbors) = adj.get(&node) {
            for &next in neighbors {
                if reachable.insert(next) {
                    queue.push_back(next);
                }
            }
        }
    }

    reachable
}

/// Determine if a scope requires authority
fn requires_authority(scope: &str) -> bool {
    // Non-pure scopes require authority
    // Pure scopes: scope:core.pure, scope:meta.*, etc.
    !scope.starts_with("scope:core.pure") && !scope.starts_with("scope:meta.")
}

/// Authority reachability violation
#[derive(Debug, Clone)]
pub struct AuthorityViolation {
    pub node_id: NodeId,
    pub scope: String,
    pub message: String,
}

impl std::fmt::Display for AuthorityViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "authority violation: node {} in scope {}: {}",
            self.node_id, self.scope, self.message
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::{DagEdge, ScopeTag, TimelineStep};
    use crate::node::{DagNode, NodeKind};

    fn create_test_node(kind: NodeKind, scope: &str) -> DagNode {
        DagNode::new(kind, ScopeTag::new(scope), vec![], vec![]).unwrap()
    }

    #[test]
    fn pure_scope_does_not_require_authority() {
        let mut dag = GovernedDag::new();

        let n1 = create_test_node(
            NodeKind::RulesetSource {
                content_hash: "n1".to_string(),
            },
            "scope:core.pure",
        );
        dag.ensure_node(n1);

        let violations = check_authority_reachability(&dag);
        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn non_pure_scope_without_authority_fails() {
        let mut dag = GovernedDag::new();

        let n1 = create_test_node(
            NodeKind::RulesetSource {
                content_hash: "n1".to_string(),
            },
            "scope:fs.write",
        );
        dag.ensure_node(n1);

        let violations = check_authority_reachability(&dag);
        assert_eq!(violations.len(), 1);
        assert!(violations[0]
            .message
            .contains("no authority roots exist in DAG"));
    }

    #[test]
    fn authority_reachability_works() {
        let mut dag = GovernedDag::new();

        // Create authority root
        let auth_root = create_test_node(
            NodeKind::AuthorityRoot {
                authority_id: "test_auth".to_string(),
                authority_hash: "hash123".to_string(),
            },
            "scope:governance",
        );
        let auth_id = auth_root.id;
        dag.ensure_node(auth_root);

        // Create effectful node
        let effectful = create_test_node(
            NodeKind::ExecutionLog {
                log_hash: "log123".to_string(),
            },
            "scope:fs.write",
        );
        let effectful_id = effectful.id;
        dag.ensure_node(effectful);

        // Connect authority to effectful node
        dag.add_edge(DagEdge::authority_depends(
            auth_id,
            effectful_id,
            "test_auth".to_string(),
            "hash123".to_string(),
            ScopeTag::new("scope:fs.write"),
            TimelineStep::new("exec", 1),
            None,
        ));

        let violations = check_authority_reachability(&dag);
        assert_eq!(violations.len(), 0);
    }

    #[test]
    fn authority_bypass_detected() {
        let mut dag = GovernedDag::new();

        // Create authority root
        let auth_root = create_test_node(
            NodeKind::AuthorityRoot {
                authority_id: "test_auth".to_string(),
                authority_hash: "hash123".to_string(),
            },
            "scope:governance",
        );
        dag.ensure_node(auth_root);

        // Create effectful node NOT connected to authority
        let effectful = create_test_node(
            NodeKind::ExecutionLog {
                log_hash: "log123".to_string(),
            },
            "scope:fs.write",
        );
        dag.ensure_node(effectful);

        // No AuthorityDepends edge connecting them

        let violations = check_authority_reachability(&dag);
        assert_eq!(violations.len(), 1);
        assert!(violations[0]
            .message
            .contains("not reachable from any authority root"));
    }
}
