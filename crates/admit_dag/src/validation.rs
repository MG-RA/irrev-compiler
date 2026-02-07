use std::collections::{HashMap, HashSet};

use crate::graph::GovernedDag;
use crate::node::NodeId;

/// Result type for validation operations
pub type ValidationResult<T> = Result<T, ValidationError>;

/// Validation error types
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ValidationError {
    CycleDetected {
        cycle: Vec<NodeId>,
        edge_type: String,
    },
    MissingNode {
        node_id: NodeId,
        referenced_by: String,
    },
    AuthorityNotReachable {
        node_id: NodeId,
        scope: String,
    },
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::CycleDetected { cycle, edge_type } => {
                write!(f, "cycle detected in {} edges: ", edge_type)?;
                for (i, node) in cycle.iter().enumerate() {
                    if i > 0 {
                        write!(f, " -> ")?;
                    }
                    write!(f, "{}", node)?;
                }
                Ok(())
            }
            ValidationError::MissingNode {
                node_id,
                referenced_by,
            } => {
                write!(
                    f,
                    "node {} referenced by {} but not found in DAG",
                    node_id, referenced_by
                )
            }
            ValidationError::AuthorityNotReachable { node_id, scope } => {
                write!(
                    f,
                    "node {} in scope {} not reachable from any authority root",
                    node_id, scope
                )
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// DFS-based cycle detection
pub fn detect_cycles_in_build_order(dag: &GovernedDag) -> ValidationResult<()> {
    // Build adjacency list for BuildDepends edges
    let mut adj: HashMap<NodeId, Vec<NodeId>> = HashMap::new();
    for edge in dag.build_order_edges() {
        adj.entry(edge.from).or_default().push(edge.to);
    }

    // Track visited nodes (DFS states)
    let mut visiting = HashSet::new();
    let mut visited = HashSet::new();
    let mut path = Vec::new();

    // Run DFS from each node
    for node_id in dag.nodes().keys() {
        if !visited.contains(node_id) {
            detect_cycle_dfs(*node_id, &adj, &mut visiting, &mut visited, &mut path)?;
        }
    }

    Ok(())
}

fn detect_cycle_dfs(
    node: NodeId,
    adj: &HashMap<NodeId, Vec<NodeId>>,
    visiting: &mut HashSet<NodeId>,
    visited: &mut HashSet<NodeId>,
    path: &mut Vec<NodeId>,
) -> ValidationResult<()> {
    if visiting.contains(&node) {
        // Cycle detected - extract the cycle from path
        if let Some(cycle_start) = path.iter().position(|&n| n == node) {
            let cycle = path[cycle_start..].to_vec();
            return Err(ValidationError::CycleDetected {
                cycle,
                edge_type: "BuildDepends".to_string(),
            });
        }
    }

    if visited.contains(&node) {
        return Ok(());
    }

    visiting.insert(node);
    path.push(node);

    if let Some(neighbors) = adj.get(&node) {
        for &next in neighbors {
            detect_cycle_dfs(next, adj, visiting, visited, path)?;
        }
    }

    path.pop();
    visiting.remove(&node);
    visited.insert(node);

    Ok(())
}

/// Check that all edges reference existing nodes
pub fn validate_node_references(dag: &GovernedDag) -> ValidationResult<()> {
    let nodes = dag.nodes();

    for edge in dag.edges() {
        if !nodes.contains_key(&edge.from) {
            return Err(ValidationError::MissingNode {
                node_id: edge.from,
                referenced_by: format!("edge from {} to {}", edge.from, edge.to),
            });
        }

        if !nodes.contains_key(&edge.to) {
            return Err(ValidationError::MissingNode {
                node_id: edge.to,
                referenced_by: format!("edge from {} to {}", edge.from, edge.to),
            });
        }

        // Check witness_ref if present
        if let Some(witness_id) = edge.witness_ref {
            if !nodes.contains_key(&witness_id) {
                return Err(ValidationError::MissingNode {
                    node_id: witness_id,
                    referenced_by: format!("witness_ref in edge from {} to {}", edge.from, edge.to),
                });
            }
        }
    }

    Ok(())
}

/// Run all basic validation checks
pub fn validate_dag(dag: &GovernedDag) -> ValidationResult<()> {
    validate_node_references(dag)?;
    detect_cycles_in_build_order(dag)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::{DagEdge, ScopeTag, TimelineStep};
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
    fn acyclic_graph_validates() {
        let mut dag = GovernedDag::new();

        let n1 = create_test_node("n1", "scope:test");
        let n2 = create_test_node("n2", "scope:test");
        let n3 = create_test_node("n3", "scope:test");
        let id1 = n1.id;
        let id2 = n2.id;
        let id3 = n3.id;

        dag.ensure_node(n1);
        dag.ensure_node(n2);
        dag.ensure_node(n3);

        let scope = ScopeTag::new("scope:test");

        // Create linear dependency: n1 -> n2 -> n3
        dag.add_edge(DagEdge::build_depends(
            id1,
            id2,
            scope.clone(),
            TimelineStep::new("build", 1),
        ));
        dag.add_edge(DagEdge::build_depends(
            id2,
            id3,
            scope,
            TimelineStep::new("build", 2),
        ));

        assert!(detect_cycles_in_build_order(&dag).is_ok());
    }

    #[test]
    fn cyclic_graph_fails() {
        let mut dag = GovernedDag::new();

        let n1 = create_test_node("n1", "scope:test");
        let n2 = create_test_node("n2", "scope:test");
        let n3 = create_test_node("n3", "scope:test");
        let id1 = n1.id;
        let id2 = n2.id;
        let id3 = n3.id;

        dag.ensure_node(n1);
        dag.ensure_node(n2);
        dag.ensure_node(n3);

        let scope = ScopeTag::new("scope:test");

        // Create cycle: n1 -> n2 -> n3 -> n1
        dag.add_edge(DagEdge::build_depends(
            id1,
            id2,
            scope.clone(),
            TimelineStep::new("build", 1),
        ));
        dag.add_edge(DagEdge::build_depends(
            id2,
            id3,
            scope.clone(),
            TimelineStep::new("build", 2),
        ));
        dag.add_edge(DagEdge::build_depends(
            id3,
            id1,
            scope,
            TimelineStep::new("build", 3),
        ));

        let result = detect_cycles_in_build_order(&dag);
        assert!(result.is_err());

        if let Err(ValidationError::CycleDetected { cycle, .. }) = result {
            assert!(!cycle.is_empty());
        } else {
            panic!("Expected CycleDetected error");
        }
    }

    #[test]
    fn missing_node_reference_fails() {
        let mut dag = GovernedDag::new();

        let n1 = create_test_node("n1", "scope:test");
        let n2 = create_test_node("n2", "scope:test");
        let id1 = n1.id;
        let id2 = n2.id;

        // Only add n1, not n2
        dag.ensure_node(n1);

        let scope = ScopeTag::new("scope:test");

        // Add edge referencing missing n2
        dag.add_edge(DagEdge::build_depends(
            id1,
            id2,
            scope,
            TimelineStep::new("build", 1),
        ));

        let result = validate_node_references(&dag);
        assert!(result.is_err());

        if let Err(ValidationError::MissingNode { node_id, .. }) = result {
            assert_eq!(node_id, id2);
        } else {
            panic!("Expected MissingNode error");
        }
    }
}
