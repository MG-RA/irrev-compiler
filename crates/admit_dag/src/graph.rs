use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use crate::edge::{DagEdge, EdgeType};
use crate::node::{DagNode, NodeId};

/// Container with `BTreeMap<NodeId, DagNode>` + `Vec<DagEdge>`.
/// Borrows the **ensure pattern** from legacy `sas-core` interpreter
/// (idempotent node insertion via map entry API).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernedDag {
    nodes: BTreeMap<NodeId, DagNode>,
    edges: Vec<DagEdge>,
}

impl GovernedDag {
    /// Create a new empty DAG
    pub fn new() -> Self {
        GovernedDag {
            nodes: BTreeMap::new(),
            edges: Vec::new(),
        }
    }

    /// Ensure a node exists in the DAG (idempotent insert).
    /// Returns true if the node was newly inserted, false if it already existed.
    pub fn ensure_node(&mut self, node: DagNode) -> bool {
        use std::collections::btree_map::Entry;

        match self.nodes.entry(node.id) {
            Entry::Vacant(e) => {
                e.insert(node);
                true
            }
            Entry::Occupied(_) => false,
        }
    }

    /// Add an edge to the DAG
    pub fn add_edge(&mut self, edge: DagEdge) {
        self.edges.push(edge);
    }

    /// Get a node by ID
    pub fn get_node(&self, id: &NodeId) -> Option<&DagNode> {
        self.nodes.get(id)
    }

    /// Get all nodes
    pub fn nodes(&self) -> &BTreeMap<NodeId, DagNode> {
        &self.nodes
    }

    /// Get all edges
    pub fn edges(&self) -> &[DagEdge] {
        &self.edges
    }

    /// Get the count of nodes
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// Get the count of edges
    pub fn edge_count(&self) -> usize {
        self.edges.len()
    }

    /// Iterator over nodes
    pub fn iter_nodes(&self) -> impl Iterator<Item = (&NodeId, &DagNode)> {
        self.nodes.iter()
    }

    /// Iterator over edges
    pub fn iter_edges(&self) -> impl Iterator<Item = &DagEdge> {
        self.edges.iter()
    }
}

impl Default for GovernedDag {
    fn default() -> Self {
        Self::new()
    }
}

/// Partial order views - these will be implemented in orders.rs
impl GovernedDag {
    /// Get BuildDepends edges only
    pub fn build_order_edges(&self) -> Vec<&DagEdge> {
        self.edges
            .iter()
            .filter(|e| matches!(e.edge_type, EdgeType::BuildDepends))
            .collect()
    }

    /// Get AuthorityDepends edges only
    pub fn authority_order_edges(&self) -> Vec<&DagEdge> {
        self.edges
            .iter()
            .filter(|e| matches!(e.edge_type, EdgeType::AuthorityDepends { .. }))
            .collect()
    }

    /// Get MutationCommitment edges, sorted by timeline+seq
    pub fn mutation_order_edges(&self) -> Vec<&DagEdge> {
        let mut edges: Vec<&DagEdge> = self
            .edges
            .iter()
            .filter(|e| matches!(e.edge_type, EdgeType::MutationCommitment { .. }))
            .collect();

        // Sort by timeline, then seq
        edges.sort_by(|a, b| {
            a.step
                .timeline
                .cmp(&b.step.timeline)
                .then(a.step.seq.cmp(&b.step.seq))
        });

        edges
    }

    /// Get CostDisplacement edges only
    pub fn accounting_order_edges(&self) -> Vec<&DagEdge> {
        self.edges
            .iter()
            .filter(|e| matches!(e.edge_type, EdgeType::CostDisplacement { .. }))
            .collect()
    }

    /// Get WitnessOf edges only
    pub fn witness_edges(&self) -> Vec<&DagEdge> {
        self.edges
            .iter()
            .filter(|e| matches!(e.edge_type, EdgeType::WitnessOf))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::{MutationRiskClass, ScopeTag, TimelineStep};
    use crate::node::{NodeKind, NodeIdPayload};

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
    fn ensure_node_idempotent() {
        let mut dag = GovernedDag::new();
        let node = create_test_node("abc123", "scope:test");
        let node_id = node.id;

        // First insert returns true
        assert!(dag.ensure_node(node.clone()));
        assert_eq!(dag.node_count(), 1);

        // Second insert returns false (already exists)
        assert!(!dag.ensure_node(node));
        assert_eq!(dag.node_count(), 1);

        // Node is retrievable
        assert!(dag.get_node(&node_id).is_some());
    }

    #[test]
    fn edge_filtering() {
        let mut dag = GovernedDag::new();

        let node1 = create_test_node("abc", "scope:test");
        let node2 = create_test_node("def", "scope:test");
        let id1 = node1.id;
        let id2 = node2.id;

        dag.ensure_node(node1);
        dag.ensure_node(node2);

        let scope = ScopeTag::new("scope:test");
        let step1 = TimelineStep::new("build", 1);
        let step2 = TimelineStep::new("build", 2);

        // Add different edge types
        dag.add_edge(DagEdge::build_depends(
            id1,
            id2,
            scope.clone(),
            step1.clone(),
        ));

        dag.add_edge(DagEdge::witness_of(
            id1,
            id2,
            scope.clone(),
            step2.clone(),
        ));

        let witness_node = create_test_node("witness", "scope:test");
        let witness_id = witness_node.id;
        dag.ensure_node(witness_node);

        dag.add_edge(
            DagEdge::mutation(
                id1,
                id2,
                "test_harness".to_string(),
                MutationRiskClass::LocalPersistent,
                scope.clone(),
                step1,
                Some(witness_id),
            )
            .unwrap(),
        );

        // Test filtering
        assert_eq!(dag.build_order_edges().len(), 1);
        assert_eq!(dag.witness_edges().len(), 1);
        assert_eq!(dag.mutation_order_edges().len(), 1);
        assert_eq!(dag.authority_order_edges().len(), 0);
        assert_eq!(dag.accounting_order_edges().len(), 0);
    }

    #[test]
    fn mutation_edges_sorted_by_timeline() {
        let mut dag = GovernedDag::new();

        let node1 = create_test_node("n1", "scope:test");
        let node2 = create_test_node("n2", "scope:test");
        let witness = create_test_node("w", "scope:test");
        let id1 = node1.id;
        let id2 = node2.id;
        let witness_id = witness.id;

        dag.ensure_node(node1);
        dag.ensure_node(node2);
        dag.ensure_node(witness);

        let scope = ScopeTag::new("scope:test");

        // Add edges out of order
        dag.add_edge(
            DagEdge::mutation(
                id1,
                id2,
                "h1".to_string(),
                MutationRiskClass::LocalPersistent,
                scope.clone(),
                TimelineStep::new("timeline_a", 3),
                Some(witness_id),
            )
            .unwrap(),
        );

        dag.add_edge(
            DagEdge::mutation(
                id1,
                id2,
                "h2".to_string(),
                MutationRiskClass::LocalPersistent,
                scope.clone(),
                TimelineStep::new("timeline_a", 1),
                Some(witness_id),
            )
            .unwrap(),
        );

        dag.add_edge(
            DagEdge::mutation(
                id1,
                id2,
                "h3".to_string(),
                MutationRiskClass::LocalPersistent,
                scope,
                TimelineStep::new("timeline_b", 2),
                Some(witness_id),
            )
            .unwrap(),
        );

        let sorted = dag.mutation_order_edges();
        assert_eq!(sorted.len(), 3);

        // Should be sorted by timeline, then seq
        assert_eq!(sorted[0].step.timeline, "timeline_a");
        assert_eq!(sorted[0].step.seq, 1);
        assert_eq!(sorted[1].step.timeline, "timeline_a");
        assert_eq!(sorted[1].step.seq, 3);
        assert_eq!(sorted[2].step.timeline, "timeline_b");
        assert_eq!(sorted[2].step.seq, 2);
    }
}
