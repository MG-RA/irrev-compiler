use std::path::Path;

use serde_json::Value;

use crate::edge::{DagEdge, EdgeType, MutationRiskClass, TimelineStep};
use crate::graph::GovernedDag;
use crate::node::{DagNode, NodeId};

pub trait Tracer {
    fn timeline(&self) -> &str;
    fn next_step(&mut self) -> TimelineStep;
    fn ensure_node(&mut self, node: DagNode) -> bool;
    fn add_edge(&mut self, edge: DagEdge);
}

#[derive(Debug, Clone)]
pub struct NoopTracer {
    timeline: String,
    next_seq: u64,
}

impl NoopTracer {
    pub fn new(timeline: impl Into<String>) -> Self {
        Self {
            timeline: timeline.into(),
            next_seq: 1,
        }
    }
}

impl Tracer for NoopTracer {
    fn timeline(&self) -> &str {
        &self.timeline
    }

    fn next_step(&mut self) -> TimelineStep {
        let step = TimelineStep::new(self.timeline.clone(), self.next_seq);
        self.next_seq += 1;
        step
    }

    fn ensure_node(&mut self, _node: DagNode) -> bool {
        false
    }

    fn add_edge(&mut self, _edge: DagEdge) {}
}

#[derive(Debug, Clone)]
pub struct DagTraceCollector {
    timeline: String,
    next_seq: u64,
    dag: GovernedDag,
}

impl DagTraceCollector {
    pub fn new(timeline: impl Into<String>) -> Self {
        Self {
            timeline: timeline.into(),
            next_seq: 1,
            dag: GovernedDag::new(),
        }
    }

    pub fn dag(&self) -> &GovernedDag {
        &self.dag
    }

    pub fn into_dag_sorted(mut self) -> GovernedDag {
        sort_edges(&mut self.dag);
        self.dag
    }

    pub fn encode_canonical_cbor(&self) -> Result<Vec<u8>, String> {
        let mut dag = self.dag.clone();
        sort_edges(&mut dag);

        let value = serde_json::to_value(&dag)
            .map_err(|err| format!("dag to value: {}", err))?;
        admit_core::encode_canonical_value(&value)
            .map_err(|err| format!("canonical cbor encode: {}", err.0))
    }

    pub fn write_canonical_cbor(&self, out: &Path) -> Result<(), String> {
        let bytes = self.encode_canonical_cbor()?;
        if let Some(parent) = out.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .map_err(|err| format!("create dag trace dir: {}", err))?;
            }
        }
        std::fs::write(out, bytes).map_err(|err| format!("write dag trace: {}", err))?;
        Ok(())
    }
}

impl Tracer for DagTraceCollector {
    fn timeline(&self) -> &str {
        &self.timeline
    }

    fn next_step(&mut self) -> TimelineStep {
        let step = TimelineStep::new(self.timeline.clone(), self.next_seq);
        self.next_seq += 1;
        step
    }

    fn ensure_node(&mut self, node: DagNode) -> bool {
        self.dag.ensure_node(node)
    }

    fn add_edge(&mut self, edge: DagEdge) {
        self.dag.add_edge(edge);
    }
}

fn edge_type_key(edge_type: &EdgeType) -> (u8, String) {
    match edge_type {
        EdgeType::BuildDepends => (0, String::new()),
        EdgeType::WitnessOf => (1, String::new()),
        EdgeType::AuthorityDepends {
            authority_id,
            authority_hash,
        } => (2, format!("{}:{}", authority_id, authority_hash)),
        EdgeType::MutationCommitment {
            harness_id,
            risk_class,
        } => (3, format!("{}:{:?}", harness_id, risk_class)),
        EdgeType::CostDisplacement { cost, displaced_to } => (4, format!("{}:{}", cost, displaced_to)),
    }
}

fn sort_edges(dag: &mut GovernedDag) {
    let mut edges: Vec<DagEdge> = dag.edges().to_vec();
    edges.sort_by(|a, b| {
        a.step
            .timeline
            .cmp(&b.step.timeline)
            .then(a.step.seq.cmp(&b.step.seq))
            .then(a.from.cmp(&b.from))
            .then(a.to.cmp(&b.to))
            .then_with(|| {
                let (ak, asub) = edge_type_key(&a.edge_type);
                let (bk, bsub) = edge_type_key(&b.edge_type);
                ak.cmp(&bk).then(asub.cmp(&bsub))
            })
            .then(a.scope.cmp(&b.scope))
            .then(a.witness_ref.cmp(&b.witness_ref))
    });

    // Replace edges via a stable reconstruction.
    // GovernedDag keeps edges private; rebuild by clearing and re-adding.
    // (This stays inside admit_dag so the invariant is controlled centrally.)
    let mut rebuilt = GovernedDag::new();
    for (_, node) in dag.nodes() {
        rebuilt.ensure_node(node.clone());
    }
    for edge in edges {
        rebuilt.add_edge(edge);
    }
    *dag = rebuilt;
}

pub fn minimal_mutation_edge(
    from: NodeId,
    to: NodeId,
    harness_id: impl Into<String>,
    risk_class: MutationRiskClass,
    scope: crate::edge::ScopeTag,
    step: TimelineStep,
    witness_ref: Option<NodeId>,
) -> Result<DagEdge, String> {
    DagEdge::mutation(
        from,
        to,
        harness_id.into(),
        risk_class,
        scope,
        step,
        witness_ref,
    )
}

pub fn to_canonical_cbor_value(value: &Value) -> Result<Vec<u8>, String> {
    admit_core::encode_canonical_value(value)
        .map_err(|err| format!("canonical cbor encode: {}", err.0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::edge::ScopeTag;
    use crate::node::NodeKind;

    fn node(kind: NodeKind) -> DagNode {
        DagNode::new(kind, ScopeTag::new("scope:core.pure"), vec![], vec![]).unwrap()
    }

    #[test]
    fn collector_sorts_edges_deterministically() {
        let mut t = DagTraceCollector::new("test");
        let a = node(NodeKind::RulesetSource {
            content_hash: "a".into(),
        });
        let b = node(NodeKind::RulesetSource {
            content_hash: "b".into(),
        });
        let id_a = a.id;
        let id_b = b.id;
        t.ensure_node(a);
        t.ensure_node(b);

        let scope = ScopeTag::new("scope:core.pure");
        // Add out of order steps
        t.add_edge(DagEdge::build_depends(
            id_b,
            id_a,
            scope.clone(),
            TimelineStep::new("t", 2),
        ));
        t.add_edge(DagEdge::build_depends(
            id_a,
            id_b,
            scope,
            TimelineStep::new("t", 1),
        ));

        let bytes_a = t.encode_canonical_cbor().unwrap();
        let bytes_b = t.encode_canonical_cbor().unwrap();
        assert_eq!(bytes_a, bytes_b, "encoding must be stable");
    }
}

