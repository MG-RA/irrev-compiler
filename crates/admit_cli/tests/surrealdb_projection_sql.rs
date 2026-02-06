use admit_dag::{DagEdge, DagNode, NodeKind, ScopeTag, TimelineStep};
use admit_surrealdb::{SurrealCliConfig, SurrealCliProjectionStore};

#[test]
fn projection_store_builds_config_defaults() {
    let cfg = SurrealCliConfig::default();
    assert_eq!(cfg.endpoint, "ws://localhost:8000");
    assert_eq!(cfg.surreal_bin, "surreal");
}

#[test]
fn trace_can_be_projected_without_panic_when_not_executed() {
    // This test does not execute surrealdb. It only checks that the crate can be used
    // and that identities/structs are constructible.
    let mut dag = admit_dag::GovernedDag::new();
    let node_a = DagNode::new(
        NodeKind::RulesetSource {
            content_hash: "a".to_string(),
        },
        ScopeTag::new("scope:core.pure"),
        vec![],
        vec![],
    )
    .unwrap();
    let node_b = DagNode::new(
        NodeKind::RulesetSource {
            content_hash: "b".to_string(),
        },
        ScopeTag::new("scope:core.pure"),
        vec![],
        vec![],
    )
    .unwrap();
    dag.ensure_node(node_a.clone());
    dag.ensure_node(node_b.clone());
    dag.add_edge(DagEdge::build_depends(
        node_a.id,
        node_b.id,
        ScopeTag::new("scope:core.pure"),
        TimelineStep::new("t", 1),
    ));

    let store = SurrealCliProjectionStore::new(SurrealCliConfig::default());
    // We intentionally don't call `project_dag_trace` because it would require a running DB.
    let _ = store.config();
    assert_eq!(dag.node_count(), 2);
    assert_eq!(dag.edge_count(), 1);
}

