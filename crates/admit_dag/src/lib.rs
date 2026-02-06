pub mod authority;
pub mod edge;
pub mod graph;
pub mod node;
pub mod projection;
pub mod scope_enforcement;
pub mod trace;
pub mod validation;

// Re-export main types for convenience
pub use authority::{check_authority_reachability, AuthorityViolation};
pub use edge::{DagEdge, EdgeType, MutationRiskClass, ScopeTag, TimelineStep};
pub use graph::GovernedDag;
pub use node::{DagNode, NodeCategory, NodeId, NodeIdPayload, NodeKind};
pub use projection::ProjectionStore;
pub use scope_enforcement::{
    default_scope_rules, EdgeTypeMatch, EdgeTypeTag, ScopeBoundaryRule, ScopeEnforcer,
    ScopeViolation, Severity, ViolationType,
};
pub use trace::{DagTraceCollector, NoopTracer, Tracer};
pub use validation::{detect_cycles_in_build_order, validate_dag, ValidationError};
