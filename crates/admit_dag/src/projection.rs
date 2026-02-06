use crate::graph::GovernedDag;

pub trait ProjectionStore {
    fn project_dag_trace(
        &self,
        trace_sha256: &str,
        trace_cbor: &[u8],
        dag: &GovernedDag,
    ) -> Result<(), String>;
}

