//! Projection Store Trait
//!
//! This module provides the `ProjectionStoreOps` trait that abstracts projection storage
//! operations. This enables:
//!
//! - **Multiple backends**: SurrealDB CLI, NullStore (no-op), future JsonlStore/SqliteStore
//! - **Testability**: Mock stores for unit testing without database
//! - **Graceful degradation**: Commands succeed without SurrealDB via NullStore
//! - **Run-scoped operations**: All projections stamped with `projection_run_id`
//!
//! The trait is separate from the DAG-level `ProjectionStore` trait in `admit_dag`
//! (which only handles trace projection) to provide richer operations for the
//! full projection lifecycle.

use std::collections::BTreeSet;
use std::path::Path;

use admit_dag::GovernedDag;

use crate::projection_run::{PhaseResult, ProjectionRun, RunStatus};
use crate::{
    DocChunkEmbeddingRow, DocEmbeddingRow, DocTitleEmbeddingRow, EmbedRunRow, FunctionArtifactRow,
    IngestEventRow, IngestRunRow, ProjectionEventRow, QueryArtifactRow,
    UnresolvedLinkSuggestionRow,
};

/// Result type for projection operations
pub type ProjectionResult<T> = Result<T, ProjectionError>;

/// Error type for projection operations
#[derive(Debug, Clone)]
pub struct ProjectionError {
    pub message: String,
    pub phase: Option<String>,
    pub batch_index: Option<usize>,
    pub recoverable: bool,
}

impl ProjectionError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            phase: None,
            batch_index: None,
            recoverable: false,
        }
    }

    pub fn with_phase(mut self, phase: impl Into<String>) -> Self {
        self.phase = Some(phase.into());
        self
    }

    pub fn with_batch(mut self, index: usize) -> Self {
        self.batch_index = Some(index);
        self
    }

    pub fn recoverable(mut self) -> Self {
        self.recoverable = true;
        self
    }
}

impl std::fmt::Display for ProjectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)?;
        if let Some(phase) = &self.phase {
            write!(f, " (phase: {})", phase)?;
        }
        if let Some(batch) = self.batch_index {
            write!(f, " (batch: {})", batch)?;
        }
        Ok(())
    }
}

impl std::error::Error for ProjectionError {}

impl From<String> for ProjectionError {
    fn from(s: String) -> Self {
        Self::new(s)
    }
}

/// Trait for projection storage backends
///
/// This trait abstracts all projection operations, enabling multiple backend
/// implementations (SurrealDB, NullStore, future alternatives).
///
/// All batch operations accept an optional `run_id` for lineage tracking.
/// When provided, projected records are stamped with `projection_run_id`.
pub trait ProjectionStoreOps {
    // =========================================================================
    // Connection and readiness
    // =========================================================================

    /// Check if the store is ready to accept operations
    fn is_ready(&self) -> ProjectionResult<bool>;

    /// Get a human-readable name for this store (for logging)
    fn store_name(&self) -> &str;

    // =========================================================================
    // Run lifecycle
    // =========================================================================

    /// Begin a new projection run, returns the run_id
    ///
    /// This creates a record of the run with status "running".
    fn begin_run(&self, run: &ProjectionRun) -> ProjectionResult<String>;

    /// End a projection run with final status and phase results
    fn end_run(
        &self,
        run_id: &str,
        status: RunStatus,
        finished_at: &str,
        phase_results: &std::collections::BTreeMap<String, PhaseResult>,
    ) -> ProjectionResult<()>;

    /// Get the latest projection run for a given trace
    fn get_latest_run(&self, trace_sha256: &str) -> ProjectionResult<Option<serde_json::Value>>;

    // =========================================================================
    // Schema management
    // =========================================================================

    /// Ensure all required schemas exist (idempotent)
    fn ensure_schemas(&self) -> ProjectionResult<()>;

    // =========================================================================
    // Observability events
    // =========================================================================

    /// Project observability events (queryable view).
    ///
    /// These events are a non-authoritative projection for debugging / UI.
    fn project_projection_events(&self, rows: &[ProjectionEventRow]) -> ProjectionResult<()>;

    /// Project ingestion run record (queryable view).
    fn project_ingest_run(&self, run: &IngestRunRow) -> ProjectionResult<()>;

    /// Project ingestion events (queryable view).
    fn project_ingest_events(&self, rows: &[IngestEventRow]) -> ProjectionResult<()>;

    // =========================================================================
    // DAG trace projection
    // =========================================================================

    /// Project a DAG trace (nodes and edges)
    ///
    /// This is the core projection that stores the execution trace.
    fn project_dag_trace(
        &self,
        trace_sha256: &str,
        trace_cbor: &[u8],
        dag: &GovernedDag,
        run_id: Option<&str>,
    ) -> ProjectionResult<PhaseResult>;

    // =========================================================================
    // Document projections
    // =========================================================================

    /// Project doc files from DAG artifacts
    fn project_doc_files(
        &self,
        dag: &GovernedDag,
        artifacts_root: &Path,
        run_id: Option<&str>,
    ) -> ProjectionResult<PhaseResult>;

    /// Project doc chunks from DAG artifacts
    fn project_doc_chunks(
        &self,
        dag: &GovernedDag,
        artifacts_root: &Path,
        doc_file_prefixes: &[&str],
        run_id: Option<&str>,
    ) -> ProjectionResult<PhaseResult>;

    /// Project chunk representations from DAG artifacts
    fn project_chunk_repr(
        &self,
        dag: &GovernedDag,
        artifacts_root: &Path,
        run_id: Option<&str>,
    ) -> ProjectionResult<PhaseResult>;

    /// Project Obsidian-vault links from DAG artifacts.
    fn project_obsidian_vault_links(
        &self,
        dag: &GovernedDag,
        artifacts_root: &Path,
        obsidian_vault_prefixes: &[&str],
        doc_filter: Option<&BTreeSet<String>>,
        run_id: Option<&str>,
    ) -> ProjectionResult<PhaseResult>;

    /// Backward-compatible alias.
    fn project_vault_links(
        &self,
        dag: &GovernedDag,
        artifacts_root: &Path,
        obsidian_vault_prefixes: &[&str],
        doc_filter: Option<&BTreeSet<String>>,
        run_id: Option<&str>,
    ) -> ProjectionResult<PhaseResult> {
        self.project_obsidian_vault_links(
            dag,
            artifacts_root,
            obsidian_vault_prefixes,
            doc_filter,
            run_id,
        )
    }

    // =========================================================================
    // Embedding projections
    // =========================================================================

    /// Project document chunk and document embeddings
    fn project_embeddings(
        &self,
        chunk_rows: &[DocChunkEmbeddingRow],
        doc_rows: &[DocEmbeddingRow],
        run_id: Option<&str>,
    ) -> ProjectionResult<()>;

    /// Project an embedding run record
    fn project_embed_run(&self, run: &EmbedRunRow) -> ProjectionResult<()>;

    /// Project document title embeddings
    fn project_title_embeddings(
        &self,
        rows: &[DocTitleEmbeddingRow],
        run_id: Option<&str>,
    ) -> ProjectionResult<()>;

    /// Project unresolved link suggestions
    fn project_unresolved_suggestions(
        &self,
        run_id: &str,
        rows: &[UnresolvedLinkSuggestionRow],
    ) -> ProjectionResult<()>;

    // =========================================================================
    // Court artifacts (stored definitions)
    // =========================================================================

    /// Project stored SurrealQL queries as governed artifacts (queryable view).
    fn project_query_artifacts(&self, rows: &[QueryArtifactRow]) -> ProjectionResult<()>;

    /// Project stored function definitions as governed artifacts (queryable view).
    fn project_function_artifacts(&self, rows: &[FunctionArtifactRow]) -> ProjectionResult<()>;

    // =========================================================================
    // Query operations
    // =========================================================================

    /// Select doc files matching the given prefixes
    fn select_doc_files(&self, prefixes: &[&str]) -> ProjectionResult<Vec<(String, String)>>;

    /// Select unresolved links matching filters
    fn select_unresolved_links(
        &self,
        prefixes: &[&str],
        kinds: &[&str],
        limit: usize,
        projection_run_id: Option<&str>,
    ) -> ProjectionResult<Vec<crate::UnresolvedLinkRow>>;

    /// Search doc title embeddings by vector similarity
    fn search_title_embeddings(
        &self,
        obsidian_vault_prefix: &str,
        model: &str,
        dim_target: u32,
        query_embedding: &[f32],
        limit: usize,
    ) -> ProjectionResult<Vec<(String, f64)>>;
}

/// No-op projection store for when SurrealDB is disabled
///
/// All operations succeed immediately without doing anything.
/// This enables graceful degradation when projection is off.
#[derive(Debug, Clone, Default)]
pub struct NullStore;

impl NullStore {
    pub fn new() -> Self {
        Self
    }
}

impl ProjectionStoreOps for NullStore {
    fn is_ready(&self) -> ProjectionResult<bool> {
        Ok(true) // Always "ready" to do nothing
    }

    fn store_name(&self) -> &str {
        "null"
    }

    fn begin_run(&self, run: &ProjectionRun) -> ProjectionResult<String> {
        Ok(run.run_id.clone())
    }

    fn end_run(
        &self,
        _run_id: &str,
        _status: RunStatus,
        _finished_at: &str,
        _phase_results: &std::collections::BTreeMap<String, PhaseResult>,
    ) -> ProjectionResult<()> {
        Ok(())
    }

    fn get_latest_run(&self, _trace_sha256: &str) -> ProjectionResult<Option<serde_json::Value>> {
        Ok(None)
    }

    fn ensure_schemas(&self) -> ProjectionResult<()> {
        Ok(())
    }

    fn project_projection_events(&self, _rows: &[ProjectionEventRow]) -> ProjectionResult<()> {
        Ok(())
    }

    fn project_ingest_run(&self, _run: &IngestRunRow) -> ProjectionResult<()> {
        Ok(())
    }

    fn project_ingest_events(&self, _rows: &[IngestEventRow]) -> ProjectionResult<()> {
        Ok(())
    }

    fn project_dag_trace(
        &self,
        _trace_sha256: &str,
        _trace_cbor: &[u8],
        _dag: &GovernedDag,
        _run_id: Option<&str>,
    ) -> ProjectionResult<PhaseResult> {
        Ok(PhaseResult::success("dag_trace".to_string(), 0, 0))
    }

    fn project_doc_files(
        &self,
        _dag: &GovernedDag,
        _artifacts_root: &Path,
        _run_id: Option<&str>,
    ) -> ProjectionResult<PhaseResult> {
        Ok(PhaseResult::success("doc_files".to_string(), 0, 0))
    }

    fn project_doc_chunks(
        &self,
        _dag: &GovernedDag,
        _artifacts_root: &Path,
        _doc_file_prefixes: &[&str],
        _run_id: Option<&str>,
    ) -> ProjectionResult<PhaseResult> {
        Ok(PhaseResult::success("doc_chunks".to_string(), 0, 0))
    }

    fn project_chunk_repr(
        &self,
        _dag: &GovernedDag,
        _artifacts_root: &Path,
        _run_id: Option<&str>,
    ) -> ProjectionResult<PhaseResult> {
        Ok(PhaseResult::success("chunk_repr".to_string(), 0, 0))
    }

    fn project_obsidian_vault_links(
        &self,
        _dag: &GovernedDag,
        _artifacts_root: &Path,
        _obsidian_vault_prefixes: &[&str],
        _doc_filter: Option<&BTreeSet<String>>,
        _run_id: Option<&str>,
    ) -> ProjectionResult<PhaseResult> {
        Ok(PhaseResult::success(
            "obsidian_vault_links".to_string(),
            0,
            0,
        ))
    }

    fn project_embeddings(
        &self,
        _chunk_rows: &[DocChunkEmbeddingRow],
        _doc_rows: &[DocEmbeddingRow],
        _run_id: Option<&str>,
    ) -> ProjectionResult<()> {
        Ok(())
    }

    fn project_embed_run(&self, _run: &EmbedRunRow) -> ProjectionResult<()> {
        Ok(())
    }

    fn project_title_embeddings(
        &self,
        _rows: &[DocTitleEmbeddingRow],
        _run_id: Option<&str>,
    ) -> ProjectionResult<()> {
        Ok(())
    }

    fn project_unresolved_suggestions(
        &self,
        _run_id: &str,
        _rows: &[UnresolvedLinkSuggestionRow],
    ) -> ProjectionResult<()> {
        Ok(())
    }

    fn project_query_artifacts(&self, _rows: &[QueryArtifactRow]) -> ProjectionResult<()> {
        Ok(())
    }

    fn project_function_artifacts(&self, _rows: &[FunctionArtifactRow]) -> ProjectionResult<()> {
        Ok(())
    }

    fn select_doc_files(&self, _prefixes: &[&str]) -> ProjectionResult<Vec<(String, String)>> {
        Ok(Vec::new())
    }

    fn select_unresolved_links(
        &self,
        _prefixes: &[&str],
        _kinds: &[&str],
        _limit: usize,
        _projection_run_id: Option<&str>,
    ) -> ProjectionResult<Vec<crate::UnresolvedLinkRow>> {
        Ok(Vec::new())
    }

    fn search_title_embeddings(
        &self,
        _obsidian_vault_prefix: &str,
        _model: &str,
        _dim_target: u32,
        _query_embedding: &[f32],
        _limit: usize,
    ) -> ProjectionResult<Vec<(String, f64)>> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_null_store_is_ready() {
        let store = NullStore::new();
        assert!(store.is_ready().unwrap());
        assert_eq!(store.store_name(), "null");
    }

    #[test]
    fn test_null_store_begin_run() {
        use crate::projection_run::ProjectionRun;

        let store = NullStore::new();
        let run = ProjectionRun::new(
            "abc123".to_string(),
            "0.1.0".to_string(),
            "config_hash".to_string(),
            vec!["dag_trace".to_string()],
            None,
        );

        let run_id = store.begin_run(&run).unwrap();
        assert_eq!(run_id, run.run_id);
    }

    #[test]
    fn test_null_store_end_run() {
        let store = NullStore::new();
        let phase_results = std::collections::BTreeMap::new();

        store
            .end_run(
                "run_123",
                RunStatus::Complete,
                "2026-02-05T12:00:00Z",
                &phase_results,
            )
            .unwrap();
    }

    #[test]
    fn test_null_store_get_latest_run() {
        let store = NullStore::new();
        let result = store.get_latest_run("trace_sha").unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_null_store_queries_return_empty() {
        let store = NullStore::new();

        assert!(store
            .select_doc_files(&["irrev-vault/"])
            .unwrap()
            .is_empty());
        assert!(store
            .select_unresolved_links(&["irrev-vault/"], &["missing"], 100, None)
            .unwrap()
            .is_empty());
        assert!(store
            .search_title_embeddings("irrev-vault/", "model", 384, &[0.1, 0.2], 10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn test_projection_error_display() {
        let err = ProjectionError::new("connection failed")
            .with_phase("dag_trace")
            .with_batch(5);

        let display = format!("{}", err);
        assert!(display.contains("connection failed"));
        assert!(display.contains("dag_trace"));
        assert!(display.contains("5"));
    }

    #[test]
    fn test_projection_error_from_string() {
        let err: ProjectionError = "test error".to_string().into();
        assert_eq!(err.message, "test error");
        assert!(!err.recoverable);
    }
}
