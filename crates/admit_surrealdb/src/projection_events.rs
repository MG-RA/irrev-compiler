use serde::{Deserialize, Serialize};

/// A single projection observability event (queryable view).
///
/// This is a *projection* of runtime/ledger facts into SurrealDB for debugging and UI.
/// It must not be treated as an authority source of truth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectionEventRow {
    /// Content-addressed event identity (typically a SHA-256 hex digest).
    pub event_id: String,

    /// Event type string (e.g. "projection.run.started").
    pub event_type: String,

    /// ISO 8601 UTC timestamp (e.g. RFC 3339).
    pub timestamp: String,

    /// Projection run id that this event belongs to.
    pub projection_run_id: String,

    /// Optional phase name (e.g. "doc_chunks").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,

    /// Optional status (e.g. "complete", "partial", "failed").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    /// Optional duration in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,

    /// Optional error string.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Optional trace sha256 for run boundary events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_sha256: Option<String>,

    /// Optional config hash for run boundary events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,

    /// Optional projector version for run boundary events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projector_version: Option<String>,

    /// Optional structured metadata (for warnings/admin events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}
