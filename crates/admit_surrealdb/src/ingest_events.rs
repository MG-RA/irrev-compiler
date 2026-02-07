use serde::{Deserialize, Serialize};

/// Queryable ingestion events (non-authoritative projection of ledger events).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestEventRow {
    pub event_id: String,
    pub event_type: String,
    pub timestamp: String,
    pub ingest_run_id: String,
    pub status: Option<String>,
    pub duration_ms: Option<u64>,
    pub error: Option<String>,
    pub root: Option<String>,
    pub config_sha256: Option<String>,
    pub coverage_sha256: Option<String>,
    pub ingest_run_sha256: Option<String>,
    pub snapshot_sha256: Option<String>,
    pub parse_sha256: Option<String>,
    pub files: Option<u64>,
    pub chunks: Option<u64>,
    pub total_bytes: Option<u64>,
}
