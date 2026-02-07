use serde::{Deserialize, Serialize};

/// Queryable ingestion run record (non-authoritative projection).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestRunRow {
    pub ingest_run_id: String,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub status: String,
    pub root: String,
    pub config_sha256: String,
    pub coverage_sha256: Option<String>,
    pub ingest_run_sha256: Option<String>,
    pub snapshot_sha256: Option<String>,
    pub parse_sha256: Option<String>,
    pub files: Option<u64>,
    pub chunks: Option<u64>,
    pub total_bytes: Option<u64>,
}
