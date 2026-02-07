use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Represents a single projection execution with full lineage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectionRun {
    /// Unique identifier for this run (UUID or timestamp-based)
    pub run_id: String,

    /// Optional ingest run id that this projection is derived from.
    ///
    /// This is required to preserve lineage: ingest -> projection -> views.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingest_run_id: Option<String>,

    /// Source trace identity (SHA-256 of trace CBOR)
    pub trace_sha256: String,

    /// When the run started
    pub started_at: String, // ISO 8601 UTC timestamp

    /// When the run finished (None if still running)
    pub finished_at: Option<String>, // ISO 8601 UTC timestamp

    /// Projector crate version + git sha
    pub projector_version: String,

    /// Hash of the resolved ProjectionConfig
    pub config_hash: String,

    /// List of enabled phase names
    pub phases_enabled: Vec<String>,

    /// Overall run status
    pub status: RunStatus,

    /// Results for each phase
    pub phase_results: BTreeMap<String, PhaseResult>,
}

impl ProjectionRun {
    /// Create a new projection run in "Running" state
    pub fn new(
        trace_sha256: String,
        projector_version: String,
        config_hash: String,
        phases_enabled: Vec<String>,
        ingest_run_id: Option<String>,
    ) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        let run_id = Self::generate_run_id(&now);

        Self {
            run_id,
            ingest_run_id,
            trace_sha256,
            started_at: now,
            finished_at: None,
            projector_version,
            config_hash,
            phases_enabled,
            status: RunStatus::Running,
            phase_results: BTreeMap::new(),
        }
    }

    /// Generate a run ID from timestamp
    fn generate_run_id(timestamp: &str) -> String {
        // Format: YYYYMMDD-HHMMSS-<hash>
        let formatted = chrono::DateTime::parse_from_rfc3339(timestamp)
            .ok()
            .map(|dt| dt.format("%Y%m%d-%H%M%S").to_string())
            .unwrap_or_else(|| "unknown".to_string());

        // Add short hash for uniqueness
        let mut hasher = Sha256::new();
        hasher.update(timestamp.as_bytes());
        let hash = format!("{:x}", hasher.finalize());

        format!("{}-{}", formatted, &hash[..8])
    }

    /// Mark run as complete and compute final status
    pub fn complete(&mut self) {
        self.finished_at = Some(chrono::Utc::now().to_rfc3339());
        self.status = self.compute_status();
    }

    /// Compute run status from phase results
    fn compute_status(&self) -> RunStatus {
        if self.phase_results.is_empty() {
            return RunStatus::Running;
        }

        let total_phases = self.phases_enabled.len();
        let completed_phases = self
            .phase_results
            .values()
            .filter(|r| r.status == PhaseStatus::Complete)
            .count();
        let failed_phases = self
            .phase_results
            .values()
            .filter(|r| r.status == PhaseStatus::Failed)
            .count();
        let partial_phases = self
            .phase_results
            .values()
            .filter(|r| r.status == PhaseStatus::Partial)
            .count();

        if failed_phases == total_phases {
            RunStatus::Failed
        } else if completed_phases == total_phases {
            RunStatus::Complete
        } else if completed_phases > 0 || failed_phases > 0 || partial_phases > 0 {
            RunStatus::Partial
        } else {
            RunStatus::Running
        }
    }

    /// Add a phase result
    pub fn add_phase_result(&mut self, phase: String, result: PhaseResult) {
        self.phase_results.insert(phase, result);
    }

    /// Get duration in milliseconds (if finished)
    pub fn duration_ms(&self) -> Option<u64> {
        let finished = self.finished_at.as_ref()?;
        let start = chrono::DateTime::parse_from_rfc3339(&self.started_at).ok()?;
        let end = chrono::DateTime::parse_from_rfc3339(finished).ok()?;

        let duration = end.signed_duration_since(start);
        Some(duration.num_milliseconds() as u64)
    }
}

/// Status of a projection run
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// Run is in progress
    Running,

    /// Some phases succeeded, some failed
    Partial,

    /// All enabled phases succeeded
    Complete,

    /// All phases failed
    Failed,

    /// Newer run completed (used for cleanup)
    Superseded,
}

impl std::fmt::Display for RunStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunStatus::Running => write!(f, "running"),
            RunStatus::Partial => write!(f, "partial"),
            RunStatus::Complete => write!(f, "complete"),
            RunStatus::Failed => write!(f, "failed"),
            RunStatus::Superseded => write!(f, "superseded"),
        }
    }
}

/// Result of a single projection phase
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PhaseResult {
    /// Phase name
    pub phase: String,

    /// Phase completion status
    pub status: PhaseStatus,

    /// Total number of batches attempted
    pub total_batches: usize,

    /// Number of batches that succeeded
    pub successful_batches: usize,

    /// Failed batches with details
    pub failed_batches: Vec<FailedBatch>,

    /// Phase duration in milliseconds
    pub duration_ms: u64,

    /// Records processed in this phase
    #[serde(default)]
    pub records_processed: u64,

    /// Batches executed (redundant with total_batches, kept for metrics clarity)
    #[serde(default)]
    pub batches_executed: u64,

    /// Bytes written to the projection store
    #[serde(default)]
    pub bytes_written: u64,

    /// Files read (if applicable)
    #[serde(default)]
    pub files_read: Option<u64>,

    /// Estimated parse time in milliseconds (if applicable)
    #[serde(default)]
    pub parse_time_ms: Option<u64>,

    /// Time spent writing to the projection store in milliseconds (if applicable)
    #[serde(default)]
    pub db_write_time_ms: Option<u64>,

    /// Per-batch error messages (if any)
    #[serde(default)]
    pub errors: Vec<String>,

    /// Error message (if phase-level failure)
    pub error: Option<String>,
}

impl PhaseResult {
    /// Create a successful phase result
    pub fn success(phase: String, total_batches: usize, duration_ms: u64) -> Self {
        Self {
            phase,
            status: PhaseStatus::Complete,
            total_batches,
            successful_batches: total_batches,
            failed_batches: Vec::new(),
            duration_ms,
            records_processed: 0,
            batches_executed: total_batches as u64,
            bytes_written: 0,
            files_read: None,
            parse_time_ms: None,
            db_write_time_ms: None,
            errors: Vec::new(),
            error: None,
        }
    }

    /// Create a failed phase result
    pub fn failed(phase: String, error: String, duration_ms: u64) -> Self {
        Self {
            phase,
            status: PhaseStatus::Failed,
            total_batches: 0,
            successful_batches: 0,
            failed_batches: Vec::new(),
            duration_ms,
            records_processed: 0,
            batches_executed: 0,
            bytes_written: 0,
            files_read: None,
            parse_time_ms: None,
            db_write_time_ms: None,
            errors: vec![error.clone()],
            error: Some(error),
        }
    }

    /// Create a partial phase result (some batches failed)
    pub fn partial(
        phase: String,
        total_batches: usize,
        successful_batches: usize,
        failed_batches: Vec<FailedBatch>,
        duration_ms: u64,
    ) -> Self {
        let errors = failed_batches
            .iter()
            .map(|b| format!("batch {}: {}", b.batch_index, b.error))
            .collect();
        Self {
            phase,
            status: PhaseStatus::Partial,
            total_batches,
            successful_batches,
            failed_batches,
            duration_ms,
            records_processed: 0,
            batches_executed: total_batches as u64,
            bytes_written: 0,
            files_read: None,
            parse_time_ms: None,
            db_write_time_ms: None,
            errors,
            error: None,
        }
    }
}

/// Status of a projection phase
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseStatus {
    /// Phase completed successfully
    Complete,

    /// Phase partially succeeded (some batches failed)
    Partial,

    /// Phase failed completely
    Failed,

    /// Phase is still running
    Running,
}

/// Information about a failed batch
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedBatch {
    /// Stable hash of batch contents (hash of item_ids + phase + run_id)
    pub batch_hash: String,

    /// Batch index (for display purposes only, not stable)
    pub batch_index: usize,

    /// Stable item identifiers (e.g., node IDs, doc paths)
    pub item_ids: Vec<String>,

    /// Error message
    pub error: String,

    /// Number of retry attempts made
    pub attempt_count: usize,
}

impl FailedBatch {
    /// Create a new failed batch
    pub fn new(
        phase: &str,
        run_id: &str,
        batch_index: usize,
        item_ids: Vec<String>,
        error: String,
        attempt_count: usize,
    ) -> Self {
        let batch_hash = Self::compute_hash(phase, run_id, &item_ids);

        Self {
            batch_hash,
            batch_index,
            item_ids,
            error,
            attempt_count,
        }
    }

    /// Compute stable batch hash
    fn compute_hash(phase: &str, run_id: &str, item_ids: &[String]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(phase.as_bytes());
        hasher.update(run_id.as_bytes());
        let mut ids: Vec<&String> = item_ids.iter().collect();
        ids.sort();
        for id in ids {
            hasher.update(id.as_bytes());
        }
        format!("{:x}", hasher.finalize())
    }
}

/// Helper to get current projector version
pub fn get_projector_version() -> String {
    // Format: crate_version-git_sha (if available)
    let version = env!("CARGO_PKG_VERSION");

    // Try to get git sha from environment (set by build script or CI)
    if let Ok(git_sha) = std::env::var("GIT_SHA") {
        format!("{}-{}", version, &git_sha[..8])
    } else {
        version.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_projection_run_lifecycle() {
        let mut run = ProjectionRun::new(
            "abc123".to_string(),
            "0.1.0".to_string(),
            "config_hash_123".to_string(),
            vec!["dag_trace".to_string(), "doc_chunks".to_string()],
            None,
        );

        assert_eq!(run.status, RunStatus::Running);
        assert!(run.finished_at.is_none());
        assert_eq!(run.phases_enabled.len(), 2);

        // Add phase results
        run.add_phase_result(
            "dag_trace".to_string(),
            PhaseResult::success("dag_trace".to_string(), 5, 100),
        );
        run.add_phase_result(
            "doc_chunks".to_string(),
            PhaseResult::success("doc_chunks".to_string(), 3, 50),
        );

        run.complete();

        assert_eq!(run.status, RunStatus::Complete);
        assert!(run.finished_at.is_some());
        assert!(run.duration_ms().is_some());
    }

    #[test]
    fn test_run_status_computation() {
        let mut run = ProjectionRun::new(
            "abc123".to_string(),
            "0.1.0".to_string(),
            "config_hash_123".to_string(),
            vec!["phase1".to_string(), "phase2".to_string()],
            None,
        );

        // Partial: one success, one failure
        run.add_phase_result(
            "phase1".to_string(),
            PhaseResult::success("phase1".to_string(), 5, 100),
        );
        run.add_phase_result(
            "phase2".to_string(),
            PhaseResult::failed("phase2".to_string(), "test error".to_string(), 50),
        );

        assert_eq!(run.compute_status(), RunStatus::Partial);

        // All failed
        let mut run2 = ProjectionRun::new(
            "abc123".to_string(),
            "0.1.0".to_string(),
            "config_hash_123".to_string(),
            vec!["phase1".to_string()],
            None,
        );
        run2.add_phase_result(
            "phase1".to_string(),
            PhaseResult::failed("phase1".to_string(), "test error".to_string(), 50),
        );

        assert_eq!(run2.compute_status(), RunStatus::Failed);
    }

    #[test]
    fn test_failed_batch_hash_stability() {
        let item_ids = vec!["id1".to_string(), "id2".to_string(), "id3".to_string()];

        let batch1 = FailedBatch::new(
            "test_phase",
            "run_123",
            0,
            item_ids.clone(),
            "error".to_string(),
            1,
        );

        let batch2 = FailedBatch::new(
            "test_phase",
            "run_123",
            999, // Different index
            item_ids.clone(),
            "different error".to_string(),
            2,
        );

        // Hash should be the same (ignores index and error)
        assert_eq!(batch1.batch_hash, batch2.batch_hash);

        // Different item_ids should produce different hash
        let batch3 = FailedBatch::new(
            "test_phase",
            "run_123",
            0,
            vec!["different_id".to_string()],
            "error".to_string(),
            1,
        );

        assert_ne!(batch1.batch_hash, batch3.batch_hash);
    }

    #[test]
    fn test_phase_result_constructors() {
        let success = PhaseResult::success("test".to_string(), 10, 100);
        assert_eq!(success.status, PhaseStatus::Complete);
        assert_eq!(success.successful_batches, 10);
        assert!(success.error.is_none());

        let failed = PhaseResult::failed("test".to_string(), "boom".to_string(), 50);
        assert_eq!(failed.status, PhaseStatus::Failed);
        assert!(failed.error.is_some());

        let partial = PhaseResult::partial("test".to_string(), 10, 8, vec![], 100);
        assert_eq!(partial.status, PhaseStatus::Partial);
        assert_eq!(partial.successful_batches, 8);
    }

    #[test]
    fn test_run_id_generation() {
        let timestamp = "2026-02-05T10:30:00Z";
        let run_id = ProjectionRun::generate_run_id(timestamp);

        // Should start with formatted date
        assert!(run_id.starts_with("20260205-103000-"));

        // Should have hash suffix
        assert!(run_id.len() > 20);
    }

    #[test]
    fn test_projector_version() {
        let version = get_projector_version();
        // Should at least contain the cargo version
        assert!(!version.is_empty());
    }

    #[test]
    fn test_run_duration_calculation() {
        let mut run = ProjectionRun::new(
            "abc123".to_string(),
            "0.1.0".to_string(),
            "config_hash_123".to_string(),
            vec!["test".to_string()],
            None,
        );

        // Not finished yet
        assert!(run.duration_ms().is_none());

        // Sleep a bit and complete
        std::thread::sleep(std::time::Duration::from_millis(10));
        run.complete();

        // Should have duration
        let duration = run.duration_ms();
        assert!(duration.is_some());
        assert!(duration.unwrap() >= 10);
    }
}
