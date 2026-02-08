//! Scope governance and configuration.
//!
//! This module provides scope identification and configuration for the ingestion scope.

/// Scope ID for directory ingestion.
pub const INGEST_DIR_SCOPE_ID: &str = "ingest.dir";

/// Scope phase identifier.
pub const INGEST_DIR_PHASE: &str = "P1";

/// Check if a given scope ID matches the ingestion scope.
pub fn is_ingest_dir_scope(scope_id: &str) -> bool {
    scope_id == INGEST_DIR_SCOPE_ID
}
