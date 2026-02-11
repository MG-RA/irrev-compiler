//! Scope governance and configuration for text metrics.

/// Scope ID for text metrics fact extraction.
pub const TEXT_METRICS_SCOPE_ID: &str = "text.metrics";

/// Schema ID for text metrics facts bundle.
pub const TEXT_METRICS_SCHEMA_ID: &str = "facts-bundle/text.metrics@1";

/// Check if a given scope ID matches the text metrics scope.
pub fn is_text_metrics_scope(scope_id: &str) -> bool {
    scope_id == TEXT_METRICS_SCOPE_ID
}
