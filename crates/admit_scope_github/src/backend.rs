//! Scope governance and configuration for GitHub ceremony observation.

/// Scope ID for GitHub PR/review/check ceremony facts.
pub const GITHUB_CEREMONY_SCOPE_ID: &str = "github.ceremony";

/// Schema ID for GitHub ceremony facts bundle.
pub const GITHUB_CEREMONY_SCHEMA_ID: &str = "facts-bundle/github.ceremony@1";

/// Check if a given scope ID matches GitHub ceremony.
pub fn is_github_ceremony_scope(scope_id: &str) -> bool {
    scope_id == GITHUB_CEREMONY_SCOPE_ID
}
