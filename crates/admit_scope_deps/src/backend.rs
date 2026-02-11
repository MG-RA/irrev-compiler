//! Scope governance and configuration for dependency manifest observation.

/// Scope ID for dependency manifests.
pub const DEPS_MANIFEST_SCOPE_ID: &str = "deps.manifest";

/// Schema ID for dependency-manifest facts bundle.
pub const DEPS_MANIFEST_SCHEMA_ID: &str = "facts-bundle/deps.manifest@1";

/// Check if a given scope ID matches dependency manifests.
pub fn is_deps_manifest_scope(scope_id: &str) -> bool {
    scope_id == DEPS_MANIFEST_SCOPE_ID
}
