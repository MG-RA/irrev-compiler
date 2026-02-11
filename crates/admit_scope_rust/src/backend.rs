//! Scope governance and configuration for Rust structural analysis.

/// Scope ID for Rust structural fact extraction.
pub const RUST_SCOPE_ID: &str = "rust.structure";

/// Schema ID for the structural facts bundle.
pub const RUST_STRUCTURE_SCHEMA_ID: &str = "facts-bundle/rust.structure@1";

/// Check if a given scope ID matches the Rust structure scope.
pub fn is_rust_structure_scope(scope_id: &str) -> bool {
    scope_id == RUST_SCOPE_ID
}
