//! Scope governance and configuration for Git working-tree observation.

/// Scope ID for Git working-tree state facts.
pub const GIT_WORKING_TREE_SCOPE_ID: &str = "git.working_tree";

/// Schema ID for the Git working-tree facts bundle.
pub const GIT_WORKING_TREE_SCHEMA_ID: &str = "facts-bundle/git.working_tree@1";

/// Check if a given scope ID matches the Git working-tree scope.
pub fn is_git_working_tree_scope(scope_id: &str) -> bool {
    scope_id == GIT_WORKING_TREE_SCOPE_ID
}
