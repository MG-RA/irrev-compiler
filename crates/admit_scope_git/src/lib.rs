//! Git working-tree scope.
//!
//! Exposes deterministic, read-only facts about repository state transitions
//! using `git status --porcelain=v2`.

pub mod backend;
pub mod provider_impl;

pub use backend::{
    is_git_working_tree_scope, GIT_WORKING_TREE_SCHEMA_ID, GIT_WORKING_TREE_SCOPE_ID,
};
pub use provider_impl::GitWorkingTreeProvider;
