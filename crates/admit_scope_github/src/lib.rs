//! GitHub ceremony scope.
//!
//! Exposes witnessable PR/review/checks facts via `gh` CLI.

pub mod backend;
pub mod provider_impl;

pub use backend::{is_github_ceremony_scope, GITHUB_CEREMONY_SCHEMA_ID, GITHUB_CEREMONY_SCOPE_ID};
pub use provider_impl::GithubCeremonyProvider;
