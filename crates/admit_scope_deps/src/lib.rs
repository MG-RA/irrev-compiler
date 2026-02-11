//! Dependency manifest scope.
//!
//! Exposes deterministic facts for dependency manifests and lockfiles.

pub mod backend;
pub mod provider_impl;

pub use backend::{is_deps_manifest_scope, DEPS_MANIFEST_SCHEMA_ID, DEPS_MANIFEST_SCOPE_ID};
pub use provider_impl::DepsManifestProvider;
