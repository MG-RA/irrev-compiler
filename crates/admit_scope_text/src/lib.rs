//! Text metrics scope.
//!
//! Emits deterministic file-level metrics facts that can be consumed by
//! rulesets (e.g., max LOC, line length, file size, TODO governance).

pub mod backend;
pub mod provider_impl;

pub use backend::{is_text_metrics_scope, TEXT_METRICS_SCHEMA_ID, TEXT_METRICS_SCOPE_ID};
pub use provider_impl::TextMetricsProvider;
