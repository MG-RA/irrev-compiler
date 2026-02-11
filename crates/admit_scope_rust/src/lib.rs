//! Rust structural analysis scope — extracts governed facts from Rust source.
//!
//! Contract: all `rust/*` rule_ids are non-normative observations (Severity::Info).
//! Normativity happens in separate constraint packs that consume these facts.

pub mod backend;
pub mod extractor;
pub mod file_walker;
pub mod provider_impl;

pub use backend::RUST_SCOPE_ID;
pub use extractor::extract_facts;
pub use file_walker::{load_rust_sources, RustSourceFile};
pub use provider_impl::RustStructureProvider;
