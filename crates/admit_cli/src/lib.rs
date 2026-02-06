mod internal;
mod types;
mod ledger;
mod artifact;
mod registry;
mod witness;
mod verify;
mod plan;
mod scope_validation;
mod scope_commands;
mod ingest_dir;
mod ingest_cache;
mod ingest_protocol;
mod court;
mod vault_prefix;
mod ollama_defaults;
pub mod calc_commands;

// Re-export all public types
pub use types::*;

// Ledger operations
pub use ledger::{
    append_event, append_checked_event, append_executed_event, append_projection_event,
    read_cost_declared_event, read_checked_event,
    append_ingest_event, build_ingest_event,
    append_court_event, build_court_event,
    build_projection_event, default_ledger_path,
    read_file_bytes,
};

// Artifact operations
pub use artifact::{list_artifacts, read_artifact_projection, default_artifacts_dir, store_value_artifact};

// Registry operations
pub use registry::{registry_init, registry_build, load_meta_registry};

// Witness & cost lifecycle
pub use witness::{declare_cost, verify_witness, check_cost_declared, execute_checked};

// Ledger verification
pub use verify::verify_ledger;

// Plan operations
pub use plan::{create_plan, append_plan_created_event, render_plan_text, export_plan_markdown};

// Scope validation and commands
pub use scope_validation::{ScopeValidator, ScopeValidationLevel, parse_scope_spec};
pub use scope_commands::{
    scope_add, scope_verify, scope_list, scope_show,
    ScopeAddArgs, ScopeVerifyArgs, ScopeListArgs, ScopeShowArgs,
};

// Directory ingestion (snapshot + parse)
pub use ingest_dir::{
    ingest_dir, ingest_dir_with_cache, IngestDirOutput, IngestIncremental, IngestWarning,
    IngestedChunk, IngestedFile,
};

// Ingestion protocol (run events + coverage artifact)
pub use ingest_protocol::{
    ingest_dir_protocol, ingest_dir_protocol_with_cache, IngestDirProtocolOutput,
};

// Court artifacts (governed definitions)
pub use court::{register_query_artifact, register_function_artifact};

// Vault prefix helpers
pub use vault_prefix::{effective_vault_prefixes_for_doc_paths, select_vault_prefix_for_doc_path};
pub use ollama_defaults::default_prefixes_for_model as default_ollama_prefixes_for_model;
