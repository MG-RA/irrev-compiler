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
pub mod calc_commands;

// Re-export all public types
pub use types::*;

// Ledger operations
pub use ledger::{
    append_event, append_checked_event, append_executed_event,
    read_cost_declared_event, read_checked_event,
    default_ledger_path, read_file_bytes,
};

// Artifact operations
pub use artifact::{list_artifacts, read_artifact_projection, default_artifacts_dir};

// Registry operations
pub use registry::{registry_init, registry_build};

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
pub use ingest_dir::{ingest_dir, IngestDirOutput, IngestedChunk, IngestedFile};
