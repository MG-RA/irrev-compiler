mod artifact;
pub mod calc_commands;
mod engine;
mod ingest_cache;
mod ingest_dir;
mod ingest_protocol;
mod internal;
mod ledger;
mod ollama_defaults;
mod plan;
mod project_init;
mod registry;
mod rust_ir_lint;
mod scope_commands;
mod scope_enablement;
#[path = "obsidian_adapter.rs"]
pub mod scope_obsidian;
mod scope_validation;
mod status_summary;
mod types;
mod vault_prefix;
mod vault_schema_lint;
mod verify;
mod witness;

// Re-export all public types
pub use types::*;

// Ledger operations
pub use ledger::{
    append_checked_event, append_engine_event, append_event, append_executed_event,
    append_ingest_event, append_projection_event, build_engine_event, build_ingest_event,
    build_projection_event, default_ledger_path, read_checked_event, read_cost_declared_event,
    read_file_bytes,
};

// Artifact operations
pub use artifact::{
    default_artifacts_dir, list_artifacts, read_artifact_projection, store_value_artifact,
};

// Registry operations
pub use registry::{load_meta_registry, registry_build, registry_init};

// Witness & cost lifecycle
pub use witness::{check_cost_declared, declare_cost, execute_checked, verify_witness};

// Ledger verification
pub use verify::verify_ledger;

// Plan operations
pub use plan::{
    append_plan_created_event, create_plan, diagnostic_prompts, export_plan_markdown,
    parse_plan_answers_markdown, render_plan_prompt_template, render_plan_text,
};
pub use project_init::{init_project, InitProjectInput, InitProjectOutput};

// Scope validation and commands
pub use scope_commands::{
    scope_add, scope_list, scope_show, scope_verify, ScopeAddArgs, ScopeListArgs, ScopeShowArgs,
    ScopeVerifyArgs,
};
pub use scope_enablement::{
    operation_is_enabled, resolve_scope_enablement, scope_is_enabled, scope_operation_human_hint,
    KnownScope, ScopeEnablement, ScopeOperation, KNOWN_SCOPES,
};
pub use scope_validation::{parse_scope_spec, ScopeValidationLevel, ScopeValidator};
pub use status_summary::{summarize_ledger, StatusEventSummary, StatusSummary};

// Directory ingestion (snapshot + parse)
pub use ingest_dir::{
    ingest_dir, ingest_dir_with_cache, IngestDirOutput, IngestIncremental, IngestWarning,
    IngestedChunk, IngestedFile,
};

// Ingestion protocol (run events + coverage artifact)
pub use ingest_protocol::{
    ingest_dir_protocol, ingest_dir_protocol_with_cache, IngestDirProtocolOutput,
};

// Engine artifacts (governed definitions)
pub use engine::{register_function_artifact, register_query_artifact};
pub use rust_ir_lint::{
    append_rust_ir_lint_event, run_rust_ir_lint, RustIrLintInput, RustIrLintRunOutput,
};
pub use vault_schema_lint::{
    run_vault_schema_lint, VaultSchemaFinding, VaultSchemaLintInput, VaultSchemaLintOutput,
};

// Vault prefix helpers
pub use ollama_defaults::default_prefixes_for_model as default_ollama_prefixes_for_model;
pub use vault_prefix::{effective_vault_prefixes_for_doc_paths, select_vault_prefix_for_doc_path};
