use std::path::{Path, PathBuf};

use clap::{Parser, Subcommand};
use sha2::Digest;

use admit_dag::ProjectionStore;
use admit_dag::{DagEdge, DagNode, DagTraceCollector, NodeKind, ScopeTag, Tracer};
use admit_embed::{OllamaEmbedConfig, OllamaEmbedder};
use admit_surrealdb::{
    projection_config::ProjectionConfig, DocChunkEmbeddingRow, DocEmbeddingRow, EmbedRunRow,
    FunctionArtifactRow, IngestEventRow, IngestRunRow, ProjectionEventRow, ProjectionStoreOps,
    QueryArtifactRow, SurrealCliConfig, SurrealCliProjectionStore,
};

use admit_cli::scope_obsidian as obsidian_adapter;
use admit_cli::{
    append_checked_event, append_court_event, append_event, append_executed_event,
    append_ingest_event, append_plan_created_event, append_projection_event,
    append_rust_ir_lint_event, build_court_event, build_projection_event, check_cost_declared,
    create_plan, declare_cost, default_artifacts_dir, default_ledger_path, execute_checked,
    export_plan_markdown, ingest_dir_protocol_with_cache, init_project, list_artifacts,
    load_meta_registry, parse_plan_answers_markdown, read_artifact_projection, read_file_bytes,
    register_function_artifact, register_query_artifact, registry_build, registry_init,
    render_plan_prompt_template, render_plan_text, resolve_scope_enablement, run_rust_ir_lint,
    scope_add, scope_list, scope_operation_human_hint, scope_show, scope_verify,
    store_value_artifact, summarize_ledger, verify_ledger, verify_witness, ArtifactInput,
    DeclareCostInput, InitProjectInput, MetaRegistryV0, PlanNewInput, RustIrLintInput,
    ScopeAddArgs as ScopeAddArgsLib, ScopeGateMode, ScopeListArgs as ScopeListArgsLib,
    ScopeOperation, ScopeShowArgs as ScopeShowArgsLib, ScopeVerifyArgs as ScopeVerifyArgsLib,
    VerifyWitnessInput,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
enum SurrealDbMode {
    Off,
    Auto,
    On,
}

#[derive(Debug, Clone)]
struct ProjectionSummary {
    run_id: String,
    status: admit_surrealdb::projection_run::RunStatus,
    total_phases: usize,
    successful_phases: usize,
}

#[derive(Debug)]
struct ProjectionCoordinator {
    mode: SurrealDbMode,
    store: Option<SurrealCliProjectionStore>,
    disabled_reason: Option<String>,
    touched: bool,
    last_summary: Option<ProjectionSummary>,
}

impl ProjectionCoordinator {
    fn off() -> Self {
        Self {
            mode: SurrealDbMode::Off,
            store: None,
            disabled_reason: Some("off".to_string()),
            touched: false,
            last_summary: None,
        }
    }

    fn active(mode: SurrealDbMode, store: SurrealCliProjectionStore) -> Self {
        Self {
            mode,
            store: Some(store),
            disabled_reason: None,
            touched: false,
            last_summary: None,
        }
    }

    fn disabled(mode: SurrealDbMode, reason: String) -> Self {
        Self {
            mode,
            store: None,
            disabled_reason: Some(reason),
            touched: false,
            last_summary: None,
        }
    }

    fn is_active(&self) -> bool {
        self.store.is_some() && self.disabled_reason.is_none()
    }

    fn store(&self) -> Option<&SurrealCliProjectionStore> {
        if self.is_active() {
            self.store.as_ref()
        } else {
            None
        }
    }

    fn touch(&mut self) {
        self.touched = true;
    }

    fn disable(&mut self, reason: String) {
        if self.disabled_reason.is_none() {
            self.disabled_reason = Some(reason);
        }
    }

    fn handle_error(&mut self, err: String) -> Result<(), String> {
        match self.mode {
            SurrealDbMode::On => Err(err),
            SurrealDbMode::Auto | SurrealDbMode::Off => {
                if self.disabled_reason.is_none() {
                    eprintln!("Warning: SurrealDB projection disabled: {}", err);
                }
                self.disable(err);
                Ok(())
            }
        }
    }

    fn with_store<T, F>(&mut self, context: &str, op: F) -> Result<Option<T>, String>
    where
        F: FnOnce(&SurrealCliProjectionStore) -> Result<T, String>,
    {
        self.touch();
        let Some(store) = self.store() else {
            return Ok(None);
        };
        match op(store) {
            Ok(value) => Ok(Some(value)),
            Err(err) => {
                self.handle_error(format!("{}: {}", context, err))?;
                Ok(None)
            }
        }
    }

    fn require_store(&self, purpose: &str) -> Result<&SurrealCliProjectionStore, String> {
        if let Some(store) = self.store.as_ref() {
            if self.disabled_reason.is_none() {
                return Ok(store);
            }
        }
        let reason = self
            .disabled_reason
            .as_deref()
            .unwrap_or("surrealdb projection not configured");
        Err(format!(
            "{} requires surrealdb projection (use --surrealdb-mode=on and set namespace/database): {}",
            purpose, reason
        ))
    }

    fn record_summary(&mut self, summary: ProjectionSummary) {
        self.last_summary = Some(summary);
    }

    fn print_summary(&self, json_mode: bool) {
        if !self.touched {
            return;
        }
        let line = if self.mode == SurrealDbMode::Off {
            "Projection: off".to_string()
        } else if let Some(reason) = self.disabled_reason.as_ref() {
            format!("Projection: skipped ({})", reason)
        } else if let Some(summary) = self.last_summary.as_ref() {
            let status = match summary.status {
                admit_surrealdb::projection_run::RunStatus::Complete => "complete",
                admit_surrealdb::projection_run::RunStatus::Partial => "partial",
                admit_surrealdb::projection_run::RunStatus::Failed => "failed",
                admit_surrealdb::projection_run::RunStatus::Running => "running",
                admit_surrealdb::projection_run::RunStatus::Superseded => "superseded",
            };
            if summary.total_phases == 0 {
                format!("Projection: {} (run_id={})", status, summary.run_id)
            } else {
                format!(
                    "Projection: {} ({}/{} phases; run_id={})",
                    status, summary.successful_phases, summary.total_phases, summary.run_id
                )
            }
        } else {
            "Projection: complete".to_string()
        };
        if json_mode {
            eprintln!("{}", line);
        } else {
            println!("{}", line);
        }
    }
}

#[derive(Parser)]
#[command(
    name = "admit-cli",
    version,
    about = "Admissibility compiler CLI utilities"
)]
struct Cli {
    /// Emit a governed DAG trace (canonical CBOR). If PATH is omitted, writes to out/dag-trace.cbor
    #[arg(
        long,
        value_name = "PATH",
        num_args = 0..=1,
        default_missing_value = "out/dag-trace.cbor"
    )]
    dag_trace: Option<PathBuf>,

    /// Project DAG traces to SurrealDB (uses `surreal sql` CLI) (deprecated: use --surrealdb-mode=on)
    #[arg(long, conflicts_with = "surrealdb_mode")]
    surrealdb_project: bool,

    /// SurrealDB projection mode: off|auto|on (default: off). In auto mode, projection activates only when namespace+database are configured and the endpoint is ready.
    #[arg(long, value_enum, default_value_t = SurrealDbMode::Off)]
    surrealdb_mode: SurrealDbMode,

    /// SurrealDB endpoint (passed to `surreal sql --endpoint`)
    #[arg(long, default_value = "ws://localhost:8000", value_name = "URL")]
    surrealdb_endpoint: String,

    /// SurrealDB namespace (passed to `surreal sql --namespace`)
    #[arg(long, value_name = "NS")]
    surrealdb_namespace: Option<String>,

    /// SurrealDB database (passed to `surreal sql --database`)
    #[arg(long, value_name = "DB")]
    surrealdb_database: Option<String>,

    /// SurrealDB username (passed to `surreal sql --username`)
    #[arg(long)]
    surrealdb_username: Option<String>,

    /// SurrealDB password (passed to `surreal sql --password`)
    #[arg(long)]
    surrealdb_password: Option<String>,

    /// SurrealDB token (passed to `surreal sql --token`)
    #[arg(long)]
    surrealdb_token: Option<String>,

    /// SurrealDB auth level (passed to `surreal sql --auth-level`)
    #[arg(long)]
    surrealdb_auth_level: Option<String>,

    /// SurrealDB CLI binary name/path (default: surreal)
    #[arg(long, default_value = "surreal")]
    surrealdb_bin: String,

    /// Projection phases to enable (comma-separated: dag_trace,doc_files,doc_chunks,chunk_repr,headings,obsidian_vault_links,stats,embeddings; `vault_links` alias supported)
    #[arg(long, value_delimiter = ',')]
    projection_enabled: Option<Vec<String>>,

    /// Override batch size for a projection phase (format: phase:size, e.g., nodes:100)
    #[arg(long, value_name = "PHASE:SIZE")]
    projection_batch_size: Option<Vec<String>>,

    /// Max SurrealQL bytes per `surreal sql` invocation (default: 1000000)
    #[arg(long, value_name = "BYTES")]
    projection_max_sql_bytes: Option<usize>,

    /// Force projection even if an identical complete run already exists
    #[arg(long)]
    projection_force: bool,

    /// Projection failure handling mode: fail-fast|warn-and-continue|silent-ignore (default: warn-and-continue)
    #[arg(long, value_enum)]
    projection_failure_mode: Option<admit_surrealdb::projection_config::FailureHandling>,

    /// Obsidian vault prefix for link resolution (repeatable, e.g., irrev-vault/)
    #[arg(long, value_name = "PREFIX")]
    vault_prefix: Option<Vec<String>>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Init(InitArgs),
    Status(StatusArgs),
    DeclareCost(DeclareCostArgs),
    WitnessVerify(WitnessVerifyArgs),
    Check(CheckArgs),
    Execute(ExecuteArgs),
    VerifyLedger(VerifyLedgerArgs),
    BundleVerify(BundleVerifyArgs),
    Observe(ObserveArgs),
    ListArtifacts(ListArtifactsArgs),
    ShowArtifact(ShowArtifactArgs),
    Registry(RegistryArgs),
    Plan(PlanArgs),
    Calc(CalcArgs),
    Ingest(IngestArgs),
    Projection(ProjectionArgs),
    Court(CourtArgs),
    Lint(LintArgs),
    Git(GitArgs),
}

#[derive(Parser)]
struct InitArgs {
    /// Root directory to initialize (default: current directory)
    #[arg(value_name = "PATH", default_value = ".")]
    path: PathBuf,

    /// Output JSON instead of key=value lines
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct StatusArgs {
    /// Ledger path (default: out/ledger.jsonl)
    #[arg(long)]
    ledger: Option<PathBuf>,

    /// Output JSON instead of key=value lines
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct DeclareCostArgs {
    /// Path to a JSON witness projection (requires --witness-sha256)
    #[arg(long, value_name = "PATH", conflicts_with = "witness_cbor")]
    witness_json: Option<PathBuf>,
    /// Path to canonical witness CBOR bytes
    #[arg(long, value_name = "PATH", conflicts_with = "witness_json")]
    witness_cbor: Option<PathBuf>,
    /// Expected SHA256 hash of canonical CBOR witness bytes
    #[arg(long)]
    witness_sha256: Option<String>,
    /// Witness schema id (default: admissibility-witness/1)
    #[arg(long)]
    witness_schema_id: Option<String>,
    /// Compiler build identifier (version or commit)
    #[arg(long)]
    compiler_build_id: Option<String>,
    /// Snapshot hash to bind with the declaration
    #[arg(long)]
    snapshot_hash: Option<String>,
    /// Snapshot JSON path (required; or set SNAPSHOT_PATH)
    #[arg(long)]
    snapshot: Option<PathBuf>,
    /// Program bundle JSON path (optional; stores provenance)
    #[arg(long)]
    program_bundle: Option<PathBuf>,
    /// Program module id (required for CBOR-only input)
    #[arg(long)]
    program_module: Option<String>,
    /// Program scope id (required for CBOR-only input)
    #[arg(long)]
    program_scope: Option<String>,
    /// Timestamp string for the event (default: current UTC ISO-8601)
    #[arg(long)]
    timestamp: Option<String>,
    /// Path to meta registry JSON (or set ADMIT_META_REGISTRY)
    #[arg(long, value_name = "PATH")]
    meta_registry: Option<PathBuf>,
    /// Ledger path (default: out/ledger.jsonl)
    #[arg(long)]
    ledger: Option<PathBuf>,
    /// Artifact store root (default: out/artifacts)
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,
    /// Output JSON instead of key=value lines
    #[arg(long)]
    json: bool,

    /// Do not append to ledger
    #[arg(long)]
    dry_run: bool,
}

#[derive(Parser)]
struct WitnessVerifyArgs {
    /// Path to a JSON witness projection
    #[arg(long, value_name = "PATH", conflicts_with = "witness_cbor")]
    witness_json: Option<PathBuf>,
    /// Path to canonical witness CBOR bytes
    #[arg(long, value_name = "PATH", conflicts_with = "witness_json")]
    witness_cbor: Option<PathBuf>,
    /// Expected SHA256 hash of canonical CBOR witness bytes
    #[arg(long)]
    expected_sha256: Option<String>,
    /// Write canonical CBOR bytes to a file
    #[arg(long, value_name = "PATH")]
    out_cbor: Option<PathBuf>,
}

#[derive(Parser)]
struct CheckArgs {
    /// Cost declaration event id to check
    #[arg(long)]
    event_id: String,
    /// Facts bundle JSON path (optional; records bundle hash in the check event)
    #[arg(long)]
    facts_bundle: Option<PathBuf>,
    /// Compiler build identifier (version or commit)
    #[arg(long)]
    compiler_build_id: Option<String>,
    /// Timestamp string for the event (default: current UTC ISO-8601)
    #[arg(long)]
    timestamp: Option<String>,
    /// Path to meta registry JSON (or set ADMIT_META_REGISTRY)
    #[arg(long, value_name = "PATH")]
    meta_registry: Option<PathBuf>,
    /// Ledger path (default: out/ledger.jsonl)
    #[arg(long)]
    ledger: Option<PathBuf>,
    /// Artifact store root (default: out/artifacts)
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,
    /// Output JSON instead of key=value lines
    #[arg(long)]
    json: bool,
    /// Do not append to ledger
    #[arg(long)]
    dry_run: bool,
    /// Scope gate mode (warn|error) when registry is present
    #[arg(long, default_value = "warn", value_name = "MODE")]
    scope_gate: String,
}

#[derive(Parser)]
struct ExecuteArgs {
    /// Admissibility checked event id to execute
    #[arg(long)]
    checked_event_id: String,
    /// Compiler build identifier (version or commit)
    #[arg(long)]
    compiler_build_id: Option<String>,
    /// Timestamp string for the event (default: current UTC ISO-8601)
    #[arg(long)]
    timestamp: Option<String>,
    /// Path to meta registry JSON (or set ADMIT_META_REGISTRY)
    #[arg(long, value_name = "PATH")]
    meta_registry: Option<PathBuf>,
    /// Ledger path (default: out/ledger.jsonl)
    #[arg(long)]
    ledger: Option<PathBuf>,
    /// Artifact store root (default: out/artifacts)
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,
    /// Output JSON instead of key=value lines
    #[arg(long)]
    json: bool,
    /// Do not append to ledger
    #[arg(long)]
    dry_run: bool,
    /// Scope gate mode (warn|error) when registry is present
    #[arg(long, default_value = "warn", value_name = "MODE")]
    scope_gate: String,
}

#[derive(Parser)]
struct VerifyLedgerArgs {
    /// Ledger path (default: out/ledger.jsonl)
    #[arg(long)]
    ledger: Option<PathBuf>,
    /// Artifact store root (default: out/artifacts)
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,
    /// Output JSON instead of plain text
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct BundleVerifyArgs {
    /// Program bundle JSON path
    #[arg(long, value_name = "PATH")]
    bundle: PathBuf,
    /// Output JSON instead of key=value lines
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct ObserveArgs {
    /// Input markdown/text files (repeatable)
    #[arg(long, value_name = "PATH", required = true)]
    input: Vec<PathBuf>,
    /// Regex pattern to count (repeatable)
    #[arg(long, value_name = "REGEX", required = true)]
    pattern: Vec<String>,
    /// Difference name for each pattern (repeatable)
    #[arg(long, value_name = "DIFF", required = true)]
    diff: Vec<String>,
    /// Unit for each pattern (optional; length 1 applies to all patterns)
    #[arg(long, value_name = "UNIT")]
    unit: Vec<String>,
    /// Case-insensitive regex matching
    #[arg(long)]
    case_insensitive: bool,
    /// Timestamp string to store in the bundle (optional)
    #[arg(long)]
    generated_at: Option<String>,
    /// Source root for relative paths (default: current directory)
    #[arg(long, value_name = "PATH")]
    source_root: Option<PathBuf>,
    /// Output path for facts bundle JSON (default: out/facts-bundle.json)
    #[arg(long, value_name = "PATH")]
    out: Option<PathBuf>,
    /// Output JSON instead of key=value lines
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct ListArtifactsArgs {
    /// Artifact store root (default: out/artifacts)
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,
    /// Output JSON instead of key=value lines
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct ShowArtifactArgs {
    /// Artifact kind (e.g., witness)
    #[arg(long)]
    kind: String,
    /// Artifact sha256 (hex)
    #[arg(long)]
    sha256: String,
    /// Artifact store root (default: out/artifacts)
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,
    /// Output JSON instead of key=value lines
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct PlanArgs {
    #[command(subcommand)]
    command: PlanCommands,
}

#[derive(Parser)]
struct RegistryArgs {
    #[command(subcommand)]
    command: RegistryCommands,
}

#[derive(Parser)]
struct IngestArgs {
    #[command(subcommand)]
    command: IngestCommands,
}

#[derive(Parser)]
struct ProjectionArgs {
    #[command(subcommand)]
    command: ProjectionCommands,
}

#[derive(Parser)]
struct CourtArgs {
    #[command(subcommand)]
    command: CourtCommands,
}

#[derive(Parser)]
struct GitArgs {
    #[command(subcommand)]
    command: GitCommands,
}

#[derive(Parser)]
struct LintArgs {
    #[command(subcommand)]
    command: LintCommands,
}

#[derive(Subcommand)]
enum LintCommands {
    Rust(LintRustArgs),
}

#[derive(Parser)]
struct LintRustArgs {
    /// Root path to lint (default: current directory)
    #[arg(value_name = "PATH", default_value = ".")]
    path: PathBuf,

    /// Timestamp string for the event (default: current UTC ISO-8601)
    #[arg(long = "created-at", alias = "timestamp")]
    created_at: Option<String>,

    /// Compiler/tool version identifier
    #[arg(long)]
    tool_version: Option<String>,

    /// Path to meta registry JSON (or set ADMIT_META_REGISTRY)
    #[arg(long, value_name = "PATH")]
    meta_registry: Option<PathBuf>,

    /// Ledger path (default: out/ledger.jsonl)
    #[arg(long)]
    ledger: Option<PathBuf>,

    /// Do not append to ledger
    #[arg(long)]
    dry_run: bool,

    /// Artifact store root (default: out/artifacts)
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,

    /// Output JSON instead of key=value lines
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum GitCommands {
    Snapshot(GitSnapshotArgs),
    Diff(GitDiffArgs),
    Provenance(GitProvenanceArgs),
    VerifyCommitPlan(GitVerifyCommitPlanArgs),
    InstallPlanHook(GitInstallPlanHookArgs),
}

#[derive(Parser)]
struct GitSnapshotArgs {
    /// Repository root path (default: current directory)
    #[arg(long, value_name = "PATH", default_value = ".")]
    repo: PathBuf,

    /// Git ref to snapshot (default: HEAD)
    #[arg(long, value_name = "REF", default_value = "HEAD")]
    head: String,

    /// Include submodule commit states
    #[arg(long)]
    include_submodules: bool,

    /// Include .gitignore-filtered working tree manifest hash
    #[arg(long)]
    include_working_tree_manifest: bool,

    /// Witness created_at timestamp (default: current UTC ISO-8601)
    #[arg(long = "created-at", alias = "timestamp")]
    created_at: Option<String>,

    /// Optional metadata source reference
    #[arg(long)]
    source_ref: Option<String>,

    /// Optional metadata purpose
    #[arg(long)]
    purpose: Option<String>,

    /// Artifact store root (default: out/artifacts)
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,

    /// Write witness JSON projection to PATH
    #[arg(long, value_name = "PATH")]
    out: Option<PathBuf>,

    /// Do not store artifact in the artifact store
    #[arg(long)]
    no_store: bool,

    /// Output JSON summary
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct GitDiffArgs {
    /// Repository root path (default: current directory)
    #[arg(long, value_name = "PATH", default_value = ".")]
    repo: PathBuf,

    /// Base commit/ref for diff
    #[arg(long, value_name = "REF")]
    base: String,

    /// Head commit/ref for diff (default: HEAD)
    #[arg(long, value_name = "REF", default_value = "HEAD")]
    head: String,

    /// Witness created_at timestamp (default: current UTC ISO-8601)
    #[arg(long = "created-at", alias = "timestamp")]
    created_at: Option<String>,

    /// Optional metadata source reference
    #[arg(long)]
    source_ref: Option<String>,

    /// Optional metadata purpose
    #[arg(long)]
    purpose: Option<String>,

    /// Artifact store root (default: out/artifacts)
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,

    /// Write witness JSON projection to PATH
    #[arg(long, value_name = "PATH")]
    out: Option<PathBuf>,

    /// Do not store artifact in the artifact store
    #[arg(long)]
    no_store: bool,

    /// Output JSON summary
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct GitProvenanceArgs {
    /// Repository root path (default: current directory)
    #[arg(long, value_name = "PATH", default_value = ".")]
    repo: PathBuf,

    /// Logical repository identity (default: repo:<dir-name>)
    #[arg(long)]
    repository_id: Option<String>,

    /// Optional base commit/ref for provenance range
    #[arg(long, value_name = "REF")]
    base: Option<String>,

    /// Head commit/ref for provenance (default: HEAD)
    #[arg(long, value_name = "REF", default_value = "HEAD")]
    head: String,

    /// JSON file with `GitArtifactBinding[]`
    #[arg(long, value_name = "PATH")]
    artifact_bindings_file: Option<PathBuf>,

    /// JSON file with `GitRegistryBinding[]`
    #[arg(long, value_name = "PATH")]
    registry_bindings_file: Option<PathBuf>,

    /// JSON file with `GitSignatureAttestation[]`
    #[arg(long, value_name = "PATH")]
    signature_attestations_file: Option<PathBuf>,

    /// Auto-populate signature attestations from git verify-commit over the selected range
    #[arg(long)]
    signatures_from_git: bool,

    /// Witness created_at timestamp (default: current UTC ISO-8601)
    #[arg(long = "created-at", alias = "timestamp")]
    created_at: Option<String>,

    /// Optional metadata source reference
    #[arg(long)]
    source_ref: Option<String>,

    /// Optional metadata purpose
    #[arg(long)]
    purpose: Option<String>,

    /// Artifact store root (default: out/artifacts)
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,

    /// Write witness JSON projection to PATH
    #[arg(long, value_name = "PATH")]
    out: Option<PathBuf>,

    /// Do not store artifact in the artifact store
    #[arg(long)]
    no_store: bool,

    /// Output JSON summary
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct GitVerifyCommitPlanArgs {
    /// Repository root path (default: current directory)
    #[arg(long, value_name = "PATH", default_value = ".")]
    repo: PathBuf,

    /// Commit message file to validate (used by commit-msg hook)
    #[arg(long, value_name = "PATH", conflicts_with = "commit")]
    message_file: Option<PathBuf>,

    /// Existing commit/ref whose message will be validated (default: HEAD)
    #[arg(
        long,
        value_name = "REF",
        default_value = "HEAD",
        conflicts_with = "message_file"
    )]
    commit: String,

    /// Artifact store root (default: out/artifacts). Relative paths are resolved from repo root.
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,

    /// Accept a plan hash in the commit message without requiring a local plan_witness artifact.
    #[arg(long)]
    allow_missing_artifact: bool,

    /// Output JSON summary
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct GitInstallPlanHookArgs {
    /// Repository root path (default: current directory)
    #[arg(long, value_name = "PATH", default_value = ".")]
    repo: PathBuf,

    /// Artifact store root for hook validation (default: out/artifacts). Relative paths are resolved from repo root.
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,

    /// Accept a plan hash in commit message even if matching artifact is not found.
    #[arg(long)]
    allow_missing_artifact: bool,

    /// Binary name/path for the CLI command in the hook (default: admit-cli)
    #[arg(long, default_value = "admit-cli")]
    admit_cli_bin: String,

    /// Overwrite an existing commit-msg hook.
    #[arg(long)]
    force: bool,
}

#[derive(Subcommand)]
enum CourtCommands {
    Query(CourtQueryArgs),
    Function(CourtFunctionArgs),
}

#[derive(Parser)]
struct CourtQueryArgs {
    #[command(subcommand)]
    command: CourtQueryCommands,
}

#[derive(Subcommand)]
enum CourtQueryCommands {
    Add(CourtQueryAddArgs),
}

#[derive(Parser)]
struct CourtFunctionArgs {
    #[command(subcommand)]
    command: CourtFunctionCommands,
}

#[derive(Subcommand)]
enum CourtFunctionCommands {
    Add(CourtFunctionAddArgs),
}

#[derive(Parser)]
struct CourtQueryAddArgs {
    /// Stable query name (human readable)
    #[arg(long)]
    name: String,

    /// Query language identifier (default: surql)
    #[arg(long, default_value = "surql")]
    lang: String,

    /// Path to a file containing the query source (UTF-8)
    #[arg(long, value_name = "PATH")]
    file: PathBuf,

    /// Optional tags (repeatable)
    #[arg(long = "tag")]
    tags: Vec<String>,

    /// Path to meta registry JSON (or set ADMIT_META_REGISTRY)
    #[arg(long, value_name = "PATH")]
    meta_registry: Option<PathBuf>,

    /// Ledger path (default: out/ledger.jsonl)
    #[arg(long)]
    ledger: Option<PathBuf>,

    /// Do not append to ledger
    #[arg(long)]
    no_ledger: bool,

    /// Artifact store root (default: out/artifacts)
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,

    /// Output JSON instead of key=value lines
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct CourtFunctionAddArgs {
    /// Stable function name (human readable)
    #[arg(long)]
    name: String,

    /// Function language identifier (default: surql)
    #[arg(long, default_value = "surql")]
    lang: String,

    /// Path to a file containing the function source (UTF-8)
    #[arg(long, value_name = "PATH")]
    file: PathBuf,

    /// Optional tags (repeatable)
    #[arg(long = "tag")]
    tags: Vec<String>,

    /// Path to meta registry JSON (or set ADMIT_META_REGISTRY)
    #[arg(long, value_name = "PATH")]
    meta_registry: Option<PathBuf>,

    /// Ledger path (default: out/ledger.jsonl)
    #[arg(long)]
    ledger: Option<PathBuf>,

    /// Do not append to ledger
    #[arg(long)]
    no_ledger: bool,

    /// Artifact store root (default: out/artifacts)
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,

    /// Output JSON instead of key=value lines
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum IngestCommands {
    Dir(IngestDirArgs),
}

#[derive(Subcommand)]
enum ProjectionCommands {
    Vacuum(ProjectionVacuumArgs),
    Retry(ProjectionRetryArgs),
}

#[derive(Parser)]
struct IngestDirArgs {
    /// Root directory to ingest (default: current directory)
    #[arg(value_name = "PATH", default_value = ".")]
    path: PathBuf,
    /// Artifact store root (default: out/artifacts)
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,
    /// Path to incremental ingest cache (enables incremental mode)
    #[arg(long, value_name = "PATH")]
    incremental_cache: Option<PathBuf>,
    /// Output JSON instead of key=value lines
    #[arg(long)]
    json: bool,

    /// Run projection twice and report performance delta
    #[arg(long)]
    bench: bool,

    /// Ledger path for ingest/projection events (default: out/ledger.jsonl)
    #[arg(long)]
    ledger: Option<PathBuf>,

    /// Do not append ingest/projection events to the ledger
    #[arg(long)]
    no_ledger: bool,

    /// Compute and project Ollama embeddings for doc chunks (requires SurrealDB projection enabled)
    #[arg(long)]
    ollama_embed: bool,

    /// Ollama HTTP endpoint (default: env ADMIT_OLLAMA_ENDPOINT or http://127.0.0.1:11434)
    #[arg(long, value_name = "URL")]
    ollama_endpoint: Option<String>,

    /// Ollama embedding model name (default: env ADMIT_OLLAMA_EMBED_MODEL or qwen3-embedding:0.6b)
    #[arg(long, value_name = "MODEL")]
    ollama_model: Option<String>,

    /// Max chars per chunk sent to the embedder (default: 8000)
    #[arg(long, default_value_t = 8000)]
    ollama_max_chars: usize,

    /// Embed batch size (default: 16)
    #[arg(long, default_value_t = 16)]
    ollama_batch_size: usize,

    /// HTTP timeout for Ollama requests (milliseconds) (default: 60000)
    #[arg(long, default_value_t = 60_000)]
    ollama_timeout_ms: u64,

    /// Limit number of chunks to embed (0 = no limit)
    #[arg(long, default_value_t = 0)]
    ollama_limit: usize,

    /// Prefix to add to embedded documents (recommended by nomic-embed-text-v2-*): e.g. "search_document: "
    #[arg(long)]
    ollama_doc_prefix: Option<String>,

    /// Prefix to add to embedded queries (recommended by nomic-embed-text-v2-*): e.g. "search_query: "
    #[arg(long)]
    ollama_query_prefix: Option<String>,

    /// Truncate embeddings to N dimensions. 0 = keep full native length.
    #[arg(long, default_value_t = 0)]
    ollama_dim: usize,

    /// After ingest, propose repairs for unresolved Obsidian vault links using embeddings (writes `unresolved_link_suggestion` rows)
    #[arg(long)]
    ollama_suggest_unresolved: bool,

    /// Max number of candidates per unresolved link suggestion (default: 5)
    #[arg(long, default_value_t = 5)]
    ollama_suggest_limit: usize,
}

#[derive(Parser)]
struct ProjectionVacuumArgs {
    /// Delete runs older than the given projection run id
    #[arg(long, value_name = "RUN_ID", conflicts_with = "run")]
    before_run: Option<String>,

    /// Delete a specific projection run id
    #[arg(long, value_name = "RUN_ID", conflicts_with = "before_run")]
    run: Option<String>,

    /// Dry run: report runs that would be deleted
    #[arg(long)]
    dry_run: bool,

    /// Ledger path (default: out/ledger.jsonl)
    #[arg(long)]
    ledger: Option<PathBuf>,

    /// Do not append to ledger
    #[arg(long)]
    no_ledger: bool,

    /// Artifact store root (default: out/artifacts)
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,

    /// Output JSON summary
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct ProjectionRetryArgs {
    /// Projection run id to retry
    #[arg(long, value_name = "RUN_ID")]
    run: String,

    /// Limit retry to a specific phase
    #[arg(long, value_name = "PHASE")]
    phase: Option<String>,

    /// Limit retry to a specific failed batch hash
    #[arg(long, value_name = "BATCH_HASH")]
    batch: Option<String>,

    /// Artifact store root (default: out/artifacts)
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,

    /// Ledger path (default: out/ledger.jsonl)
    #[arg(long)]
    ledger: Option<PathBuf>,

    /// Do not append to ledger
    #[arg(long)]
    no_ledger: bool,

    /// Dry run: report what would be retried
    #[arg(long)]
    dry_run: bool,

    /// Output JSON summary
    #[arg(long)]
    json: bool,
}
#[derive(Subcommand)]
enum RegistryCommands {
    Init(RegistryInitArgs),
    Build(RegistryBuildArgs),
    Verify(RegistryVerifyArgs),
    ScopeAdd(ScopeAddArgs),
    ScopeVerify(ScopeVerifyArgs),
    ScopeList(ScopeListArgs),
    ScopeShow(ScopeShowArgs),
}

#[derive(Parser)]
struct RegistryInitArgs {
    /// Output path for the registry JSON
    #[arg(long, value_name = "PATH", default_value = "out/meta-registry.json")]
    out: PathBuf,
}

#[derive(Parser)]
struct RegistryBuildArgs {
    /// Input registry JSON path
    #[arg(long, value_name = "PATH", default_value = "out/meta-registry.json")]
    input: PathBuf,
    /// Artifact store root (default: out/artifacts)
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,
}

#[derive(Parser)]
struct RegistryVerifyArgs {
    /// Ledger path (default: out/ledger.jsonl)
    #[arg(long)]
    ledger: Option<PathBuf>,
    /// Artifact store root (default: out/artifacts)
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,
}

#[derive(Parser)]
struct ScopeAddArgs {
    /// Scope (format: "scope:domain.name@version" OR use --scope-id and --version)
    #[arg(long, conflicts_with_all = &["scope_id", "version"])]
    scope: Option<String>,

    /// Scope ID (format: "scope:domain.name" - NO @version)
    #[arg(long, requires = "version")]
    scope_id: Option<String>,

    /// Scope version number
    #[arg(long)]
    version: Option<u32>,

    /// Snapshot schema ID (optional Phase 2 field)
    #[arg(long)]
    snapshot_schema_id: Option<String>,

    /// Phase (p0, p1, p2, p3, p4) (optional Phase 2 field)
    #[arg(long)]
    phase: Option<String>,

    /// Is deterministic (optional Phase 2 field)
    #[arg(long)]
    deterministic: Option<bool>,

    /// Is foundational (optional Phase 2 field)
    #[arg(long)]
    foundational: Option<bool>,

    /// Witness schemas emitted (repeatable)
    #[arg(long = "emits", value_name = "SCHEMA_ID")]
    emits: Vec<String>,

    /// Witness schemas consumed (repeatable)
    #[arg(long = "consumes", value_name = "SCHEMA_ID")]
    consumes: Vec<String>,

    /// Scope dependencies (repeatable)
    #[arg(long = "deps", value_name = "SCOPE_ID")]
    deps: Vec<String>,

    /// Scope role (foundation, transform, verification, governance, integration, application)
    #[arg(long)]
    role: Option<String>,

    /// Path to scope contract markdown
    #[arg(long)]
    contract_ref: Option<String>,

    /// Registry JSON path to update
    #[arg(long, default_value = "out/meta-registry.json")]
    registry: PathBuf,

    /// Validation level (phase1 or phase2)
    #[arg(long, default_value = "phase1")]
    validation_level: String,

    /// Dry run (don't update registry)
    #[arg(long)]
    dry_run: bool,
}

#[derive(Parser)]
struct ScopeVerifyArgs {
    /// Scope ID to verify
    #[arg(long, required = true)]
    scope_id: String,

    /// Registry JSON path
    #[arg(long, default_value = "out/meta-registry.json")]
    registry: PathBuf,

    /// Validation level (phase1 or phase2)
    #[arg(long, default_value = "phase1")]
    validation_level: String,

    /// Output JSON instead of text
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct ScopeListArgs {
    /// Registry JSON path
    #[arg(long, default_value = "out/meta-registry.json")]
    registry: PathBuf,

    /// Filter by phase
    #[arg(long)]
    phase: Option<String>,

    /// Filter by role
    #[arg(long)]
    role: Option<String>,

    /// Output JSON instead of text
    #[arg(long)]
    json: bool,
}

#[derive(Parser)]
struct ScopeShowArgs {
    /// Scope ID to show
    #[arg(required = true)]
    scope_id: String,

    /// Registry JSON path
    #[arg(long, default_value = "out/meta-registry.json")]
    registry: PathBuf,

    /// Output JSON instead of text
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum PlanCommands {
    New(PlanNewArgs),
    Show(PlanShowArgs),
    Export(PlanExportArgs),
    PromptTemplate(PlanPromptTemplateArgs),
    AnswersFromMd(PlanAnswersFromMdArgs),
}

#[derive(Parser)]
struct PlanNewArgs {
    /// Path to JSON answers file
    #[arg(long, value_name = "PATH", required = true)]
    answers: PathBuf,
    /// Scope description for the plan
    #[arg(long, required = true)]
    scope: String,
    /// Target description for the plan
    #[arg(long, required = true)]
    target: String,
    /// Surface attribution (default: cli)
    #[arg(long, default_value = "cli")]
    surface: String,
    /// Compiler/tool version identifier
    #[arg(long)]
    tool_version: Option<String>,
    /// Obsidian vault snapshot hash (optional, binds plan to a vault state)
    #[arg(long)]
    snapshot_hash: Option<String>,
    /// Witness created_at timestamp (included in plan_id; default: current UTC ISO-8601)
    #[arg(long = "created-at", alias = "timestamp")]
    created_at: Option<String>,
    /// Path to meta registry JSON (or set ADMIT_META_REGISTRY)
    #[arg(long, value_name = "PATH")]
    meta_registry: Option<PathBuf>,
    /// Ledger path (default: out/ledger.jsonl)
    #[arg(long)]
    ledger: Option<PathBuf>,
    /// Artifact store root (default: out/artifacts)
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,
    /// Output JSON instead of key=value lines
    #[arg(long)]
    json: bool,
    /// Do not append to ledger
    #[arg(long)]
    dry_run: bool,
}

#[derive(Parser)]
struct PlanShowArgs {
    /// Plan ID (SHA256 hex of the canonical CBOR witness)
    #[arg(value_name = "PLAN_ID")]
    plan_id: String,
    /// Artifact store root (default: out/artifacts)
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,
}

#[derive(Parser)]
struct PlanExportArgs {
    /// Plan ID (SHA256 hex of the canonical CBOR witness)
    #[arg(value_name = "PLAN_ID")]
    plan_id: String,
    /// Output path for the Markdown projection
    #[arg(long, value_name = "PATH", required = true)]
    out: PathBuf,
    /// Artifact store root (default: out/artifacts)
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,
}

#[derive(Parser)]
struct PlanPromptTemplateArgs {
    /// Output path (writes to stdout when omitted)
    #[arg(long, value_name = "PATH")]
    out: Option<PathBuf>,

    /// Omit guidance text blocks
    #[arg(long)]
    no_guidance: bool,
}

#[derive(Parser)]
struct PlanAnswersFromMdArgs {
    /// Input Markdown path
    #[arg(long, value_name = "PATH", required = true)]
    input: PathBuf,

    /// Output JSON path (writes to stdout when omitted)
    #[arg(long, value_name = "PATH")]
    out: Option<PathBuf>,
}

#[derive(Parser)]
struct CalcArgs {
    #[command(subcommand)]
    command: CalcCommands,
}

#[derive(Subcommand)]
enum CalcCommands {
    Plan(CalcPlanArgs),
    Execute(CalcExecuteArgs),
    Describe(CalcDescribeArgs),
}

#[derive(Parser)]
struct CalcPlanArgs {
    /// Path to expression JSON file
    #[arg(long, value_name = "PATH", required = true)]
    expression: PathBuf,

    /// Input contracts (repeatable: name:type or name:type:unit)
    #[arg(long = "input-contract", value_name = "SPEC")]
    input_contracts: Vec<String>,

    /// Expected output unit
    #[arg(long)]
    output_unit: Option<String>,

    /// Output path for plan artifact
    #[arg(long, value_name = "PATH", required = true)]
    out: PathBuf,
}

#[derive(Parser)]
struct CalcExecuteArgs {
    /// Path to plan artifact
    #[arg(long, value_name = "PATH", required = true)]
    plan: PathBuf,

    /// Input values (repeatable: name=value)
    #[arg(long = "input", value_name = "SPEC")]
    inputs: Vec<String>,

    /// Enable trace (step-by-step computation log)
    #[arg(long)]
    trace: bool,

    /// Output path for witness
    #[arg(long, value_name = "PATH", required = true)]
    out: PathBuf,

    /// Artifact store root (default: out/artifacts)
    #[arg(long)]
    artifacts_dir: Option<PathBuf>,
}

#[derive(Parser)]
struct CalcDescribeArgs {
    /// Output JSON
    #[arg(long, default_value_t = true)]
    json: bool,
}

fn main() {
    let cli = Cli::parse();
    let dag_trace_out = cli.dag_trace.as_deref();
    let mut projection = match build_projection_coordinator(&cli) {
        Ok(coord) => coord,
        Err(err) => {
            eprintln!("{}", err);
            std::process::exit(1);
        }
    };

    let result = match cli.command {
        Commands::Init(args) => run_init(args, dag_trace_out),
        Commands::Status(args) => run_status(args, dag_trace_out),
        Commands::DeclareCost(args) => run_declare_cost(args, dag_trace_out, &mut projection),
        Commands::WitnessVerify(args) => run_witness_verify(args, dag_trace_out),
        Commands::Check(args) => run_check(args, dag_trace_out, &mut projection),
        Commands::Execute(args) => run_execute(args, dag_trace_out, &mut projection),
        Commands::VerifyLedger(args) => run_verify_ledger(args, dag_trace_out),
        Commands::BundleVerify(args) => run_bundle_verify(args, dag_trace_out),
        Commands::Observe(args) => run_observe(args, dag_trace_out),
        Commands::ListArtifacts(args) => run_list_artifacts(args, dag_trace_out),
        Commands::ShowArtifact(args) => run_show_artifact(args, dag_trace_out),
        Commands::Registry(args) => run_registry(args, dag_trace_out),
        Commands::Plan(args) => match args.command {
            PlanCommands::New(new_args) => run_plan_new(new_args, dag_trace_out, &mut projection),
            PlanCommands::Show(show_args) => run_plan_show(show_args, dag_trace_out),
            PlanCommands::Export(export_args) => run_plan_export(export_args, dag_trace_out),
            PlanCommands::PromptTemplate(template_args) => {
                run_plan_prompt_template(template_args, dag_trace_out)
            }
            PlanCommands::AnswersFromMd(parse_args) => {
                run_plan_answers_from_md(parse_args, dag_trace_out)
            }
        },
        Commands::Calc(args) => match args.command {
            CalcCommands::Plan(plan_args) => {
                run_calc_plan(plan_args, dag_trace_out, &mut projection)
            }
            CalcCommands::Execute(exec_args) => {
                run_calc_execute(exec_args, dag_trace_out, &mut projection)
            }
            CalcCommands::Describe(desc_args) => run_calc_describe(desc_args, dag_trace_out),
        },
        Commands::Ingest(args) => match args.command {
            IngestCommands::Dir(dir_args) => run_ingest_dir(
                dir_args,
                dag_trace_out,
                &mut projection,
                cli.projection_force,
            ),
        },
        Commands::Projection(args) => match args.command {
            ProjectionCommands::Vacuum(vacuum_args) => {
                run_projection_vacuum(vacuum_args, &projection)
            }
            ProjectionCommands::Retry(retry_args) => run_projection_retry(retry_args, &projection),
        },
        Commands::Court(args) => match args.command {
            CourtCommands::Query(q) => match q.command {
                CourtQueryCommands::Add(a) => run_court_query_add(a, &mut projection),
            },
            CourtCommands::Function(f) => match f.command {
                CourtFunctionCommands::Add(a) => run_court_function_add(a, &mut projection),
            },
        },
        Commands::Lint(args) => match args.command {
            LintCommands::Rust(rust_args) => run_lint_rust(rust_args, dag_trace_out),
        },
        Commands::Git(args) => run_git(args, dag_trace_out),
    };

    if let Err(err) = result {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}

fn run_init(args: InitArgs, _dag_trace_out: Option<&Path>) -> Result<(), String> {
    let out = init_project(InitProjectInput {
        root: args.path.clone(),
    })
    .map_err(|err| err.to_string())?;

    if args.json {
        let json = serde_json::to_string_pretty(&serde_json::json!({
            "root": out.root,
            "created": out.created,
            "existing": out.existing,
            "next": ["admit ingest .", "admit status", "admit lint rust"]
        }))
        .map_err(|err| format!("json encode: {}", err))?;
        println!("{}", json);
    } else {
        println!("init_root={}", out.root.display());
        println!("created={}", out.created.len());
        for item in &out.created {
            println!("created_item={}", item);
        }
        println!("existing={}", out.existing.len());
        for item in &out.existing {
            println!("existing_item={}", item);
        }
        println!();
        println!("Next:");
        println!("  admit ingest .");
        println!("  admit status");
        println!("  admit lint rust");
    }

    Ok(())
}

fn run_status(args: StatusArgs, _dag_trace_out: Option<&Path>) -> Result<(), String> {
    let ledger = args.ledger.unwrap_or_else(default_ledger_path);
    let summary = summarize_ledger(&ledger).map_err(|err| err.to_string())?;

    if args.json {
        let json = serde_json::to_string_pretty(&summary)
            .map_err(|err| format!("json encode: {}", err))?;
        println!("{}", json);
        return Ok(());
    }

    println!("ledger={}", summary.ledger_path.display());
    println!("events_total={}", summary.events_total);
    if let Some(event_type) = summary.latest_event_type.as_ref() {
        println!("latest_event_type={}", event_type);
    }
    if let Some(event_id) = summary.latest_event_id.as_ref() {
        println!("latest_event_id={}", event_id);
    }

    if let Some(ingest) = summary.latest_ingest.as_ref() {
        println!(
            "latest_ingest={} run_id={} status={}",
            ingest.timestamp,
            ingest.run_id.as_deref().unwrap_or("-"),
            ingest.status.as_deref().unwrap_or("-")
        );
    }
    if let Some(proj) = summary.latest_projection.as_ref() {
        println!(
            "latest_projection={} run_id={} status={}",
            proj.timestamp,
            proj.run_id.as_deref().unwrap_or("-"),
            proj.status.as_deref().unwrap_or("-")
        );
    }
    if let Some(plan) = summary.latest_plan.as_ref() {
        println!("latest_plan={} event_id={}", plan.timestamp, plan.event_id);
    }
    if let Some(lint) = summary.latest_rust_lint.as_ref() {
        println!(
            "latest_rust_lint={} passed={} violations={}",
            lint.timestamp,
            lint.passed
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string()),
            lint.violations
                .map(|v| v.to_string())
                .unwrap_or_else(|| "-".to_string())
        );
    }

    Ok(())
}

fn run_declare_cost(
    args: DeclareCostArgs,
    dag_trace_out: Option<&Path>,
    projection: &mut ProjectionCoordinator,
) -> Result<(), String> {
    let witness_json = match args.witness_json {
        Some(path) => {
            Some(read_file_bytes(&path).map_err(|err| format!("read witness_json: {}", err))?)
        }
        None => None,
    };

    let witness_cbor = match args.witness_cbor {
        Some(path) => {
            Some(read_file_bytes(&path).map_err(|err| format!("read witness_cbor: {}", err))?)
        }
        None => None,
    };

    let timestamp = args
        .timestamp
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));

    let snapshot_path = match (args.snapshot, std::env::var("SNAPSHOT_PATH").ok()) {
        (Some(path), _) => path,
        (None, Some(path)) => PathBuf::from(path),
        (None, None) => {
            return Err("snapshot path required (use --snapshot or SNAPSHOT_PATH)".to_string())
        }
    };

    let snapshot = vault_snapshot::load_snapshot_with_hash(&snapshot_path)
        .map_err(|err| format!("snapshot load: {}", err))?;
    if let Some(expected) = args.snapshot_hash.as_deref() {
        if expected != snapshot.sha256 {
            return Err(format!(
                "snapshot hash mismatch (expected {}, computed {})",
                expected, snapshot.sha256
            ));
        }
    }
    let program_bundle = match args.program_bundle {
        Some(path) => Some(
            program_bundle::load_bundle_with_hash(&path)
                .map_err(|err| format!("program bundle load: {}", err))?,
        ),
        None => None,
    };

    let snapshot_hash_for_trace = snapshot.sha256.clone();
    let input = DeclareCostInput {
        witness_json,
        witness_cbor,
        witness_sha256: args.witness_sha256,
        witness_schema_id: args.witness_schema_id,
        compiler_build_id: args.compiler_build_id,
        snapshot_hash: Some(snapshot.sha256),
        snapshot_canonical_bytes: Some(snapshot.canonical_bytes),
        snapshot_schema_id: Some(snapshot.snapshot.schema_id),
        program_bundle_canonical_bytes: program_bundle
            .as_ref()
            .map(|bundle| bundle.canonical_bytes.clone()),
        program_bundle_schema_id: program_bundle
            .as_ref()
            .map(|bundle| bundle.bundle.schema_id.clone()),
        program_module: args.program_module,
        program_scope: args.program_scope,
        timestamp,
        artifacts_root: args.artifacts_dir,
        meta_registry_path: args.meta_registry,
    };

    let event = declare_cost(input).map_err(|err| err.to_string())?;
    let ledger_path = args.ledger.unwrap_or_else(default_ledger_path);
    if !args.dry_run {
        append_event(&ledger_path, &event).map_err(|err| err.to_string())?;
    }

    if args.json {
        let json = serde_json::to_string(&event).map_err(|err| format!("json encode: {}", err))?;
        println!("{}", json);
    } else {
        println!("event_id={}", event.event_id);
        println!("witness_sha256={}", event.witness.sha256);
        println!("ledger={}", ledger_path.display());
        if args.dry_run {
            println!("dry_run=true");
        }
    }

    let want_trace = dag_trace_out.is_some() || projection.is_active();
    if want_trace {
        let trace = build_trace_for_cost_declared(&event, &snapshot_hash_for_trace)?;
        let (trace_sha256, trace_cbor) = encode_dag_trace(&trace)?;
        if let Some(out) = dag_trace_out {
            write_dag_trace(out, &trace_cbor)?;
            print_dag_trace_hint(args.json, out, &trace_sha256);
        }
        maybe_project_trace(projection, &trace_sha256, &trace_cbor, trace.dag())?;
    }

    Ok(())
}

fn run_witness_verify(
    args: WitnessVerifyArgs,
    _dag_trace_out: Option<&Path>,
) -> Result<(), String> {
    let witness_json = match args.witness_json {
        Some(path) => {
            Some(read_file_bytes(&path).map_err(|err| format!("read witness_json: {}", err))?)
        }
        None => None,
    };

    let witness_cbor = match args.witness_cbor {
        Some(path) => {
            Some(read_file_bytes(&path).map_err(|err| format!("read witness_cbor: {}", err))?)
        }
        None => None,
    };

    let output = verify_witness(VerifyWitnessInput {
        witness_json,
        witness_cbor,
        expected_sha256: args.expected_sha256,
    })
    .map_err(|err| err.to_string())?;

    if let Some(path) = args.out_cbor {
        std::fs::write(&path, &output.cbor_bytes)
            .map_err(|err| format!("write out_cbor: {}", err))?;
        println!("cbor_written={}", path.display());
    }

    println!("witness_sha256={}", output.sha256);
    Ok(())
}

fn run_check(
    args: CheckArgs,
    dag_trace_out: Option<&Path>,
    projection: &mut ProjectionCoordinator,
) -> Result<(), String> {
    let ledger_path = args.ledger.unwrap_or_else(default_ledger_path);
    let artifacts_dir = args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
    let timestamp = args
        .timestamp
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    let facts_bundle_input = match (args.facts_bundle, std::env::var("FACTS_BUNDLE_PATH").ok()) {
        (Some(path), _) => {
            let loaded = facts_bundle::load_bundle_with_hash(&path)
                .map_err(|err| format!("facts bundle load: {}", err))?;
            Some(ArtifactInput {
                kind: "facts_bundle".to_string(),
                schema_id: loaded.bundle.schema_id.clone(),
                bytes: loaded.canonical_bytes,
                ext: "json".to_string(),
            })
        }
        (None, Some(path)) => {
            let loaded = facts_bundle::load_bundle_with_hash(&PathBuf::from(path))
                .map_err(|err| format!("facts bundle load: {}", err))?;
            Some(ArtifactInput {
                kind: "facts_bundle".to_string(),
                schema_id: loaded.bundle.schema_id.clone(),
                bytes: loaded.canonical_bytes,
                ext: "json".to_string(),
            })
        }
        (None, None) => None,
    };

    let scope_gate_mode = parse_scope_gate_mode(&args.scope_gate)?;
    let event = check_cost_declared(
        &ledger_path,
        Some(artifacts_dir.as_path()),
        &args.event_id,
        timestamp,
        args.compiler_build_id,
        facts_bundle_input,
        args.meta_registry.as_deref(),
        scope_gate_mode,
    )
    .map_err(|err| err.to_string())?;

    if scope_gate_mode == ScopeGateMode::Warn {
        warn_missing_scope(args.meta_registry.as_deref(), &event.program.scope)?;
    }

    if !args.dry_run {
        append_checked_event(&ledger_path, &event).map_err(|err| err.to_string())?;
    }

    if args.json {
        let json = serde_json::to_string(&event).map_err(|err| format!("json encode: {}", err))?;
        println!("{}", json);
    } else {
        println!("event_id={}", event.event_id);
        println!("cost_declared_event_id={}", event.cost_declared_event_id);
        if let Some(hash) = &event.facts_bundle_hash {
            println!("facts_bundle_hash={}", hash);
        }
        println!("ledger={}", ledger_path.display());
        if args.dry_run {
            println!("dry_run=true");
        }
    }

    let want_trace = dag_trace_out.is_some() || projection.is_active();
    if want_trace {
        let trace = build_trace_for_checked(&event)?;
        let (trace_sha256, trace_cbor) = encode_dag_trace(&trace)?;
        if let Some(out) = dag_trace_out {
            write_dag_trace(out, &trace_cbor)?;
            print_dag_trace_hint(args.json, out, &trace_sha256);
        }
        maybe_project_trace(projection, &trace_sha256, &trace_cbor, trace.dag())?;
    }
    Ok(())
}

fn run_execute(
    args: ExecuteArgs,
    dag_trace_out: Option<&Path>,
    projection: &mut ProjectionCoordinator,
) -> Result<(), String> {
    let ledger_path = args.ledger.unwrap_or_else(default_ledger_path);
    let artifacts_dir = args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
    let timestamp = args
        .timestamp
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));

    let scope_gate_mode = parse_scope_gate_mode(&args.scope_gate)?;
    let event = execute_checked(
        &ledger_path,
        Some(artifacts_dir.as_path()),
        &args.checked_event_id,
        timestamp,
        args.compiler_build_id,
        args.meta_registry.as_deref(),
        scope_gate_mode,
    )
    .map_err(|err| err.to_string())?;

    if scope_gate_mode == ScopeGateMode::Warn {
        warn_missing_scope(args.meta_registry.as_deref(), &event.program.scope)?;
    }

    if !args.dry_run {
        append_executed_event(&ledger_path, &event).map_err(|err| err.to_string())?;
    }

    if args.json {
        let json = serde_json::to_string(&event).map_err(|err| format!("json encode: {}", err))?;
        println!("{}", json);
    } else {
        println!("event_id={}", event.event_id);
        println!("checked_event_id={}", event.admissibility_checked_event_id);
        println!("ledger={}", ledger_path.display());
        if args.dry_run {
            println!("dry_run=true");
        }
    }

    let want_trace = dag_trace_out.is_some() || projection.is_active();
    if want_trace {
        let trace = build_trace_for_executed(&event)?;
        let (trace_sha256, trace_cbor) = encode_dag_trace(&trace)?;
        if let Some(out) = dag_trace_out {
            write_dag_trace(out, &trace_cbor)?;
            print_dag_trace_hint(args.json, out, &trace_sha256);
        }
        maybe_project_trace(projection, &trace_sha256, &trace_cbor, trace.dag())?;
    }
    Ok(())
}

fn parse_scope_gate_mode(value: &str) -> Result<ScopeGateMode, String> {
    match value {
        "warn" => Ok(ScopeGateMode::Warn),
        "error" => Ok(ScopeGateMode::Error),
        other => Err(format!("invalid scope gate mode: {}", other)),
    }
}

fn resolve_meta_registry_path(path: Option<&std::path::Path>) -> Option<std::path::PathBuf> {
    path.map(|p| p.to_path_buf()).or_else(|| {
        std::env::var("ADMIT_META_REGISTRY")
            .ok()
            .map(std::path::PathBuf::from)
    })
}

fn warn_missing_scope(path: Option<&std::path::Path>, scope_id: &str) -> Result<(), String> {
    let path = match resolve_meta_registry_path(path) {
        Some(path) => path,
        None => return Ok(()),
    };
    if !path.exists() {
        return Err(format!("meta registry not found: {}", path.display()));
    }
    let bytes = std::fs::read(&path).map_err(|err| format!("read meta registry: {}", err))?;
    let registry: MetaRegistryV0 =
        serde_json::from_slice(&bytes).map_err(|err| format!("meta registry decode: {}", err))?;
    if !registry.scopes.iter().any(|entry| entry.id == scope_id) {
        eprintln!(
            "warning: meta registry missing scope_id (mode=warn): {}",
            scope_id
        );
    }
    Ok(())
}

fn run_verify_ledger(args: VerifyLedgerArgs, _dag_trace_out: Option<&Path>) -> Result<(), String> {
    let ledger_path = args.ledger.unwrap_or_else(default_ledger_path);
    let artifacts_dir = args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
    let report = verify_ledger(&ledger_path, Some(artifacts_dir.as_path()))
        .map_err(|err| err.to_string())?;

    if args.json {
        let json = serde_json::to_string(&report).map_err(|err| format!("json encode: {}", err))?;
        println!("{}", json);
    } else {
        println!("ledger={}", ledger_path.display());
        println!("entries={}", report.total);
        println!("issues={}", report.issues.len());
        for issue in &report.issues {
            let event_id = issue.event_id.as_deref().unwrap_or("-");
            let event_type = issue.event_type.as_deref().unwrap_or("-");
            println!(
                "issue line={} event_id={} event_type={} message={}",
                issue.line, event_id, event_type, issue.message
            );
        }
    }

    if report.issues.is_empty() {
        Ok(())
    } else {
        Err("ledger verification found issues".to_string())
    }
}

fn run_bundle_verify(args: BundleVerifyArgs, _dag_trace_out: Option<&Path>) -> Result<(), String> {
    let loaded = program_bundle::load_bundle_with_hash(&args.bundle)
        .map_err(|err| format!("bundle load: {}", err))?;

    if args.json {
        let output = serde_json::json!({
            "bundle_hash": loaded.sha256,
            "schema_id": loaded.bundle.schema_id,
            "schema_version": loaded.bundle.schema_version
        });
        let json = serde_json::to_string(&output).map_err(|err| format!("json encode: {}", err))?;
        println!("{}", json);
    } else {
        println!("bundle_hash={}", loaded.sha256);
        println!("schema_id={}", loaded.bundle.schema_id);
        println!("schema_version={}", loaded.bundle.schema_version);
    }

    Ok(())
}

fn run_observe(args: ObserveArgs, _dag_trace_out: Option<&Path>) -> Result<(), String> {
    if args.pattern.len() != args.diff.len() {
        return Err("pattern and diff counts must match".to_string());
    }
    let unit = if args.unit.is_empty() {
        None
    } else if args.unit.len() == 1 {
        Some(args.unit[0].clone())
    } else if args.unit.len() == args.pattern.len() {
        None
    } else {
        return Err("unit must be empty, length 1, or match pattern count".to_string());
    };

    let patterns: Vec<facts_bundle::ObservationPattern> = args
        .pattern
        .iter()
        .enumerate()
        .map(|(idx, regex)| facts_bundle::ObservationPattern {
            diff: args.diff[idx].clone(),
            regex: regex.clone(),
            unit: unit
                .clone()
                .or_else(|| args.unit.get(idx).cloned())
                .or_else(|| Some("count".to_string())),
        })
        .collect();

    let source_root = match args.source_root {
        Some(path) => path,
        None => std::env::current_dir().map_err(|err| format!("current_dir: {}", err))?,
    };

    let bundle = facts_bundle::observe_regex(
        &args.input,
        &patterns,
        args.case_insensitive,
        args.generated_at,
        Some(&source_root),
    )
    .map_err(|err| err.to_string())?;
    let bundle_with_hash = facts_bundle::bundle_with_hash(bundle).map_err(|err| err.to_string())?;

    let out_path = args
        .out
        .unwrap_or_else(|| PathBuf::from("out/facts-bundle.json"));
    if let Some(parent) = out_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|err| format!("create out dir: {}", err))?;
        }
    }
    std::fs::write(&out_path, &bundle_with_hash.canonical_bytes)
        .map_err(|err| format!("write facts bundle: {}", err))?;
    let hash_path = out_path.with_extension("json.sha256");
    std::fs::write(&hash_path, &bundle_with_hash.sha256)
        .map_err(|err| format!("write facts bundle hash: {}", err))?;

    if args.json {
        let output = serde_json::json!({
            "bundle_hash": bundle_with_hash.sha256,
            "bundle_path": out_path.display().to_string(),
            "hash_path": hash_path.display().to_string()
        });
        let json = serde_json::to_string(&output).map_err(|err| format!("json encode: {}", err))?;
        println!("{}", json);
    } else {
        println!("bundle_hash={}", bundle_with_hash.sha256);
        println!("bundle_path={}", out_path.display());
        println!("hash_path={}", hash_path.display());
    }
    Ok(())
}

fn run_lint_rust(args: LintRustArgs, _dag_trace_out: Option<&Path>) -> Result<(), String> {
    let scope_enablement = resolve_scope_enablement(&args.path)?;
    if !scope_enablement.allows(ScopeOperation::RustIrLint) {
        let source = scope_enablement
            .source
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "default scopes".to_string());
        return Err(format!(
            "scope {} is disabled by {} (enable it under [scopes].enabled)",
            scope_operation_human_hint(ScopeOperation::RustIrLint),
            source
        ));
    }

    let created_at = args
        .created_at
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    let tool_version = args
        .tool_version
        .unwrap_or_else(|| format!("admit-cli {}", env!("CARGO_PKG_VERSION")));
    let artifacts_dir = args
        .artifacts_dir
        .clone()
        .unwrap_or_else(default_artifacts_dir);
    let ledger_path = args.ledger.clone().unwrap_or_else(default_ledger_path);

    let output = run_rust_ir_lint(RustIrLintInput {
        root: args.path,
        timestamp: created_at,
        tool_version,
        artifacts_root: Some(artifacts_dir.clone()),
        meta_registry_path: args.meta_registry,
    })
    .map_err(|err| err.to_string())?;

    if !args.dry_run {
        append_rust_ir_lint_event(&ledger_path, &output.event).map_err(|err| err.to_string())?;
    }

    if args.json {
        let json = serde_json::to_string(&serde_json::json!({
            "event": &output.event,
            "witness": &output.witness,
            "ledger": ledger_path,
            "artifacts_dir": artifacts_dir,
            "dry_run": args.dry_run
        }))
        .map_err(|err| format!("json encode: {}", err))?;
        println!("{}", json);
    } else {
        println!("event_id={}", output.event.event_id);
        println!("witness_sha256={}", output.event.witness.sha256);
        println!("scope_id={}", output.event.scope_id);
        println!("rule_pack={}", output.event.rule_pack);
        println!("files_scanned={}", output.event.files_scanned);
        println!("violations={}", output.event.violations);
        println!("passed={}", output.event.passed);
        println!("ledger={}", ledger_path.display());
        if args.dry_run {
            println!("dry_run=true");
        }
        for violation in output.witness.violations.iter().take(200) {
            let line = violation
                .line
                .map(|line| line.to_string())
                .unwrap_or_else(|| "-".to_string());
            println!(
                "violation rule_id={} severity={} file={} line={} message={}",
                violation.rule_id, violation.severity, violation.file, line, violation.message
            );
        }
        if output.witness.violations.len() > 200 {
            println!(
                "violation_truncated=true shown=200 total={}",
                output.witness.violations.len()
            );
        }
    }

    if output.event.passed {
        Ok(())
    } else {
        Err(format!(
            "rust ir lint found {} violation(s)",
            output.event.violations
        ))
    }
}

fn run_git(args: GitArgs, _dag_trace_out: Option<&Path>) -> Result<(), String> {
    match args.command {
        GitCommands::Snapshot(snapshot_args) => run_git_snapshot(snapshot_args),
        GitCommands::Diff(diff_args) => run_git_diff(diff_args),
        GitCommands::Provenance(provenance_args) => run_git_provenance(provenance_args),
        GitCommands::VerifyCommitPlan(verify_args) => run_git_verify_commit_plan(verify_args),
        GitCommands::InstallPlanHook(hook_args) => run_git_install_plan_hook(hook_args),
    }
}

fn run_git_snapshot(args: GitSnapshotArgs) -> Result<(), String> {
    let repo = resolve_repo_path(&args.repo)?;
    let created_at = args
        .created_at
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    let metadata = build_git_metadata(args.source_ref, args.purpose);
    let head_commit_oid = git_resolve_commit_oid(&repo, &args.head)?;
    let is_clean = git_is_clean_worktree(&repo)?;
    let tracked_files = git_snapshot_tracked_files(&repo, &head_commit_oid)?;
    let submodules = if args.include_submodules {
        git_snapshot_submodules(&repo)?
    } else {
        Vec::new()
    };
    let working_tree_manifest_sha256 = if args.include_working_tree_manifest {
        Some(git_working_tree_manifest_sha256(&repo)?)
    } else {
        None
    };

    let witness = admit_core::git_snapshot(
        admit_core::GitSnapshotInput {
            head_commit_oid,
            is_clean,
            tracked_files,
            submodules,
            working_tree_manifest_sha256,
        },
        created_at,
        metadata,
    )
    .map_err(|e| e.to_string())?;
    let witness_id =
        admit_core::compute_git_snapshot_witness_id(&witness).map_err(|e| e.to_string())?;

    let artifacts_dir = args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
    let artifact_ref = if args.no_store {
        None
    } else {
        let witness_value =
            serde_json::to_value(&witness).map_err(|e| format!("snapshot witness json: {}", e))?;
        Some(
            store_value_artifact(
                &artifacts_dir,
                "git_snapshot_witness",
                "git-snapshot-witness/0",
                &witness_value,
            )
            .map_err(|e| e.to_string())?,
        )
    };

    if let Some(out_path) = args.out.as_ref() {
        write_json_pretty(out_path, &witness)?;
    }

    if args.json {
        let output = serde_json::json!({
            "witness_id": witness_id,
            "artifact_ref": artifact_ref,
            "witness": witness
        });
        println!(
            "{}",
            serde_json::to_string(&output).map_err(|e| format!("json encode: {}", e))?
        );
    } else {
        println!("witness_id={}", witness_id);
        println!("schema_id=git-snapshot-witness/0");
        println!("head_commit_oid={}", witness.head_commit_oid);
        println!("is_clean={}", witness.is_clean);
        println!("tracked_files={}", witness.tracked_files.len());
        if let Some(submodules) = witness.submodules.as_ref() {
            println!("submodules={}", submodules.len());
        }
        if let Some(artifact_ref) = artifact_ref.as_ref() {
            println!("artifact_sha256={}", artifact_ref.sha256);
            println!(
                "artifact_path={}",
                artifact_ref.path.as_deref().unwrap_or("")
            );
            println!("artifacts_dir={}", artifacts_dir.display());
        } else {
            println!("stored=false");
        }
        if let Some(out_path) = args.out.as_ref() {
            println!("out={}", out_path.display());
        }
    }

    Ok(())
}

fn run_git_diff(args: GitDiffArgs) -> Result<(), String> {
    let repo = resolve_repo_path(&args.repo)?;
    let created_at = args
        .created_at
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    let metadata = build_git_metadata(args.source_ref, args.purpose);
    let base_commit_oid = git_resolve_commit_oid(&repo, &args.base)?;
    let head_commit_oid = git_resolve_commit_oid(&repo, &args.head)?;
    let changes = git_diff_changes(&repo, &base_commit_oid, &head_commit_oid)?;

    let witness = admit_core::git_diff(
        admit_core::GitDiffInput {
            base_commit_oid,
            head_commit_oid,
            changes,
        },
        created_at,
        metadata,
    )
    .map_err(|e| e.to_string())?;
    let witness_id =
        admit_core::compute_git_diff_witness_id(&witness).map_err(|e| e.to_string())?;

    let artifacts_dir = args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
    let artifact_ref = if args.no_store {
        None
    } else {
        let witness_value =
            serde_json::to_value(&witness).map_err(|e| format!("diff witness json: {}", e))?;
        Some(
            store_value_artifact(
                &artifacts_dir,
                "git_diff_witness",
                "git-diff-witness/0",
                &witness_value,
            )
            .map_err(|e| e.to_string())?,
        )
    };

    if let Some(out_path) = args.out.as_ref() {
        write_json_pretty(out_path, &witness)?;
    }

    if args.json {
        let output = serde_json::json!({
            "witness_id": witness_id,
            "artifact_ref": artifact_ref,
            "witness": witness
        });
        println!(
            "{}",
            serde_json::to_string(&output).map_err(|e| format!("json encode: {}", e))?
        );
    } else {
        println!("witness_id={}", witness_id);
        println!("schema_id=git-diff-witness/0");
        println!("base_commit_oid={}", witness.base_commit_oid);
        println!("head_commit_oid={}", witness.head_commit_oid);
        println!("changes={}", witness.changes.len());
        if let Some(artifact_ref) = artifact_ref.as_ref() {
            println!("artifact_sha256={}", artifact_ref.sha256);
            println!(
                "artifact_path={}",
                artifact_ref.path.as_deref().unwrap_or("")
            );
            println!("artifacts_dir={}", artifacts_dir.display());
        } else {
            println!("stored=false");
        }
        if let Some(out_path) = args.out.as_ref() {
            println!("out={}", out_path.display());
        }
    }

    Ok(())
}

fn run_git_provenance(args: GitProvenanceArgs) -> Result<(), String> {
    let repo = resolve_repo_path(&args.repo)?;
    let created_at = args
        .created_at
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    let metadata = build_git_metadata(args.source_ref, args.purpose);

    let base_commit_oid = match args.base.as_ref() {
        Some(base_ref) => Some(git_resolve_commit_oid(&repo, base_ref)?),
        None => None,
    };
    let head_commit_oid = git_resolve_commit_oid(&repo, &args.head)?;
    let repository_id = args
        .repository_id
        .unwrap_or_else(|| default_repository_id(&repo));

    let artifact_bindings: Vec<admit_core::GitArtifactBinding> = match args.artifact_bindings_file {
        Some(path) => read_json_file(&path)?,
        None => Vec::new(),
    };
    let registry_bindings: Vec<admit_core::GitRegistryBinding> = match args.registry_bindings_file {
        Some(path) => read_json_file(&path)?,
        None => Vec::new(),
    };

    let mut signature_map: std::collections::BTreeMap<String, admit_core::GitSignatureAttestation> =
        std::collections::BTreeMap::new();
    if args.signatures_from_git {
        for attestation in
            git_collect_signature_attestations(&repo, base_commit_oid.as_deref(), &head_commit_oid)?
        {
            signature_map.insert(attestation.commit_oid.clone(), attestation);
        }
    }
    let explicit_signatures: Vec<admit_core::GitSignatureAttestation> =
        match args.signature_attestations_file {
            Some(path) => read_json_file(&path)?,
            None => Vec::new(),
        };
    for attestation in explicit_signatures {
        signature_map.insert(attestation.commit_oid.clone(), attestation);
    }
    let signature_attestations = signature_map.into_values().collect::<Vec<_>>();

    let witness = admit_core::git_provenance(
        admit_core::GitProvenanceInput {
            repository_id,
            base_commit_oid,
            head_commit_oid,
            artifact_bindings,
            registry_bindings,
            signature_attestations,
        },
        created_at,
        metadata,
    )
    .map_err(|e| e.to_string())?;
    let witness_id =
        admit_core::compute_git_provenance_witness_id(&witness).map_err(|e| e.to_string())?;

    let artifacts_dir = args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
    let artifact_ref = if args.no_store {
        None
    } else {
        let witness_value = serde_json::to_value(&witness)
            .map_err(|e| format!("provenance witness json: {}", e))?;
        Some(
            store_value_artifact(
                &artifacts_dir,
                "git_provenance_witness",
                "git-provenance-witness/0",
                &witness_value,
            )
            .map_err(|e| e.to_string())?,
        )
    };

    if let Some(out_path) = args.out.as_ref() {
        write_json_pretty(out_path, &witness)?;
    }

    if args.json {
        let output = serde_json::json!({
            "witness_id": witness_id,
            "artifact_ref": artifact_ref,
            "witness": witness
        });
        println!(
            "{}",
            serde_json::to_string(&output).map_err(|e| format!("json encode: {}", e))?
        );
    } else {
        println!("witness_id={}", witness_id);
        println!("schema_id=git-provenance-witness/0");
        println!("repository_id={}", witness.repository_id);
        println!("head_commit_oid={}", witness.head_commit_oid);
        println!("artifact_bindings={}", witness.artifact_bindings.len());
        println!("registry_bindings={}", witness.registry_bindings.len());
        println!(
            "signature_attestations={}",
            witness.signature_attestations.len()
        );
        if let Some(artifact_ref) = artifact_ref.as_ref() {
            println!("artifact_sha256={}", artifact_ref.sha256);
            println!(
                "artifact_path={}",
                artifact_ref.path.as_deref().unwrap_or("")
            );
            println!("artifacts_dir={}", artifacts_dir.display());
        } else {
            println!("stored=false");
        }
        if let Some(out_path) = args.out.as_ref() {
            println!("out={}", out_path.display());
        }
    }

    Ok(())
}

fn run_git_verify_commit_plan(args: GitVerifyCommitPlanArgs) -> Result<(), String> {
    let repo = resolve_repo_path(&args.repo)?;
    let artifacts_dir = resolve_artifacts_dir(&repo, args.artifacts_dir);

    let (source, message) = if let Some(path) = args.message_file.as_ref() {
        let message_path = if path.is_absolute() {
            path.clone()
        } else {
            repo.join(path)
        };
        let message = std::fs::read_to_string(&message_path)
            .map_err(|e| format!("read {}: {}", message_path.display(), e))?;
        (format!("message_file:{}", message_path.display()), message)
    } else {
        let message = read_commit_message_from_ref(&repo, &args.commit)?;
        (format!("commit:{}", args.commit), message)
    };

    let plan_witness_hash = extract_plan_witness_hash_from_message(&message)?;
    let artifact_present = plan_witness_artifact_exists(&artifacts_dir, &plan_witness_hash);
    if !artifact_present && !args.allow_missing_artifact {
        return Err(format!(
            "plan witness artifact not found for hash {} (expected {} or {})",
            plan_witness_hash,
            artifacts_dir
                .join("plan_witness")
                .join(format!("{}.cbor", plan_witness_hash))
                .display(),
            artifacts_dir
                .join("plan_witness")
                .join(format!("{}.json", plan_witness_hash))
                .display()
        ));
    }

    if args.json {
        let output = serde_json::json!({
            "valid": true,
            "plan_witness_hash": plan_witness_hash,
            "artifact_present": artifact_present,
            "source": source,
            "artifacts_dir": artifacts_dir.display().to_string(),
        });
        println!(
            "{}",
            serde_json::to_string(&output).map_err(|e| format!("json encode: {}", e))?
        );
    } else {
        println!("valid=true");
        println!("plan_witness_hash={}", plan_witness_hash);
        println!("artifact_present={}", artifact_present);
        println!("source={}", source);
        println!("artifacts_dir={}", artifacts_dir.display());
    }

    Ok(())
}

fn run_git_install_plan_hook(args: GitInstallPlanHookArgs) -> Result<(), String> {
    let repo = resolve_repo_path(&args.repo)?;
    let artifacts_dir = resolve_artifacts_dir(&repo, args.artifacts_dir);
    let git_dir = resolve_git_dir(&repo)?;
    let hooks_dir = git_dir.join("hooks");
    if !hooks_dir.exists() {
        std::fs::create_dir_all(&hooks_dir)
            .map_err(|e| format!("create hooks dir {}: {}", hooks_dir.display(), e))?;
    }
    let hook_path = hooks_dir.join("commit-msg");
    if hook_path.exists() && !args.force {
        return Err(format!(
            "hook already exists at {} (use --force to overwrite)",
            hook_path.display()
        ));
    }

    let repo_text = repo.display().to_string().replace('\\', "/");
    let artifacts_text = artifacts_dir.display().to_string().replace('\\', "/");
    let mut script = String::new();
    script.push_str("#!/bin/sh\n");
    script.push_str("set -eu\n");
    script.push_str(&format!(
        "ADMIT_CLI_BIN=\"${{ADMIT_CLI_BIN:-{}}}\"\n",
        args.admit_cli_bin
    ));
    script.push_str(&format!(
        "\"$ADMIT_CLI_BIN\" git verify-commit-plan --repo {} --message-file \"$1\" --artifacts-dir {}",
        shell_single_quote(&repo_text),
        shell_single_quote(&artifacts_text)
    ));
    if args.allow_missing_artifact {
        script.push_str(" --allow-missing-artifact");
    }
    script.push('\n');

    std::fs::write(&hook_path, script)
        .map_err(|e| format!("write hook {}: {}", hook_path.display(), e))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&hook_path)
            .map_err(|e| format!("metadata {}: {}", hook_path.display(), e))?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&hook_path, perms)
            .map_err(|e| format!("chmod {}: {}", hook_path.display(), e))?;
    }

    println!("hook_installed={}", hook_path.display());
    println!("repo={}", repo.display());
    println!("artifacts_dir={}", artifacts_dir.display());
    if args.allow_missing_artifact {
        println!("allow_missing_artifact=true");
    }
    Ok(())
}

fn read_commit_message_from_ref(repo: &Path, reference: &str) -> Result<String, String> {
    git_output(
        repo,
        &[
            String::from("show"),
            String::from("-s"),
            String::from("--format=%B"),
            reference.to_string(),
        ],
    )
}

fn extract_plan_witness_hash_from_message(message: &str) -> Result<String, String> {
    let mut found: Option<String> = None;
    for (line_idx, line) in message.lines().enumerate() {
        match parse_plan_hash_from_line(line) {
            Ok(Some(hash)) => {
                if let Some(existing) = found.as_ref() {
                    if existing != &hash {
                        return Err(format!(
                            "multiple plan hashes found in commit message: {} and {}",
                            existing, hash
                        ));
                    }
                } else {
                    found = Some(hash);
                }
            }
            Ok(None) => {}
            Err(err) => {
                return Err(format!(
                    "invalid plan witness hash on line {}: {}",
                    line_idx + 1,
                    err
                ))
            }
        }
    }
    found.ok_or_else(|| {
        "missing plan witness hash in commit message (add `Plan-Witness: <64-hex>`)".to_string()
    })
}

fn parse_plan_hash_from_line(line: &str) -> Result<Option<String>, String> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    for sep in [':', '='] {
        if let Some((label, value)) = trimmed.split_once(sep) {
            let normalized = normalize_plan_label(label);
            if normalized != "planwitness" && normalized != "planid" && normalized != "planhash" {
                continue;
            }
            let token = value
                .trim()
                .split_whitespace()
                .next()
                .unwrap_or("")
                .trim_matches(|ch: char| ",.;)]}".contains(ch));
            if token.is_empty() {
                return Err("missing hash value after plan label".to_string());
            }
            if !is_valid_sha256_hex(token) {
                return Err(format!(
                    "expected 64 hex characters after plan label, got `{}`",
                    token
                ));
            }
            return Ok(Some(token.to_ascii_lowercase()));
        }
    }
    Ok(None)
}

fn normalize_plan_label(label: &str) -> String {
    label
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect::<String>()
}

fn is_valid_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn resolve_artifacts_dir(repo: &Path, artifacts_dir: Option<PathBuf>) -> PathBuf {
    let dir = artifacts_dir.unwrap_or_else(default_artifacts_dir);
    if dir.is_absolute() {
        dir
    } else {
        repo.join(dir)
    }
}

fn plan_witness_artifact_exists(artifacts_dir: &Path, plan_hash: &str) -> bool {
    let kind_dir = artifacts_dir.join("plan_witness");
    let cbor = kind_dir.join(format!("{}.cbor", plan_hash));
    let json = kind_dir.join(format!("{}.json", plan_hash));
    cbor.exists() || json.exists()
}

fn resolve_git_dir(repo: &Path) -> Result<PathBuf, String> {
    let git_dir_text = git_output(
        repo,
        &[String::from("rev-parse"), String::from("--git-dir")],
    )?;
    let git_dir = PathBuf::from(git_dir_text.trim());
    if git_dir.is_absolute() {
        Ok(git_dir)
    } else {
        Ok(repo.join(git_dir))
    }
}

fn shell_single_quote(value: &str) -> String {
    let escaped = value.replace('\'', "'\"'\"'");
    format!("'{}'", escaped)
}

fn resolve_repo_path(path: &Path) -> Result<PathBuf, String> {
    if !path.exists() {
        return Err(format!("repo path not found: {}", path.display()));
    }
    let repo = path
        .canonicalize()
        .map_err(|e| format!("canonicalize repo path: {}", e))?;
    if !repo.is_dir() {
        return Err(format!("repo path must be a directory: {}", repo.display()));
    }
    Ok(repo)
}

fn build_git_metadata(
    source_ref: Option<String>,
    purpose: Option<String>,
) -> Option<admit_core::GitWitnessMetadata> {
    if source_ref.is_none() && purpose.is_none() {
        None
    } else {
        Some(admit_core::GitWitnessMetadata {
            source_ref,
            purpose,
        })
    }
}

fn default_repository_id(repo: &Path) -> String {
    if let Some(name) = repo.file_name().and_then(|n| n.to_str()) {
        format!("repo:{}", name)
    } else {
        format!("repo:{}", repo.display().to_string().replace('\\', "/"))
    }
}

fn git_resolve_commit_oid(repo: &Path, reference: &str) -> Result<String, String> {
    let oid = git_output(repo, &[String::from("rev-parse"), reference.to_string()])?;
    let oid = oid.trim().to_string();
    if oid.is_empty() {
        return Err(format!("git rev-parse {} returned empty oid", reference));
    }
    Ok(oid)
}

fn git_is_clean_worktree(repo: &Path) -> Result<bool, String> {
    let status = git_output(
        repo,
        &[String::from("status"), String::from("--porcelain=1")],
    )?;
    Ok(status.trim().is_empty())
}

fn git_snapshot_tracked_files(
    repo: &Path,
    head_commit_oid: &str,
) -> Result<Vec<admit_core::GitSnapshotFile>, String> {
    let tree = git_output(
        repo,
        &[
            String::from("ls-tree"),
            String::from("-r"),
            String::from("--full-tree"),
            head_commit_oid.to_string(),
        ],
    )?;
    let mut files = Vec::new();
    for line in tree.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let (left, path) = line
            .split_once('\t')
            .ok_or_else(|| format!("unexpected ls-tree line: {}", line))?;
        let mut left_parts = left.split_whitespace();
        let _mode = left_parts.next();
        let kind = left_parts.next();
        let oid = left_parts.next();
        if kind != Some("blob") {
            continue;
        }
        let Some(blob_oid) = oid else {
            return Err(format!("missing blob oid in ls-tree line: {}", line));
        };
        files.push(admit_core::GitSnapshotFile {
            path: normalize_repo_path(path),
            blob_oid: blob_oid.to_string(),
        });
    }
    Ok(files)
}

fn git_snapshot_submodules(repo: &Path) -> Result<Vec<admit_core::GitSubmoduleState>, String> {
    let output = git_command(
        repo,
        &[
            String::from("submodule"),
            String::from("status"),
            String::from("--recursive"),
        ],
    )?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        if stderr.contains("No submodule mapping found")
            || stderr.contains("not initialized")
            || stderr.contains("No url found")
        {
            return Ok(Vec::new());
        }
        return Err(format!("git submodule status failed: {}", stderr));
    }
    let stdout = String::from_utf8(output.stdout).map_err(|e| format!("utf8 decode: {}", e))?;
    let mut submodules = Vec::new();
    for line in stdout.lines() {
        let mut parts = line.split_whitespace();
        let Some(raw_oid) = parts.next() else {
            continue;
        };
        let Some(path) = parts.next() else {
            continue;
        };
        let commit_oid = raw_oid.trim_start_matches(['-', '+', 'U', ' ']).to_string();
        submodules.push(admit_core::GitSubmoduleState {
            path: normalize_repo_path(path),
            commit_oid,
        });
    }
    Ok(submodules)
}

fn git_working_tree_manifest_sha256(repo: &Path) -> Result<String, String> {
    let output = git_command(
        repo,
        &[
            String::from("ls-files"),
            String::from("--cached"),
            String::from("--others"),
            String::from("--exclude-standard"),
            String::from("-z"),
        ],
    )?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!("git ls-files manifest failed: {}", stderr));
    }
    let mut paths = Vec::new();
    for entry in output
        .stdout
        .split(|b| *b == 0)
        .filter(|entry| !entry.is_empty())
    {
        let path = String::from_utf8(entry.to_vec()).map_err(|e| format!("utf8 decode: {}", e))?;
        paths.push(normalize_repo_path(&path));
    }
    paths.sort();
    paths.dedup();
    let manifest_value = serde_json::Value::Array(
        paths
            .into_iter()
            .map(serde_json::Value::String)
            .collect::<Vec<_>>(),
    );
    let cbor = admit_core::encode_canonical_value(&manifest_value).map_err(|e| e.to_string())?;
    Ok(hex::encode(sha2::Sha256::digest(cbor)))
}

fn git_diff_changes(
    repo: &Path,
    base_commit_oid: &str,
    head_commit_oid: &str,
) -> Result<Vec<admit_core::GitDiffFileChange>, String> {
    let status = git_output(
        repo,
        &[
            String::from("diff"),
            String::from("--name-status"),
            String::from("--find-renames"),
            String::from("--find-copies"),
            base_commit_oid.to_string(),
            head_commit_oid.to_string(),
        ],
    )?;
    let mut changes = Vec::new();
    for line in status.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let cols = line.split('\t').collect::<Vec<_>>();
        if cols.is_empty() {
            continue;
        }
        let status_code = cols[0];
        let kind = map_git_change_kind(status_code);
        let (old_path, new_path, path) =
            if status_code.starts_with('R') || status_code.starts_with('C') {
                if cols.len() < 3 {
                    return Err(format!("unexpected rename/copy diff line: {}", line));
                }
                let old_path = normalize_repo_path(cols[1]);
                let new_path = normalize_repo_path(cols[2]);
                let path = new_path.clone();
                (Some(old_path), Some(new_path), path)
            } else {
                if cols.len() < 2 {
                    return Err(format!("unexpected diff line: {}", line));
                }
                let p = normalize_repo_path(cols[1]);
                (Some(p.clone()), Some(p.clone()), p)
            };

        let old_blob_oid = match kind {
            admit_core::GitDiffChangeKind::Added => None,
            admit_core::GitDiffChangeKind::Renamed | admit_core::GitDiffChangeKind::Copied => {
                if let Some(old_path) = old_path.as_ref() {
                    git_blob_oid_at_commit(repo, base_commit_oid, old_path)?
                } else {
                    None
                }
            }
            _ => {
                if let Some(path_for_old) = old_path.as_ref() {
                    git_blob_oid_at_commit(repo, base_commit_oid, path_for_old)?
                } else {
                    None
                }
            }
        };

        let new_blob_oid = match kind {
            admit_core::GitDiffChangeKind::Deleted => None,
            admit_core::GitDiffChangeKind::Renamed | admit_core::GitDiffChangeKind::Copied => {
                if let Some(new_path) = new_path.as_ref() {
                    git_blob_oid_at_commit(repo, head_commit_oid, new_path)?
                } else {
                    None
                }
            }
            _ => {
                if let Some(path_for_new) = new_path.as_ref() {
                    git_blob_oid_at_commit(repo, head_commit_oid, path_for_new)?
                } else {
                    None
                }
            }
        };

        changes.push(admit_core::GitDiffFileChange {
            path,
            change_kind: kind,
            old_blob_oid,
            new_blob_oid,
            additions: None,
            deletions: None,
        });
    }
    Ok(changes)
}

fn map_git_change_kind(status_code: &str) -> admit_core::GitDiffChangeKind {
    if status_code.starts_with('A') {
        admit_core::GitDiffChangeKind::Added
    } else if status_code.starts_with('M') {
        admit_core::GitDiffChangeKind::Modified
    } else if status_code.starts_with('D') {
        admit_core::GitDiffChangeKind::Deleted
    } else if status_code.starts_with('R') {
        admit_core::GitDiffChangeKind::Renamed
    } else if status_code.starts_with('C') {
        admit_core::GitDiffChangeKind::Copied
    } else if status_code.starts_with('T') {
        admit_core::GitDiffChangeKind::TypeChanged
    } else if status_code.starts_with('U') {
        admit_core::GitDiffChangeKind::Unmerged
    } else {
        admit_core::GitDiffChangeKind::Unknown
    }
}

fn git_blob_oid_at_commit(
    repo: &Path,
    commit_oid: &str,
    path: &str,
) -> Result<Option<String>, String> {
    let spec = format!("{}:{}", commit_oid, path);
    let output = git_command(repo, &[String::from("rev-parse"), spec])?;
    if output.status.success() {
        let oid = String::from_utf8(output.stdout)
            .map_err(|e| format!("utf8 decode: {}", e))?
            .trim()
            .to_string();
        if oid.is_empty() {
            Ok(None)
        } else {
            Ok(Some(oid))
        }
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).to_lowercase();
        if stderr.contains("unknown revision or path")
            || stderr.contains("exists on disk, but not in")
            || stderr.contains("path '")
        {
            Ok(None)
        } else {
            Err(format!("git rev-parse {} failed: {}", path, stderr.trim()))
        }
    }
}

fn git_collect_signature_attestations(
    repo: &Path,
    base_commit_oid: Option<&str>,
    head_commit_oid: &str,
) -> Result<Vec<admit_core::GitSignatureAttestation>, String> {
    let rev_range = match base_commit_oid {
        Some(base) => format!("{}..{}", base, head_commit_oid),
        None => head_commit_oid.to_string(),
    };
    let commits_text = git_output(
        repo,
        &[
            String::from("rev-list"),
            String::from("--reverse"),
            rev_range,
        ],
    )?;
    let mut attestations = Vec::new();
    for commit_oid in commits_text
        .lines()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
    {
        let verify_out = git_command(
            repo,
            &[String::from("verify-commit"), commit_oid.to_string()],
        )?;
        let signer = git_output(
            repo,
            &[
                String::from("show"),
                String::from("-s"),
                String::from("--format=%GS"),
                commit_oid.to_string(),
            ],
        )
        .unwrap_or_default()
        .trim()
        .to_string();
        let signer = if signer.is_empty() {
            None
        } else {
            Some(signer)
        };
        let verification = if verify_out.status.success() {
            admit_core::GitSignatureVerification::Verified
        } else if signer.is_some() {
            admit_core::GitSignatureVerification::Unverified
        } else {
            admit_core::GitSignatureVerification::Unknown
        };
        attestations.push(admit_core::GitSignatureAttestation {
            commit_oid: commit_oid.to_string(),
            verification,
            signer,
        });
    }
    Ok(attestations)
}

fn normalize_repo_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    if let Some(stripped) = path.strip_prefix("./") {
        stripped.to_string()
    } else {
        path
    }
}

fn git_output(repo: &Path, args: &[String]) -> Result<String, String> {
    let output = git_command(repo, args)?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        return Err(format!("git {} failed: {}", args.join(" "), stderr));
    }
    String::from_utf8(output.stdout).map_err(|e| format!("utf8 decode: {}", e))
}

fn git_command(repo: &Path, args: &[String]) -> Result<std::process::Output, String> {
    std::process::Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .map_err(|e| format!("failed to execute git: {}", e))
}

fn write_json_pretty<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|e| format!("create out dir: {}", e))?;
        }
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(|e| format!("json encode: {}", e))?;
    std::fs::write(path, bytes).map_err(|e| format!("write {}: {}", path.display(), e))
}

fn read_json_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes = std::fs::read(path).map_err(|e| format!("read {}: {}", path.display(), e))?;
    serde_json::from_slice(&bytes).map_err(|e| format!("decode {}: {}", path.display(), e))
}

fn run_list_artifacts(
    args: ListArtifactsArgs,
    _dag_trace_out: Option<&Path>,
) -> Result<(), String> {
    let artifacts_dir = args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
    let entries = list_artifacts(&artifacts_dir).map_err(|err| err.to_string())?;

    if args.json {
        let json =
            serde_json::to_string(&entries).map_err(|err| format!("json encode: {}", err))?;
        println!("{}", json);
    } else {
        println!("artifacts_dir={}", artifacts_dir.display());
        println!("count={}", entries.len());
        for entry in entries {
            println!(
                "artifact kind={} sha256={} size_bytes={} path={}",
                entry.kind, entry.sha256, entry.size_bytes, entry.path
            );
        }
    }
    Ok(())
}

fn run_show_artifact(args: ShowArtifactArgs, _dag_trace_out: Option<&Path>) -> Result<(), String> {
    let artifacts_dir = args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
    let projection = read_artifact_projection(&artifacts_dir, &args.kind, &args.sha256)
        .map_err(|err| err.to_string())?;
    if let Some(bytes) = projection {
        let text = String::from_utf8(bytes).map_err(|err| format!("utf8 error: {}", err))?;
        println!("{}", text);
        return Ok(());
    }

    // Fallback: if there is no JSON projection, locate the artifact bytes on disk.
    // Most artifacts are stored as `<sha256>.cbor`, but some kinds (e.g. `file_blob`, `text_chunk`)
    // store the original extension (`.rs`, `.md`, `.toml`, ...).
    let kind_dir = artifacts_dir.join(&args.kind);
    let preferred = kind_dir.join(format!("{}.cbor", args.sha256));
    let path = if preferred.exists() {
        preferred
    } else {
        let mut found: Option<PathBuf> = None;
        if kind_dir.exists() {
            if let Ok(entries) = std::fs::read_dir(&kind_dir) {
                for entry in entries.flatten() {
                    let p = entry.path();
                    if !p.is_file() {
                        continue;
                    }
                    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("");
                    if stem == args.sha256 {
                        found = Some(p);
                        break;
                    }
                }
            }
        }
        found.ok_or_else(|| "artifact not found".to_string())?
    };

    let size = std::fs::metadata(&path)
        .map_err(|err| format!("artifact not found: {}", err))?
        .len();

    // If this is a text artifact, print it (best-effort UTF-8).
    if let Ok(bytes) = std::fs::read(&path) {
        if let Ok(text) = String::from_utf8(bytes) {
            println!("{}", text);
            return Ok(());
        }
    }
    if args.json {
        let output = serde_json::json!({
            "kind": args.kind,
            "sha256": args.sha256,
            "size_bytes": size,
            "path": path.strip_prefix(&artifacts_dir).ok().and_then(|p| p.to_str()).unwrap_or("")
        });
        let json = serde_json::to_string(&output).map_err(|err| format!("json encode: {}", err))?;
        println!("{}", json);
    } else {
        println!("kind={}", args.kind);
        println!("sha256={}", args.sha256);
        println!("size_bytes={}", size);
        let rel = path
            .strip_prefix(&artifacts_dir)
            .ok()
            .and_then(|p| p.to_str())
            .unwrap_or("");
        println!("path={}", rel);
    }
    Ok(())
}

fn run_registry(args: RegistryArgs, _dag_trace_out: Option<&Path>) -> Result<(), String> {
    match args.command {
        RegistryCommands::Init(init_args) => {
            registry_init(&init_args.out).map_err(|err| err.to_string())?;
            println!("registry_written={}", init_args.out.display());
            Ok(())
        }
        RegistryCommands::Build(build_args) => {
            let artifacts_dir = build_args
                .artifacts_dir
                .unwrap_or_else(default_artifacts_dir);
            let reference =
                registry_build(&build_args.input, &artifacts_dir).map_err(|err| err.to_string())?;
            println!("registry_hash={}", reference.sha256);
            println!("registry_path={}", reference.path.unwrap_or_default());
            Ok(())
        }
        RegistryCommands::Verify(verify_args) => {
            let ledger_path = verify_args.ledger.unwrap_or_else(default_ledger_path);
            let artifacts_dir = verify_args
                .artifacts_dir
                .unwrap_or_else(default_artifacts_dir);
            let report = verify_ledger(&ledger_path, Some(artifacts_dir.as_path()))
                .map_err(|err| err.to_string())?;
            println!("ledger={}", ledger_path.display());
            println!("entries={}", report.total);
            println!("issues={}", report.issues.len());
            for issue in &report.issues {
                let event_id = issue.event_id.as_deref().unwrap_or("-");
                let event_type = issue.event_type.as_deref().unwrap_or("-");
                println!(
                    "issue line={} event_id={} event_type={} message={}",
                    issue.line, event_id, event_type, issue.message
                );
            }
            if report.issues.is_empty() {
                Ok(())
            } else {
                Err("registry verification found issues".to_string())
            }
        }
        RegistryCommands::ScopeAdd(args) => run_scope_add(args),
        RegistryCommands::ScopeVerify(args) => run_scope_verify(args),
        RegistryCommands::ScopeList(args) => run_scope_list(args),
        RegistryCommands::ScopeShow(args) => run_scope_show(args),
    }
}

fn run_plan_new(
    args: PlanNewArgs,
    dag_trace_out: Option<&Path>,
    projection: &mut ProjectionCoordinator,
) -> Result<(), String> {
    let created_at = args
        .created_at
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));

    let input = PlanNewInput {
        answers_path: args.answers,
        scope: args.scope,
        target: args.target,
        surface: args.surface,
        tool_version: args.tool_version.unwrap_or_else(|| "unknown".to_string()),
        snapshot_hash: args.snapshot_hash,
        timestamp: created_at,
        artifacts_root: args.artifacts_dir,
        meta_registry_path: args.meta_registry,
    };

    let event = create_plan(input).map_err(|err| err.to_string())?;
    let ledger_path = args.ledger.unwrap_or_else(default_ledger_path);
    if !args.dry_run {
        append_plan_created_event(&ledger_path, &event).map_err(|err| err.to_string())?;
    }

    if args.json {
        let json = serde_json::to_string(&event).map_err(|err| format!("json encode: {}", err))?;
        println!("{}", json);
    } else {
        println!("event_id={}", event.event_id);
        println!("plan_id={}", event.plan_witness.sha256);
        println!("template_id={}", event.template_id);
        println!("ledger={}", ledger_path.display());
        if args.dry_run {
            println!("dry_run=true");
        }
    }

    let want_trace = dag_trace_out.is_some() || projection.is_active();
    if want_trace {
        let trace = build_trace_for_plan_created(&event)?;
        let (trace_sha256, trace_cbor) = encode_dag_trace(&trace)?;
        if let Some(out) = dag_trace_out {
            write_dag_trace(out, &trace_cbor)?;
            print_dag_trace_hint(args.json, out, &trace_sha256);
        }
        maybe_project_trace(projection, &trace_sha256, &trace_cbor, trace.dag())?;
    }

    Ok(())
}

fn run_plan_show(args: PlanShowArgs, _dag_trace_out: Option<&Path>) -> Result<(), String> {
    let artifacts_dir = args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
    let text = render_plan_text(&artifacts_dir, &args.plan_id).map_err(|err| err.to_string())?;
    print!("{}", text);
    Ok(())
}

fn run_plan_export(args: PlanExportArgs, _dag_trace_out: Option<&Path>) -> Result<(), String> {
    let artifacts_dir = args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
    let md = export_plan_markdown(&artifacts_dir, &args.plan_id).map_err(|err| err.to_string())?;

    if let Some(parent) = args.out.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent).map_err(|err| format!("create out dir: {}", err))?;
        }
    }
    std::fs::write(&args.out, &md).map_err(|err| format!("write export: {}", err))?;
    println!("exported={}", args.out.display());
    Ok(())
}

fn run_plan_prompt_template(
    args: PlanPromptTemplateArgs,
    _dag_trace_out: Option<&Path>,
) -> Result<(), String> {
    let template = render_plan_prompt_template(!args.no_guidance);
    if let Some(out) = args.out.as_ref() {
        if let Some(parent) = out.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .map_err(|err| format!("create out dir: {}", err))?;
            }
        }
        std::fs::write(out, template).map_err(|err| format!("write template: {}", err))?;
        println!("written={}", out.display());
    } else {
        print!("{}", template);
    }
    Ok(())
}

fn run_plan_answers_from_md(
    args: PlanAnswersFromMdArgs,
    _dag_trace_out: Option<&Path>,
) -> Result<(), String> {
    let markdown = std::fs::read_to_string(&args.input)
        .map_err(|err| format!("read {}: {}", args.input.display(), err))?;
    let answers = parse_plan_answers_markdown(&markdown).map_err(|err| err.to_string())?;
    let bytes =
        serde_json::to_vec_pretty(&answers).map_err(|err| format!("json encode: {}", err))?;

    if let Some(out) = args.out.as_ref() {
        if let Some(parent) = out.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)
                    .map_err(|err| format!("create out dir: {}", err))?;
            }
        }
        std::fs::write(out, bytes).map_err(|err| format!("write {}: {}", out.display(), err))?;
        println!("written={}", out.display());
    } else {
        let text = String::from_utf8(bytes).map_err(|err| format!("utf8 encode: {}", err))?;
        println!("{}", text);
    }
    Ok(())
}

fn run_scope_add(args: ScopeAddArgs) -> Result<(), String> {
    // Convert main.rs args to scope_commands args
    let cmd_args = ScopeAddArgsLib {
        scope: args.scope,
        scope_id: args.scope_id,
        version: args.version,
        snapshot_schema_id: args.snapshot_schema_id,
        phase: args.phase,
        deterministic: args.deterministic,
        foundational: args.foundational,
        emits: args.emits,
        consumes: args.consumes,
        deps: args.deps,
        role: args.role,
        contract_ref: args.contract_ref,
        registry: args.registry.clone(),
        validation_level: args.validation_level,
        dry_run: args.dry_run,
    };

    let witness = scope_add(cmd_args).map_err(|err| err.to_string())?;

    println!("scope_id={}", witness.scope_id);
    println!("scope_version={}", witness.scope_version);
    println!(
        "registry_version={} -> {}",
        witness.registry_version_before, witness.registry_version_after
    );
    println!("registry_hash_before={}", witness.registry_hash_before);
    println!("registry_hash_after={}", witness.registry_hash_after);
    println!("registry={}", args.registry.display());

    if args.dry_run {
        println!("dry_run=true (registry not modified)");
    }

    // Show validation results
    let warnings: Vec<_> = witness
        .validations
        .iter()
        .filter(|v| !v.passed && v.severity.to_string() == "warning")
        .collect();

    if !warnings.is_empty() {
        eprintln!("\nWarnings:");
        for w in warnings {
            eprintln!(
                "  {}: {}",
                w.check,
                w.message.as_deref().unwrap_or("failed")
            );
        }
    }

    Ok(())
}

fn run_scope_verify(args: ScopeVerifyArgs) -> Result<(), String> {
    let cmd_args = ScopeVerifyArgsLib {
        scope_id: args.scope_id.clone(),
        registry: args.registry.clone(),
        validation_level: args.validation_level,
        json: args.json,
    };

    let validations = scope_verify(cmd_args).map_err(|err| err.to_string())?;

    if args.json {
        let json =
            serde_json::to_string(&validations).map_err(|err| format!("json encode: {}", err))?;
        println!("{}", json);
    } else {
        println!("scope_id={}", args.scope_id);
        println!("registry={}", args.registry.display());
        println!("validations={}", validations.len());

        let passed = validations.iter().filter(|v| v.passed).count();
        let failed = validations.len() - passed;
        println!("passed={} failed={}", passed, failed);

        for v in &validations {
            let status = if v.passed { "PASS" } else { "FAIL" };
            let msg = v.message.as_deref().unwrap_or("");
            println!("{} [{}] {}: {}", status, v.severity, v.check, msg);
        }

        if failed > 0 {
            return Err(format!("validation failed with {} error(s)", failed));
        }
    }

    Ok(())
}

fn run_scope_list(args: ScopeListArgs) -> Result<(), String> {
    let cmd_args = ScopeListArgsLib {
        registry: args.registry.clone(),
        phase: args.phase,
        role: args.role,
        json: args.json,
    };

    let scopes = scope_list(cmd_args).map_err(|err| err.to_string())?;

    if args.json {
        let json = serde_json::to_string(&scopes).map_err(|err| format!("json encode: {}", err))?;
        println!("{}", json);
    } else {
        println!("registry={}", args.registry.display());
        println!("count={}", scopes.len());
        for scope in &scopes {
            let phase_str = scope
                .phase
                .map(|p| format!("{:?}", p))
                .unwrap_or_else(|| "-".to_string());
            let role_str = scope
                .role
                .as_ref()
                .map(|r| format!("{:?}", r))
                .unwrap_or_else(|| "-".to_string());
            println!(
                "scope id={} version={} phase={} role={}",
                scope.id, scope.version, phase_str, role_str
            );
        }
    }

    Ok(())
}

fn run_scope_show(args: ScopeShowArgs) -> Result<(), String> {
    let cmd_args = ScopeShowArgsLib {
        scope_id: args.scope_id.clone(),
        registry: args.registry.clone(),
        json: args.json,
    };

    let scope = scope_show(cmd_args).map_err(|err| err.to_string())?;

    if args.json {
        let json = serde_json::to_string(&scope).map_err(|err| format!("json encode: {}", err))?;
        println!("{}", json);
    } else {
        println!("scope_id={}", scope.id);
        println!("version={}", scope.version);
        if let Some(phase) = scope.phase {
            println!("phase={:?}", phase);
        }
        if let Some(role) = scope.role.as_ref() {
            println!("role={:?}", role);
        }
        if let Some(det) = scope.deterministic {
            println!("deterministic={}", det);
        }
        if let Some(found) = scope.foundational {
            println!("foundational={}", found);
        }
        if let Some(snapshot_id) = scope.snapshot_schema_id.as_ref() {
            println!("snapshot_schema_id={}", snapshot_id);
        }
        if let Some(emits) = scope.emits.as_ref() {
            println!("emits={}", emits.join(", "));
        }
        if let Some(consumes) = scope.consumes.as_ref() {
            println!("consumes={}", consumes.join(", "));
        }
        if let Some(deps) = scope.deps.as_ref() {
            println!("deps={}", deps.join(", "));
        }
        if let Some(contract) = scope.contract_ref.as_ref() {
            println!("contract_ref={}", contract);
        }
    }

    Ok(())
}

fn run_calc_plan(
    args: CalcPlanArgs,
    dag_trace_out: Option<&Path>,
    projection: &mut ProjectionCoordinator,
) -> Result<(), String> {
    use admit_cli::calc_commands::calc_plan;

    let plan = calc_plan(
        &args.expression,
        args.input_contracts,
        args.output_unit,
        &args.out,
    )
    .map_err(|err| err.to_string())?;

    // Compute plan hash for output
    let plan_value = serde_json::to_value(&plan)
        .map_err(|e| format!("failed to convert plan to value: {}", e))?;
    let plan_cbor = admit_core::encode_canonical_value(&plan_value)
        .map_err(|e| format!("failed to encode plan: {}", e))?;
    let plan_hash = hex::encode(sha2::Sha256::digest(&plan_cbor));

    println!("plan_hash={}", plan_hash);
    println!("mechanism_id={}", plan.mechanism_id);
    println!("touched_scope={}", plan.touched_scope);
    println!("inputs={}", plan.inputs.len());
    println!("out={}", args.out.display());

    let want_trace = dag_trace_out.is_some() || projection.is_active();
    if want_trace {
        let trace = build_trace_for_calc_plan(&plan_hash)?;
        let (trace_sha256, trace_cbor) = encode_dag_trace(&trace)?;
        if let Some(out) = dag_trace_out {
            write_dag_trace(out, &trace_cbor)?;
            print_dag_trace_hint(false, out, &trace_sha256);
        }
        maybe_project_trace(projection, &trace_sha256, &trace_cbor, trace.dag())?;
    }

    Ok(())
}

fn run_calc_execute(
    args: CalcExecuteArgs,
    dag_trace_out: Option<&Path>,
    projection: &mut ProjectionCoordinator,
) -> Result<(), String> {
    use admit_cli::calc_commands::calc_execute;

    let witness = calc_execute(
        &args.plan,
        args.inputs,
        args.trace,
        &args.out,
        args.artifacts_dir.as_deref(),
    )
    .map_err(|err| err.to_string())?;

    // Compute witness identity hash (core payload only)
    let core_value = serde_json::to_value(&witness.core)
        .map_err(|e| format!("failed to convert core to value: {}", e))?;
    let core_cbor = admit_core::encode_canonical_value(&core_value)
        .map_err(|e| format!("failed to encode core: {}", e))?;
    let witness_hash = hex::encode(sha2::Sha256::digest(&core_cbor));

    println!("witness_hash={}", witness_hash);
    println!("plan_hash={}", witness.core.plan_hash);
    println!("output_value={:?}", witness.core.output.value);
    if let Some(unit) = &witness.core.output.unit {
        println!("output_unit={}", unit);
    }
    if let Some(trace) = &witness.envelope.trace {
        println!("trace_steps={}", trace.len());
    }
    println!("out={}", args.out.display());

    let want_trace = dag_trace_out.is_some() || projection.is_active();
    if want_trace {
        let trace = build_trace_for_calc_result(&witness.core.plan_hash, &witness_hash)?;
        let (trace_sha256, trace_cbor) = encode_dag_trace(&trace)?;
        if let Some(out) = dag_trace_out {
            write_dag_trace(out, &trace_cbor)?;
            print_dag_trace_hint(false, out, &trace_sha256);
        }
        maybe_project_trace(projection, &trace_sha256, &trace_cbor, trace.dag())?;
    }

    Ok(())
}

fn run_calc_describe(_args: CalcDescribeArgs, _dag_trace_out: Option<&Path>) -> Result<(), String> {
    use admit_cli::calc_commands::calc_describe;

    let desc = calc_describe();
    let json = serde_json::to_string_pretty(&desc)
        .map_err(|e| format!("failed to serialize description: {}", e))?;

    println!("{}", json);

    Ok(())
}

fn run_ingest_dir(
    args: IngestDirArgs,
    dag_trace_out: Option<&Path>,
    projection: &mut ProjectionCoordinator,
    projection_force: bool,
) -> Result<(), String> {
    let scope_enablement = resolve_scope_enablement(&args.path)?;
    let obsidian_scope_enabled = scope_enablement.allows(ScopeOperation::ObsidianLinksProjection);

    let artifacts_dir = args
        .artifacts_dir
        .clone()
        .unwrap_or_else(default_artifacts_dir);
    let ledger_path = args.ledger.clone().unwrap_or_else(default_ledger_path);
    let incremental_cache = args.incremental_cache.clone().or_else(|| {
        std::env::var("ADMIT_INCREMENTAL_CACHE")
            .ok()
            .map(PathBuf::from)
    });
    let proto = ingest_dir_protocol_with_cache(
        &args.path,
        Some(&artifacts_dir),
        incremental_cache.as_deref(),
    )
    .map_err(|err| err.to_string())?;
    let admit_cli::IngestDirProtocolOutput {
        ingest_run_id,
        config,
        events,
        error,
        out,
        coverage,
        ingest_run: ingest_run_record,
        ..
    } = proto;

    if !args.no_ledger {
        for ev in events.iter() {
            append_ingest_event(&ledger_path, ev).map_err(|e| e.to_string())?;
        }
    }

    projection.with_store("surrealdb ingest projection", |surreal| {
        let store_ops: &dyn ProjectionStoreOps = surreal;
        store_ops
            .ensure_schemas()
            .map_err(|err| format!("surrealdb ensure schemas failed: {}", err))?;

        let rows: Vec<IngestEventRow> = events.iter().map(to_ingest_event_row).collect();
        store_ops
            .project_ingest_events(&rows)
            .map_err(|err| format!("surrealdb project ingest events failed: {}", err))?;

        let started_at = events
            .iter()
            .find(|e| e.event_type == "ingest.run.started")
            .map(|e| e.timestamp.clone())
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        let completed = events
            .iter()
            .rev()
            .find(|e| e.event_type == "ingest.run.completed");
        let finished_at = completed.map(|e| e.timestamp.clone());
        let status = completed
            .and_then(|e| e.status.clone())
            .unwrap_or_else(|| "unknown".to_string());
        let root = events
            .iter()
            .find_map(|e| e.root.clone())
            .unwrap_or_else(|| args.path.to_string_lossy().to_string());

        store_ops
            .project_ingest_run(&IngestRunRow {
                ingest_run_id: ingest_run_id.clone(),
                started_at,
                finished_at,
                status,
                root,
                config_sha256: config.sha256.clone(),
                coverage_sha256: coverage.as_ref().map(|a| a.sha256.clone()),
                ingest_run_sha256: ingest_run_record.as_ref().map(|a| a.sha256.clone()),
                snapshot_sha256: completed.and_then(|e| e.snapshot_sha256.clone()),
                parse_sha256: completed.and_then(|e| e.parse_sha256.clone()),
                files: completed.and_then(|e| e.files),
                chunks: completed.and_then(|e| e.chunks),
                total_bytes: completed.and_then(|e| e.total_bytes),
            })
            .map_err(|err| format!("surrealdb project ingest run failed: {}", err))?;
        Ok(())
    })?;

    let out = match out {
        Some(out) => out,
        None => return Err(error.unwrap_or_else(|| "ingest failed".to_string())),
    };

    if args.json {
        let value = serde_json::json!({
            "ingest_run_id": ingest_run_id,
            "root": out.root,
            "snapshot_sha256": out.snapshot_sha256,
            "parse_sha256": out.parse_sha256,
            "coverage_sha256": coverage.as_ref().map(|a| a.sha256.clone()),
            "config_sha256": config.sha256,
            "files": out.files.len(),
            "chunks": out.chunks.len(),
            "total_bytes": out.total_bytes,
            "artifacts_dir": artifacts_dir,
            "incremental": out.incremental.as_ref().map(|inc| serde_json::json!({
                "enabled": inc.enabled,
                "cache_path": inc.cache_path.as_ref().map(|p| p.to_string_lossy().to_string()),
                "cache_reset": inc.cache_reset,
                "cache_reset_reason": inc.cache_reset_reason,
                "files_cached": inc.files_cached,
                "files_parsed": inc.files_parsed,
                "chunks_cached": inc.chunks_cached,
                "chunks_parsed": inc.chunks_parsed,
                "docs_to_resolve_links": inc.docs_to_resolve_links.len(),
            })),
        });
        println!(
            "{}",
            serde_json::to_string(&value).map_err(|err| format!("json encode: {}", err))?
        );
    } else {
        println!("ingest_run_id={}", ingest_run_id);
        println!("root={}", out.root.display());
        println!("snapshot_sha256={}", out.snapshot_sha256);
        println!("parse_sha256={}", out.parse_sha256);
        println!("config_sha256={}", config.sha256);
        if let Some(cov) = coverage.as_ref() {
            println!("coverage_sha256={}", cov.sha256);
        }
        println!("files={}", out.files.len());
        println!("chunks={}", out.chunks.len());
        println!("total_bytes={}", out.total_bytes);
        println!("artifacts_dir={}", artifacts_dir.display());
        if let Some(inc) = out.incremental.as_ref() {
            println!("incremental_enabled={}", inc.enabled);
            if let Some(path) = inc.cache_path.as_ref() {
                println!("incremental_cache={}", path.display());
            }
            println!("incremental_files_cached={}", inc.files_cached);
            println!("incremental_files_parsed={}", inc.files_parsed);
            println!("incremental_chunks_cached={}", inc.chunks_cached);
            println!("incremental_chunks_parsed={}", inc.chunks_parsed);
            println!(
                "incremental_docs_to_resolve_links={}",
                inc.docs_to_resolve_links.len()
            );
        }
    }

    let want_trace = dag_trace_out.is_some() || projection.is_active();
    if want_trace {
        let trace = build_trace_for_ingest_dir(&out)?;
        let (trace_sha256, trace_cbor) = encode_dag_trace(&trace)?;
        if let Some(out_path) = dag_trace_out {
            write_dag_trace(out_path, &trace_cbor)?;
            print_dag_trace_hint(args.json, out_path, &trace_sha256);
        }
        let docs_to_resolve = out.incremental.as_ref().and_then(|inc| {
            if !inc.enabled {
                return None;
            }
            let set = inc
                .docs_to_resolve_links
                .iter()
                .cloned()
                .collect::<std::collections::BTreeSet<String>>();
            // Important: an empty set means "skip link work" (fast path), not "resolve everything".
            Some(set)
        });
        let mut projection_run_id: Option<String> = None;
        let mut bench_first_ms: Option<u64> = None;
        let mut bench_second_ms: Option<u64> = None;
        let start = std::time::Instant::now();
        let summary = projection.with_store("surrealdb projection", |surreal| {
            project_ingest_dir_projections(
                &args,
                surreal,
                &ledger_path,
                &trace_sha256,
                &trace_cbor,
                trace.dag(),
                &artifacts_dir,
                &ingest_run_id,
                docs_to_resolve.as_ref(),
                obsidian_scope_enabled,
                args.bench,
                projection_force,
            )
        })?;
        let elapsed = start.elapsed().as_millis() as u64;
        if args.bench {
            if args.json {
                eprintln!("projection_bench_first_ms={}", elapsed);
            } else {
                println!("projection_bench_first_ms={}", elapsed);
            }
        }
        if let Some(summary) = summary {
            projection_run_id = Some(summary.run_id.clone());
            bench_first_ms = Some(elapsed);
            projection.record_summary(summary);
        }

        if args.bench {
            let start = std::time::Instant::now();
            let summary = projection.with_store("surrealdb projection", |surreal| {
                project_ingest_dir_projections(
                    &args,
                    surreal,
                    &ledger_path,
                    &trace_sha256,
                    &trace_cbor,
                    trace.dag(),
                    &artifacts_dir,
                    &ingest_run_id,
                    docs_to_resolve.as_ref(),
                    obsidian_scope_enabled,
                    args.bench,
                    projection_force,
                )
            })?;
            let elapsed = start.elapsed().as_millis() as u64;
            if args.json {
                eprintln!("projection_bench_second_ms={}", elapsed);
            } else {
                println!("projection_bench_second_ms={}", elapsed);
            }
            if let Some(summary) = summary {
                projection_run_id = Some(summary.run_id.clone());
                bench_second_ms = Some(elapsed);
                projection.record_summary(summary);
            }

            if let (Some(first), Some(second)) = (bench_first_ms, bench_second_ms) {
                let delta = first as i64 - second as i64;
                let sign = if delta >= 0 { "-" } else { "+" };
                let delta_abs = delta.unsigned_abs();
                if args.json {
                    eprintln!(
                        "projection_bench_total_ms={{\"first\":{},\"second\":{},\"delta_ms\":\"{}{}\"}}",
                        first, second, sign, delta_abs
                    );
                } else {
                    println!("projection_bench_first_ms={}", first);
                    println!("projection_bench_second_ms={}", second);
                    println!("projection_bench_delta_ms={}{}", sign, delta_abs);
                }
            } else if bench_first_ms.is_none() {
                if args.json {
                    eprintln!("projection_bench_skipped=true");
                } else {
                    println!("projection_bench_skipped=true");
                }
            }
        }

        if args.ollama_embed {
            let surreal = projection.require_store("ollama embedding")?;
            project_ollama_embeddings_for_trace(
                &args,
                surreal,
                trace.dag(),
                &artifacts_dir,
                projection_run_id.as_deref(),
            )?;
        }
    }

    projection.print_summary(args.json);

    Ok(())
}

fn run_projection_vacuum(
    args: ProjectionVacuumArgs,
    projection: &ProjectionCoordinator,
) -> Result<(), String> {
    use admit_surrealdb::projection_store::ProjectionStoreOps;

    let store = projection.require_store("projection vacuum")?;
    let store_ops: &dyn ProjectionStoreOps = store;
    if !store
        .is_ready()
        .map_err(|e| format!("surrealdb is-ready failed: {}", e))?
    {
        return Err("surrealdb endpoint not ready".to_string());
    }
    store_ops
        .ensure_schemas()
        .map_err(|err| format!("surrealdb ensure schemas failed: {}", err))?;

    let ledger_path = args.ledger.clone().unwrap_or_else(default_ledger_path);
    let artifacts_dir = args
        .artifacts_dir
        .clone()
        .unwrap_or_else(default_artifacts_dir);

    let run_ids = if let Some(run_id) = args.run.clone() {
        vec![run_id]
    } else if let Some(before_run) = args.before_run.as_ref() {
        let Some(started_at) = store
            .projection_run_started_at(before_run)
            .map_err(|e| format!("lookup projection run {}: {}", before_run, e))?
        else {
            return Err(format!("projection run not found: {}", before_run));
        };
        store
            .projection_run_ids_before(&started_at)
            .map_err(|e| format!("list projection runs before {}: {}", before_run, e))?
    } else {
        return Err("projection vacuum requires --before-run or --run".to_string());
    };

    if run_ids.is_empty() {
        if args.json {
            let value = serde_json::json!({
                "before_run": args.before_run,
                "run": args.run,
                "dry_run": args.dry_run,
                "runs": run_ids,
            });
            println!(
                "{}",
                serde_json::to_string(&value).map_err(|err| format!("json encode: {}", err))?
            );
        } else {
            println!("projection_vacuum_runs=0");
        }
        return Ok(());
    }

    let before_run = args.before_run.clone();
    let run = args.run.clone();

    let op_started_at = chrono::Utc::now().to_rfc3339();
    let op_id = sha256_hex(&format!(
        "projection.vacuum.v1|{}|{}|{}|{}|{}|{}|{}",
        op_started_at,
        before_run.clone().unwrap_or_default(),
        run.clone().unwrap_or_default(),
        args.dry_run,
        store.config().endpoint,
        store.config().namespace.clone().unwrap_or_default(),
        store.config().database.clone().unwrap_or_default(),
    ));

    let meta_base = serde_json::json!({
        "before_run": before_run.clone(),
        "run": run.clone(),
        "dry_run": args.dry_run,
        "runs": run_ids.clone(),
        "runs_deleted": run_ids.len(),
        "surrealdb": {
            "endpoint": store.config().endpoint,
            "namespace": store.config().namespace,
            "database": store.config().database,
        },
    });

    let ev_started = build_projection_event(
        "projection.vacuum.started",
        &op_id,
        op_started_at.clone(),
        None,
        None,
        Some("running".to_string()),
        None,
        None,
        None,
        None,
        Some(meta_base.clone()),
    )
    .map_err(|e| e.to_string())?;
    if !args.no_ledger {
        append_projection_event(&ledger_path, &ev_started).map_err(|e| e.to_string())?;
    }
    store_ops
        .project_projection_events(&[to_projection_event_row(&ev_started)])
        .map_err(|err| format!("surrealdb project events failed: {}", err))?;

    let start = std::time::Instant::now();
    if !args.dry_run {
        store
            .vacuum_projection_runs(&run_ids)
            .map_err(|e| format!("projection vacuum failed: {}", e))?;
    }
    let duration_ms = start.elapsed().as_millis() as u64;

    let vacuum_value = serde_json::json!({
        "schema_id": "projection-vacuum/1",
        "created_at_utc": chrono::Utc::now().to_rfc3339(),
        "op_id": op_id,
        "before_run": before_run.clone(),
        "run": run.clone(),
        "dry_run": args.dry_run,
        "runs_deleted": run_ids.len(),
        "runs": run_ids.clone(),
        "surrealdb": {
            "endpoint": store.config().endpoint,
            "namespace": store.config().namespace,
            "database": store.config().database,
        },
    });
    let vacuum_artifact = admit_cli::store_value_artifact(
        &artifacts_dir,
        "projection_vacuum",
        "projection-vacuum/1",
        &vacuum_value,
    )
    .map_err(|e| e.to_string())?;

    let completed_at = chrono::Utc::now().to_rfc3339();
    let ev_completed = build_projection_event(
        "projection.vacuum.completed",
        &op_id,
        completed_at.clone(),
        None,
        None,
        Some(if args.dry_run {
            "dry_run".to_string()
        } else {
            "complete".to_string()
        }),
        Some(duration_ms),
        None,
        None,
        None,
        Some(serde_json::json!({
            "artifact": vacuum_artifact,
            "details": meta_base,
        })),
    )
    .map_err(|e| e.to_string())?;
    if !args.no_ledger {
        append_projection_event(&ledger_path, &ev_completed).map_err(|e| e.to_string())?;
    }
    store_ops
        .project_projection_events(&[to_projection_event_row(&ev_completed)])
        .map_err(|err| format!("surrealdb project events failed: {}", err))?;

    if args.json {
        let value = serde_json::json!({
            "before_run": before_run,
            "run": run,
            "dry_run": args.dry_run,
            "runs": ev_started.meta.as_ref().and_then(|m| m.get("runs")).cloned().unwrap_or_else(|| serde_json::json!([])),
            "runs_deleted": run_ids.len(),
            "ledger": ledger_path,
            "artifacts_dir": artifacts_dir,
            "artifact": vacuum_artifact,
            "events": [ev_started, ev_completed],
        });
        println!(
            "{}",
            serde_json::to_string(&value).map_err(|err| format!("json encode: {}", err))?
        );
    } else {
        println!("projection_vacuum_runs={}", run_ids.len());
        for run_id in &run_ids {
            println!("run_id={}", run_id);
        }
    }

    Ok(())
}

fn run_projection_retry(
    args: ProjectionRetryArgs,
    projection: &ProjectionCoordinator,
) -> Result<(), String> {
    use admit_surrealdb::projection_run::{PhaseResult, PhaseStatus};
    use admit_surrealdb::projection_store::ProjectionStoreOps;

    let store = projection.require_store("projection retry")?;
    let store_ops: &dyn ProjectionStoreOps = store;
    if !store
        .is_ready()
        .map_err(|e| format!("surrealdb is-ready failed: {}", e))?
    {
        return Err("surrealdb endpoint not ready".to_string());
    }
    store_ops
        .ensure_schemas()
        .map_err(|err| format!("surrealdb ensure schemas failed: {}", err))?;

    let ledger_path = args.ledger.clone().unwrap_or_else(default_ledger_path);

    let run_value = store
        .projection_run_record(&args.run)
        .map_err(|e| format!("load projection run {}: {}", args.run, e))?
        .ok_or_else(|| format!("projection run not found: {}", args.run))?;

    let trace_sha256 = run_value
        .get("trace_sha256")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "projection run missing trace_sha256".to_string())?
        .to_string();

    let phases_enabled: Vec<String> = run_value
        .get("phases_enabled")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let phase_results_value = run_value
        .get("phase_results")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let phase_results_value = if let serde_json::Value::String(s) = &phase_results_value {
        serde_json::from_str::<serde_json::Value>(s)
            .map_err(|e| format!("parse phase_results: {}", e))?
    } else {
        phase_results_value
    };

    let mut phase_results: std::collections::BTreeMap<String, PhaseResult> =
        serde_json::from_value(phase_results_value)
            .map_err(|e| format!("decode phase_results: {}", e))?;

    let mut target_phases: Vec<String> = if let Some(phase) = args.phase.clone() {
        vec![phase]
    } else {
        phase_results
            .iter()
            .filter(|(_, r)| r.status == PhaseStatus::Failed || !r.failed_batches.is_empty())
            .map(|(k, _)| k.clone())
            .collect()
    };
    target_phases = target_phases
        .into_iter()
        .map(|p| obsidian_adapter::normalize_obsidian_vault_links_phase(&p))
        .collect();
    target_phases.sort();
    target_phases.dedup();

    if let Some(batch_hash) = args.batch.as_ref() {
        let mut found_phase = None;
        for (phase, result) in phase_results.iter() {
            if result
                .failed_batches
                .iter()
                .any(|b| &b.batch_hash == batch_hash)
            {
                found_phase = Some(phase.clone());
                break;
            }
        }
        if let Some(phase) = found_phase {
            target_phases = vec![phase];
        } else {
            return Err(format!("batch hash not found in run {}", args.run));
        }
    }

    if target_phases.is_empty() {
        if args.json {
            let value = serde_json::json!({
                "run": args.run,
                "dry_run": args.dry_run,
                "phases": [],
            });
            println!(
                "{}",
                serde_json::to_string(&value).map_err(|err| format!("json encode: {}", err))?
            );
        } else {
            println!("projection_retry_phases=0");
        }
        return Ok(());
    }

    let artifacts_dir = args
        .artifacts_dir
        .clone()
        .unwrap_or_else(default_artifacts_dir);

    let mut retry_plan: Vec<(String, usize)> = Vec::new();
    for phase in &target_phases {
        if let Some(result) = phase_results.get(phase) {
            let mut count = result.failed_batches.len();
            if let Some(batch_hash) = args.batch.as_ref() {
                count = result
                    .failed_batches
                    .iter()
                    .filter(|b| &b.batch_hash == batch_hash)
                    .count();
            }
            retry_plan.push((phase.clone(), count));
        }
    }

    if args.dry_run {
        if args.json {
            let value = serde_json::json!({
                "run": args.run,
                "dry_run": true,
                "phases": retry_plan.iter().map(|(p, c)| serde_json::json!({"phase": p, "failed_batches": c})).collect::<Vec<_>>(),
            });
            println!(
                "{}",
                serde_json::to_string(&value).map_err(|err| format!("json encode: {}", err))?
            );
        } else {
            println!("projection_retry_phases={}", retry_plan.len());
            for (phase, count) in retry_plan {
                println!("phase={} failed_batches={}", phase, count);
            }
        }
        return Ok(());
    }

    let requested_phase = args.phase.clone();
    let requested_batch = args.batch.clone();

    let ev_started = build_projection_event(
        "projection.retry.started",
        &args.run,
        chrono::Utc::now().to_rfc3339(),
        Some(trace_sha256.clone()),
        requested_phase.clone(),
        Some("running".to_string()),
        None,
        None,
        None,
        None,
        Some(serde_json::json!({
            "requested_phase": requested_phase,
            "requested_batch": requested_batch,
            "retry_plan": retry_plan.iter().map(|(p, c)| serde_json::json!({"phase": p, "failed_batches": c})).collect::<Vec<_>>(),
        })),
    )
    .map_err(|e| e.to_string())?;
    if !args.no_ledger {
        append_projection_event(&ledger_path, &ev_started).map_err(|e| e.to_string())?;
    }
    store_ops
        .project_projection_events(&[to_projection_event_row(&ev_started)])
        .map_err(|err| format!("surrealdb project events failed: {}", err))?;

    let trace_bytes = store
        .dag_trace_bytes_for_trace(&trace_sha256)
        .map_err(|e| format!("load dag_trace {}: {}", trace_sha256, e))?;
    let trace_value: serde_json::Value = serde_cbor::from_slice(&trace_bytes)
        .map_err(|e| format!("decode dag_trace cbor: {}", e))?;
    let dag: admit_dag::GovernedDag =
        serde_json::from_value(trace_value).map_err(|e| format!("decode dag from trace: {}", e))?;

    for phase in target_phases.iter() {
        let Some(original) = phase_results.get(phase).cloned() else {
            continue;
        };

        let mut selected_batches: Vec<admit_surrealdb::projection_run::FailedBatch> =
            original.failed_batches.clone();
        if let Some(batch_hash) = args.batch.as_ref() {
            selected_batches = selected_batches
                .into_iter()
                .filter(|b| &b.batch_hash == batch_hash)
                .collect();
        }

        let start = std::time::Instant::now();
        let new_result = match phase.as_str() {
            "dag_trace" => {
                if selected_batches.is_empty() || original.status == PhaseStatus::Failed {
                    store_ops
                        .project_dag_trace(&trace_sha256, &trace_bytes, &dag, Some(&args.run))
                        .map_err(|e| e.to_string())?
                } else {
                    let (succeeded, still_failed) = store
                        .retry_dag_trace_batches(&dag, &args.run, &selected_batches)
                        .map_err(|e| format!("retry dag_trace: {}", e))?;
                    merge_retry_results(original.clone(), succeeded, still_failed, start.elapsed())
                }
            }
            "doc_files" => {
                if selected_batches.is_empty() || original.status == PhaseStatus::Failed {
                    store_ops
                        .project_doc_files(&dag, &artifacts_dir, Some(&args.run))
                        .map_err(|e| e.to_string())?
                } else {
                    let (succeeded, still_failed) = store
                        .retry_doc_files_batches(&dag, &artifacts_dir, &args.run, &selected_batches)
                        .map_err(|e| format!("retry doc_files: {}", e))?;
                    merge_retry_results(original.clone(), succeeded, still_failed, start.elapsed())
                }
            }
            "doc_chunks" => {
                if selected_batches.is_empty() || original.status == PhaseStatus::Failed {
                    store_ops
                        .project_doc_chunks(&dag, &artifacts_dir, &[], Some(&args.run))
                        .map_err(|e| e.to_string())?
                } else {
                    let (succeeded, still_failed) = store
                        .retry_doc_chunks_batches(
                            &dag,
                            &artifacts_dir,
                            &args.run,
                            &selected_batches,
                        )
                        .map_err(|e| format!("retry doc_chunks: {}", e))?;
                    merge_retry_results(original.clone(), succeeded, still_failed, start.elapsed())
                }
            }
            "chunk_repr" => {
                if selected_batches.is_empty() || original.status == PhaseStatus::Failed {
                    store_ops
                        .project_chunk_repr(&dag, &artifacts_dir, Some(&args.run))
                        .map_err(|e| e.to_string())?
                } else {
                    let (succeeded, still_failed) = store
                        .retry_chunk_repr_batches(
                            &dag,
                            &artifacts_dir,
                            &args.run,
                            &selected_batches,
                        )
                        .map_err(|e| format!("retry chunk_repr: {}", e))?;
                    merge_retry_results(original.clone(), succeeded, still_failed, start.elapsed())
                }
            }
            phase if obsidian_adapter::is_obsidian_vault_links_phase(phase) => {
                let (effective_vault_prefixes, _did_fallback, _doc_paths) =
                    obsidian_adapter::effective_vault_prefixes_for_dag(
                        &dag,
                        &store.projection_config().obsidian_vault_prefixes,
                    );
                let vault_prefix_refs: Vec<&str> = effective_vault_prefixes
                    .iter()
                    .map(|s| s.as_str())
                    .collect();
                store_ops
                    .project_obsidian_vault_links(
                        &dag,
                        &artifacts_dir,
                        &vault_prefix_refs,
                        None,
                        Some(&args.run),
                    )
                    .map_err(|e| e.to_string())?
            }
            _ => {
                eprintln!("projection retry: unsupported phase '{}'", phase);
                original.clone()
            }
        };

        phase_results.insert(phase.clone(), new_result);
    }

    let new_status = compute_run_status(&phases_enabled, &phase_results);
    let finished_at = chrono::Utc::now().to_rfc3339();
    store
        .end_projection_run(&args.run, new_status, &finished_at, &phase_results)
        .map_err(|e| format!("update projection run after retry: {}", e))?;

    let phase_statuses: Vec<serde_json::Value> = phase_results
        .iter()
        .map(|(phase, result)| {
            let status = match result.status {
                PhaseStatus::Complete => "complete",
                PhaseStatus::Partial => "partial",
                PhaseStatus::Failed => "failed",
                PhaseStatus::Running => "running",
            };
            serde_json::json!({
                "phase": phase,
                "status": status,
                "failed_batches": result.failed_batches.len(),
                "successful_batches": result.successful_batches,
                "total_batches": result.total_batches,
            })
        })
        .collect();
    let ev_completed = build_projection_event(
        "projection.retry.completed",
        &args.run,
        chrono::Utc::now().to_rfc3339(),
        Some(trace_sha256.clone()),
        args.phase.clone(),
        Some(new_status.to_string()),
        None,
        None,
        None,
        None,
        Some(serde_json::json!({
            "phases": phase_statuses,
        })),
    )
    .map_err(|e| e.to_string())?;
    if !args.no_ledger {
        append_projection_event(&ledger_path, &ev_completed).map_err(|e| e.to_string())?;
    }
    store_ops
        .project_projection_events(&[to_projection_event_row(&ev_completed)])
        .map_err(|err| format!("surrealdb project events failed: {}", err))?;

    if args.json {
        let value = serde_json::json!({
            "run": args.run,
            "status": new_status.to_string(),
            "phases": phase_results,
        });
        println!(
            "{}",
            serde_json::to_string(&value).map_err(|err| format!("json encode: {}", err))?
        );
    } else {
        println!("projection_retry_run={}", args.run);
        println!("projection_retry_status={}", new_status);
        for (phase, result) in phase_results {
            println!(
                "phase={} status={} failed_batches={}",
                phase,
                match result.status {
                    PhaseStatus::Complete => "complete",
                    PhaseStatus::Partial => "partial",
                    PhaseStatus::Failed => "failed",
                    PhaseStatus::Running => "running",
                },
                result.failed_batches.len()
            );
        }
    }

    Ok(())
}

fn merge_retry_results(
    mut original: admit_surrealdb::projection_run::PhaseResult,
    retried_successes: usize,
    retried_failures: Vec<admit_surrealdb::projection_run::FailedBatch>,
    duration: std::time::Duration,
) -> admit_surrealdb::projection_run::PhaseResult {
    let mut failed_map: std::collections::BTreeMap<
        String,
        admit_surrealdb::projection_run::FailedBatch,
    > = retried_failures
        .into_iter()
        .map(|b| (b.batch_hash.clone(), b))
        .collect();

    let mut new_failed: Vec<admit_surrealdb::projection_run::FailedBatch> = Vec::new();
    let mut recovered = 0usize;
    for batch in original.failed_batches.iter() {
        if let Some(updated) = failed_map.remove(&batch.batch_hash) {
            new_failed.push(updated);
        } else {
            recovered += 1;
        }
    }

    original.successful_batches = original
        .successful_batches
        .saturating_add(retried_successes + recovered);
    original.failed_batches = new_failed;
    original.duration_ms = duration.as_millis() as u64;
    if original.failed_batches.is_empty() {
        original.status = admit_surrealdb::projection_run::PhaseStatus::Complete;
        original.error = None;
    } else if original.successful_batches == 0 {
        original.status = admit_surrealdb::projection_run::PhaseStatus::Failed;
        original.error = Some(format!(
            "{} of {} batches failed",
            original.failed_batches.len(),
            original.total_batches
        ));
    } else {
        original.status = admit_surrealdb::projection_run::PhaseStatus::Partial;
        original.error = Some(format!(
            "{} of {} batches failed",
            original.failed_batches.len(),
            original.total_batches
        ));
    }
    original
}

fn compute_run_status(
    phases_enabled: &[String],
    phase_results: &std::collections::BTreeMap<
        String,
        admit_surrealdb::projection_run::PhaseResult,
    >,
) -> admit_surrealdb::projection_run::RunStatus {
    use admit_surrealdb::projection_run::PhaseStatus;
    use admit_surrealdb::projection_run::RunStatus;

    if phase_results.is_empty() {
        return RunStatus::Running;
    }

    let total_phases = if phases_enabled.is_empty() {
        phase_results.len()
    } else {
        phases_enabled.len()
    };

    let completed = phase_results
        .values()
        .filter(|r| r.status == PhaseStatus::Complete)
        .count();
    let failed = phase_results
        .values()
        .filter(|r| r.status == PhaseStatus::Failed)
        .count();
    let partial = phase_results
        .values()
        .filter(|r| r.status == PhaseStatus::Partial)
        .count();

    if failed == total_phases {
        RunStatus::Failed
    } else if completed == total_phases {
        RunStatus::Complete
    } else if completed > 0 || failed > 0 || partial > 0 {
        RunStatus::Partial
    } else {
        RunStatus::Running
    }
}

fn run_court_query_add(
    args: CourtQueryAddArgs,
    projection: &mut ProjectionCoordinator,
) -> Result<(), String> {
    let artifacts_dir = args
        .artifacts_dir
        .clone()
        .unwrap_or_else(default_artifacts_dir);
    let ledger_path = args.ledger.clone().unwrap_or_else(default_ledger_path);

    let source_bytes =
        read_file_bytes(&args.file).map_err(|e| format!("read query file: {}", e))?;
    let source =
        String::from_utf8(source_bytes).map_err(|e| format!("query file must be UTF-8: {}", e))?;

    let mut tags = args.tags.clone();
    tags.sort();
    tags.dedup();

    let (registry, _registry_hash): (Option<MetaRegistryV0>, Option<String>) =
        match load_meta_registry(args.meta_registry.as_deref()).map_err(|e| e.to_string())? {
            Some((r, h)) => (Some(r), Some(h)),
            None => (None, None),
        };

    let artifact = register_query_artifact(
        &artifacts_dir,
        &args.name,
        &args.lang,
        &source,
        tags.clone(),
        registry.as_ref(),
    )
    .map_err(|e| e.to_string())?;

    let timestamp = chrono::Utc::now().to_rfc3339();
    let event = build_court_event(
        "court.query.registered",
        timestamp.clone(),
        "query",
        artifact.clone(),
        Some(args.name.clone()),
        Some(args.lang.clone()),
        Some(tags.clone()),
    )
    .map_err(|e| e.to_string())?;

    if !args.no_ledger {
        append_court_event(&ledger_path, &event).map_err(|e| e.to_string())?;
    }

    projection.with_store("surrealdb project query artifact", |surreal| {
        let store_ops: &dyn ProjectionStoreOps = surreal;
        store_ops
            .ensure_schemas()
            .map_err(|err| format!("surrealdb ensure schemas failed: {}", err))?;
        store_ops
            .project_query_artifacts(&[QueryArtifactRow {
                artifact_sha256: artifact.sha256.clone(),
                schema_id: artifact.schema_id.clone(),
                name: args.name.clone(),
                lang: args.lang.clone(),
                source,
                tags: tags.clone(),
                created_at_utc: timestamp.clone(),
            }])
            .map_err(|err| format!("surrealdb project query artifact failed: {}", err))?;
        Ok(())
    })?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "event": event,
                "artifact": artifact,
                "ledger": ledger_path,
                "artifacts_dir": artifacts_dir,
            }))
            .map_err(|e| format!("json encode: {}", e))?
        );
    } else {
        println!("event_id={}", event.event_id);
        println!("artifact_kind={}", artifact.kind);
        println!("artifact_sha256={}", artifact.sha256);
        println!("schema_id={}", artifact.schema_id);
        println!("ledger={}", ledger_path.display());
        println!("artifacts_dir={}", artifacts_dir.display());
        if args.no_ledger {
            println!("no_ledger=true");
        }
    }

    Ok(())
}

fn run_court_function_add(
    args: CourtFunctionAddArgs,
    projection: &mut ProjectionCoordinator,
) -> Result<(), String> {
    let artifacts_dir = args
        .artifacts_dir
        .clone()
        .unwrap_or_else(default_artifacts_dir);
    let ledger_path = args.ledger.clone().unwrap_or_else(default_ledger_path);

    let source_bytes =
        read_file_bytes(&args.file).map_err(|e| format!("read function file: {}", e))?;
    let source = String::from_utf8(source_bytes)
        .map_err(|e| format!("function file must be UTF-8: {}", e))?;

    let mut tags = args.tags.clone();
    tags.sort();
    tags.dedup();

    let (registry, _registry_hash): (Option<MetaRegistryV0>, Option<String>) =
        match load_meta_registry(args.meta_registry.as_deref()).map_err(|e| e.to_string())? {
            Some((r, h)) => (Some(r), Some(h)),
            None => (None, None),
        };

    let artifact = register_function_artifact(
        &artifacts_dir,
        &args.name,
        &args.lang,
        &source,
        tags.clone(),
        registry.as_ref(),
    )
    .map_err(|e| e.to_string())?;

    let timestamp = chrono::Utc::now().to_rfc3339();
    let event = build_court_event(
        "court.function.registered",
        timestamp.clone(),
        "function",
        artifact.clone(),
        Some(args.name.clone()),
        Some(args.lang.clone()),
        Some(tags.clone()),
    )
    .map_err(|e| e.to_string())?;

    if !args.no_ledger {
        append_court_event(&ledger_path, &event).map_err(|e| e.to_string())?;
    }

    projection.with_store("surrealdb project function artifact", |surreal| {
        let store_ops: &dyn ProjectionStoreOps = surreal;
        store_ops
            .ensure_schemas()
            .map_err(|err| format!("surrealdb ensure schemas failed: {}", err))?;
        store_ops
            .project_function_artifacts(&[FunctionArtifactRow {
                artifact_sha256: artifact.sha256.clone(),
                schema_id: artifact.schema_id.clone(),
                name: args.name.clone(),
                lang: args.lang.clone(),
                source,
                tags: tags.clone(),
                created_at_utc: timestamp.clone(),
            }])
            .map_err(|err| format!("surrealdb project function artifact failed: {}", err))?;
        Ok(())
    })?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "event": event,
                "artifact": artifact,
                "ledger": ledger_path,
                "artifacts_dir": artifacts_dir,
            }))
            .map_err(|e| format!("json encode: {}", e))?
        );
    } else {
        println!("event_id={}", event.event_id);
        println!("artifact_kind={}", artifact.kind);
        println!("artifact_sha256={}", artifact.sha256);
        println!("schema_id={}", artifact.schema_id);
        println!("ledger={}", ledger_path.display());
        println!("artifacts_dir={}", artifacts_dir.display());
        if args.no_ledger {
            println!("no_ledger=true");
        }
    }

    Ok(())
}

fn to_projection_event_row(event: &admit_cli::ProjectionEvent) -> ProjectionEventRow {
    ProjectionEventRow {
        event_id: event.event_id.clone(),
        event_type: event.event_type.clone(),
        timestamp: event.timestamp.clone(),
        projection_run_id: event.projection_run_id.clone(),
        phase: event.phase.clone(),
        status: event.status.clone(),
        duration_ms: event.duration_ms,
        error: event.error.clone(),
        trace_sha256: event.trace_sha256.clone(),
        config_hash: event.config_hash.clone(),
        projector_version: event.projector_version.clone(),
        meta: event.meta.clone(),
    }
}

fn to_ingest_event_row(event: &admit_cli::IngestEvent) -> IngestEventRow {
    IngestEventRow {
        event_id: event.event_id.clone(),
        event_type: event.event_type.clone(),
        timestamp: event.timestamp.clone(),
        ingest_run_id: event.ingest_run_id.clone(),
        status: event.status.clone(),
        duration_ms: event.duration_ms,
        error: event.error.clone(),
        root: event.root.clone(),
        config_sha256: event.config.as_ref().map(|a| a.sha256.clone()),
        coverage_sha256: event.coverage.as_ref().map(|a| a.sha256.clone()),
        ingest_run_sha256: event.ingest_run.as_ref().map(|a| a.sha256.clone()),
        snapshot_sha256: event.snapshot_sha256.clone(),
        parse_sha256: event.parse_sha256.clone(),
        files: event.files,
        chunks: event.chunks,
        total_bytes: event.total_bytes,
    }
}

fn project_ingest_dir_projections(
    args: &IngestDirArgs,
    store: &SurrealCliProjectionStore,
    ledger_path: &Path,
    trace_sha256: &str,
    trace_cbor: &[u8],
    dag: &admit_dag::GovernedDag,
    artifacts_dir: &Path,
    ingest_run_id: &str,
    docs_to_resolve_links: Option<&std::collections::BTreeSet<String>>,
    obsidian_scope_enabled: bool,
    emit_metrics: bool,
    projection_force: bool,
) -> Result<ProjectionSummary, String> {
    use admit_surrealdb::projection_run::{get_projector_version, PhaseResult, PhaseStatus};

    let projection_config = store.projection_config().clone();
    let projector_version = get_projector_version();
    let config_hash = projection_config.compute_hash();
    let phases_enabled: Vec<String> = projection_config
        .enabled_phases
        .enabled_phase_names()
        .into_iter()
        .map(|p| obsidian_adapter::normalize_obsidian_vault_links_phase(&p))
        .filter(|p| match p.as_str() {
            "dag_trace" | "doc_files" | "doc_chunks" | "chunk_repr" => true,
            phase if obsidian_adapter::is_obsidian_vault_links_phase(phase) => {
                obsidian_scope_enabled
            }
            _ => false,
        })
        .collect();
    if !obsidian_scope_enabled
        && projection_config
            .enabled_phases
            .enabled_phase_names()
            .iter()
            .any(|phase| obsidian_adapter::is_obsidian_vault_links_phase(phase))
    {
        eprintln!(
            "projection: skipping obsidian_vault_links (scope obsidian.links or vault.ir_lint not enabled)"
        );
    }

    let store_ops: &dyn ProjectionStoreOps = store;
    store_ops
        .ensure_schemas()
        .map_err(|err| format!("surrealdb ensure schemas failed: {}", err))?;

    let (effective_vault_prefixes, did_vault_prefix_fallback, dag_doc_paths) =
        obsidian_adapter::effective_vault_prefixes_for_dag(
            dag,
            &projection_config.obsidian_vault_prefixes,
        );

    // Skip projection work if an identical complete run already exists (unless forced/benching).
    let effective_force = projection_force || emit_metrics;
    if !effective_force {
        if let Some(existing) = store
            .find_complete_projection_run(trace_sha256, &config_hash, &phases_enabled)
            .map_err(|e| format!("surrealdb find complete projection run failed: {}", e))?
        {
            if let Some(existing_run_id) = existing.get("run_id").and_then(|v| v.as_str()) {
                let mut skipped_events: Vec<admit_cli::ProjectionEvent> = Vec::new();
                for phase in phases_enabled.iter() {
                    let ev = build_projection_event(
                        "projection.phase.skipped",
                        existing_run_id,
                        chrono::Utc::now().to_rfc3339(),
                        Some(trace_sha256.to_string()),
                        Some(phase.clone()),
                        Some("skipped".to_string()),
                        Some(0),
                        None,
                        Some(config_hash.clone()),
                        Some(projector_version.clone()),
                        Some(serde_json::json!({
                            "reason": "already_complete",
                            "skipped_projection_run_id": existing_run_id,
                        })),
                    )
                    .map_err(|err| err.to_string())?;
                    skipped_events.push(ev);
                }

                if !args.no_ledger {
                    for ev in skipped_events.iter() {
                        append_projection_event(ledger_path, ev).map_err(|e| e.to_string())?;
                    }
                }
                let rows: Vec<ProjectionEventRow> =
                    skipped_events.iter().map(to_projection_event_row).collect();
                store_ops
                    .project_projection_events(&rows)
                    .map_err(|err| format!("surrealdb project events failed: {}", err))?;

                return Ok(ProjectionSummary {
                    run_id: existing_run_id.to_string(),
                    status: admit_surrealdb::projection_run::RunStatus::Complete,
                    total_phases: phases_enabled.len(),
                    successful_phases: phases_enabled.len(),
                });
            }
        }
    }

    let mut run = admit_surrealdb::projection_run::ProjectionRun::new(
        trace_sha256.to_string(),
        projector_version.clone(),
        config_hash.clone(),
        phases_enabled.clone(),
        Some(ingest_run_id.to_string()),
    );
    let run_id = store_ops
        .begin_run(&run)
        .map_err(|err| format!("surrealdb begin projection run failed: {}", err))?;

    let mut events: Vec<admit_cli::ProjectionEvent> = Vec::new();
    let timestamp = chrono::Utc::now().to_rfc3339();
    let run_started = build_projection_event(
        "projection.run.started",
        &run_id,
        timestamp,
        Some(trace_sha256.to_string()),
        None,
        Some("running".to_string()),
        None,
        None,
        Some(config_hash.clone()),
        Some(projector_version.clone()),
        None,
    )
    .map_err(|err| err.to_string())?;
    events.push(run_started);

    // Helper: emit to ledger and SurrealDB.
    let flush_events = |store_ops: &dyn ProjectionStoreOps,
                        ledger_path: &Path,
                        events: &mut Vec<admit_cli::ProjectionEvent>|
     -> Result<(), String> {
        if events.is_empty() {
            return Ok(());
        }
        if !args.no_ledger {
            for ev in events.iter() {
                append_projection_event(ledger_path, ev).map_err(|e| e.to_string())?;
            }
        }
        let rows: Vec<ProjectionEventRow> = events.iter().map(to_projection_event_row).collect();
        store_ops
            .project_projection_events(&rows)
            .map_err(|err| format!("surrealdb project events failed: {}", err))?;
        events.clear();
        Ok(())
    };

    flush_events(store_ops, ledger_path, &mut events)?;

    if did_vault_prefix_fallback {
        let sample: Vec<String> = dag_doc_paths.iter().take(5).cloned().collect();
        let ev = build_projection_event(
            "projection.warning.vault_prefix_fallback",
            &run_id,
            chrono::Utc::now().to_rfc3339(),
            Some(trace_sha256.to_string()),
            Some(obsidian_adapter::OBSIDIAN_VAULT_LINKS_PHASE.to_string()),
            Some("warning".to_string()),
            None,
            None,
            Some(config_hash.clone()),
            Some(projector_version.clone()),
            Some(serde_json::json!({
                "root": args.path.to_string_lossy().to_string(),
                "original_prefixes": projection_config.obsidian_vault_prefixes.clone(),
                "effective_prefixes": effective_vault_prefixes.clone(),
                "doc_paths_sample": sample,
                "doc_paths_total": dag_doc_paths.len(),
            })),
        )
        .map_err(|err| err.to_string())?;
        events.push(ev);
        flush_events(store_ops, ledger_path, &mut events)?;
    }

    // Run enabled phases with basic per-phase timing.
    for phase in phases_enabled {
        let started_at = std::time::Instant::now();
        eprintln!("projection: phase {} started", phase);

        let phase_result = match phase.as_str() {
            "dag_trace" => {
                store_ops.project_dag_trace(trace_sha256, trace_cbor, dag, Some(&run_id))
            }
            "doc_files" => store_ops.project_doc_files(dag, artifacts_dir, Some(&run_id)),
            "doc_chunks" => store_ops.project_doc_chunks(dag, artifacts_dir, &[], Some(&run_id)),
            "chunk_repr" => store_ops.project_chunk_repr(dag, artifacts_dir, Some(&run_id)),
            phase if obsidian_adapter::is_obsidian_vault_links_phase(phase) => {
                let vault_prefix_refs: Vec<&str> = effective_vault_prefixes
                    .iter()
                    .map(|s| s.as_str())
                    .collect();
                store_ops.project_obsidian_vault_links(
                    dag,
                    artifacts_dir,
                    &vault_prefix_refs,
                    docs_to_resolve_links,
                    Some(&run_id),
                )
            }
            // Phases which are not yet driven by ingest_dir are treated as skipped here.
            _ => Ok(admit_surrealdb::projection_run::PhaseResult::success(
                phase.clone(),
                0,
                0,
            )),
        };

        let duration_ms = started_at.elapsed().as_millis() as u64;
        match phase_result {
            Ok(mut result) => {
                result.duration_ms = duration_ms;
                let status_str = match result.status {
                    admit_surrealdb::projection_run::PhaseStatus::Complete => "complete",
                    admit_surrealdb::projection_run::PhaseStatus::Partial => "partial",
                    admit_surrealdb::projection_run::PhaseStatus::Failed => "failed",
                    admit_surrealdb::projection_run::PhaseStatus::Running => "running",
                };

                run.add_phase_result(phase.clone(), result.clone());
                eprintln!(
                    "projection: phase {} {} ({} ms)",
                    phase, status_str, duration_ms
                );
                if emit_metrics {
                    let db_ms = result.db_write_time_ms.unwrap_or(0);
                    let parse_ms = result
                        .parse_time_ms
                        .unwrap_or_else(|| duration_ms.saturating_sub(db_ms));
                    let files_read = result
                        .files_read
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "-".to_string());
                    eprintln!(
                        "projection: phase {} metrics records={} batches={} bytes={} files_read={} parse_ms={} db_write_ms={}",
                        phase,
                        result.records_processed,
                        result.batches_executed,
                        result.bytes_written,
                        files_read,
                        parse_ms,
                        db_ms
                    );
                }

                let ev = build_projection_event(
                    "projection.phase.completed",
                    &run_id,
                    chrono::Utc::now().to_rfc3339(),
                    None,
                    Some(phase.clone()),
                    Some(status_str.to_string()),
                    Some(duration_ms),
                    result.error.clone(),
                    None,
                    None,
                    None,
                )
                .map_err(|err| err.to_string())?;
                events.push(ev);

                if matches!(
                    result.status,
                    admit_surrealdb::projection_run::PhaseStatus::Partial
                        | admit_surrealdb::projection_run::PhaseStatus::Failed
                ) {
                    match projection_config.failure_handling {
                        admit_surrealdb::projection_config::FailureHandling::FailFast => {
                            flush_events(store_ops, ledger_path, &mut events)?;
                            return Err(format!(
                                "projection phase '{}' completed with status {}",
                                phase, status_str
                            ));
                        }
                        admit_surrealdb::projection_config::FailureHandling::WarnAndContinue => {
                            eprintln!(
                                "Warning: projection phase '{}' completed with status {}",
                                phase, status_str
                            );
                        }
                        admit_surrealdb::projection_config::FailureHandling::SilentIgnore => {}
                    }
                }
            }
            Err(err) => {
                run.add_phase_result(
                    phase.clone(),
                    PhaseResult::failed(phase.clone(), err.to_string(), duration_ms),
                );
                eprintln!(
                    "projection: phase {} failed ({} ms): {}",
                    phase, duration_ms, err
                );
                let ev = build_projection_event(
                    "projection.phase.completed",
                    &run_id,
                    chrono::Utc::now().to_rfc3339(),
                    None,
                    Some(phase.clone()),
                    Some("failed".to_string()),
                    Some(duration_ms),
                    Some(err.to_string()),
                    None,
                    None,
                    None,
                )
                .map_err(|err| err.to_string())?;
                events.push(ev);

                match projection_config.failure_handling {
                    admit_surrealdb::projection_config::FailureHandling::FailFast => {
                        flush_events(store_ops, ledger_path, &mut events)?;
                        return Err(format!("projection phase '{}' failed: {}", phase, err));
                    }
                    admit_surrealdb::projection_config::FailureHandling::WarnAndContinue => {
                        eprintln!("Warning: projection phase '{}' failed: {}", phase, err);
                    }
                    admit_surrealdb::projection_config::FailureHandling::SilentIgnore => {}
                }
            }
        }

        flush_events(store_ops, ledger_path, &mut events)?;
    }

    run.complete();
    let finished_at = run
        .finished_at
        .clone()
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());

    store_ops
        .end_run(&run_id, run.status, &finished_at, &run.phase_results)
        .map_err(|err| format!("surrealdb end projection run failed: {}", err))?;

    let ev = build_projection_event(
        "projection.run.completed",
        &run_id,
        chrono::Utc::now().to_rfc3339(),
        Some(trace_sha256.to_string()),
        None,
        Some(run.status.to_string()),
        run.duration_ms(),
        None,
        Some(config_hash),
        Some(projector_version),
        None,
    )
    .map_err(|err| err.to_string())?;

    if !args.no_ledger {
        append_projection_event(ledger_path, &ev).map_err(|e| e.to_string())?;
    }
    store_ops
        .project_projection_events(&[to_projection_event_row(&ev)])
        .map_err(|err| format!("surrealdb project events failed: {}", err))?;
    eprintln!("projection: run {} completed", run_id);

    let total_phases = run.phase_results.len();
    let successful_phases = run
        .phase_results
        .values()
        .filter(|r| r.status == PhaseStatus::Complete)
        .count();

    Ok(ProjectionSummary {
        run_id,
        status: run.status,
        total_phases,
        successful_phases,
    })
}

fn project_ollama_embeddings_for_trace(
    args: &IngestDirArgs,
    surreal: &SurrealCliProjectionStore,
    dag: &admit_dag::GovernedDag,
    artifacts_dir: &Path,
    projection_run_id: Option<&str>,
) -> Result<(), String> {
    let endpoint = args
        .ollama_endpoint
        .clone()
        .or_else(|| std::env::var("ADMIT_OLLAMA_ENDPOINT").ok())
        .unwrap_or_else(|| "http://127.0.0.1:11434".to_string());
    let model = args
        .ollama_model
        .clone()
        .or_else(|| std::env::var("ADMIT_OLLAMA_EMBED_MODEL").ok())
        .unwrap_or_else(|| "qwen3-embedding:0.6b".to_string());

    let (default_doc_prefix, default_query_prefix) =
        admit_cli::default_ollama_prefixes_for_model(&model);

    let doc_prefix = args
        .ollama_doc_prefix
        .clone()
        .or_else(|| std::env::var("ADMIT_OLLAMA_DOC_PREFIX").ok())
        .unwrap_or(default_doc_prefix);

    let query_prefix = args
        .ollama_query_prefix
        .clone()
        .or_else(|| std::env::var("ADMIT_OLLAMA_QUERY_PREFIX").ok())
        .unwrap_or(default_query_prefix);

    let embedder = OllamaEmbedder::new(OllamaEmbedConfig {
        endpoint,
        model: model.clone(),
        timeout_ms: args.ollama_timeout_ms.max(1_000),
        batch_size: args.ollama_batch_size.max(1),
        max_chars: args.ollama_max_chars.max(256),
    });

    // Determine native embedding dim (Ollama returns fixed dims per model) so `--ollama-dim=0`
    // can be stored as the actual dim in projections and `embed_run` accounting.
    let native_dim = {
        let probe = if doc_prefix.is_empty() {
            "probe".to_string()
        } else {
            format!("{}{}", doc_prefix, "probe")
        };
        let mut embs = embedder.embed_texts(&[probe])?;
        let Some(e0) = embs.pop() else {
            return Err("ollama embed probe returned no embedding".to_string());
        };
        let n = e0.len();
        if n == 0 {
            return Err("ollama embed probe returned empty embedding".to_string());
        }
        n
    };

    let dim_target_usize: usize = if args.ollama_dim == 0 {
        native_dim
    } else {
        args.ollama_dim
    };
    if dim_target_usize == 0 {
        return Err("ollama_dim must be >= 1 (or 0 for full native dim)".to_string());
    }
    if dim_target_usize > native_dim {
        return Err(format!(
            "ollama_dim {} exceeds native embedding dim {} for model {}",
            dim_target_usize, native_dim, model
        ));
    }
    let dim_target: u32 =
        u32::try_from(dim_target_usize).map_err(|_| "ollama_dim too large".to_string())?;

    let (snapshot_sha256, parse_sha256) = find_ingest_hashes(dag);
    let created_at_utc = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let run_id = sha256_hex(&format!(
        "admit_embed_run_v1|{}|{}|{}|{}",
        parse_sha256.clone().unwrap_or_default(),
        model,
        dim_target,
        created_at_utc
    ));
    surreal.project_embed_run(&EmbedRunRow {
        run_id: run_id.clone(),
        kind: "ollama_embed".to_string(),
        trace_sha256: None,
        snapshot_sha256: snapshot_sha256.clone(),
        parse_sha256: parse_sha256.clone(),
        root: Some(args.path.to_string_lossy().to_string()),
        model: model.clone(),
        dim_target,
        dim_actual: Some(native_dim as u32),
        doc_prefix: doc_prefix.clone(),
        query_prefix: query_prefix.clone(),
        created_at_utc: created_at_utc.clone(),
    })?;

    // Collect chunk texts from artifacts referenced by TextChunk nodes.
    let mut chunks: Vec<(String, String, u32, String, String)> = Vec::new();
    // (node_id_hex, doc_path, start_line, chunk_sha256, text)
    for (id, node) in dag.nodes() {
        let admit_dag::NodeKind::TextChunk {
            chunk_sha256,
            doc_path,
            start_line,
            ..
        } = &node.kind
        else {
            continue;
        };
        let Some(artifact_ref) = node.artifact_ref.as_ref() else {
            continue;
        };
        let Some(rel_path) = artifact_ref.path.as_ref() else {
            continue;
        };
        let abs = artifacts_dir.join(Path::new(rel_path));
        let bytes =
            std::fs::read(&abs).map_err(|err| format!("read chunk {}: {}", abs.display(), err))?;
        let mut text = String::from_utf8_lossy(&bytes).to_string();
        if !doc_prefix.is_empty() {
            text = format!("{}{}", doc_prefix, text);
        }
        chunks.push((
            id.to_string(),
            doc_path.clone(),
            *start_line,
            chunk_sha256.clone(),
            text,
        ));
        if args.ollama_limit > 0 && chunks.len() >= args.ollama_limit {
            break;
        }
    }

    // Batch embed.
    let batch_size = embedder.cfg().batch_size.max(1);
    let mut chunk_rows: Vec<DocChunkEmbeddingRow> = Vec::with_capacity(chunks.len());
    let mut doc_sums: std::collections::BTreeMap<String, (Vec<f32>, u32)> =
        std::collections::BTreeMap::new();

    let mut i = 0usize;
    while i < chunks.len() {
        let end = (i + batch_size).min(chunks.len());
        eprintln!(
            "ollama_embed: model={} dim_target={} batch {}..{} of {}",
            model,
            dim_target,
            i + 1,
            end,
            chunks.len()
        );
        let batch_started = std::time::Instant::now();
        let inputs: Vec<String> = chunks[i..end].iter().map(|t| t.4.clone()).collect();
        let embs = embedder.embed_texts(&inputs)?;
        let batch_ms = batch_started.elapsed().as_millis() as u64;
        eprintln!(
            "ollama_embed: batch {}..{} done ({} ms)",
            i + 1,
            end,
            batch_ms
        );
        if embs.len() != inputs.len() {
            return Err(format!(
                "ollama returned {} embeddings for {} inputs",
                embs.len(),
                inputs.len()
            ));
        }
        for ((node_id, doc_path, start_line, chunk_sha256, _text), emb) in
            chunks[i..end].iter().cloned().zip(embs.into_iter())
        {
            if emb.is_empty() {
                continue;
            }
            let mut emb = emb;
            if dim_target > 0 && (dim_target as usize) < emb.len() {
                emb.truncate(dim_target as usize);
            }
            let dim = emb.len();
            let entry = doc_sums
                .entry(doc_path.clone())
                .or_insert_with(|| (vec![0.0; dim], 0));
            if entry.0.len() == dim {
                for (a, b) in entry.0.iter_mut().zip(emb.iter()) {
                    *a += *b;
                }
                entry.1 += 1;
            }

            chunk_rows.push(DocChunkEmbeddingRow {
                node_id,
                doc_path,
                start_line,
                chunk_sha256,
                model: model.clone(),
                dim_target,
                embedding: emb,
            });
        }
        i = end;
    }

    // Mean pool to doc-level embeddings.
    let mut doc_rows: Vec<DocEmbeddingRow> = Vec::with_capacity(doc_sums.len());
    for (doc_path, (mut sum, n)) in doc_sums {
        if n == 0 {
            continue;
        }
        for v in sum.iter_mut() {
            *v /= n as f32;
        }
        doc_rows.push(DocEmbeddingRow {
            doc_path,
            model: model.clone(),
            dim_target,
            embedding: sum,
            chunk_count: n,
        });
    }

    surreal.project_doc_embeddings(&chunk_rows, &doc_rows)?;
    eprintln!(
        "ollama_embed: projected chunk_embeddings={} doc_embeddings={}",
        chunk_rows.len(),
        doc_rows.len()
    );

    let suggest_dim_target = dim_target;

    if args.ollama_suggest_unresolved {
        let vault_prefixes = surreal.projection_config().obsidian_vault_prefixes.clone();
        obsidian_adapter::project_unresolved_link_suggestions_via_ollama(
            surreal,
            &embedder,
            projection_run_id,
            &run_id,
            &model,
            suggest_dim_target,
            &doc_prefix,
            &query_prefix,
            args.ollama_suggest_limit,
            &vault_prefixes,
        )?;
    }
    Ok(())
}

fn find_ingest_hashes(dag: &admit_dag::GovernedDag) -> (Option<String>, Option<String>) {
    let mut snapshot_sha256: Option<String> = None;
    let mut parse_sha256: Option<String> = None;
    for (_id, node) in dag.nodes() {
        match &node.kind {
            NodeKind::DirectorySnapshot { snapshot_sha256: s } => {
                snapshot_sha256 = Some(s.clone());
            }
            NodeKind::DirectoryParse {
                parse_sha256: p, ..
            } => {
                parse_sha256 = Some(p.clone());
            }
            _ => {}
        }
    }
    (snapshot_sha256, parse_sha256)
}

fn sha256_hex(input: &str) -> String {
    hex::encode(sha2::Sha256::digest(input.as_bytes()))
}

fn encode_dag_trace(trace: &DagTraceCollector) -> Result<(String, Vec<u8>), String> {
    let bytes = trace.encode_canonical_cbor()?;
    Ok((hex::encode(sha2::Sha256::digest(&bytes)), bytes))
}

fn write_dag_trace(out: &Path, bytes: &[u8]) -> Result<(), String> {
    if let Some(parent) = out.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)
                .map_err(|err| format!("create dag trace dir: {}", err))?;
        }
    }
    std::fs::write(out, bytes).map_err(|err| format!("write dag trace: {}", err))?;
    Ok(())
}

fn print_dag_trace_hint(json_mode: bool, out: &Path, sha256: &str) {
    if json_mode {
        eprintln!("dag_trace={}", out.display());
        eprintln!("dag_trace_sha256={}", sha256);
    } else {
        println!("dag_trace={}", out.display());
        println!("dag_trace_sha256={}", sha256);
    }
}

fn build_surreal_projection_store(cli: &Cli) -> Result<SurrealCliProjectionStore, String> {
    let namespace = cli
        .surrealdb_namespace
        .clone()
        .or_else(|| std::env::var("SURREAL_NAMESPACE").ok());
    let database = cli
        .surrealdb_database
        .clone()
        .or_else(|| std::env::var("SURREAL_DATABASE").ok());

    if namespace.is_none() || database.is_none() {
        return Err(
            "surrealdb projection requires --surrealdb-namespace and --surrealdb-database (or env SURREAL_NAMESPACE/SURREAL_DATABASE)"
                .to_string(),
        );
    }

    let config = SurrealCliConfig {
        endpoint: cli.surrealdb_endpoint.clone(),
        namespace,
        database,
        username: cli
            .surrealdb_username
            .clone()
            .or_else(|| std::env::var("SURREAL_USER").ok()),
        password: cli
            .surrealdb_password
            .clone()
            .or_else(|| std::env::var("SURREAL_PASS").ok()),
        token: cli
            .surrealdb_token
            .clone()
            .or_else(|| std::env::var("SURREAL_TOKEN").ok()),
        auth_level: cli
            .surrealdb_auth_level
            .clone()
            .or_else(|| std::env::var("SURREAL_AUTH_LEVEL").ok()),
        surreal_bin: cli.surrealdb_bin.clone(),
    };

    // Build projection configuration from CLI flags
    let projection_config = build_projection_config(cli);

    Ok(SurrealCliProjectionStore::with_projection_config(
        config,
        projection_config,
    ))
}

fn build_projection_coordinator(cli: &Cli) -> Result<ProjectionCoordinator, String> {
    let mode = if cli.surrealdb_project {
        SurrealDbMode::On
    } else {
        cli.surrealdb_mode
    };

    if mode == SurrealDbMode::Off {
        return Ok(ProjectionCoordinator::off());
    }

    let namespace = cli
        .surrealdb_namespace
        .clone()
        .or_else(|| std::env::var("SURREAL_NAMESPACE").ok());
    let database = cli
        .surrealdb_database
        .clone()
        .or_else(|| std::env::var("SURREAL_DATABASE").ok());

    if namespace.is_none() || database.is_none() {
        if mode == SurrealDbMode::Auto {
            return Ok(ProjectionCoordinator::disabled(
                mode,
                "missing surrealdb namespace/database".to_string(),
            ));
        }
        return Err(
            "surrealdb projection requires --surrealdb-namespace and --surrealdb-database (or env SURREAL_NAMESPACE/SURREAL_DATABASE)"
                .to_string(),
        );
    }

    let store = build_surreal_projection_store(cli)?;
    let ready = store.is_ready()?;
    if ready {
        Ok(ProjectionCoordinator::active(mode, store))
    } else if mode == SurrealDbMode::Auto {
        Ok(ProjectionCoordinator::disabled(
            mode,
            format!("endpoint not ready: {}", store.config().endpoint),
        ))
    } else {
        Err(format!(
            "surrealdb projection enabled but endpoint not ready: {}",
            store.config().endpoint
        ))
    }
}

/// Build ProjectionConfig from CLI flags and environment
fn build_projection_config(cli: &Cli) -> ProjectionConfig {
    use std::collections::BTreeMap;

    // Parse batch size overrides from "phase:size" format
    let batch_size_overrides = cli.projection_batch_size.as_ref().and_then(|specs| {
        let mut map = BTreeMap::new();
        for spec in specs {
            if let Some((phase, size_str)) = spec.split_once(':') {
                if let Ok(size) = size_str.parse::<usize>() {
                    map.insert(phase.to_string(), size);
                } else {
                    eprintln!("Warning: invalid batch size '{}' in '{}'", size_str, spec);
                }
            } else {
                eprintln!(
                    "Warning: invalid batch size spec '{}', expected format 'phase:size'",
                    spec
                );
            }
        }
        if map.is_empty() {
            None
        } else {
            Some(map)
        }
    });

    ProjectionConfig::from_cli_and_env(
        cli.projection_enabled.clone(),
        batch_size_overrides,
        cli.projection_max_sql_bytes,
        cli.projection_failure_mode,
        cli.vault_prefix.clone(),
    )
}

fn maybe_project_trace(
    projection: &mut ProjectionCoordinator,
    trace_sha256: &str,
    trace_cbor: &[u8],
    dag: &admit_dag::GovernedDag,
) -> Result<(), String> {
    projection
        .with_store("surrealdb projection", |surreal| {
            ProjectionStore::project_dag_trace(surreal, trace_sha256, trace_cbor, dag)
                .map_err(|err| format!("surrealdb projection failed: {}", err))?;
            Ok(())
        })?
        .map(|_| ());
    Ok(())
}

#[allow(dead_code)]
fn maybe_project_doc_chunks(
    projection: &mut ProjectionCoordinator,
    dag: &admit_dag::GovernedDag,
    artifacts_dir: &Path,
) -> Result<(), String> {
    projection
        .with_store("surrealdb doc_chunk projection", |surreal| {
            surreal
                .project_doc_chunks_from_artifacts(dag, artifacts_dir, &[])
                .map_err(|err| format!("surrealdb doc_chunk projection failed: {}", err))?;
            Ok(())
        })?
        .map(|_| ());
    Ok(())
}

#[allow(dead_code)]
fn maybe_project_doc_files(
    projection: &mut ProjectionCoordinator,
    dag: &admit_dag::GovernedDag,
    artifacts_dir: &Path,
) -> Result<(), String> {
    projection
        .with_store("surrealdb doc_file projection", |surreal| {
            surreal
                .project_doc_files_from_artifacts(dag, artifacts_dir)
                .map_err(|err| format!("surrealdb doc_file projection failed: {}", err))?;
            Ok(())
        })?
        .map(|_| ());
    Ok(())
}

#[allow(dead_code)]
fn maybe_project_vault_links(
    projection: &mut ProjectionCoordinator,
    dag: &admit_dag::GovernedDag,
    artifacts_dir: &Path,
) -> Result<(), String> {
    projection
        .with_store("surrealdb obsidian vault link projection", |surreal| {
            surreal
                .project_obsidian_vault_links_from_artifacts(
                    dag,
                    artifacts_dir,
                    &["irrev-vault/", "chatgpt/vault/"],
                    None,
                    None,
                )
                .map_err(|err| {
                    format!("surrealdb obsidian vault link projection failed: {}", err)
                })?;
            Ok(())
        })?
        .map(|_| ());
    Ok(())
}

fn build_trace_for_cost_declared(
    event: &admit_cli::CostDeclaredEvent,
    snapshot_hash: &str,
) -> Result<DagTraceCollector, String> {
    let scope = ScopeTag::new("scope:core.pure");
    let mut trace = DagTraceCollector::new("cli.declare_cost");

    let mut snapshot_node = DagNode::new(
        NodeKind::SnapshotExport {
            snapshot_hash: snapshot_hash.to_string(),
        },
        scope.clone(),
        vec![],
        vec![],
    )?;
    snapshot_node.artifact_ref = Some(event.snapshot_ref.clone());

    let mut witness_node = DagNode::new(
        NodeKind::Witness {
            witness_sha256: event.witness.sha256.clone(),
            schema_id: event.witness.schema_id.clone(),
        },
        scope.clone(),
        vec![],
        vec![],
    )?;
    witness_node.artifact_ref = Some(event.witness.clone());

    let cost_node = DagNode::new(
        NodeKind::CostDeclaration {
            content_hash: event.event_id.clone(),
        },
        scope.clone(),
        vec![],
        vec![],
    )?;

    trace.ensure_node(snapshot_node.clone());
    trace.ensure_node(witness_node.clone());
    trace.ensure_node(cost_node.clone());

    let step = trace.next_step();
    trace.add_edge(DagEdge::build_depends(
        snapshot_node.id,
        cost_node.id,
        scope.clone(),
        step,
    ));
    let step = trace.next_step();
    trace.add_edge(DagEdge::witness_of(
        witness_node.id,
        cost_node.id,
        scope.clone(),
        step,
    ));

    if let Some(registry_hash) = event.registry_hash.as_ref() {
        let authority_node = DagNode::new(
            NodeKind::AuthorityRoot {
                authority_id: "meta_registry/0".to_string(),
                authority_hash: registry_hash.clone(),
            },
            scope.clone(),
            vec![],
            vec![],
        )?;
        trace.ensure_node(authority_node.clone());
        let step = trace.next_step();
        trace.add_edge(DagEdge::authority_depends(
            authority_node.id,
            cost_node.id,
            "meta_registry/0".to_string(),
            registry_hash.clone(),
            scope,
            step,
            None,
        ));
    }

    Ok(trace)
}

fn build_trace_for_ingest_dir(
    out: &admit_cli::IngestDirOutput,
) -> Result<DagTraceCollector, String> {
    let scope = ScopeTag::new("scope:core.pure");
    let mut trace = DagTraceCollector::new("cli.ingest.dir");

    let mut snapshot_node = DagNode::new(
        NodeKind::DirectorySnapshot {
            snapshot_sha256: out.snapshot_sha256.clone(),
        },
        scope.clone(),
        vec![],
        vec![],
    )?;
    snapshot_node.artifact_ref = Some(out.snapshot.clone());

    let mut parse_node = DagNode::new(
        NodeKind::DirectoryParse {
            parse_sha256: out.parse_sha256.clone(),
        },
        scope.clone(),
        vec![],
        vec![],
    )?;
    parse_node.artifact_ref = Some(out.parse.clone());

    trace.ensure_node(snapshot_node.clone());
    trace.ensure_node(parse_node.clone());

    let step = trace.next_step();
    trace.add_edge(DagEdge::build_depends(
        snapshot_node.id,
        parse_node.id,
        scope.clone(),
        step,
    ));

    let mut file_nodes = Vec::new();
    for file in &out.files {
        let mut node = DagNode::new(
            NodeKind::FileAtPath {
                path: file.rel_path.clone(),
                content_sha256: file.artifact.sha256.clone(),
            },
            scope.clone(),
            vec![],
            vec![],
        )?;
        node.artifact_ref = Some(file.artifact.clone());
        trace.ensure_node(node.clone());
        file_nodes.push((file.rel_path.clone(), node));
    }

    for (_, node) in &file_nodes {
        let step = trace.next_step();
        trace.add_edge(DagEdge::build_depends(
            node.id,
            snapshot_node.id,
            scope.clone(),
            step,
        ));
    }

    let mut chunk_nodes = Vec::new();
    for chunk in &out.chunks {
        let mut node = DagNode::new(
            NodeKind::TextChunk {
                chunk_sha256: chunk.chunk_sha256.clone(),
                doc_path: chunk.rel_path.clone(),
                heading_path: chunk.heading_path.clone(),
                start_line: chunk.start_line,
            },
            scope.clone(),
            vec![],
            vec![],
        )?;
        node.artifact_ref = Some(chunk.artifact.clone());
        node.kind_meta = Some(serde_json::json!({
            "format": chunk.format.clone(),
            "language": chunk.language.clone(),
            "chunk_kind": chunk.chunk_kind.clone(),
            "start_line": chunk.start_line,
            "end_line": chunk.end_line,
            "start_byte": chunk.start_byte,
            "end_byte": chunk.end_byte,
            "repr_artifact": chunk.repr_artifact.clone(),
        }));
        trace.ensure_node(node.clone());
        chunk_nodes.push((chunk.rel_path.clone(), node));
    }

    // Link file -> chunk (chunk depends on file)
    let file_index: std::collections::HashMap<&str, &DagNode> =
        file_nodes.iter().map(|(p, n)| (p.as_str(), n)).collect();
    for (path, chunk_node) in &chunk_nodes {
        if let Some(file_node) = file_index.get(path.as_str()) {
            let step = trace.next_step();
            trace.add_edge(DagEdge::build_depends(
                file_node.id,
                chunk_node.id,
                scope.clone(),
                step,
            ));
        }

        // parse depends on each chunk (for easy traversal "what did parsing produce?")
        let step = trace.next_step();
        trace.add_edge(DagEdge::build_depends(
            chunk_node.id,
            parse_node.id,
            scope.clone(),
            step,
        ));
    }

    Ok(trace)
}

fn build_trace_for_checked(
    event: &admit_cli::AdmissibilityCheckedEvent,
) -> Result<DagTraceCollector, String> {
    let scope = ScopeTag::new("scope:core.pure");
    let mut trace = DagTraceCollector::new("cli.check");

    let mut witness_node = DagNode::new(
        NodeKind::Witness {
            witness_sha256: event.witness.sha256.clone(),
            schema_id: event.witness.schema_id.clone(),
        },
        scope.clone(),
        vec![],
        vec![],
    )?;
    witness_node.artifact_ref = Some(event.witness.clone());

    let cost_node = DagNode::new(
        NodeKind::CostDeclaration {
            content_hash: event.cost_declared_event_id.clone(),
        },
        scope.clone(),
        vec![],
        vec![],
    )?;

    let check_node = DagNode::new(
        NodeKind::AdmissibilityCheck {
            content_hash: event.event_id.clone(),
        },
        scope.clone(),
        vec![],
        vec![],
    )?;

    trace.ensure_node(witness_node.clone());
    trace.ensure_node(cost_node.clone());
    trace.ensure_node(check_node.clone());

    if let Some(snapshot_hash) = event.snapshot_hash.as_ref() {
        let mut snapshot_node = DagNode::new(
            NodeKind::SnapshotExport {
                snapshot_hash: snapshot_hash.clone(),
            },
            scope.clone(),
            vec![],
            vec![],
        )?;
        snapshot_node.artifact_ref = Some(event.snapshot_ref.clone());
        trace.ensure_node(snapshot_node.clone());
        let step = trace.next_step();
        trace.add_edge(DagEdge::build_depends(
            snapshot_node.id,
            check_node.id,
            scope.clone(),
            step,
        ));
    }

    if let Some(bundle_hash) = event.facts_bundle_hash.as_ref() {
        let facts_node = DagNode::new(
            NodeKind::FactsBundle {
                bundle_hash: bundle_hash.clone(),
            },
            scope.clone(),
            vec![],
            vec![],
        )?;
        trace.ensure_node(facts_node.clone());
        let step = trace.next_step();
        trace.add_edge(DagEdge::build_depends(
            facts_node.id,
            check_node.id,
            scope.clone(),
            step,
        ));
    }

    let step = trace.next_step();
    trace.add_edge(DagEdge::build_depends(
        cost_node.id,
        check_node.id,
        scope.clone(),
        step,
    ));
    let step = trace.next_step();
    trace.add_edge(DagEdge::witness_of(
        witness_node.id,
        check_node.id,
        scope.clone(),
        step,
    ));

    if let Some(registry_hash) = event.registry_hash.as_ref() {
        let authority_node = DagNode::new(
            NodeKind::AuthorityRoot {
                authority_id: "meta_registry/0".to_string(),
                authority_hash: registry_hash.clone(),
            },
            scope.clone(),
            vec![],
            vec![],
        )?;
        trace.ensure_node(authority_node.clone());
        let step = trace.next_step();
        trace.add_edge(DagEdge::authority_depends(
            authority_node.id,
            check_node.id,
            "meta_registry/0".to_string(),
            registry_hash.clone(),
            scope,
            step,
            None,
        ));
    }

    Ok(trace)
}

fn build_trace_for_executed(
    event: &admit_cli::AdmissibilityExecutedEvent,
) -> Result<DagTraceCollector, String> {
    let scope = ScopeTag::new("scope:core.pure");
    let mut trace = DagTraceCollector::new("cli.execute");

    let executed_node = DagNode::new(
        NodeKind::AdmissibilityExecution {
            content_hash: event.event_id.clone(),
        },
        scope.clone(),
        vec![],
        vec![],
    )?;

    let checked_node = DagNode::new(
        NodeKind::AdmissibilityCheck {
            content_hash: event.admissibility_checked_event_id.clone(),
        },
        scope.clone(),
        vec![],
        vec![],
    )?;

    let cost_node = DagNode::new(
        NodeKind::CostDeclaration {
            content_hash: event.cost_declared_event_id.clone(),
        },
        scope.clone(),
        vec![],
        vec![],
    )?;

    let mut witness_node = DagNode::new(
        NodeKind::Witness {
            witness_sha256: event.witness.sha256.clone(),
            schema_id: event.witness.schema_id.clone(),
        },
        scope.clone(),
        vec![],
        vec![],
    )?;
    witness_node.artifact_ref = Some(event.witness.clone());

    trace.ensure_node(executed_node.clone());
    trace.ensure_node(checked_node.clone());
    trace.ensure_node(cost_node.clone());
    trace.ensure_node(witness_node.clone());

    let step = trace.next_step();
    trace.add_edge(DagEdge::build_depends(
        checked_node.id,
        executed_node.id,
        scope.clone(),
        step,
    ));
    let step = trace.next_step();
    trace.add_edge(DagEdge::build_depends(
        cost_node.id,
        executed_node.id,
        scope.clone(),
        step,
    ));
    let step = trace.next_step();
    trace.add_edge(DagEdge::witness_of(
        witness_node.id,
        executed_node.id,
        scope.clone(),
        step,
    ));

    if let Some(registry_hash) = event.registry_hash.as_ref() {
        let authority_node = DagNode::new(
            NodeKind::AuthorityRoot {
                authority_id: "meta_registry/0".to_string(),
                authority_hash: registry_hash.clone(),
            },
            scope.clone(),
            vec![],
            vec![],
        )?;
        trace.ensure_node(authority_node.clone());
        let step = trace.next_step();
        trace.add_edge(DagEdge::authority_depends(
            authority_node.id,
            executed_node.id,
            "meta_registry/0".to_string(),
            registry_hash.clone(),
            scope,
            step,
            None,
        ));
    }

    Ok(trace)
}

fn build_trace_for_plan_created(
    event: &admit_cli::PlanCreatedEvent,
) -> Result<DagTraceCollector, String> {
    let scope = ScopeTag::new("scope:core.pure");
    let mut trace = DagTraceCollector::new("cli.plan.new");

    let mut plan_node = DagNode::new(
        NodeKind::PlanArtifact {
            plan_hash: event.plan_witness.sha256.clone(),
            template_id: event.template_id.clone(),
        },
        scope.clone(),
        vec![],
        vec![],
    )?;
    plan_node.artifact_ref = Some(event.plan_witness.clone());
    trace.ensure_node(plan_node.clone());

    if let Some(registry_hash) = event.registry_hash.as_ref() {
        let authority_node = DagNode::new(
            NodeKind::AuthorityRoot {
                authority_id: "meta_registry/0".to_string(),
                authority_hash: registry_hash.clone(),
            },
            scope.clone(),
            vec![],
            vec![],
        )?;
        trace.ensure_node(authority_node.clone());
        let step = trace.next_step();
        trace.add_edge(DagEdge::authority_depends(
            authority_node.id,
            plan_node.id,
            "meta_registry/0".to_string(),
            registry_hash.clone(),
            scope,
            step,
            None,
        ));
    }

    Ok(trace)
}

fn build_trace_for_calc_plan(plan_hash: &str) -> Result<DagTraceCollector, String> {
    let scope = ScopeTag::new("scope:core.pure");
    let mut trace = DagTraceCollector::new("cli.calc.plan");
    let plan_node = DagNode::new(
        NodeKind::CalcPlan {
            plan_hash: plan_hash.to_string(),
        },
        scope,
        vec![],
        vec![],
    )?;
    trace.ensure_node(plan_node);
    Ok(trace)
}

fn build_trace_for_calc_result(
    plan_hash: &str,
    witness_hash: &str,
) -> Result<DagTraceCollector, String> {
    let scope = ScopeTag::new("scope:core.pure");
    let mut trace = DagTraceCollector::new("cli.calc.execute");
    let plan_node = DagNode::new(
        NodeKind::CalcPlan {
            plan_hash: plan_hash.to_string(),
        },
        scope.clone(),
        vec![],
        vec![],
    )?;
    let result_node = DagNode::new(
        NodeKind::CalcResult {
            witness_hash: witness_hash.to_string(),
        },
        scope.clone(),
        vec![],
        vec![],
    )?;
    trace.ensure_node(plan_node.clone());
    trace.ensure_node(result_node.clone());
    let step = trace.next_step();
    trace.add_edge(DagEdge::build_depends(
        plan_node.id,
        result_node.id,
        scope,
        step,
    ));
    Ok(trace)
}
