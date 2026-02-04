use std::path::PathBuf;

use clap::{Parser, Subcommand};
use sha2::Digest;

use admit_cli::{
    append_checked_event, append_event, append_executed_event, append_plan_created_event,
    check_cost_declared, create_plan, declare_cost, default_artifacts_dir, default_ledger_path,
    execute_checked, export_plan_markdown, list_artifacts, read_artifact_projection,
    read_file_bytes, registry_build, registry_init, render_plan_text, verify_ledger,
    verify_witness, ArtifactInput, DeclareCostInput, MetaRegistryV0, PlanNewInput,
    ScopeGateMode, VerifyWitnessInput,
    scope_add, scope_verify, scope_list, scope_show,
    ScopeAddArgs as ScopeAddArgsLib, ScopeVerifyArgs as ScopeVerifyArgsLib,
    ScopeListArgs as ScopeListArgsLib, ScopeShowArgs as ScopeShowArgsLib,
};

#[derive(Parser)]
#[command(name = "admit-cli", version, about = "Admissibility compiler CLI utilities")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
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
    /// Vault snapshot hash (optional, binds plan to a vault state)
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

    let result = match cli.command {
        Commands::DeclareCost(args) => run_declare_cost(args),
        Commands::WitnessVerify(args) => run_witness_verify(args),
        Commands::Check(args) => run_check(args),
        Commands::Execute(args) => run_execute(args),
        Commands::VerifyLedger(args) => run_verify_ledger(args),
        Commands::BundleVerify(args) => run_bundle_verify(args),
        Commands::Observe(args) => run_observe(args),
        Commands::ListArtifacts(args) => run_list_artifacts(args),
        Commands::ShowArtifact(args) => run_show_artifact(args),
        Commands::Registry(args) => run_registry(args),
        Commands::Plan(args) => match args.command {
            PlanCommands::New(new_args) => run_plan_new(new_args),
            PlanCommands::Show(show_args) => run_plan_show(show_args),
            PlanCommands::Export(export_args) => run_plan_export(export_args),
        },
        Commands::Calc(args) => match args.command {
            CalcCommands::Plan(plan_args) => run_calc_plan(plan_args),
            CalcCommands::Execute(exec_args) => run_calc_execute(exec_args),
            CalcCommands::Describe(desc_args) => run_calc_describe(desc_args),
        },
    };

    if let Err(err) = result {
        eprintln!("{}", err);
        std::process::exit(1);
    }
}

fn run_declare_cost(args: DeclareCostArgs) -> Result<(), String> {
    let witness_json = match args.witness_json {
        Some(path) => Some(
            read_file_bytes(&path)
                .map_err(|err| format!("read witness_json: {}", err))?,
        ),
        None => None,
    };

    let witness_cbor = match args.witness_cbor {
        Some(path) => Some(
            read_file_bytes(&path)
                .map_err(|err| format!("read witness_cbor: {}", err))?,
        ),
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
        let json =
            serde_json::to_string(&event).map_err(|err| format!("json encode: {}", err))?;
        println!("{}", json);
    } else {
        println!("event_id={}", event.event_id);
        println!("witness_sha256={}", event.witness.sha256);
        println!("ledger={}", ledger_path.display());
        if args.dry_run {
            println!("dry_run=true");
        }
    }

    Ok(())
}

fn run_witness_verify(args: WitnessVerifyArgs) -> Result<(), String> {
    let witness_json = match args.witness_json {
        Some(path) => Some(
            read_file_bytes(&path)
                .map_err(|err| format!("read witness_json: {}", err))?,
        ),
        None => None,
    };

    let witness_cbor = match args.witness_cbor {
        Some(path) => Some(
            read_file_bytes(&path)
                .map_err(|err| format!("read witness_cbor: {}", err))?,
        ),
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

fn run_check(args: CheckArgs) -> Result<(), String> {
    let ledger_path = args.ledger.unwrap_or_else(default_ledger_path);
    let artifacts_dir = args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
    let timestamp = args
        .timestamp
        .unwrap_or_else(|| chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true));
    let facts_bundle_input = match (
        args.facts_bundle,
        std::env::var("FACTS_BUNDLE_PATH").ok(),
    ) {
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
        let json =
            serde_json::to_string(&event).map_err(|err| format!("json encode: {}", err))?;
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
    Ok(())
}

fn run_execute(args: ExecuteArgs) -> Result<(), String> {
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
        let json =
            serde_json::to_string(&event).map_err(|err| format!("json encode: {}", err))?;
        println!("{}", json);
    } else {
        println!("event_id={}", event.event_id);
        println!("checked_event_id={}", event.admissibility_checked_event_id);
        println!("ledger={}", ledger_path.display());
        if args.dry_run {
            println!("dry_run=true");
        }
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
    path.map(|p| p.to_path_buf())
        .or_else(|| std::env::var("ADMIT_META_REGISTRY").ok().map(std::path::PathBuf::from))
}

fn warn_missing_scope(path: Option<&std::path::Path>, scope_id: &str) -> Result<(), String> {
    let path = match resolve_meta_registry_path(path) {
        Some(path) => path,
        None => return Ok(()),
    };
    if !path.exists() {
        return Err(format!("meta registry not found: {}", path.display()));
    }
    let bytes =
        std::fs::read(&path).map_err(|err| format!("read meta registry: {}", err))?;
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

fn run_verify_ledger(args: VerifyLedgerArgs) -> Result<(), String> {
    let ledger_path = args.ledger.unwrap_or_else(default_ledger_path);
    let artifacts_dir = args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
    let report =
        verify_ledger(&ledger_path, Some(artifacts_dir.as_path())).map_err(|err| err.to_string())?;

    if args.json {
        let json =
            serde_json::to_string(&report).map_err(|err| format!("json encode: {}", err))?;
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

fn run_bundle_verify(args: BundleVerifyArgs) -> Result<(), String> {
    let loaded = program_bundle::load_bundle_with_hash(&args.bundle)
        .map_err(|err| format!("bundle load: {}", err))?;

    if args.json {
        let output = serde_json::json!({
            "bundle_hash": loaded.sha256,
            "schema_id": loaded.bundle.schema_id,
            "schema_version": loaded.bundle.schema_version
        });
        let json =
            serde_json::to_string(&output).map_err(|err| format!("json encode: {}", err))?;
        println!("{}", json);
    } else {
        println!("bundle_hash={}", loaded.sha256);
        println!("schema_id={}", loaded.bundle.schema_id);
        println!("schema_version={}", loaded.bundle.schema_version);
    }

    Ok(())
}

fn run_observe(args: ObserveArgs) -> Result<(), String> {
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
        None => std::env::current_dir()
            .map_err(|err| format!("current_dir: {}", err))?,
    };

    let bundle = facts_bundle::observe_regex(
        &args.input,
        &patterns,
        args.case_insensitive,
        args.generated_at,
        Some(&source_root),
    )
    .map_err(|err| err.to_string())?;
    let bundle_with_hash =
        facts_bundle::bundle_with_hash(bundle).map_err(|err| err.to_string())?;

    let out_path = args
        .out
        .unwrap_or_else(|| PathBuf::from("out/facts-bundle.json"));
    if let Some(parent) = out_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)
                .map_err(|err| format!("create out dir: {}", err))?;
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
        let json =
            serde_json::to_string(&output).map_err(|err| format!("json encode: {}", err))?;
        println!("{}", json);
    } else {
        println!("bundle_hash={}", bundle_with_hash.sha256);
        println!("bundle_path={}", out_path.display());
        println!("hash_path={}", hash_path.display());
    }
    Ok(())
}

fn run_list_artifacts(args: ListArtifactsArgs) -> Result<(), String> {
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

fn run_show_artifact(args: ShowArtifactArgs) -> Result<(), String> {
    let artifacts_dir = args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
    let projection = read_artifact_projection(&artifacts_dir, &args.kind, &args.sha256)
        .map_err(|err| err.to_string())?;
    if let Some(bytes) = projection {
        let text = String::from_utf8(bytes).map_err(|err| format!("utf8 error: {}", err))?;
        println!("{}", text);
        return Ok(());
    }

    let path = artifacts_dir.join(&args.kind).join(format!("{}.cbor", args.sha256));
    let size = std::fs::metadata(&path)
        .map_err(|err| format!("artifact not found: {}", err))?
        .len();
    if args.json {
        let output = serde_json::json!({
            "kind": args.kind,
            "sha256": args.sha256,
            "size_bytes": size,
            "path": format!("{}/{}.cbor", args.kind, args.sha256)
        });
        let json =
            serde_json::to_string(&output).map_err(|err| format!("json encode: {}", err))?;
        println!("{}", json);
    } else {
        println!("kind={}", args.kind);
        println!("sha256={}", args.sha256);
        println!("size_bytes={}", size);
        println!("path={}/{}.cbor", args.kind, args.sha256);
    }
    Ok(())
}

fn run_registry(args: RegistryArgs) -> Result<(), String> {
    match args.command {
        RegistryCommands::Init(init_args) => {
            registry_init(&init_args.out).map_err(|err| err.to_string())?;
            println!("registry_written={}", init_args.out.display());
            Ok(())
        }
        RegistryCommands::Build(build_args) => {
            let artifacts_dir = build_args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
            let reference =
                registry_build(&build_args.input, &artifacts_dir).map_err(|err| err.to_string())?;
            println!("registry_hash={}", reference.sha256);
            println!("registry_path={}", reference.path.unwrap_or_default());
            Ok(())
        }
        RegistryCommands::Verify(verify_args) => {
            let ledger_path = verify_args.ledger.unwrap_or_else(default_ledger_path);
            let artifacts_dir = verify_args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
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

fn run_plan_new(args: PlanNewArgs) -> Result<(), String> {
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
        let json =
            serde_json::to_string(&event).map_err(|err| format!("json encode: {}", err))?;
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

    Ok(())
}

fn run_plan_show(args: PlanShowArgs) -> Result<(), String> {
    let artifacts_dir = args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
    let text =
        render_plan_text(&artifacts_dir, &args.plan_id).map_err(|err| err.to_string())?;
    print!("{}", text);
    Ok(())
}

fn run_plan_export(args: PlanExportArgs) -> Result<(), String> {
    let artifacts_dir = args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
    let md =
        export_plan_markdown(&artifacts_dir, &args.plan_id).map_err(|err| err.to_string())?;

    if let Some(parent) = args.out.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)
                .map_err(|err| format!("create out dir: {}", err))?;
        }
    }
    std::fs::write(&args.out, &md).map_err(|err| format!("write export: {}", err))?;
    println!("exported={}", args.out.display());
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
    println!("registry_version={} -> {}", witness.registry_version_before, witness.registry_version_after);
    println!("registry_hash_before={}", witness.registry_hash_before);
    println!("registry_hash_after={}", witness.registry_hash_after);
    println!("registry={}", args.registry.display());

    if args.dry_run {
        println!("dry_run=true (registry not modified)");
    }

    // Show validation results
    let warnings: Vec<_> = witness.validations.iter()
        .filter(|v| !v.passed && v.severity.to_string() == "warning")
        .collect();

    if !warnings.is_empty() {
        eprintln!("\nWarnings:");
        for w in warnings {
            eprintln!("  {}: {}", w.check, w.message.as_deref().unwrap_or("failed"));
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
        let json = serde_json::to_string(&validations)
            .map_err(|err| format!("json encode: {}", err))?;
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
        let json = serde_json::to_string(&scopes)
            .map_err(|err| format!("json encode: {}", err))?;
        println!("{}", json);
    } else {
        println!("registry={}", args.registry.display());
        println!("count={}", scopes.len());
        for scope in &scopes {
            let phase_str = scope.phase.map(|p| format!("{:?}", p)).unwrap_or_else(|| "-".to_string());
            let role_str = scope.role.as_ref().map(|r| format!("{:?}", r)).unwrap_or_else(|| "-".to_string());
            println!("scope id={} version={} phase={} role={}", scope.id, scope.version, phase_str, role_str);
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
        let json = serde_json::to_string(&scope)
            .map_err(|err| format!("json encode: {}", err))?;
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

fn run_calc_plan(args: CalcPlanArgs) -> Result<(), String> {
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

    Ok(())
}

fn run_calc_execute(args: CalcExecuteArgs) -> Result<(), String> {
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

    Ok(())
}

fn run_calc_describe(_args: CalcDescribeArgs) -> Result<(), String> {
    use admit_cli::calc_commands::calc_describe;

    let desc = calc_describe();
    let json = serde_json::to_string_pretty(&desc)
        .map_err(|e| format!("failed to serialize description: {}", e))?;

    println!("{}", json);

    Ok(())
}
