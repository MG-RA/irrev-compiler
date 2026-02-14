use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use admit_core::provider_trait::Provider;
use admit_core::provider_types::{FactsBundle, Rfc3339Timestamp, Sha256Hex, SnapshotRequest};
use admit_core::{
    evaluate_ruleset_with_inputs, Fact, LintFailOn, RuleSet, ScopeId, Severity, Verdict,
};
use clap::{Parser, ValueEnum};
use sha2::Digest;

use admit_cli::{
    append_lens_activated_event, build_lens_activated_event, default_artifacts_dir,
    check_plan_contract, load_meta_registry, store_value_artifact, PlanCheckInput, ProgramRef,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum CiMode {
    Observe,
    Audit,
    Enforce,
}

impl CiMode {
    fn as_str(self) -> &'static str {
        match self {
            CiMode::Observe => "observe",
            CiMode::Audit => "audit",
            CiMode::Enforce => "enforce",
        }
    }
}

#[derive(Parser, Debug, Clone)]
pub(crate) struct CiArgs {
    /// Path to ci config TOML (default: <root>/.admit/config.toml)
    #[arg(long, value_name = "PATH")]
    pub config: Option<PathBuf>,
    /// Root path for repository/scopes (default: current directory)
    #[arg(long, value_name = "PATH")]
    pub root: Option<PathBuf>,
    /// Artifact store root (default: out/artifacts)
    #[arg(long)]
    pub artifacts_dir: Option<PathBuf>,
    /// Optional path to meta registry JSON (fallback: ADMIT_META_REGISTRY env)
    #[arg(long, value_name = "PATH")]
    pub meta_registry: Option<PathBuf>,
    /// CI mode: observe|audit|enforce
    #[arg(long, value_enum)]
    pub mode: Option<CiMode>,
    /// Output JSON instead of key=value lines
    #[arg(long)]
    pub json: bool,
    /// Require GitHub scope to be available when ruleset references github.ceremony
    #[arg(long)]
    pub require_github: bool,
    /// Optional plan artifact path (`plan-artifact/0`) for typed contract validation
    #[arg(long, value_name = "PATH")]
    pub plan: Option<PathBuf>,
    /// Optional proposal manifest path (`proposal-manifest/0`) for typed contract validation
    #[arg(long, value_name = "PATH")]
    pub manifest: Option<PathBuf>,
    /// Rollout mode for plan contract validation
    #[arg(long, value_enum, default_value = "advisory")]
    pub plan_rollout: PlanRolloutMode,
    /// Scope pack gate mode: warn emits witness warnings, error fails CI
    #[arg(long, value_enum, default_value = "warn")]
    pub scope_pack_gate: ScopePackGateModeArg,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum PlanRolloutMode {
    Advisory,
    Enforce,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub(crate) enum ScopePackGateModeArg {
    Warn,
    Error,
}

#[derive(Debug, Clone)]
struct CiResolvedConfig {
    ruleset_path: PathBuf,
    ruleset_ref: String,
    mode: CiMode,
    config_path: PathBuf,
    config_text: String,
    require_github_scope: bool,
}

const RULE_GITHUB_SCOPE_UNAVAILABLE: &str = "github/scope_unavailable";

#[derive(Debug, Clone)]
struct GithubWitnessContext {
    pr_number: i64,
    head_sha: String,
    payload_hash: String,
}

pub(crate) fn run_ci_check(args: CiArgs) -> Result<(), String> {
    let root = args.root.unwrap_or_else(|| PathBuf::from("."));
    let config_path = args
        .config
        .clone()
        .unwrap_or_else(|| root.join(".admit").join("config.toml"));
    let resolved = load_ci_config(&config_path, args.mode)?;
    let require_github = args.require_github || resolved.require_github_scope;

    let ruleset_bytes = std::fs::read(&resolved.ruleset_path).map_err(|err| {
        format!(
            "read ci ruleset '{}': {}",
            resolved.ruleset_path.display(),
            err
        )
    })?;
    let ruleset: RuleSet = serde_json::from_slice(&ruleset_bytes).map_err(|err| {
        format!(
            "decode ci ruleset '{}': {}",
            resolved.ruleset_path.display(),
            err
        )
    })?;

    let mut bundles: BTreeMap<ScopeId, FactsBundle> = BTreeMap::new();
    let mut scope_warning_facts: Vec<Fact> = Vec::new();
    let required_scopes = enabled_scope_ids(&ruleset);
    let needs_changed_paths = ruleset_needs_changed_paths_overlay(&ruleset);

    if required_scopes.contains(admit_scope_git::backend::GIT_WORKING_TREE_SCOPE_ID)
        || needs_changed_paths
    {
        let git_provider = admit_scope_git::provider_impl::GitWorkingTreeProvider::new();
        let git_snapshot = git_provider
            .snapshot(&SnapshotRequest {
                scope_id: ScopeId(admit_scope_git::backend::GIT_WORKING_TREE_SCOPE_ID.to_string()),
                params: serde_json::json!({ "root": root.to_string_lossy() }),
            })
            .map_err(|err| format!("git scope snapshot failed: {}", err.message))?;
        bundles.insert(
            git_snapshot.facts_bundle.scope_id.clone(),
            git_snapshot.facts_bundle,
        );
    }

    if required_scopes.contains(admit_scope_deps::backend::DEPS_MANIFEST_SCOPE_ID) {
        let deps_provider = admit_scope_deps::provider_impl::DepsManifestProvider::new();
        let deps_snapshot = deps_provider
            .snapshot(&SnapshotRequest {
                scope_id: ScopeId(admit_scope_deps::backend::DEPS_MANIFEST_SCOPE_ID.to_string()),
                params: serde_json::json!({ "root": root.to_string_lossy() }),
            })
            .map_err(|err| format!("deps scope snapshot failed: {}", err.message))?;
        bundles.insert(
            deps_snapshot.facts_bundle.scope_id.clone(),
            deps_snapshot.facts_bundle,
        );
    }

    if required_scopes.contains(admit_scope_github::backend::GITHUB_CEREMONY_SCOPE_ID) {
        let github_provider = admit_scope_github::provider_impl::GithubCeremonyProvider::new();
        match github_provider.snapshot(&SnapshotRequest {
            scope_id: ScopeId(admit_scope_github::backend::GITHUB_CEREMONY_SCOPE_ID.to_string()),
            params: serde_json::json!({ "root": root.to_string_lossy() }),
        }) {
            Ok(snapshot) => {
                bundles.insert(
                    snapshot.facts_bundle.scope_id.clone(),
                    snapshot.facts_bundle,
                );
            }
            Err(err) => {
                let warning = build_scope_unavailable_warning_fact(
                    admit_scope_github::backend::GITHUB_CEREMONY_SCOPE_ID,
                    &format!("gh scope unavailable: {}", err.message),
                );
                let fallback_bundle = build_scope_unavailable_bundle(
                    ScopeId(admit_scope_github::backend::GITHUB_CEREMONY_SCOPE_ID.to_string()),
                    admit_scope_github::backend::GITHUB_CEREMONY_SCHEMA_ID,
                    warning.clone(),
                )?;
                bundles.insert(fallback_bundle.scope_id.clone(), fallback_bundle);
                scope_warning_facts.push(warning);
            }
        }
    }

    if require_github
        && required_scopes.contains(admit_scope_github::backend::GITHUB_CEREMONY_SCOPE_ID)
        && !scope_warning_facts.is_empty()
    {
        let reasons = scope_warning_facts
            .iter()
            .filter_map(|fact| match fact {
                Fact::LintFinding { message, .. } => Some(message.clone()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "ci require-github failed: github.ceremony unavailable ({})",
            reasons
        ));
    }

    let changed_paths = observed_changed_paths(&bundles);
    let runtime_overlays = build_runtime_overlays(&ruleset, &changed_paths);
    let plan_enforce = matches!(args.plan_rollout, PlanRolloutMode::Enforce);
    let mut plan_contract = check_plan_contract(PlanCheckInput {
        plan_path: args.plan.clone(),
        manifest_path: args.manifest.clone(),
        changed_paths_observed: changed_paths.clone(),
        enforce: plan_enforce,
    });

    let registry = crate::build_ruleset_provider_registry(&ruleset)?;
    let scope_pack_gate_mode = match args.scope_pack_gate {
        ScopePackGateModeArg::Warn => admit_cli::ScopeGateMode::Warn,
        ScopePackGateModeArg::Error => admit_cli::ScopeGateMode::Error,
    };
    let meta_registry = load_meta_registry(args.meta_registry.as_deref())
        .map_err(|err| err.to_string())?
        .map(|(registry, _hash)| registry);
    let scope_pack_issues = crate::collect_scope_pack_issues(meta_registry.as_ref(), &registry)?;
    if scope_pack_gate_mode == admit_cli::ScopeGateMode::Error && !scope_pack_issues.is_empty() {
        return Err(crate::format_scope_pack_gate_error(&scope_pack_issues));
    }
    let mut outcome = evaluate_ruleset_with_inputs(
        &ruleset,
        &registry,
        Some(&bundles),
        (!runtime_overlays.is_empty()).then_some(&runtime_overlays),
    )
    .map_err(|err| err.0)?;
    append_scope_warning_facts(&mut outcome.witness.facts, &scope_warning_facts);
    if scope_pack_gate_mode == admit_cli::ScopeGateMode::Warn && !scope_pack_issues.is_empty() {
        outcome
            .witness
            .facts
            .extend(crate::scope_pack_issue_facts(&scope_pack_issues));
    }
    if matches!(outcome.witness.verdict, Verdict::Inadmissible) {
        plan_contract.apply_semantic_failure("semantic_ci_failure");
    }
    if plan_enforce && (plan_contract.requires_manual_approval || !plan_contract.errors.is_empty()) {
        plan_contract.exit_code = 2;
    }
    if plan_contract.requires_manual_approval
        || !plan_contract.errors.is_empty()
        || !plan_contract.warnings.is_empty()
    {
        let plan_contract_evidence = serde_json::to_value(&plan_contract).unwrap_or_else(|_| {
            serde_json::json!({
                "requires_manual_approval": plan_contract.requires_manual_approval,
                "stop_reasons": plan_contract.stop_reasons,
                "errors": plan_contract.errors,
                "warnings": plan_contract.warnings,
            })
        });
        outcome.witness.facts.push(Fact::LintFinding {
            rule_id: "plan/contract".to_string(),
            severity: if plan_contract.requires_manual_approval {
                Severity::Warning
            } else {
                Severity::Info
            },
            invariant: Some("ci.plan_contract".to_string()),
            path: ".".to_string(),
            span: admit_core::Span {
                file: ".".to_string(),
                start: None,
                end: None,
                line: None,
                col: None,
            },
            message: format!(
                "plan_contract plan_valid={} manifest_valid={} manual_approval={}",
                plan_contract.plan_valid,
                plan_contract.manifest_valid,
                plan_contract.requires_manual_approval
            ),
            evidence: Some(plan_contract_evidence),
        });
    }

    let github_context = bundles
        .get(&ScopeId(
            admit_scope_github::backend::GITHUB_CEREMONY_SCOPE_ID.to_string(),
        ))
        .and_then(extract_github_witness_context);
    let input_id = build_ci_input_id(&changed_paths, github_context.as_ref())?;
    let config_hash = build_ci_config_hash(
        &resolved.config_path,
        &resolved.config_text,
        &resolved.ruleset_ref,
    )?;
    let snapshot_hash = build_ci_snapshot_hash(&bundles)?;
    apply_ci_witness_metadata(
        &mut outcome.witness,
        &input_id,
        &config_hash,
        &snapshot_hash,
        github_context.as_ref(),
    );

    let witness_value =
        serde_json::to_value(&outcome.witness).map_err(|err| format!("witness encode: {}", err))?;
    let witness_hash = canonical_sha256(&witness_value)?;
    let witness_schema_id = outcome
        .witness
        .schema_id
        .as_deref()
        .unwrap_or(admit_core::DEFAULT_WITNESS_SCHEMA_ID);
    let artifacts_dir = args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
    let witness_artifact = store_value_artifact(
        artifacts_dir.as_path(),
        "witness",
        witness_schema_id,
        &witness_value,
    )
    .map_err(|err| err.to_string())?;

    let ledger_path = artifacts_dir.join("ledger.jsonl");
    if !outcome.witness.lens_id.trim().is_empty() && !outcome.witness.lens_hash.trim().is_empty() {
        let lens_event = build_lens_activated_event(
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true),
            outcome.witness.lens_id.clone(),
            outcome.witness.lens_hash.clone(),
            Some("ci".to_string()),
            ProgramRef {
                module: outcome.witness.program.module.0.clone(),
                scope: outcome.witness.program.scope.0.clone(),
            },
            None,
        )
        .map_err(|err| err.to_string())?;
        append_lens_activated_event(&ledger_path, &lens_event).map_err(|err| err.to_string())?;
    }

    let mut integrity_failures = Vec::new();
    if outcome.witness.lens_id.trim().is_empty() {
        integrity_failures.push("missing lens_id".to_string());
    }
    if outcome
        .witness
        .program
        .snapshot_hash
        .as_deref()
        .is_none_or(|v| v.trim().is_empty())
    {
        integrity_failures.push("missing snapshot_hash".to_string());
    }
    if resolved.mode == CiMode::Audit {
        let mut second = evaluate_ruleset_with_inputs(
            &ruleset,
            &registry,
            Some(&bundles),
            (!runtime_overlays.is_empty()).then_some(&runtime_overlays),
        )
        .map_err(|err| err.0)?;
        append_scope_warning_facts(&mut second.witness.facts, &scope_warning_facts);
        if scope_pack_gate_mode == admit_cli::ScopeGateMode::Warn && !scope_pack_issues.is_empty() {
            second
                .witness
                .facts
                .extend(crate::scope_pack_issue_facts(&scope_pack_issues));
        }
        apply_ci_witness_metadata(
            &mut second.witness,
            &input_id,
            &config_hash,
            &snapshot_hash,
            github_context.as_ref(),
        );
        let second_value = serde_json::to_value(&second.witness)
            .map_err(|err| format!("witness encode: {}", err))?;
        let second_hash = canonical_sha256(&second_value)?;
        if second_hash != witness_hash {
            integrity_failures.push("non-deterministic witness hash".to_string());
        }
    }

    let verdict_label = match outcome.witness.verdict {
        Verdict::Admissible => "admissible",
        Verdict::Inadmissible => "inadmissible",
    };
    let top_warnings: Vec<serde_json::Value> = outcome
        .rule_results
        .iter()
        .filter(|row| row.triggered && matches!(row.severity, Severity::Warning))
        .take(5)
        .map(|row| {
            serde_json::json!({
                "rule_id": row.rule_id,
                "scope_id": row.scope_id.0,
                "predicate": row.predicate
            })
        })
        .collect();
    let bucket_routes: Vec<String> = outcome
        .witness
        .displacement_trace
        .totals
        .iter()
        .map(|total| format!("{}:{}", total.bucket.name, total.total.unit))
        .collect();
    let fail_threshold = match ruleset.fail_on {
        LintFailOn::Error => "error",
        LintFailOn::Warning => "warning",
        LintFailOn::Info => "info",
    };
    let plan_contract_value =
        serde_json::to_value(&plan_contract).map_err(|err| format!("plan_contract encode: {}", err))?;
    let plan_requires_manual_approval = plan_contract.requires_manual_approval;
    let plan_stop_reasons = plan_contract.stop_reasons.clone();

    let summary = serde_json::json!({
        "mode": resolved.mode.as_str(),
        "verdict": verdict_label,
        "top_warnings": top_warnings,
        "scope_warnings": scope_warning_facts.iter().filter_map(|fact| {
            match fact {
                Fact::LintFinding { message, .. } => Some(message.clone()),
                _ => None
            }
        }).collect::<Vec<_>>(),
        "bucket_routes": bucket_routes,
        "fail_threshold": fail_threshold,
        "witness_hash": witness_hash,
        "witness_artifact_path": witness_artifact.path,
        "input_id": input_id,
        "config_hash": config_hash,
        "integrity_failures": integrity_failures,
        "github_required": require_github,
        "github_binding": github_context.as_ref().map(|ctx| serde_json::json!({
            "pr_number": ctx.pr_number,
            "head_sha": ctx.head_sha,
            "payload_hash": ctx.payload_hash
        })),
        "plan_contract": plan_contract_value,
        "requires_manual_approval": plan_requires_manual_approval,
        "stop_reasons": plan_stop_reasons,
    });

    if args.json {
        let text = serde_json::to_string_pretty(&summary)
            .map_err(|err| format!("json encode: {}", err))?;
        println!("{}", text);
    } else {
        println!("mode={}", resolved.mode.as_str());
        println!("verdict={}", verdict_label);
        println!("fail_threshold={}", fail_threshold);
        println!(
            "witness_hash={}",
            summary["witness_hash"].as_str().unwrap_or_default()
        );
        println!(
            "witness_artifact_path={}",
            summary["witness_artifact_path"]
                .as_str()
                .unwrap_or_default()
        );
        println!(
            "input_id={}",
            summary["input_id"].as_str().unwrap_or_default()
        );
        println!(
            "config_hash={}",
            summary["config_hash"].as_str().unwrap_or_default()
        );
        println!(
            "integrity_failures={}",
            summary["integrity_failures"]
                .as_array()
                .map(|rows| rows.len().to_string())
                .unwrap_or_else(|| "0".to_string())
        );
    }

    if resolved.mode == CiMode::Audit && !integrity_failures.is_empty() {
        return Err(format!(
            "ci audit failed: {}",
            integrity_failures.join(", ")
        ));
    }
    if resolved.mode == CiMode::Enforce && matches!(outcome.witness.verdict, Verdict::Inadmissible)
    {
        return Err("ci enforce failed: witness verdict is inadmissible".to_string());
    }
    if plan_enforce && plan_contract.exit_code == 2 {
        return Err(format!(
            "ci plan enforce failed: manual approval required ({})",
            plan_contract.stop_reasons.join(", ")
        ));
    }

    Ok(())
}

fn enabled_scope_ids(ruleset: &RuleSet) -> std::collections::BTreeSet<&str> {
    let enabled: std::collections::BTreeSet<&str> = if ruleset.enabled_rules.is_empty() {
        ruleset
            .bindings
            .iter()
            .map(|b| b.rule_id.as_str())
            .collect()
    } else {
        ruleset.enabled_rules.iter().map(|r| r.as_str()).collect()
    };
    ruleset
        .bindings
        .iter()
        .filter(|binding| enabled.contains(binding.rule_id.as_str()))
        .map(|binding| binding.when.scope_id.0.as_str())
        .collect()
}

fn ruleset_needs_changed_paths_overlay(ruleset: &RuleSet) -> bool {
    let enabled: std::collections::BTreeSet<&str> = if ruleset.enabled_rules.is_empty() {
        ruleset
            .bindings
            .iter()
            .map(|b| b.rule_id.as_str())
            .collect()
    } else {
        ruleset.enabled_rules.iter().map(|r| r.as_str()).collect()
    };
    ruleset.bindings.iter().any(|binding| {
        enabled.contains(binding.rule_id.as_str())
            && binding.when.scope_id.0 == admit_scope_deps::backend::DEPS_MANIFEST_SCOPE_ID
            && binding.when.predicate == "manifest_changed_without_lockfile"
    })
}

fn build_scope_unavailable_warning_fact(scope_id: &str, message: &str) -> Fact {
    Fact::LintFinding {
        rule_id: RULE_GITHUB_SCOPE_UNAVAILABLE.to_string(),
        severity: Severity::Info,
        invariant: Some("ci.scope_availability".to_string()),
        path: ".".to_string(),
        span: admit_core::Span {
            file: ".".to_string(),
            start: None,
            end: None,
            line: None,
            col: None,
        },
        message: message.to_string(),
        evidence: Some(serde_json::json!({
            "scope_id": scope_id
        })),
    }
}

fn build_scope_unavailable_bundle(
    scope_id: ScopeId,
    schema_id: &str,
    warning_fact: Fact,
) -> Result<FactsBundle, String> {
    let facts = vec![warning_fact];
    let facts_value = serde_json::to_value(&facts)
        .map_err(|err| format!("facts encode for fallback: {}", err))?;
    let snapshot_hash = canonical_sha256(&facts_value)?;
    Ok(FactsBundle {
        schema_id: schema_id.to_string(),
        scope_id,
        facts,
        snapshot_hash: Sha256Hex::new(snapshot_hash),
        created_at: Rfc3339Timestamp::new(chrono::Utc::now().to_rfc3339()),
    })
}

fn append_scope_warning_facts(target: &mut Vec<Fact>, warnings: &[Fact]) {
    for warning in warnings {
        target.push(warning.clone());
    }
}

fn load_ci_config(
    config_path: &Path,
    mode_override: Option<CiMode>,
) -> Result<CiResolvedConfig, String> {
    let config_text = std::fs::read_to_string(config_path)
        .map_err(|err| format!("read ci config '{}': {}", config_path.display(), err))?;
    let value: toml::Value = toml::from_str(&config_text)
        .map_err(|err| format!("parse ci config '{}': {}", config_path.display(), err))?;
    let ci = value
        .get("ci")
        .and_then(|v| v.as_table())
        .ok_or_else(|| format!("ci config '{}' missing [ci] section", config_path.display()))?;
    let ruleset_ref = ci
        .get("default_ruleset")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            format!(
                "ci config '{}' missing ci.default_ruleset",
                config_path.display()
            )
        })?
        .to_string();
    let config_mode = ci
        .get("mode")
        .and_then(|v| v.as_str())
        .map(parse_ci_mode)
        .transpose()?
        .unwrap_or(CiMode::Observe);
    let require_github_scope = ci
        .get("require_github_scope")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let mode = mode_override.unwrap_or(config_mode);

    let ruleset_path = {
        let p = PathBuf::from(&ruleset_ref);
        if p.is_absolute() {
            p
        } else {
            config_path
                .parent()
                .unwrap_or_else(|| Path::new("."))
                .join(p)
        }
    };

    Ok(CiResolvedConfig {
        ruleset_path,
        ruleset_ref,
        mode,
        config_path: config_path.to_path_buf(),
        config_text,
        require_github_scope,
    })
}

fn parse_ci_mode(raw: &str) -> Result<CiMode, String> {
    match raw {
        "observe" => Ok(CiMode::Observe),
        "audit" => Ok(CiMode::Audit),
        "enforce" => Ok(CiMode::Enforce),
        other => Err(format!(
            "invalid ci mode '{}'; expected observe|audit|enforce",
            other
        )),
    }
}

fn extract_git_changed_paths(bundle: &FactsBundle) -> Vec<String> {
    let mut paths = Vec::new();
    for fact in &bundle.facts {
        if let Fact::LintFinding {
            rule_id,
            evidence: Some(evidence),
            ..
        } = fact
        {
            if rule_id == "git/changed_paths" {
                if let Some(arr) = evidence.get("paths").and_then(|v| v.as_array()) {
                    for item in arr {
                        if let Some(path) = item.as_str() {
                            paths.push(path.to_string());
                        }
                    }
                }
                break;
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

fn extract_github_changed_paths(bundle: &FactsBundle) -> Vec<String> {
    let mut paths = Vec::new();
    for fact in &bundle.facts {
        if let Fact::LintFinding {
            rule_id,
            evidence: Some(evidence),
            ..
        } = fact
        {
            if rule_id == "github/changed_files" {
                if let Some(arr) = evidence.get("files").and_then(|v| v.as_array()) {
                    for item in arr {
                        if let Some(path) = item.as_str() {
                            paths.push(path.to_string());
                        }
                    }
                }
                break;
            }
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

fn observed_changed_paths(bundles: &BTreeMap<ScopeId, FactsBundle>) -> Vec<String> {
    let mut github_paths = Vec::new();
    if let Some(bundle) = bundles.get(&ScopeId(
        admit_scope_github::backend::GITHUB_CEREMONY_SCOPE_ID.to_string(),
    )) {
        github_paths = extract_github_changed_paths(bundle);
    }
    if !github_paths.is_empty() {
        return github_paths;
    }

    let mut observed = BTreeSet::new();
    if let Some(bundle) = bundles.get(&ScopeId(
        admit_scope_git::backend::GIT_WORKING_TREE_SCOPE_ID.to_string(),
    )) {
        for path in extract_git_changed_paths(bundle) {
            observed.insert(path);
        }
    }
    observed.into_iter().collect()
}

fn build_runtime_overlays(
    ruleset: &RuleSet,
    changed_paths: &[String],
) -> BTreeMap<String, serde_json::Value> {
    let mut overlays = BTreeMap::new();
    for binding in &ruleset.bindings {
        if binding.when.scope_id.0 == admit_scope_deps::backend::DEPS_MANIFEST_SCOPE_ID
            && binding.when.predicate == "manifest_changed_without_lockfile"
        {
            overlays.insert(
                binding.rule_id.clone(),
                serde_json::json!({ "changed_paths": changed_paths }),
            );
        }
    }
    overlays
}

fn extract_github_witness_context(bundle: &FactsBundle) -> Option<GithubWitnessContext> {
    for fact in &bundle.facts {
        let Fact::LintFinding {
            rule_id,
            evidence: Some(evidence),
            ..
        } = fact
        else {
            continue;
        };
        if rule_id != "github/pr_state" {
            continue;
        }
        let pr_number = evidence.get("number").and_then(|v| v.as_i64())?;
        let head_sha = evidence.get("sha").and_then(|v| v.as_str())?.to_string();
        if head_sha.trim().is_empty() {
            continue;
        }
        return Some(GithubWitnessContext {
            pr_number,
            head_sha,
            payload_hash: bundle.snapshot_hash.0.clone(),
        });
    }
    None
}

fn build_ci_input_id(
    changed_paths: &[String],
    github_context: Option<&GithubWitnessContext>,
) -> Result<String, String> {
    let value = serde_json::json!({
        "inputs": {
            "git": {
                "changed_paths": changed_paths
            },
            "github": github_context.map(|ctx| serde_json::json!({
                "pr_number": ctx.pr_number,
                "head_sha": ctx.head_sha,
                "payload_hash": ctx.payload_hash
            }))
        }
    });
    canonical_sha256(&value)
}

fn build_ci_config_hash(
    config_path: &Path,
    config_text: &str,
    ruleset_ref: &str,
) -> Result<String, String> {
    let value = serde_json::json!({
        "config_path": config_path.to_string_lossy(),
        "config_toml": config_text,
        "ruleset_ref": ruleset_ref
    });
    canonical_sha256(&value)
}

fn build_ci_snapshot_hash(bundles: &BTreeMap<ScopeId, FactsBundle>) -> Result<String, String> {
    let rows: Vec<serde_json::Value> = bundles
        .iter()
        .map(|(scope, bundle)| {
            serde_json::json!({
                "scope_id": scope.0,
                "schema_id": bundle.schema_id,
                "snapshot_hash": bundle.snapshot_hash.0
            })
        })
        .collect();
    canonical_sha256(&serde_json::json!({ "inputs": rows }))
}

fn apply_ci_witness_metadata(
    witness: &mut admit_core::Witness,
    input_id: &str,
    config_hash: &str,
    snapshot_hash: &str,
    github_context: Option<&GithubWitnessContext>,
) {
    witness.input_id = Some(input_id.to_string());
    witness.config_hash = Some(config_hash.to_string());
    witness.program.snapshot_hash = Some(snapshot_hash.to_string());
    if let Some(ctx) = github_context {
        witness.program.content_id = Some(format!(
            "github-pr:{}:{}:{}",
            ctx.pr_number, ctx.head_sha, ctx.payload_hash
        ));
    }
}

fn canonical_sha256(value: &serde_json::Value) -> Result<String, String> {
    let bytes = admit_core::encode_canonical_value(value).map_err(|err| err.0)?;
    Ok(hex::encode(sha2::Sha256::digest(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use admit_core::provider_types::FactsBundle;
    use admit_core::witness::Fact;

    fn mk_bundle(scope_id: &str, rule_id: &str, evidence: serde_json::Value) -> FactsBundle {
        FactsBundle {
            schema_id: format!("facts-bundle/{}@1", scope_id),
            scope_id: ScopeId(scope_id.to_string()),
            facts: vec![Fact::LintFinding {
                rule_id: rule_id.to_string(),
                severity: Severity::Info,
                invariant: None,
                path: ".".to_string(),
                span: admit_core::Span {
                    file: ".".to_string(),
                    start: None,
                    end: None,
                    line: None,
                    col: None,
                },
                message: "fixture".to_string(),
                evidence: Some(evidence),
            }],
            snapshot_hash: Sha256Hex::new("abc123"),
            created_at: Rfc3339Timestamp::new("2026-02-14T00:00:00Z"),
        }
    }

    #[test]
    fn observed_changed_paths_prefers_github_when_available() {
        let mut bundles = BTreeMap::new();
        bundles.insert(
            ScopeId(admit_scope_git::backend::GIT_WORKING_TREE_SCOPE_ID.to_string()),
            mk_bundle(
                admit_scope_git::backend::GIT_WORKING_TREE_SCOPE_ID,
                "git/changed_paths",
                serde_json::json!({ "paths": ["Cargo.toml", "tmp/generated.json"] }),
            ),
        );
        bundles.insert(
            ScopeId(admit_scope_github::backend::GITHUB_CEREMONY_SCOPE_ID.to_string()),
            mk_bundle(
                admit_scope_github::backend::GITHUB_CEREMONY_SCOPE_ID,
                "github/changed_files",
                serde_json::json!({ "files": ["src/lib.rs", "Cargo.toml"] }),
            ),
        );

        let observed = observed_changed_paths(&bundles);
        assert_eq!(observed, vec!["Cargo.toml".to_string(), "src/lib.rs".to_string()]);
    }

    #[test]
    fn observed_changed_paths_falls_back_to_git_when_github_missing() {
        let mut bundles = BTreeMap::new();
        bundles.insert(
            ScopeId(admit_scope_git::backend::GIT_WORKING_TREE_SCOPE_ID.to_string()),
            mk_bundle(
                admit_scope_git::backend::GIT_WORKING_TREE_SCOPE_ID,
                "git/changed_paths",
                serde_json::json!({ "paths": ["src/main.rs", "Cargo.toml", "src/main.rs"] }),
            ),
        );
        bundles.insert(
            ScopeId(admit_scope_github::backend::GITHUB_CEREMONY_SCOPE_ID.to_string()),
            mk_bundle(
                admit_scope_github::backend::GITHUB_CEREMONY_SCOPE_ID,
                "github/scope_unavailable",
                serde_json::json!({ "scope_id": admit_scope_github::backend::GITHUB_CEREMONY_SCOPE_ID }),
            ),
        );

        let observed = observed_changed_paths(&bundles);
        assert_eq!(
            observed,
            vec!["Cargo.toml".to_string(), "src/main.rs".to_string()]
        );
    }
}
