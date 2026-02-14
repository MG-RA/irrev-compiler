//! Governance visualization commands (`status`, `show`, `explain`, `log`).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use admit_cli::{
    default_artifacts_dir, default_ledger_path, list_artifacts, resolve_scope_enablement,
    KNOWN_SCOPES,
};
use admit_core::provider_types::FactsBundle;
use admit_core::{Fact, RuleSet, Severity, Witness};
use chrono::{DateTime, Duration, Utc};
use sha2::Digest;

use crate::{
    ExplainArgs, LogArgs, LogSourceArg, LogVerdictArg, SchemaKindArg, ShowArgs, StatusArgs,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SchemaKind {
    Witness,
    Ruleset,
    FactsBundle,
    Unknown,
}

impl SchemaKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Witness => "witness",
            Self::Ruleset => "ruleset",
            Self::FactsBundle => "facts_bundle",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
struct ResolvedArtifact {
    target: String,
    source_path: PathBuf,
    store_kind: Option<String>,
    store_rel_path: Option<String>,
    schema_id: Option<String>,
    schema_kind: SchemaKind,
    payload: serde_json::Value,
    canonical_cbor: Vec<u8>,
    canonical_sha256: String,
}

#[derive(Debug, Clone)]
struct ShowSections {
    inputs: Vec<serde_json::Value>,
    rules: Vec<serde_json::Value>,
    findings: Vec<serde_json::Value>,
    trace: Vec<serde_json::Value>,
}

impl ShowSections {
    fn empty() -> Self {
        Self {
            inputs: Vec::new(),
            rules: Vec::new(),
            findings: Vec::new(),
            trace: Vec::new(),
        }
    }

    fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "inputs": self.inputs,
            "rules": self.rules,
            "findings": self.findings,
            "trace": self.trace,
        })
    }
}

#[derive(Debug, Clone)]
struct ExplainData {
    verdict: String,
    rules: Vec<serde_json::Value>,
    predicate_trace: Vec<serde_json::Value>,
    findings: Vec<serde_json::Value>,
    grouped_by_file: Vec<serde_json::Value>,
}

#[derive(Debug, Clone)]
struct GitRepoContext {
    root: Option<String>,
    branch: Option<String>,
    head: Option<String>,
}

#[derive(Debug, Clone)]
struct WitnessSummary {
    verdict: Option<String>,
    ruleset_hash: Option<String>,
}

#[derive(Debug, Clone)]
struct LedgerRow {
    timestamp: String,
    timestamp_dt: Option<DateTime<Utc>>,
    event_type: String,
    event_id: String,
    witness_sha: Option<String>,
    snapshot_hash: Option<String>,
    scope: Option<String>,
    verdict: Option<String>,
    ruleset_hash: Option<String>,
    facts_bundle_hash: Option<String>,
    admissibility_checked_event_id: Option<String>,
}

impl LedgerRow {
    fn to_json_value(&self) -> serde_json::Value {
        serde_json::json!({
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "event_id": self.event_id,
            "witness_sha": self.witness_sha,
            "snapshot_hash": self.snapshot_hash,
            "scope": self.scope,
            "verdict": self.verdict,
            "ruleset_hash": self.ruleset_hash,
            "facts_bundle_hash": self.facts_bundle_hash,
            "admissibility_checked_event_id": self.admissibility_checked_event_id,
        })
    }
}

pub fn run_status(args: StatusArgs) -> Result<(), String> {
    let ledger_path = args.ledger.unwrap_or_else(default_ledger_path);
    let artifacts_dir = args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
    let rows = if ledger_path.exists() {
        parse_ledger_rows(ledger_path.as_path(), artifacts_dir.as_path())?
    } else {
        Vec::new()
    };
    let repo = detect_repo_context();
    let latest_event = rows.last().cloned();
    let latest_check = rows
        .iter()
        .rev()
        .find(|row| row.event_type == "admissibility.checked")
        .cloned();
    let latest_execute = rows
        .iter()
        .rev()
        .find(|row| row.event_type == "admissibility.executed")
        .cloned();
    let (evidence_state, evidence_reason) =
        evidence_state_reason(latest_check.as_ref(), latest_execute.as_ref());
    let scope_enablement = match resolve_scope_enablement(Path::new(".")) {
        Ok(value) => Some(value),
        Err(err) => {
            if !args.json {
                eprintln!("Warning: scope config unavailable: {}", err);
            }
            None
        }
    };
    let known_scope_ids: Vec<&str> = KNOWN_SCOPES.iter().map(|scope| scope.id).collect();
    let governance_ruleset_hash = latest_check
        .as_ref()
        .and_then(|row| row.ruleset_hash.clone());

    if args.json {
        let value = serde_json::json!({
            "command": "status",
            "repo": {
                "root": repo.root,
                "branch": repo.branch,
                "head": repo.head,
            },
            "ledger": {
                "path": ledger_path.display().to_string(),
                "events_total": rows.len(),
                "latest_event": latest_event.as_ref().map(|row| row.to_json_value()),
            },
            "governance": {
                "latest_check": latest_check.as_ref().map(|row| row.to_json_value()),
                "latest_execute": latest_execute.as_ref().map(|row| row.to_json_value()),
                "ruleset_hash": governance_ruleset_hash,
                "evidence": {
                    "state": evidence_state,
                    "reason": evidence_reason,
                    "latest_snapshot_hash": latest_check.as_ref().and_then(|row| row.snapshot_hash.clone()),
                    "latest_facts_bundle_hash": latest_check.as_ref().and_then(|row| row.facts_bundle_hash.clone()),
                    "latest_witness_sha": latest_check.as_ref().and_then(|row| row.witness_sha.clone()),
                },
            },
            "scopes": {
                "known": known_scope_ids,
                "enabled": scope_enablement.as_ref().map(|v| v.enabled_scope_ids().to_vec()).unwrap_or_default(),
                "source": scope_enablement
                    .as_ref()
                    .and_then(|v| v.source.as_ref())
                    .map(|p| p.display().to_string()),
            }
        });
        println!(
            "{}",
            serde_json::to_string(&value).map_err(|err| format!("json encode: {}", err))?
        );
        return Ok(());
    }

    println!("Status");
    println!("\nRepo:");
    println!("- root={}", repo.root.as_deref().unwrap_or("-"));
    println!("- branch={}", repo.branch.as_deref().unwrap_or("-"));
    println!("- head={}", repo.head.as_deref().unwrap_or("-"));

    println!("\nLedger:");
    println!("- path={}", ledger_path.display());
    println!("- events_total={}", rows.len());
    if let Some(row) = latest_event.as_ref() {
        println!(
            "- latest_event={} {} {}",
            row.timestamp, row.event_type, row.event_id
        );
    } else {
        println!("- latest_event=-");
    }

    println!("\nGovernance:");
    if let Some(row) = latest_check.as_ref() {
        println!(
            "- latest_check={} event_id={} verdict={} scope={} snapshot_hash={} ruleset_hash={}",
            row.timestamp,
            row.event_id,
            row.verdict.as_deref().unwrap_or("-"),
            row.scope.as_deref().unwrap_or("-"),
            row.snapshot_hash.as_deref().unwrap_or("-"),
            row.ruleset_hash.as_deref().unwrap_or("-")
        );
    } else {
        println!("- latest_check=-");
    }
    if let Some(row) = latest_execute.as_ref() {
        println!(
            "- latest_execute={} event_id={} checked_event_id={} verdict={}",
            row.timestamp,
            row.event_id,
            row.admissibility_checked_event_id.as_deref().unwrap_or("-"),
            row.verdict.as_deref().unwrap_or("-")
        );
    } else {
        println!("- latest_execute=-");
    }

    println!("\nEvidence:");
    println!("- state={}", evidence_state);
    println!("- reason={}", evidence_reason);
    println!(
        "- latest_snapshot_hash={}",
        latest_check
            .as_ref()
            .and_then(|row| row.snapshot_hash.as_deref())
            .unwrap_or("-")
    );
    println!(
        "- latest_facts_bundle_hash={}",
        latest_check
            .as_ref()
            .and_then(|row| row.facts_bundle_hash.as_deref())
            .unwrap_or("-")
    );

    println!("\nScopes:");
    println!("- known={}", known_scope_ids.join(","));
    if let Some(enablement) = scope_enablement.as_ref() {
        println!("- enabled={}", enablement.enabled_scope_ids().join(","));
        if let Some(source) = enablement.source.as_ref() {
            println!("- source={}", source.display());
        } else {
            println!("- source=-");
        }
    } else {
        println!("- enabled=-");
        println!("- source=-");
    }

    Ok(())
}

pub fn run_show(args: ShowArgs) -> Result<(), String> {
    let mode_count = usize::from(args.json) + usize::from(args.cbor) + usize::from(args.quiet);
    if mode_count > 1 {
        return Err(
            "show output flags are mutually exclusive: use only one of --json/--cbor/--quiet"
                .to_string(),
        );
    }

    let artifacts_dir = args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
    let resolved = resolve_target(&args.target, artifacts_dir.as_path(), args.kind)?;

    if args.quiet {
        println!("sha256:{}", resolved.canonical_sha256);
        return Ok(());
    }

    if args.cbor {
        let mut stdout = std::io::stdout();
        stdout
            .write_all(&resolved.canonical_cbor)
            .map_err(|err| format!("write stdout: {}", err))?;
        stdout
            .flush()
            .map_err(|err| format!("flush stdout: {}", err))?;
        return Ok(());
    }

    let sections = build_show_sections(&resolved);
    if args.json {
        let value = serde_json::json!({
            "command": "show",
            "target": resolved.target,
            "artifact": show_artifact_json(&resolved),
            "detected_type": resolved.schema_kind.as_str(),
            "header": show_header_json(&resolved),
            "sections": sections.to_json(),
        });
        println!(
            "{}",
            serde_json::to_string(&value).map_err(|err| format!("json encode: {}", err))?
        );
        return Ok(());
    }

    render_show_pretty(&resolved, &sections);
    Ok(())
}

pub fn run_explain(args: ExplainArgs) -> Result<(), String> {
    if let Some(kind) = args.kind {
        if map_arg_kind(kind) != SchemaKind::Witness {
            return Err("explain only supports --kind witness".to_string());
        }
    }
    let artifacts_dir = args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
    let resolved = resolve_target(&args.target, artifacts_dir.as_path(), args.kind)?;
    if resolved.schema_kind != SchemaKind::Witness {
        return Err(format!(
            "target '{}' is not a witness artifact (detected {})",
            args.target,
            resolved.schema_kind.as_str()
        ));
    }
    let witness: Witness = serde_json::from_value(resolved.payload.clone())
        .map_err(|err| format!("decode witness: {}", err))?;
    let explain = build_explain_data(&witness, args.rule.as_deref())?;

    if args.json {
        let value = serde_json::json!({
            "command": "explain",
            "artifact": {
                "sha256": resolved.canonical_sha256,
                "schema_id": resolved.schema_id,
            },
            "verdict": explain.verdict,
            "summary": {
                "rules_total": explain.rules.len(),
                "rules_failed": explain.rules.iter().filter(|rule| rule.get("triggered").and_then(|v| v.as_bool()) == Some(true)).count(),
                "findings_total": explain.findings.len(),
            },
            "rules": explain.rules,
            "predicate_trace": explain.predicate_trace,
            "findings": explain.findings,
            "grouped_by_file": explain.grouped_by_file,
        });
        println!(
            "{}",
            serde_json::to_string(&value).map_err(|err| format!("json encode: {}", err))?
        );
        return Ok(());
    }

    render_explain_pretty(&explain, args.rule.as_deref(), args.files);
    Ok(())
}

pub fn run_log(args: LogArgs) -> Result<(), String> {
    if args.json && args.ndjson {
        return Err(
            "log output flags are mutually exclusive: choose --json or --ndjson".to_string(),
        );
    }

    match args.source {
        LogSourceArg::Artifacts => run_log_artifacts(args),
        LogSourceArg::Ledger => run_log_ledger(args),
    }
}

fn run_log_artifacts(args: LogArgs) -> Result<(), String> {
    if args.event_type.is_some() {
        return Err("--type is only valid for --source ledger".to_string());
    }
    if args.since.is_some() {
        return Err("--since is only valid for --source ledger".to_string());
    }
    if args.scope.is_some() {
        return Err("--scope is only valid for --source ledger".to_string());
    }
    if args.verdict.is_some() {
        return Err("--verdict is only valid for --source ledger".to_string());
    }
    let artifacts_dir = args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
    let mut entries = list_artifacts(artifacts_dir.as_path()).map_err(|err| err.to_string())?;

    if let Some(kind_filter) = args.kind {
        let expected = map_arg_kind(kind_filter);
        entries = entries
            .into_iter()
            .filter(|entry| {
                detect_artifact_entry_schema_kind(artifacts_dir.as_path(), entry)
                    .map(|kind| kind == expected)
                    .unwrap_or(false)
            })
            .collect();
    }

    if let Some(limit) = args.limit {
        entries.truncate(limit);
    }

    if args.quiet {
        for entry in &entries {
            println!("sha256:{}", entry.sha256);
        }
        return Ok(());
    }

    let rows: Vec<serde_json::Value> = entries
        .iter()
        .map(|entry| {
            serde_json::json!({
                "kind": entry.kind,
                "sha256": entry.sha256,
                "size_bytes": entry.size_bytes,
                "path": entry.path
            })
        })
        .collect();

    if args.ndjson {
        for row in &rows {
            println!(
                "{}",
                serde_json::to_string(row).map_err(|err| format!("json encode: {}", err))?
            );
        }
        return Ok(());
    }

    if args.json {
        let out = serde_json::json!({
            "command": "log",
            "source": "artifacts",
            "rows": rows
        });
        println!(
            "{}",
            serde_json::to_string(&out).map_err(|err| format!("json encode: {}", err))?
        );
        return Ok(());
    }

    println!("Log");
    println!("\nHeader:");
    println!("- source=artifacts");
    println!("- count={}", entries.len());
    println!("\nRows:");
    for entry in &entries {
        println!(
            "- kind={} sha256={} size_bytes={} path={}",
            entry.kind, entry.sha256, entry.size_bytes, entry.path
        );
    }
    Ok(())
}

fn run_log_ledger(args: LogArgs) -> Result<(), String> {
    let ledger_path = args.ledger.unwrap_or_else(default_ledger_path);
    let artifacts_dir = args.artifacts_dir.unwrap_or_else(default_artifacts_dir);
    if args.kind.is_some() {
        return Err("--kind is only valid for --source artifacts".to_string());
    }

    let mut rows = if ledger_path.exists() {
        parse_ledger_rows(ledger_path.as_path(), artifacts_dir.as_path())?
    } else {
        Vec::new()
    };

    if let Some(since) = args.since.as_deref() {
        let cutoff = parse_since_cutoff(since)?;
        rows.retain(|row| row.timestamp_dt.map(|ts| ts >= cutoff).unwrap_or(false));
    }
    if let Some(event_type) = args.event_type.as_deref() {
        rows.retain(|row| row.event_type == event_type);
    }
    if let Some(scope) = args.scope.as_deref() {
        rows.retain(|row| row.scope.as_deref() == Some(scope));
    }
    if let Some(verdict) = args.verdict {
        rows.retain(|row| row.verdict.as_deref() == Some(log_verdict_arg_str(verdict)));
    }
    rows.reverse();
    if let Some(limit) = args.limit {
        rows.truncate(limit);
    }

    if args.quiet {
        for row in &rows {
            println!("{}", row.event_id);
        }
        return Ok(());
    }

    let json_rows: Vec<serde_json::Value> = rows.iter().map(|row| row.to_json_value()).collect();

    if args.ndjson {
        for row in &json_rows {
            println!(
                "{}",
                serde_json::to_string(row).map_err(|err| format!("json encode: {}", err))?
            );
        }
        return Ok(());
    }

    if args.json {
        let out = serde_json::json!({
            "command": "log",
            "source": "ledger",
            "rows": json_rows
        });
        println!(
            "{}",
            serde_json::to_string(&out).map_err(|err| format!("json encode: {}", err))?
        );
        return Ok(());
    }

    println!("Log");
    println!("\nHeader:");
    println!("- source=ledger");
    println!("- count={}", rows.len());
    println!("\nRows:");
    for row in &rows {
        println!(
            "- timestamp={} event_type={} event_id={} witness_sha={} snapshot_hash={} scope={} verdict={} ruleset_hash={}",
            row.timestamp,
            row.event_type,
            row.event_id,
            row.witness_sha.as_deref().unwrap_or("-"),
            row.snapshot_hash.as_deref().unwrap_or("-"),
            row.scope.as_deref().unwrap_or("-"),
            row.verdict.as_deref().unwrap_or("-"),
            row.ruleset_hash.as_deref().unwrap_or("-"),
        );
    }
    Ok(())
}

fn parse_ledger_rows(ledger_path: &Path, artifacts_dir: &Path) -> Result<Vec<LedgerRow>, String> {
    let contents = std::fs::read_to_string(ledger_path)
        .map_err(|err| format!("read ledger '{}': {}", ledger_path.display(), err))?;
    let mut witness_cache = HashMap::<String, WitnessSummary>::new();
    let mut rows = Vec::new();
    for (idx, line) in contents.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = serde_json::from_str(line)
            .map_err(|err| format!("decode ledger line {}: {}", idx + 1, err))?;
        let timestamp = value
            .get("created_at")
            .and_then(|v| v.as_str())
            .or_else(|| value.get("timestamp").and_then(|v| v.as_str()))
            .unwrap_or("-")
            .to_string();
        let event_type = value
            .get("event_type")
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();
        let event_id = value
            .get("event_id")
            .and_then(|v| v.as_str())
            .unwrap_or("-")
            .to_string();
        let witness_sha = value
            .get("witness")
            .and_then(|v| v.get("sha256"))
            .and_then(|v| v.as_str())
            .or_else(|| value.get("witness_sha256").and_then(|v| v.as_str()))
            .map(|s| s.to_string());
        let witness_summary = load_witness_summary(
            &value,
            artifacts_dir,
            witness_sha.as_deref(),
            &mut witness_cache,
        );
        let snapshot_hash = value
            .get("snapshot_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let scope = value
            .get("program")
            .and_then(|v| v.get("scope"))
            .and_then(|v| v.as_str())
            .or_else(|| value.get("scope_id").and_then(|v| v.as_str()))
            .map(|s| s.to_string());
        let facts_bundle_hash = value
            .get("facts_bundle_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let admissibility_checked_event_id = value
            .get("admissibility_checked_event_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        rows.push(LedgerRow {
            timestamp: timestamp.clone(),
            timestamp_dt: parse_rfc3339_utc(&timestamp),
            event_type,
            event_id,
            witness_sha,
            snapshot_hash,
            scope,
            verdict: witness_summary.verdict,
            ruleset_hash: witness_summary.ruleset_hash,
            facts_bundle_hash,
            admissibility_checked_event_id,
        });
    }
    Ok(rows)
}

fn log_verdict_arg_str(value: LogVerdictArg) -> &'static str {
    match value {
        LogVerdictArg::Admissible => "admissible",
        LogVerdictArg::Inadmissible => "inadmissible",
    }
}

fn parse_since_cutoff(raw: &str) -> Result<DateTime<Utc>, String> {
    if let Some(duration) = parse_relative_duration(raw) {
        return Ok(Utc::now() - duration);
    }
    chrono::DateTime::parse_from_rfc3339(raw)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|_| {
            format!(
                "invalid --since value '{}': expected RFC3339 timestamp or relative duration like 7d/12h/30m",
                raw
            )
        })
}

fn parse_relative_duration(raw: &str) -> Option<Duration> {
    if raw.len() < 2 {
        return None;
    }
    let (amount_raw, unit_raw) = raw.split_at(raw.len() - 1);
    let amount = amount_raw.parse::<i64>().ok()?;
    if amount < 0 {
        return None;
    }
    match unit_raw {
        "s" => Some(Duration::seconds(amount)),
        "m" => Some(Duration::minutes(amount)),
        "h" => Some(Duration::hours(amount)),
        "d" => Some(Duration::days(amount)),
        "w" => Some(Duration::weeks(amount)),
        _ => None,
    }
}

fn parse_rfc3339_utc(value: &str) -> Option<DateTime<Utc>> {
    chrono::DateTime::parse_from_rfc3339(value)
        .ok()
        .map(|value| value.with_timezone(&Utc))
}

fn evidence_state_reason(
    latest_check: Option<&LedgerRow>,
    latest_execute: Option<&LedgerRow>,
) -> (&'static str, &'static str) {
    match (latest_check, latest_execute) {
        (None, _) => ("missing", "no_admissibility_checked_event"),
        (Some(_), None) => ("pending_apply", "latest_checked_event_not_executed"),
        (Some(check), Some(executed)) => {
            if executed.admissibility_checked_event_id.as_deref() == Some(check.event_id.as_str()) {
                ("fresh", "latest_checked_event_is_executed")
            } else {
                (
                    "pending_apply",
                    "latest_execute_references_older_checked_event",
                )
            }
        }
    }
}

fn detect_repo_context() -> GitRepoContext {
    let root = run_git_capture(["rev-parse", "--show-toplevel"]);
    let branch = run_git_capture(["rev-parse", "--abbrev-ref", "HEAD"]).map(|value| {
        if value == "HEAD" {
            "detached".to_string()
        } else {
            value
        }
    });
    let head = run_git_capture(["rev-parse", "HEAD"]);
    GitRepoContext { root, branch, head }
}

fn run_git_capture<const N: usize>(args: [&str; N]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn load_witness_summary(
    event: &serde_json::Value,
    artifacts_dir: &Path,
    witness_sha: Option<&str>,
    witness_cache: &mut HashMap<String, WitnessSummary>,
) -> WitnessSummary {
    if let Some(sha) = witness_sha {
        if let Some(cached) = witness_cache.get(sha) {
            return cached.clone();
        }
    }

    let mut candidate_paths = Vec::<PathBuf>::new();
    if let Some(path) = event
        .get("witness")
        .and_then(|value| value.get("path"))
        .and_then(|value| value.as_str())
    {
        let candidate = PathBuf::from(path);
        if candidate.is_absolute() {
            candidate_paths.push(candidate);
        } else {
            candidate_paths.push(artifacts_dir.join(candidate));
        }
    }
    if let Some(sha) = witness_sha {
        candidate_paths.push(artifacts_dir.join("witness").join(format!("{}.cbor", sha)));
        candidate_paths.push(artifacts_dir.join("witness").join(format!("{}.json", sha)));
    }

    let mut summary = WitnessSummary {
        verdict: None,
        ruleset_hash: None,
    };

    for path in candidate_paths {
        if !path.exists() {
            continue;
        }
        let Ok(bytes) = std::fs::read(&path) else {
            continue;
        };
        let Ok(decoded) = decode_payload_bytes(&bytes) else {
            continue;
        };
        let Ok(witness) = serde_json::from_value::<Witness>(decoded.payload) else {
            continue;
        };
        summary = WitnessSummary {
            verdict: Some(match witness.verdict {
                admit_core::Verdict::Admissible => "admissible".to_string(),
                admit_core::Verdict::Inadmissible => "inadmissible".to_string(),
            }),
            ruleset_hash: witness.program.ruleset_hash.clone(),
        };
        break;
    }

    if let Some(sha) = witness_sha {
        witness_cache.insert(sha.to_string(), summary.clone());
    }
    summary
}

fn resolve_target(
    target: &str,
    artifacts_dir: &Path,
    requested_kind: Option<SchemaKindArg>,
) -> Result<ResolvedArtifact, String> {
    if target.starts_with("sha256:") {
        return resolve_by_hash(target, artifacts_dir, requested_kind);
    }

    let path = PathBuf::from(target);
    if !path.exists() {
        return Err(format!("target not found: {}", target));
    }

    let bytes =
        std::fs::read(&path).map_err(|err| format!("read '{}': {}", path.display(), err))?;
    let decoded = decode_payload_bytes(&bytes)?;
    let schema_kind = detect_schema_kind(decoded.schema_id.as_deref(), &decoded.payload);
    if let Some(kind) = requested_kind {
        let expected = map_arg_kind(kind);
        if schema_kind != expected {
            return Err(format!(
                "target '{}' resolved to {}, but --kind requires {}",
                target,
                schema_kind.as_str(),
                expected.as_str()
            ));
        }
    }
    Ok(ResolvedArtifact {
        target: target.to_string(),
        source_path: path,
        store_kind: None,
        store_rel_path: None,
        schema_id: decoded.schema_id,
        schema_kind,
        payload: decoded.payload,
        canonical_cbor: decoded.canonical_cbor,
        canonical_sha256: decoded.canonical_sha256,
    })
}

fn resolve_by_hash(
    target: &str,
    artifacts_dir: &Path,
    requested_kind: Option<SchemaKindArg>,
) -> Result<ResolvedArtifact, String> {
    let hash = target
        .strip_prefix("sha256:")
        .ok_or_else(|| format!("invalid hash target '{}': expected sha256:<hash>", target))?;
    if !is_valid_sha256(hash) {
        return Err(format!(
            "invalid hash target '{}': expected 64 lowercase hex chars",
            target
        ));
    }
    if !artifacts_dir.exists() {
        return Err(format!(
            "artifact store not found: {}",
            artifacts_dir.display()
        ));
    }

    let mut candidates = Vec::<ResolvedArtifact>::new();
    let mut dirs: Vec<PathBuf> = std::fs::read_dir(artifacts_dir)
        .map_err(|err| format!("read artifacts dir '{}': {}", artifacts_dir.display(), err))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|path| path.is_dir())
        .collect();
    dirs.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));

    for kind_dir in dirs {
        let Some(kind) = kind_dir.file_name().and_then(|s| s.to_str()) else {
            continue;
        };
        let cbor_path = kind_dir.join(format!("{}.cbor", hash));
        let json_path = kind_dir.join(format!("{}.json", hash));
        if !cbor_path.exists() && !json_path.exists() {
            continue;
        }

        let mut decoded_paths = Vec::<(PathBuf, DecodedPayload, SchemaKind)>::new();
        for path in [cbor_path, json_path] {
            if !path.exists() {
                continue;
            }
            let bytes = std::fs::read(&path)
                .map_err(|err| format!("read '{}': {}", path.display(), err))?;
            let decoded = decode_payload_bytes(&bytes)?;
            if decoded.canonical_sha256 != hash {
                return Err(format!(
                    "artifact '{}' canonical hash mismatch: expected {}, computed {}",
                    path.display(),
                    hash,
                    decoded.canonical_sha256
                ));
            }
            let schema_kind = detect_schema_kind(decoded.schema_id.as_deref(), &decoded.payload);
            decoded_paths.push((path, decoded, schema_kind));
        }
        decoded_paths.sort_by(|a, b| a.0.to_string_lossy().cmp(&b.0.to_string_lossy()));

        let (path, decoded, schema_kind) = if decoded_paths.len() == 1 {
            decoded_paths.remove(0)
        } else if decoded_paths.len() == 2 {
            let first = &decoded_paths[0];
            let second = &decoded_paths[1];
            if first.1.canonical_sha256 == second.1.canonical_sha256 && first.2 == second.2 {
                if first.0.extension().and_then(|e| e.to_str()) == Some("cbor") {
                    decoded_paths.remove(0)
                } else {
                    decoded_paths.remove(1)
                }
            } else {
                return Err(format!(
                    "ambiguous artifact encoding for {} in kind '{}': {} and {} decode differently",
                    target,
                    kind,
                    first.0.display(),
                    second.0.display()
                ));
            }
        } else {
            return Err(format!(
                "unexpected duplicate artifact encodings for {} in kind '{}'",
                target, kind
            ));
        };

        candidates.push(ResolvedArtifact {
            target: target.to_string(),
            source_path: path.clone(),
            store_kind: Some(kind.to_string()),
            store_rel_path: path
                .strip_prefix(artifacts_dir)
                .ok()
                .and_then(|p| p.to_str())
                .map(|s| s.to_string()),
            schema_id: decoded.schema_id,
            schema_kind,
            payload: decoded.payload,
            canonical_cbor: decoded.canonical_cbor,
            canonical_sha256: decoded.canonical_sha256,
        });
    }

    if let Some(kind) = requested_kind {
        let expected = map_arg_kind(kind);
        candidates.retain(|candidate| candidate.schema_kind == expected);
    }
    if candidates.is_empty() {
        return Err(format!(
            "no artifact found for {} under {}",
            target,
            artifacts_dir.display()
        ));
    }

    candidates.sort_by(|a, b| {
        a.store_kind
            .as_deref()
            .unwrap_or("")
            .cmp(b.store_kind.as_deref().unwrap_or(""))
            .then(
                a.source_path
                    .to_string_lossy()
                    .cmp(&b.source_path.to_string_lossy()),
            )
    });

    if candidates.len() > 1 {
        if requested_kind.is_some() {
            return Ok(candidates.remove(0));
        }
        let choices = candidates
            .iter()
            .map(|c| {
                format!(
                    "{} ({})",
                    c.store_kind.as_deref().unwrap_or("-"),
                    c.schema_kind.as_str()
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "ambiguous target {}: multiple matches [{}]. Use --kind to disambiguate.",
            target, choices
        ));
    }

    Ok(candidates.remove(0))
}

struct DecodedPayload {
    payload: serde_json::Value,
    schema_id: Option<String>,
    canonical_cbor: Vec<u8>,
    canonical_sha256: String,
}

fn decode_payload_bytes(bytes: &[u8]) -> Result<DecodedPayload, String> {
    let value = serde_json::from_slice::<serde_json::Value>(bytes)
        .or_else(|_| serde_cbor::from_slice::<serde_json::Value>(bytes))
        .map_err(|err| format!("decode artifact bytes as json/cbor: {}", err))?;

    let (payload, schema_id) =
        if let Some(wrapper_payload) = extract_witness_wrapper_payload(&value) {
            wrapper_payload
        } else {
            (value.clone(), schema_id_from_value(&value))
        };

    let schema_id = schema_id.or_else(|| infer_witness_schema(&payload));

    let canonical_cbor = admit_core::encode_canonical_value(&payload).map_err(|err| err.0)?;
    let canonical_sha256 = hex::encode(sha2::Sha256::digest(&canonical_cbor));
    Ok(DecodedPayload {
        payload,
        schema_id,
        canonical_cbor,
        canonical_sha256,
    })
}

fn extract_witness_wrapper_payload(
    value: &serde_json::Value,
) -> Option<(serde_json::Value, Option<String>)> {
    let obj = value.as_object()?;
    let witness = obj.get("witness")?;
    if !witness.is_object() {
        return None;
    }
    let schema_id = obj
        .get("schema_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .or_else(|| schema_id_from_value(witness));
    Some((witness.clone(), schema_id))
}

fn infer_witness_schema(payload: &serde_json::Value) -> Option<String> {
    if !looks_like_witness(payload) {
        return None;
    }
    let has_v2_lens_fields = payload.as_object().is_some_and(|obj| {
        let lens_id = obj
            .get("lens_id")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .is_some_and(|value| !value.is_empty());
        let lens_hash = obj
            .get("lens_hash")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .is_some_and(|value| !value.is_empty());
        let activation_id = obj
            .get("lens_activation_event_id")
            .and_then(|value| value.as_str())
            .map(str::trim)
            .is_some_and(|value| !value.is_empty());
        lens_id && lens_hash && activation_id
    });
    if has_v2_lens_fields {
        Some("admissibility-witness/2".to_string())
    } else {
        Some("admissibility-witness/1".to_string())
    }
}

fn schema_id_from_value(value: &serde_json::Value) -> Option<String> {
    value
        .get("schema_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn map_arg_kind(kind: SchemaKindArg) -> SchemaKind {
    match kind {
        SchemaKindArg::Witness => SchemaKind::Witness,
        SchemaKindArg::Ruleset => SchemaKind::Ruleset,
        SchemaKindArg::FactsBundle => SchemaKind::FactsBundle,
    }
}

fn detect_schema_kind(schema_id: Option<&str>, payload: &serde_json::Value) -> SchemaKind {
    if let Some(schema_id) = schema_id {
        if schema_id.starts_with("admissibility-witness/") {
            return SchemaKind::Witness;
        }
        if schema_id == "ruleset/admit@1" {
            return SchemaKind::Ruleset;
        }
        if schema_id.starts_with("facts-bundle/") {
            return SchemaKind::FactsBundle;
        }
    }
    if looks_like_witness(payload) {
        SchemaKind::Witness
    } else if looks_like_ruleset(payload) {
        SchemaKind::Ruleset
    } else if looks_like_facts_bundle(payload) {
        SchemaKind::FactsBundle
    } else {
        SchemaKind::Unknown
    }
}

fn looks_like_witness(value: &serde_json::Value) -> bool {
    value.get("verdict").is_some() && value.get("program").is_some() && value.get("facts").is_some()
}

fn looks_like_ruleset(value: &serde_json::Value) -> bool {
    value.get("ruleset_id").is_some() && value.get("bindings").is_some()
}

fn looks_like_facts_bundle(value: &serde_json::Value) -> bool {
    value.get("facts").is_some()
        && (value.get("scope_id").is_some() || value.get("schema_version").is_some())
}

fn is_valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|ch| ch.is_ascii_hexdigit())
}

fn detect_artifact_entry_schema_kind(
    artifacts_dir: &Path,
    entry: &admit_cli::ArtifactEntry,
) -> Result<SchemaKind, String> {
    let path = artifacts_dir.join(&entry.path);
    let bytes =
        std::fs::read(&path).map_err(|err| format!("read '{}': {}", path.display(), err))?;
    let decoded = decode_payload_bytes(&bytes)?;
    Ok(detect_schema_kind(
        decoded.schema_id.as_deref(),
        &decoded.payload,
    ))
}

fn build_show_sections(resolved: &ResolvedArtifact) -> ShowSections {
    match resolved.schema_kind {
        SchemaKind::Witness => {
            let witness: Witness = match serde_json::from_value(resolved.payload.clone()) {
                Ok(value) => value,
                Err(_) => return ShowSections::empty(),
            };
            witness_sections(&witness)
        }
        SchemaKind::Ruleset => {
            let ruleset: RuleSet = match serde_json::from_value(resolved.payload.clone()) {
                Ok(value) => value,
                Err(_) => return ShowSections::empty(),
            };
            ruleset_sections(&ruleset)
        }
        SchemaKind::FactsBundle => facts_sections(&resolved.payload),
        SchemaKind::Unknown => ShowSections::empty(),
    }
}

fn show_artifact_json(resolved: &ResolvedArtifact) -> serde_json::Value {
    serde_json::json!({
        "kind": resolved
            .store_kind
            .clone()
            .unwrap_or_else(|| resolved.schema_kind.as_str().to_string()),
        "sha256": resolved.canonical_sha256,
        "path": resolved
            .store_rel_path
            .clone()
            .unwrap_or_else(|| resolved.source_path.display().to_string()),
        "schema_id": resolved.schema_id,
    })
}

fn show_header_json(resolved: &ResolvedArtifact) -> serde_json::Value {
    let created_at = resolved
        .payload
        .get("created_at")
        .and_then(|v| v.as_str())
        .or_else(|| {
            resolved
                .payload
                .get("generated_at")
                .and_then(|v| v.as_str())
        });
    let scope_id = resolved
        .payload
        .get("scope_id")
        .and_then(|v| v.as_str())
        .or_else(|| {
            resolved
                .payload
                .get("program")
                .and_then(|v| v.get("scope"))
                .and_then(|v| v.as_str())
        });
    let engine = resolved
        .payload
        .get("engine_version")
        .and_then(|v| v.as_str())
        .or_else(|| {
            resolved
                .payload
                .get("court_version")
                .and_then(|v| v.as_str())
        });
    serde_json::json!({
        "schema_id": resolved.schema_id,
        "hash": format!("sha256:{}", resolved.canonical_sha256),
        "scope_id": scope_id,
        "created_at": created_at,
        "engine_version": engine,
    })
}

fn render_show_pretty(resolved: &ResolvedArtifact, sections: &ShowSections) {
    println!("Show");
    println!("\nArtifact:");
    println!(
        "- type={} schema_id={}",
        match resolved.schema_kind {
            SchemaKind::Witness => "Witness",
            SchemaKind::Ruleset => "RuleSet",
            SchemaKind::FactsBundle => "FactsBundle",
            SchemaKind::Unknown => "Artifact",
        },
        resolved.schema_id.as_deref().unwrap_or("(unknown)")
    );
    println!(
        "{}  {}",
        match resolved.schema_kind {
            SchemaKind::Witness => "Witness",
            SchemaKind::Ruleset => "RuleSet",
            SchemaKind::FactsBundle => "FactsBundle",
            SchemaKind::Unknown => "Artifact",
        },
        resolved.schema_id.as_deref().unwrap_or("(unknown)")
    );
    println!("- hash=sha256:{}", resolved.canonical_sha256);
    println!("hash: sha256:{}", resolved.canonical_sha256);
    if let Some(engine) = resolved
        .payload
        .get("engine_version")
        .and_then(|v| v.as_str())
        .or_else(|| {
            resolved
                .payload
                .get("court_version")
                .and_then(|v| v.as_str())
        })
    {
        println!("- engine={}", engine);
    }
    if let Some(created_at) = resolved
        .payload
        .get("created_at")
        .and_then(|v| v.as_str())
        .or_else(|| {
            resolved
                .payload
                .get("generated_at")
                .and_then(|v| v.as_str())
        })
    {
        println!("- created_at={}", created_at);
    }
    if let Some(scope_id) = resolved
        .payload
        .get("scope_id")
        .and_then(|v| v.as_str())
        .or_else(|| {
            resolved
                .payload
                .get("program")
                .and_then(|v| v.get("scope"))
                .and_then(|v| v.as_str())
        })
    {
        println!("- scope_id={}", scope_id);
    }

    if !sections.inputs.is_empty() {
        println!("\nInputs:");
        for row in &sections.inputs {
            println!("- {}", render_row_inline(row));
        }
    }
    if !sections.rules.is_empty() {
        println!("\nRules:");
        for row in &sections.rules {
            println!("- {}", render_row_inline(row));
        }
    }
    if !sections.findings.is_empty() {
        println!("\nFindings:");
        for row in sections.findings.iter().take(50) {
            println!("- {}", render_row_inline(row));
        }
        if sections.findings.len() > 50 {
            println!(
                "- ... truncated {} additional findings",
                sections.findings.len() - 50
            );
        }
    }
    if !sections.trace.is_empty() {
        println!("\nTrace:");
        for row in sections.trace.iter().take(50) {
            println!("- {}", render_row_inline(row));
        }
        if sections.trace.len() > 50 {
            println!(
                "- ... truncated {} additional rows",
                sections.trace.len() - 50
            );
        }
    }
}

fn render_row_inline(value: &serde_json::Value) -> String {
    if let Some(obj) = value.as_object() {
        let mut keys: Vec<&str> = obj.keys().map(|k| k.as_str()).collect();
        keys.sort();
        return keys
            .into_iter()
            .filter_map(|key| obj.get(key).map(|v| (key, v)))
            .map(|(key, v)| {
                let rendered = match v {
                    serde_json::Value::String(s) => s.clone(),
                    _ => v.to_string(),
                };
                format!("{}={}", key, rendered)
            })
            .collect::<Vec<_>>()
            .join(" ");
    }
    value.to_string()
}

fn witness_sections(witness: &Witness) -> ShowSections {
    let mut inputs = vec![
        serde_json::json!({ "field": "module", "value": witness.program.module.0 }),
        serde_json::json!({ "field": "scope", "value": witness.program.scope.0 }),
    ];
    if let Some(snapshot_hash) = witness.program.snapshot_hash.as_deref() {
        inputs.push(serde_json::json!({ "field": "snapshot_hash", "value": snapshot_hash }));
    }
    if let Some(ruleset_hash) = witness.program.ruleset_hash.as_deref() {
        inputs.push(serde_json::json!({ "field": "ruleset_hash", "value": ruleset_hash }));
    }

    let mut rules = collect_rule_rows(&witness.facts);
    let mut findings = collect_findings(&witness.facts);
    let mut trace = collect_predicate_trace(&witness.facts);

    rules.sort_by(|a, b| json_rule_id(a).cmp(json_rule_id(b)));
    findings.sort_by(findings_sort_key_json);
    trace.sort_by(trace_sort_key_json);

    ShowSections {
        inputs,
        rules,
        findings,
        trace,
    }
}

fn ruleset_sections(ruleset: &RuleSet) -> ShowSections {
    let mut rules = ruleset
        .bindings
        .iter()
        .map(|binding| {
            serde_json::json!({
                "rule_id": binding.rule_id,
                "severity": format!("{:?}", binding.severity).to_lowercase(),
                "scope_id": binding.when.scope_id.0,
                "predicate": binding.when.predicate
            })
        })
        .collect::<Vec<_>>();
    rules.sort_by(|a, b| json_rule_id(a).cmp(json_rule_id(b)));

    ShowSections {
        inputs: vec![
            serde_json::json!({"field": "ruleset_id", "value": ruleset.ruleset_id}),
            serde_json::json!({"field": "fail_on", "value": format!("{:?}", ruleset.fail_on).to_lowercase()}),
        ],
        rules,
        findings: Vec::new(),
        trace: Vec::new(),
    }
}

fn facts_sections(value: &serde_json::Value) -> ShowSections {
    if let Ok(bundle) = serde_json::from_value::<FactsBundle>(value.clone()) {
        let mut findings = collect_findings(&bundle.facts);
        findings.sort_by(findings_sort_key_json);
        return ShowSections {
            inputs: vec![
                serde_json::json!({"field": "scope_id", "value": bundle.scope_id.0}),
                serde_json::json!({"field": "snapshot_hash", "value": bundle.snapshot_hash.0}),
                serde_json::json!({"field": "schema_id", "value": bundle.schema_id}),
            ],
            rules: Vec::new(),
            findings,
            trace: Vec::new(),
        };
    }
    ShowSections {
        inputs: vec![
            serde_json::json!({"field": "schema_id", "value": schema_id_from_value(value)}),
        ],
        rules: Vec::new(),
        findings: Vec::new(),
        trace: Vec::new(),
    }
}

fn build_explain_data(witness: &Witness, rule_filter: Option<&str>) -> Result<ExplainData, String> {
    let mut rules = collect_rule_rows(&witness.facts);
    if let Some(rule_id) = rule_filter {
        rules.retain(|row| row.get("rule_id").and_then(|v| v.as_str()) == Some(rule_id));
    }
    rules.sort_by(|a, b| json_rule_id(a).cmp(json_rule_id(b)));

    let selected_predicates: BTreeSet<String> = rules
        .iter()
        .filter_map(|row| {
            row.get("predicate")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .collect();

    let mut predicate_trace = collect_predicate_trace(&witness.facts);
    if rule_filter.is_some() {
        predicate_trace.retain(|row| {
            row.get("predicate")
                .and_then(|v| v.as_str())
                .map(|name| {
                    selected_predicates
                        .iter()
                        .any(|needle| name.contains(needle))
                })
                .unwrap_or(false)
        });
    }
    predicate_trace.sort_by(trace_sort_key_json);

    let mut findings = collect_findings(&witness.facts);
    if let Some(rule_id) = rule_filter {
        findings.retain(|row| row.get("rule_id").and_then(|v| v.as_str()) == Some(rule_id));
    }
    findings.sort_by(findings_sort_key_json);

    let grouped_by_file = group_findings_by_file(&findings);
    let verdict = match witness.verdict {
        admit_core::Verdict::Admissible => "admissible",
        admit_core::Verdict::Inadmissible => "inadmissible",
    }
    .to_string();

    Ok(ExplainData {
        verdict,
        rules,
        predicate_trace,
        findings,
        grouped_by_file,
    })
}

fn render_explain_pretty(data: &ExplainData, rule_filter: Option<&str>, files: bool) {
    println!("Explain");
    println!("\nSummary:");
    if let Some(rule) = rule_filter {
        println!(
            "- rule={} status={}",
            rule,
            if data.findings.is_empty() {
                "pass"
            } else {
                "fail"
            }
        );
    }
    println!("- verdict={}", data.verdict);
    println!(
        "- rules_total={} rules_failed={} findings_total={}",
        data.rules.len(),
        data.rules
            .iter()
            .filter(|rule| rule.get("triggered").and_then(|v| v.as_bool()) == Some(true))
            .count(),
        data.findings.len()
    );

    if !data.rules.is_empty() {
        println!("\nRules:");
        for row in &data.rules {
            println!("- {}", render_row_inline(row));
        }
    }
    if !data.predicate_trace.is_empty() {
        println!("\nPredicate trace:");
        for row in &data.predicate_trace {
            println!("- {}", render_row_inline(row));
        }
    }
    if !data.findings.is_empty() {
        println!("\nFindings:");
        for row in data.findings.iter().take(100) {
            println!("- {}", render_row_inline(row));
        }
        if data.findings.len() > 100 {
            println!(
                "- ... truncated {} additional findings",
                data.findings.len() - 100
            );
        }
    }

    if files && !data.grouped_by_file.is_empty() {
        println!("\nFiles:");
        for row in &data.grouped_by_file {
            println!("- {}", render_row_inline(row));
        }
    }
}

fn collect_rule_rows(facts: &[Fact]) -> Vec<serde_json::Value> {
    let mut findings_by_rule: BTreeMap<String, usize> = BTreeMap::new();
    for fact in facts {
        if let Fact::LintFinding { rule_id, .. } = fact {
            *findings_by_rule.entry(rule_id.clone()).or_insert(0) += 1;
        }
    }

    let mut rows = Vec::new();
    for fact in facts {
        if let Fact::RuleEvaluated {
            rule_id,
            severity,
            triggered,
            scope_id,
            predicate,
            ..
        } = fact
        {
            rows.push(serde_json::json!({
                "rule_id": rule_id,
                "severity": severity_to_str(severity),
                "triggered": triggered,
                "scope_id": scope_id.0,
                "predicate": predicate,
                "findings_count": findings_by_rule.get(rule_id).copied().unwrap_or(0),
            }));
        }
    }
    rows
}

fn collect_predicate_trace(facts: &[Fact]) -> Vec<serde_json::Value> {
    facts
        .iter()
        .filter_map(|fact| match fact {
            Fact::PredicateEvaluated {
                predicate,
                result,
                span,
            } => Some(serde_json::json!({
                "predicate": predicate,
                "result": result,
                "file": span.file,
                "line": span.line,
                "col": span.col,
            })),
            _ => None,
        })
        .collect()
}

fn collect_findings(facts: &[Fact]) -> Vec<serde_json::Value> {
    facts
        .iter()
        .filter_map(|fact| match fact {
            Fact::LintFinding {
                rule_id,
                severity,
                path,
                span,
                message,
                evidence,
                ..
            } => Some(serde_json::json!({
                "severity": severity_to_str(severity),
                "rule_id": rule_id,
                "path": path,
                "file": span.file,
                "line": span.line,
                "col": span.col,
                "message": message,
                "evidence": evidence,
            })),
            _ => None,
        })
        .collect()
}

fn group_findings_by_file(findings: &[serde_json::Value]) -> Vec<serde_json::Value> {
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for finding in findings {
        let file = finding
            .get("file")
            .and_then(|v| v.as_str())
            .or_else(|| finding.get("path").and_then(|v| v.as_str()))
            .unwrap_or("-")
            .to_string();
        *counts.entry(file).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .map(|(file, findings)| serde_json::json!({ "file": file, "findings": findings }))
        .collect()
}

fn severity_to_str(severity: &Severity) -> &'static str {
    match severity {
        Severity::Error => "error",
        Severity::Warning => "warning",
        Severity::Info => "info",
    }
}

fn severity_rank(value: &str) -> u8 {
    match value {
        "error" => 0,
        "warning" => 1,
        "info" => 2,
        _ => 3,
    }
}

fn json_rule_id(value: &serde_json::Value) -> &str {
    value.get("rule_id").and_then(|v| v.as_str()).unwrap_or("")
}

fn findings_sort_key_json(a: &serde_json::Value, b: &serde_json::Value) -> std::cmp::Ordering {
    let severity_a = a.get("severity").and_then(|v| v.as_str()).unwrap_or("");
    let severity_b = b.get("severity").and_then(|v| v.as_str()).unwrap_or("");
    severity_rank(severity_a)
        .cmp(&severity_rank(severity_b))
        .then(json_rule_id(a).cmp(json_rule_id(b)))
        .then(
            a.get("file")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .cmp(b.get("file").and_then(|v| v.as_str()).unwrap_or("")),
        )
        .then(
            a.get("line")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .cmp(&b.get("line").and_then(|v| v.as_u64()).unwrap_or(0)),
        )
        .then(
            a.get("col")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .cmp(&b.get("col").and_then(|v| v.as_u64()).unwrap_or(0)),
        )
        .then(
            a.get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .cmp(b.get("message").and_then(|v| v.as_str()).unwrap_or("")),
        )
}

fn trace_sort_key_json(a: &serde_json::Value, b: &serde_json::Value) -> std::cmp::Ordering {
    a.get("predicate")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .cmp(b.get("predicate").and_then(|v| v.as_str()).unwrap_or(""))
        .then(
            a.get("file")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .cmp(b.get("file").and_then(|v| v.as_str()).unwrap_or("")),
        )
        .then(
            a.get("line")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .cmp(&b.get("line").and_then(|v| v.as_u64()).unwrap_or(0)),
        )
        .then(
            a.get("col")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                .cmp(&b.get("col").and_then(|v| v.as_u64()).unwrap_or(0)),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_file(name: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("admit-visualize-{}-{}.jsonl", name, nanos))
    }

    #[test]
    fn decode_payload_detects_witness_wrapper() {
        let value = serde_json::json!({
            "schema_id": "admissibility-witness/2",
            "sha256": "abcd",
            "witness": {
                "verdict": "inadmissible",
                "program": {
                    "module": "module:test@1",
                    "scope": "scope:test"
                },
                "reason": "x",
                "facts": [],
                "displacement_trace": {
                    "mode": "potential",
                    "totals": [],
                    "contributions": []
                }
            }
        });
        let bytes = serde_json::to_vec(&value).expect("encode");
        let decoded = decode_payload_bytes(&bytes).expect("decode");
        assert_eq!(
            decoded.schema_id.as_deref(),
            Some("admissibility-witness/2")
        );
        assert!(looks_like_witness(&decoded.payload));
    }

    #[test]
    fn detect_schema_kind_works_for_ruleset_schema() {
        let value = serde_json::json!({
            "schema_id": "ruleset/admit@1",
            "ruleset_id": "default",
            "enabled_rules": [],
            "bindings": [],
            "fail_on": "error"
        });
        assert_eq!(
            detect_schema_kind(schema_id_from_value(&value).as_deref(), &value),
            SchemaKind::Ruleset
        );
    }

    #[test]
    fn parse_ledger_rows_uses_created_at_then_timestamp() {
        let path = temp_file("ledger");
        let lines = [
            serde_json::json!({
                "event_type": "x",
                "event_id": "e1",
                "created_at": "2026-02-01T00:00:00Z"
            }),
            serde_json::json!({
                "event_type": "y",
                "event_id": "e2",
                "timestamp": "2026-02-02T00:00:00Z"
            }),
            serde_json::json!({
                "event_type": "z",
                "event_id": "e3"
            }),
        ];
        let mut text = String::new();
        for line in &lines {
            text.push_str(&serde_json::to_string(line).expect("line json"));
            text.push('\n');
        }
        std::fs::write(&path, text).expect("write");
        let rows = parse_ledger_rows(path.as_path(), Path::new(".")).expect("parse");
        assert_eq!(rows[0].timestamp.as_str(), "2026-02-01T00:00:00Z");
        assert_eq!(rows[1].timestamp.as_str(), "2026-02-02T00:00:00Z");
        assert_eq!(rows[2].timestamp.as_str(), "-");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn parse_since_cutoff_accepts_rfc3339() {
        let cutoff = parse_since_cutoff("2026-02-01T00:00:00Z").expect("parse cutoff");
        assert_eq!(cutoff.to_rfc3339(), "2026-02-01T00:00:00+00:00");
    }

    #[test]
    fn parse_since_cutoff_rejects_invalid_value() {
        let err = parse_since_cutoff("not-a-time").expect_err("invalid since");
        assert!(err.contains("invalid --since value"), "{}", err);
    }

    #[test]
    fn evidence_state_fresh_when_latest_checked_is_executed() {
        let check = LedgerRow {
            timestamp: "2026-02-01T00:00:00Z".to_string(),
            timestamp_dt: parse_rfc3339_utc("2026-02-01T00:00:00Z"),
            event_type: "admissibility.checked".to_string(),
            event_id: "check-1".to_string(),
            witness_sha: None,
            snapshot_hash: None,
            scope: None,
            verdict: None,
            ruleset_hash: None,
            facts_bundle_hash: None,
            admissibility_checked_event_id: None,
        };
        let execute = LedgerRow {
            timestamp: "2026-02-01T00:01:00Z".to_string(),
            timestamp_dt: parse_rfc3339_utc("2026-02-01T00:01:00Z"),
            event_type: "admissibility.executed".to_string(),
            event_id: "exec-1".to_string(),
            witness_sha: None,
            snapshot_hash: None,
            scope: None,
            verdict: None,
            ruleset_hash: None,
            facts_bundle_hash: None,
            admissibility_checked_event_id: Some("check-1".to_string()),
        };
        let (state, reason) = evidence_state_reason(Some(&check), Some(&execute));
        assert_eq!(state, "fresh");
        assert_eq!(reason, "latest_checked_event_is_executed");
    }
}
