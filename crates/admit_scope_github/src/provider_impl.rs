//! Provider implementation for the `github.ceremony` scope.
//!
//! Snapshot uses `gh pr view --json ...` and materializes deterministic facts.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use admit_core::provider_trait::Provider;
use admit_core::provider_types::*;
use admit_core::witness::{
    DisplacementMode, DisplacementTrace, Fact, Severity, Verdict, WitnessBuilder, WitnessProgram,
};
use admit_core::{ModuleId, ScopeId, Span};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::backend::{GITHUB_CEREMONY_SCHEMA_ID, GITHUB_CEREMONY_SCOPE_ID};

const RULE_PR_STATE: &str = "github/pr_state";
const RULE_REVIEW_SUMMARY: &str = "github/review_summary";
const RULE_CHECKS_SUMMARY: &str = "github/checks_summary";
const RULE_CHANGED_FILES: &str = "github/changed_files";
const RULE_SCOPE_UNAVAILABLE: &str = "github/scope_unavailable";

const PRED_REQUIRED_CHECKS_GREEN: &str = "required_checks_green";
const PRED_MIN_APPROVALS_MET: &str = "min_approvals_met";
const PRED_WORKFLOW_CHANGE_REQUIRES_EXTRA_APPROVAL: &str =
    "workflow_change_requires_extra_approval";
const PRED_PROTECTED_BRANCH_FLOW: &str = "protected_branch_flow";

/// Provider for GitHub PR/review/check ceremony observation facts.
pub struct GithubCeremonyProvider;

impl GithubCeremonyProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GithubCeremonyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Provider for GithubCeremonyProvider {
    fn describe(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            scope_id: ScopeId(GITHUB_CEREMONY_SCOPE_ID.to_string()),
            version: 1,
            schema_ids: vec![GITHUB_CEREMONY_SCHEMA_ID.to_string()],
            supported_phases: vec![ProviderPhase::Describe, ProviderPhase::Snapshot],
            deterministic: false,
            closure: ClosureRequirements {
                requires_process: true,
                requires_network: true,
                ..ClosureRequirements::default()
            },
            required_approvals: vec![],
            predicates: vec![
                PredicateDescriptor {
                    predicate_id: "github.ceremony/required_checks_green@1".to_string(),
                    name: PRED_REQUIRED_CHECKS_GREEN.to_string(),
                    doc: "Triggers when any required check is not SUCCESS.".to_string(),
                    result_kind: PredicateResultKind::Bool,
                    emits_findings: true,
                    param_schema: Some(serde_json::json!({ "type": "object" })),
                    evidence_schema: None,
                },
                PredicateDescriptor {
                    predicate_id: "github.ceremony/min_approvals_met@1".to_string(),
                    name: PRED_MIN_APPROVALS_MET.to_string(),
                    doc: "Triggers when approvals are below params.min (default 1).".to_string(),
                    result_kind: PredicateResultKind::Bool,
                    emits_findings: true,
                    param_schema: Some(serde_json::json!({
                        "type": "object",
                        "properties": {
                            "min": { "type": "integer", "minimum": 0 }
                        }
                    })),
                    evidence_schema: None,
                },
                PredicateDescriptor {
                    predicate_id:
                        "github.ceremony/workflow_change_requires_extra_approval@1".to_string(),
                    name: PRED_WORKFLOW_CHANGE_REQUIRES_EXTRA_APPROVAL.to_string(),
                    doc: "Triggers when workflow files changed and approvals are below params.min_for_workflow (default 2).".to_string(),
                    result_kind: PredicateResultKind::Bool,
                    emits_findings: true,
                    param_schema: Some(serde_json::json!({
                        "type": "object",
                        "properties": {
                            "min_for_workflow": { "type": "integer", "minimum": 0 }
                        }
                    })),
                    evidence_schema: None,
                },
                PredicateDescriptor {
                    predicate_id: "github.ceremony/protected_branch_flow@1".to_string(),
                    name: PRED_PROTECTED_BRANCH_FLOW.to_string(),
                    doc: "Triggers when PR targets protected base branches but does not originate from an allowed head branch pattern.".to_string(),
                    result_kind: PredicateResultKind::Bool,
                    emits_findings: true,
                    param_schema: Some(serde_json::json!({
                        "type": "object",
                        "properties": {
                            "protected_bases": {
                                "type": "array",
                                "items": { "type": "string" }
                            },
                            "allowed_heads": {
                                "type": "array",
                                "items": { "type": "string" }
                            }
                        }
                    })),
                    evidence_schema: None,
                },
            ],
        }
    }

    fn snapshot(&self, req: &SnapshotRequest) -> Result<SnapshotResult, ProviderError> {
        let scope_id = ScopeId(GITHUB_CEREMONY_SCOPE_ID.to_string());
        let root_str = req
            .params
            .get("root")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ProviderError {
                scope: scope_id.clone(),
                phase: ProviderPhase::Snapshot,
                message: "params.root (string) is required".to_string(),
            })?;
        let root = Path::new(root_str);
        if !root.is_dir() {
            return Err(ProviderError {
                scope: scope_id.clone(),
                phase: ProviderPhase::Snapshot,
                message: format!("root path is not a directory: {}", root_str),
            });
        }

        let payload = gh_pr_view_payload(root, &scope_id)?;
        let mut facts = payload_to_facts(&payload);
        facts.sort_by(|a, b| fact_sort_key(a).cmp(&fact_sort_key(b)));
        let snapshot_hash = canonical_sha256(&payload).map_err(|err| ProviderError {
            scope: scope_id.clone(),
            phase: ProviderPhase::Snapshot,
            message: err,
        })?;

        let created_at = req
            .params
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(now_rfc3339);

        let facts_bundle = FactsBundle {
            schema_id: GITHUB_CEREMONY_SCHEMA_ID.to_string(),
            scope_id: scope_id.clone(),
            facts: facts.clone(),
            snapshot_hash: Sha256Hex::new(snapshot_hash),
            created_at: Rfc3339Timestamp::new(created_at),
        };

        let witness_program = WitnessProgram {
            module: ModuleId(format!("provider/{}", GITHUB_CEREMONY_SCOPE_ID)),
            scope: scope_id,
            ruleset_id: None,
            ruleset_version: None,
            content_id: None,
            program_hash: None,
            snapshot_hash: Some(facts_bundle.snapshot_hash.0.clone()),
            facts_bundle_hash: None,
            ruleset_hash: None,
        };
        let witness =
            WitnessBuilder::new(witness_program, Verdict::Admissible, "snapshot complete")
                .with_facts(facts)
                .with_displacement_trace(DisplacementTrace {
                    mode: DisplacementMode::Potential,
                    totals: vec![],
                    contributions: vec![],
                })
                .build();

        Ok(SnapshotResult {
            facts_bundle,
            witness,
        })
    }

    fn eval_predicate(
        &self,
        name: &str,
        params: &serde_json::Value,
        ctx: &PredicateEvalContext,
    ) -> Result<PredicateResult, ProviderError> {
        let scope_id = ScopeId(GITHUB_CEREMONY_SCOPE_ID.to_string());
        let facts = decode_facts(params, ctx, &scope_id)?;
        if has_scope_unavailable(&facts) {
            return Ok(PredicateResult {
                triggered: false,
                findings: vec![],
            });
        }
        match name {
            PRED_REQUIRED_CHECKS_GREEN => eval_required_checks_green(params, &facts),
            PRED_MIN_APPROVALS_MET => eval_min_approvals_met(params, &facts),
            PRED_WORKFLOW_CHANGE_REQUIRES_EXTRA_APPROVAL => {
                eval_workflow_change_requires_extra_approval(params, &facts)
            }
            PRED_PROTECTED_BRANCH_FLOW => eval_protected_branch_flow(params, &facts),
            _ => Err(ProviderError {
                scope: scope_id,
                phase: ProviderPhase::Snapshot,
                message: format!("predicate '{}' not supported", name),
            }),
        }
    }
}

#[derive(Debug, Clone)]
struct CheckRow {
    name: String,
    status: String,
    conclusion: Option<String>,
    state: String,
}

fn gh_pr_view_payload(root: &Path, scope_id: &ScopeId) -> Result<Value, ProviderError> {
    let mut cmd = Command::new("gh");
    cmd.arg("pr").arg("view");
    let selector = resolve_pr_selector_from_env();
    if let Some(selector) = selector.as_deref() {
        cmd.arg(selector);
    }
    if let Some(repo) = resolve_repo_from_env().filter(|_| selector.is_some()) {
        cmd.arg("--repo").arg(repo);
    }
    let output = cmd
        .arg("--json")
        .arg("state,baseRefName,headRefName,headRefOid,number,title,labels,reviews,reviewDecision,statusCheckRollup,files")
        .current_dir(path_for_gh(root))
        .output()
        .map_err(|err| ProviderError {
            scope: scope_id.clone(),
            phase: ProviderPhase::Snapshot,
            message: format!("gh pr view execution failed: {}", err),
        })?;
    if !output.status.success() {
        return Err(ProviderError {
            scope: scope_id.clone(),
            phase: ProviderPhase::Snapshot,
            message: format!(
                "gh pr view failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        });
    }
    serde_json::from_slice(&output.stdout).map_err(|err| ProviderError {
        scope: scope_id.clone(),
        phase: ProviderPhase::Snapshot,
        message: format!("decode gh pr view json failed: {}", err),
    })
}

fn resolve_pr_number_from_env() -> Option<u64> {
    std::env::var("GH_PR_NUMBER")
        .ok()
        .and_then(|raw| raw.trim().parse::<u64>().ok())
        .or_else(|| {
            let ref_name = std::env::var("GITHUB_REF").ok()?;
            let mut parts = ref_name.split('/');
            let first = parts.next()?;
            let second = parts.next()?;
            let third = parts.next()?;
            if first != "refs" || second != "pull" {
                return None;
            }
            third.parse::<u64>().ok()
        })
}

fn resolve_pr_selector_from_env() -> Option<String> {
    if let Some(pr_number) = resolve_pr_number_from_env() {
        return Some(pr_number.to_string());
    }
    if let Some(head_ref) = std::env::var("GITHUB_HEAD_REF")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
    {
        return Some(head_ref);
    }
    std::env::var("GITHUB_REF_NAME")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn resolve_repo_from_env() -> Option<String> {
    std::env::var("GH_REPO")
        .ok()
        .filter(|s| !s.trim().is_empty())
        .or_else(|| {
            std::env::var("GITHUB_REPOSITORY")
                .ok()
                .filter(|s| !s.trim().is_empty())
        })
}

fn payload_to_facts(payload: &Value) -> Vec<Fact> {
    let mut facts = Vec::new();
    let mut labels = extract_labels(payload);
    labels.sort();
    labels.dedup();

    let review_summary = extract_review_summary(payload);
    let checks = extract_checks(payload);
    let files = extract_files(payload);

    let number = payload.get("number").and_then(|v| v.as_i64()).unwrap_or(0);
    let state = payload
        .get("state")
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN")
        .to_string();

    facts.push(Fact::LintFinding {
        rule_id: RULE_PR_STATE.to_string(),
        severity: Severity::Info,
        invariant: None,
        path: ".".to_string(),
        span: span_for_path("."),
        message: format!("pr #{} state {}", number, state),
        evidence: Some(serde_json::json!({
            "state": state,
            "base": payload.get("baseRefName").and_then(|v| v.as_str()).unwrap_or_default(),
            "head": payload.get("headRefName").and_then(|v| v.as_str()).unwrap_or_default(),
            "sha": payload.get("headRefOid").and_then(|v| v.as_str()).unwrap_or_default(),
            "number": number,
            "title": payload.get("title").and_then(|v| v.as_str()).unwrap_or_default(),
            "labels": labels,
        })),
    });

    facts.push(Fact::LintFinding {
        rule_id: RULE_REVIEW_SUMMARY.to_string(),
        severity: Severity::Info,
        invariant: None,
        path: ".".to_string(),
        span: span_for_path("."),
        message: format!(
            "reviews approvals={} changes_requested={}",
            review_summary
                .get("approvals")
                .and_then(|v| v.as_u64())
                .unwrap_or(0),
            review_summary
                .get("changes_requested")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
        ),
        evidence: Some(review_summary),
    });

    facts.push(Fact::LintFinding {
        rule_id: RULE_CHECKS_SUMMARY.to_string(),
        severity: Severity::Info,
        invariant: None,
        path: ".".to_string(),
        span: span_for_path("."),
        message: format!("checks total={}", checks.len()),
        evidence: Some(serde_json::json!({
            "total_checks": checks.len(),
            "passed": checks.iter().filter(|row| row.state == "green").count(),
            "failed": checks.iter().filter(|row| row.state == "red").count(),
            "pending": checks.iter().filter(|row| row.state == "pending").count(),
            "check_names": checks.iter().map(|row| row.name.clone()).collect::<Vec<_>>(),
            "checks": checks.iter().map(|row| {
                serde_json::json!({
                    "name": row.name,
                    "status": row.status,
                    "conclusion": row.conclusion,
                    "state": row.state
                })
            }).collect::<Vec<_>>()
        })),
    });

    facts.push(Fact::LintFinding {
        rule_id: RULE_CHANGED_FILES.to_string(),
        severity: Severity::Info,
        invariant: None,
        path: ".".to_string(),
        span: span_for_path("."),
        message: format!("{} changed file(s)", files.len()),
        evidence: Some(serde_json::json!({
            "files": files,
            "count": files.len()
        })),
    });
    facts
}

fn extract_labels(payload: &Value) -> Vec<String> {
    payload
        .get("labels")
        .and_then(|v| v.as_array())
        .map(|labels| {
            labels
                .iter()
                .filter_map(|row| row.get("name").and_then(|v| v.as_str()))
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn extract_review_summary(payload: &Value) -> Value {
    let reviews = payload
        .get("reviews")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    // Count approvals by latest state per reviewer, not raw review event count.
    let mut latest_by_reviewer: BTreeMap<String, (Option<String>, usize, String)> = BTreeMap::new();
    for (idx, row) in reviews.iter().enumerate() {
        let reviewer = row
            .get("author")
            .and_then(|v| v.get("login"))
            .and_then(|v| v.as_str())
            .or_else(|| row.get("author").and_then(|v| v.as_str()))
            .map(|s| s.to_string())
            .unwrap_or_else(|| format!("(unknown:{})", idx));
        let submitted_at = row
            .get("submittedAt")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let state = row
            .get("state")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        let should_replace = match latest_by_reviewer.get(&reviewer) {
            Some((existing_time, existing_idx, _)) => {
                review_is_newer(&submitted_at, idx, existing_time, *existing_idx)
            }
            None => true,
        };
        if should_replace {
            latest_by_reviewer.insert(reviewer, (submitted_at, idx, state));
        }
    }

    let approvals = latest_by_reviewer
        .values()
        .filter(|(_, _, state)| state.eq_ignore_ascii_case("APPROVED"))
        .count();
    let changes_requested = latest_by_reviewer
        .values()
        .filter(|(_, _, state)| state.eq_ignore_ascii_case("CHANGES_REQUESTED"))
        .count();
    serde_json::json!({
        "total_reviews": reviews.len(),
        "effective_reviewers": latest_by_reviewer.len(),
        "approvals": approvals,
        "changes_requested": changes_requested,
        "review_decision": payload.get("reviewDecision").and_then(|v| v.as_str())
    })
}

fn review_is_newer(
    new_time: &Option<String>,
    new_idx: usize,
    old_time: &Option<String>,
    old_idx: usize,
) -> bool {
    match (new_time.as_deref(), old_time.as_deref()) {
        (Some(new_ts), Some(old_ts)) => new_ts >= old_ts,
        (Some(_), None) => true,
        (None, Some(_)) => false,
        (None, None) => new_idx >= old_idx,
    }
}

fn extract_checks(payload: &Value) -> Vec<CheckRow> {
    let mut checks = payload
        .get("statusCheckRollup")
        .and_then(|v| v.as_array())
        .map(|rows| {
            rows.iter()
                .map(|row| {
                    let name = row
                        .get("name")
                        .and_then(|v| v.as_str())
                        .or_else(|| row.get("context").and_then(|v| v.as_str()))
                        .or_else(|| row.get("workflowName").and_then(|v| v.as_str()))
                        .unwrap_or("(unnamed-check)")
                        .to_string();
                    let status = row
                        .get("status")
                        .and_then(|v| v.as_str())
                        .unwrap_or("UNKNOWN")
                        .to_string();
                    let conclusion = row
                        .get("conclusion")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string());
                    let state = check_state(&status, conclusion.as_deref()).to_string();
                    CheckRow {
                        name,
                        status,
                        conclusion,
                        state,
                    }
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    checks.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then(a.status.cmp(&b.status))
            .then(a.conclusion.cmp(&b.conclusion))
    });
    checks
}

fn extract_files(payload: &Value) -> Vec<String> {
    let mut files = payload
        .get("files")
        .and_then(|v| v.as_array())
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row.get("path").and_then(|v| v.as_str()))
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    files.sort();
    files.dedup();
    files
}

fn check_state(status: &str, conclusion: Option<&str>) -> &'static str {
    if matches!(conclusion, Some("SUCCESS")) {
        return "green";
    }
    if status.eq_ignore_ascii_case("COMPLETED") {
        return "red";
    }
    "pending"
}

fn decode_facts(
    params: &serde_json::Value,
    ctx: &PredicateEvalContext,
    scope_id: &ScopeId,
) -> Result<Vec<Fact>, ProviderError> {
    if let Some(facts) = &ctx.facts {
        return Ok(facts.clone());
    }
    let value = params.get("facts").cloned().ok_or_else(|| ProviderError {
        scope: scope_id.clone(),
        phase: ProviderPhase::Snapshot,
        message: "predicate requires context.facts or params.facts".to_string(),
    })?;
    serde_json::from_value(value).map_err(|err| ProviderError {
        scope: scope_id.clone(),
        phase: ProviderPhase::Snapshot,
        message: format!("decode params.facts: {}", err),
    })
}

fn has_scope_unavailable(facts: &[Fact]) -> bool {
    facts.iter().any(|fact| match fact {
        Fact::LintFinding { rule_id, .. } => rule_id == RULE_SCOPE_UNAVAILABLE,
        _ => false,
    })
}

fn extract_review_approvals(facts: &[Fact]) -> usize {
    facts
        .iter()
        .find_map(|fact| match fact {
            Fact::LintFinding {
                rule_id,
                evidence: Some(evidence),
                ..
            } if rule_id == RULE_REVIEW_SUMMARY => evidence
                .get("approvals")
                .and_then(|v| v.as_u64())
                .map(|v| v as usize),
            _ => None,
        })
        .unwrap_or(0)
}

fn extract_check_rows(facts: &[Fact]) -> Vec<CheckRow> {
    let mut rows = Vec::new();
    for fact in facts {
        let Fact::LintFinding {
            rule_id,
            evidence: Some(evidence),
            ..
        } = fact
        else {
            continue;
        };
        if rule_id != RULE_CHECKS_SUMMARY {
            continue;
        }
        let Some(checks) = evidence.get("checks").and_then(|v| v.as_array()) else {
            continue;
        };
        for check in checks {
            let name = check
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("(unnamed-check)")
                .to_string();
            let status = check
                .get("status")
                .and_then(|v| v.as_str())
                .unwrap_or("UNKNOWN")
                .to_string();
            let conclusion = check
                .get("conclusion")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let state = check
                .get("state")
                .and_then(|v| v.as_str())
                .unwrap_or_else(|| check_state(&status, conclusion.as_deref()))
                .to_string();
            rows.push(CheckRow {
                name,
                status,
                conclusion,
                state,
            });
        }
    }
    rows.sort_by(|a, b| {
        a.name
            .cmp(&b.name)
            .then(a.status.cmp(&b.status))
            .then(a.conclusion.cmp(&b.conclusion))
    });
    rows
}

fn extract_changed_files(facts: &[Fact]) -> Vec<String> {
    let mut files = Vec::new();
    for fact in facts {
        let Fact::LintFinding {
            rule_id,
            evidence: Some(evidence),
            ..
        } = fact
        else {
            continue;
        };
        if rule_id != RULE_CHANGED_FILES {
            continue;
        }
        if let Some(arr) = evidence.get("files").and_then(|v| v.as_array()) {
            for item in arr {
                if let Some(path) = item.as_str() {
                    files.push(path.to_string());
                }
            }
        }
    }
    files.sort();
    files.dedup();
    files
}

fn extract_pr_base_head(facts: &[Fact]) -> Option<(String, String, i64, String)> {
    for fact in facts {
        let Fact::LintFinding {
            rule_id,
            evidence: Some(evidence),
            ..
        } = fact
        else {
            continue;
        };
        if rule_id != RULE_PR_STATE {
            continue;
        }
        let base = evidence
            .get("base")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let head = evidence
            .get("head")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let number = evidence.get("number").and_then(|v| v.as_i64()).unwrap_or(0);
        let sha = evidence
            .get("sha")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        return Some((base, head, number, sha));
    }
    None
}

fn eval_required_checks_green(
    params: &serde_json::Value,
    facts: &[Fact],
) -> Result<PredicateResult, ProviderError> {
    let required: Vec<String> = params
        .get("required")
        .and_then(|v| v.as_array())
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let checks = extract_check_rows(facts);

    let mut findings = Vec::new();
    if required.is_empty() {
        for row in &checks {
            if row.state != "green" {
                findings.push(admit_core::LintFinding {
                    rule_id: "scope:github.ceremony/predicate:required_checks_green".to_string(),
                    severity: Severity::Info,
                    invariant: Some("github.required_checks".to_string()),
                    path: ".".to_string(),
                    span: span_for_path("."),
                    message: format!("check is not green: {}", row.name),
                    evidence: Some(serde_json::json!({
                        "check_name": row.name,
                        "status": row.status,
                        "conclusion": row.conclusion,
                        "state": row.state
                    })),
                });
            }
        }
    } else {
        for required_name in &required {
            let check = checks.iter().find(|row| row.name == *required_name);
            match check {
                Some(row) if row.state == "green" => {}
                Some(row) => findings.push(admit_core::LintFinding {
                    rule_id: "scope:github.ceremony/predicate:required_checks_green".to_string(),
                    severity: Severity::Info,
                    invariant: Some("github.required_checks".to_string()),
                    path: ".".to_string(),
                    span: span_for_path("."),
                    message: format!("required check not green: {}", required_name),
                    evidence: Some(serde_json::json!({
                        "check_name": row.name,
                        "status": row.status,
                        "conclusion": row.conclusion,
                        "state": row.state
                    })),
                }),
                None => findings.push(admit_core::LintFinding {
                    rule_id: "scope:github.ceremony/predicate:required_checks_green".to_string(),
                    severity: Severity::Info,
                    invariant: Some("github.required_checks".to_string()),
                    path: ".".to_string(),
                    span: span_for_path("."),
                    message: format!("required check missing from rollup: {}", required_name),
                    evidence: Some(serde_json::json!({
                        "check_name": required_name,
                        "missing": true
                    })),
                }),
            }
        }
    }

    sort_findings(&mut findings);
    Ok(PredicateResult {
        triggered: !findings.is_empty(),
        findings,
    })
}

fn eval_min_approvals_met(
    params: &serde_json::Value,
    facts: &[Fact],
) -> Result<PredicateResult, ProviderError> {
    let min = params.get("min").and_then(|v| v.as_u64()).unwrap_or(1) as usize;
    let approvals = extract_review_approvals(facts);
    let mut findings = Vec::new();
    if approvals < min {
        findings.push(admit_core::LintFinding {
            rule_id: "scope:github.ceremony/predicate:min_approvals_met".to_string(),
            severity: Severity::Info,
            invariant: Some("github.review_gate".to_string()),
            path: ".".to_string(),
            span: span_for_path("."),
            message: format!("approvals {} below required minimum {}", approvals, min),
            evidence: Some(serde_json::json!({
                "approvals": approvals,
                "required_min": min
            })),
        });
    }
    Ok(PredicateResult {
        triggered: !findings.is_empty(),
        findings,
    })
}

fn eval_workflow_change_requires_extra_approval(
    params: &serde_json::Value,
    facts: &[Fact],
) -> Result<PredicateResult, ProviderError> {
    let min = params
        .get("min_for_workflow")
        .and_then(|v| v.as_u64())
        .unwrap_or(2) as usize;
    let approvals = extract_review_approvals(facts);
    let files = extract_changed_files(facts);
    let workflow_touched = files
        .iter()
        .any(|path| path.starts_with(".github/workflows/"));

    let mut findings = Vec::new();
    if workflow_touched && approvals < min {
        findings.push(admit_core::LintFinding {
            rule_id: "scope:github.ceremony/predicate:workflow_change_requires_extra_approval"
                .to_string(),
            severity: Severity::Info,
            invariant: Some("github.workflow_guard".to_string()),
            path: ".github/workflows/".to_string(),
            span: span_for_path(".github/workflows/"),
            message: format!(
                "workflow changes require {} approvals; observed {}",
                min, approvals
            ),
            evidence: Some(serde_json::json!({
                "approvals": approvals,
                "required_min_for_workflow": min
            })),
        });
    }
    Ok(PredicateResult {
        triggered: !findings.is_empty(),
        findings,
    })
}

fn eval_protected_branch_flow(
    params: &serde_json::Value,
    facts: &[Fact],
) -> Result<PredicateResult, ProviderError> {
    let (base, head, pr_number, sha) = match extract_pr_base_head(facts) {
        Some(v) => v,
        None => {
            return Ok(PredicateResult {
                triggered: false,
                findings: vec![],
            });
        }
    };

    let protected_bases: Vec<String> = params
        .get("protected_bases")
        .and_then(|v| v.as_array())
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_else(|| vec!["main".to_string(), "master".to_string()]);
    let allowed_heads: Vec<String> = params
        .get("allowed_heads")
        .and_then(|v| v.as_array())
        .map(|rows| {
            rows.iter()
                .filter_map(|row| row.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_else(|| vec!["dev".to_string(), "dev/*".to_string()]);

    if !protected_bases.iter().any(|b| b == &base) {
        return Ok(PredicateResult {
            triggered: false,
            findings: vec![],
        });
    }

    let mut matcher = globset::GlobSetBuilder::new();
    for pattern in &allowed_heads {
        let glob = globset::Glob::new(pattern).map_err(|err| ProviderError {
            scope: ScopeId(GITHUB_CEREMONY_SCOPE_ID.to_string()),
            phase: ProviderPhase::Snapshot,
            message: format!("invalid allowed_heads pattern '{}': {}", pattern, err),
        })?;
        matcher.add(glob);
    }
    let matcher = matcher.build().map_err(|err| ProviderError {
        scope: ScopeId(GITHUB_CEREMONY_SCOPE_ID.to_string()),
        phase: ProviderPhase::Snapshot,
        message: format!("allowed_heads globset build failed: {}", err),
    })?;

    if matcher.is_match(&head) {
        return Ok(PredicateResult {
            triggered: false,
            findings: vec![],
        });
    }

    let finding = admit_core::LintFinding {
        rule_id: "scope:github.ceremony/predicate:protected_branch_flow".to_string(),
        severity: Severity::Info,
        invariant: Some("github.branch_flow".to_string()),
        path: ".".to_string(),
        span: span_for_path("."),
        message: format!(
            "protected base '{}' requires head in {:?}; observed '{}'",
            base, allowed_heads, head
        ),
        evidence: Some(serde_json::json!({
            "pr_number": pr_number,
            "head_sha": sha,
            "base": base,
            "head": head,
            "allowed_heads": allowed_heads,
            "protected_bases": protected_bases
        })),
    };
    Ok(PredicateResult {
        triggered: true,
        findings: vec![finding],
    })
}

fn sort_findings(findings: &mut [admit_core::LintFinding]) {
    findings.sort_by(|a, b| {
        a.rule_id
            .cmp(&b.rule_id)
            .then(a.path.cmp(&b.path))
            .then(a.span.file.cmp(&b.span.file))
            .then(a.span.line.unwrap_or(0).cmp(&b.span.line.unwrap_or(0)))
            .then(a.span.col.unwrap_or(0).cmp(&b.span.col.unwrap_or(0)))
            .then(a.message.cmp(&b.message))
    });
}

fn fact_sort_key(fact: &Fact) -> (u8, String, String, u32, u32) {
    let type_rank = match fact {
        Fact::ConstraintTriggered { .. } => 0,
        Fact::PermissionUsed { .. } => 1,
        Fact::ErasureRuleUsed { .. } => 2,
        Fact::CommitUsed { .. } => 3,
        Fact::PredicateEvaluated { .. } => 4,
        Fact::RuleEvaluated { .. } => 5,
        Fact::ScopeChangeUsed { .. } => 6,
        Fact::UnaccountedBoundaryChange { .. } => 7,
        Fact::LensActivated { .. } => 8,
        Fact::MetaChangeChecked { .. } => 9,
        Fact::LintFinding { .. } => 10,
    };
    let aux = match fact {
        Fact::RuleEvaluated { rule_id, .. } => rule_id.clone(),
        Fact::LintFinding { rule_id, .. } => rule_id.clone(),
        _ => String::new(),
    };
    let span = match fact {
        Fact::ConstraintTriggered { span, .. }
        | Fact::PermissionUsed { span, .. }
        | Fact::ErasureRuleUsed { span, .. }
        | Fact::CommitUsed { span, .. }
        | Fact::PredicateEvaluated { span, .. }
        | Fact::RuleEvaluated { span, .. }
        | Fact::ScopeChangeUsed { span, .. }
        | Fact::UnaccountedBoundaryChange { span, .. }
        | Fact::LensActivated { span, .. }
        | Fact::MetaChangeChecked { span, .. }
        | Fact::LintFinding { span, .. } => span,
    };
    (
        type_rank,
        aux,
        span.file.clone(),
        span.line.unwrap_or(0),
        span.col.unwrap_or(0),
    )
}

fn canonical_sha256(value: &Value) -> Result<String, String> {
    let bytes = admit_core::encode_canonical_value(value).map_err(|err| err.0)?;
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

fn span_for_path(path: &str) -> Span {
    Span {
        file: path.to_string(),
        start: None,
        end: None,
        line: None,
        col: None,
    }
}

fn now_rfc3339() -> String {
    use std::time::SystemTime;
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}Z", dur.as_secs())
}

#[cfg(windows)]
fn path_for_gh(path: &Path) -> std::path::PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        return std::path::PathBuf::from(stripped);
    }
    path.to_path_buf()
}

#[cfg(not(windows))]
fn path_for_gh(path: &Path) -> std::path::PathBuf {
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_fact(rule_id: &str, evidence: serde_json::Value) -> Fact {
        Fact::LintFinding {
            rule_id: rule_id.to_string(),
            severity: Severity::Info,
            invariant: None,
            path: ".".to_string(),
            span: span_for_path("."),
            message: rule_id.to_string(),
            evidence: Some(evidence),
        }
    }

    #[test]
    fn required_checks_green_triggers_for_non_green_required_check() {
        let provider = GithubCeremonyProvider::new();
        let facts = vec![make_fact(
            RULE_CHECKS_SUMMARY,
            serde_json::json!({
                "checks": [
                    {"name": "CI", "status": "COMPLETED", "conclusion": "SUCCESS", "state": "green"},
                    {"name": "lint", "status": "COMPLETED", "conclusion": "FAILURE", "state": "red"}
                ]
            }),
        )];
        let out = provider
            .eval_predicate(
                PRED_REQUIRED_CHECKS_GREEN,
                &serde_json::json!({
                    "facts": facts,
                    "required": ["CI", "lint"]
                }),
                &PredicateEvalContext::default(),
            )
            .expect("predicate");
        assert!(out.triggered);
        assert_eq!(
            out.findings[0].rule_id,
            "scope:github.ceremony/predicate:required_checks_green"
        );
    }

    #[test]
    fn min_approvals_met_triggers_when_below_minimum() {
        let provider = GithubCeremonyProvider::new();
        let facts = vec![make_fact(
            RULE_REVIEW_SUMMARY,
            serde_json::json!({"approvals": 1}),
        )];
        let out = provider
            .eval_predicate(
                PRED_MIN_APPROVALS_MET,
                &serde_json::json!({
                    "facts": facts,
                    "min": 2
                }),
                &PredicateEvalContext::default(),
            )
            .expect("predicate");
        assert!(out.triggered);
        assert_eq!(
            out.findings[0].rule_id,
            "scope:github.ceremony/predicate:min_approvals_met"
        );
    }

    #[test]
    fn workflow_change_requires_extra_approval_triggers() {
        let provider = GithubCeremonyProvider::new();
        let facts = vec![
            make_fact(RULE_REVIEW_SUMMARY, serde_json::json!({"approvals": 1})),
            make_fact(
                RULE_CHANGED_FILES,
                serde_json::json!({"files": [".github/workflows/ci.yml"]}),
            ),
        ];
        let out = provider
            .eval_predicate(
                PRED_WORKFLOW_CHANGE_REQUIRES_EXTRA_APPROVAL,
                &serde_json::json!({
                    "facts": facts,
                    "min_for_workflow": 2
                }),
                &PredicateEvalContext::default(),
            )
            .expect("predicate");
        assert!(out.triggered);
        assert_eq!(
            out.findings[0].rule_id,
            "scope:github.ceremony/predicate:workflow_change_requires_extra_approval"
        );
    }

    #[test]
    fn predicates_skip_when_scope_unavailable_marker_present() {
        let provider = GithubCeremonyProvider::new();
        let facts = vec![make_fact(
            RULE_SCOPE_UNAVAILABLE,
            serde_json::json!({"reason": "gh unavailable"}),
        )];
        let out = provider
            .eval_predicate(
                PRED_MIN_APPROVALS_MET,
                &serde_json::json!({ "facts": facts }),
                &PredicateEvalContext::default(),
            )
            .expect("predicate");
        assert!(!out.triggered);
        assert!(out.findings.is_empty());
    }

    #[test]
    fn protected_branch_flow_triggers_for_non_dev_head_into_main() {
        let provider = GithubCeremonyProvider::new();
        let facts = vec![make_fact(
            RULE_PR_STATE,
            serde_json::json!({
                "base": "main",
                "head": "feature/x",
                "number": 42,
                "sha": "abc123"
            }),
        )];
        let out = provider
            .eval_predicate(
                PRED_PROTECTED_BRANCH_FLOW,
                &serde_json::json!({
                    "facts": facts,
                    "protected_bases": ["main", "master"],
                    "allowed_heads": ["dev", "dev/*"]
                }),
                &PredicateEvalContext::default(),
            )
            .expect("predicate");
        assert!(out.triggered);
        assert_eq!(
            out.findings[0].rule_id,
            "scope:github.ceremony/predicate:protected_branch_flow"
        );
    }

    #[test]
    fn protected_branch_flow_allows_dev_head_into_main() {
        let provider = GithubCeremonyProvider::new();
        let facts = vec![make_fact(
            RULE_PR_STATE,
            serde_json::json!({
                "base": "main",
                "head": "dev/feature-x",
                "number": 99,
                "sha": "def456"
            }),
        )];
        let out = provider
            .eval_predicate(
                PRED_PROTECTED_BRANCH_FLOW,
                &serde_json::json!({
                    "facts": facts,
                    "protected_bases": ["main", "master"],
                    "allowed_heads": ["dev", "dev/*"]
                }),
                &PredicateEvalContext::default(),
            )
            .expect("predicate");
        assert!(!out.triggered);
    }

    #[test]
    fn min_approvals_met_uses_context_facts() {
        let provider = GithubCeremonyProvider::new();
        let facts = vec![make_fact(
            RULE_REVIEW_SUMMARY,
            serde_json::json!({"approvals": 1}),
        )];
        let out = provider
            .eval_predicate(
                PRED_MIN_APPROVALS_MET,
                &serde_json::json!({ "min": 2 }),
                &PredicateEvalContext {
                    facts: Some(facts),
                    snapshot_hash: None,
                    facts_schema_id: None,
                },
            )
            .expect("predicate");
        assert!(out.triggered);
    }

    #[test]
    fn review_summary_counts_latest_state_per_reviewer() {
        let payload = serde_json::json!({
            "reviews": [
                { "author": { "login": "alice" }, "state": "APPROVED", "submittedAt": "2026-02-14T10:00:00Z" },
                { "author": { "login": "alice" }, "state": "CHANGES_REQUESTED", "submittedAt": "2026-02-14T11:00:00Z" },
                { "author": { "login": "bob" }, "state": "APPROVED", "submittedAt": "2026-02-14T10:30:00Z" }
            ],
            "reviewDecision": "REVIEW_REQUIRED"
        });
        let summary = extract_review_summary(&payload);
        assert_eq!(summary.get("approvals").and_then(|v| v.as_u64()), Some(1));
        assert_eq!(
            summary.get("changes_requested").and_then(|v| v.as_u64()),
            Some(1)
        );
    }
}
