//! Provider implementation for the `git.working_tree` scope.
//!
//! Snapshot is read-only and deterministic:
//! - source: `git status --porcelain=v2 --branch --untracked-files=all --ignored=no`
//! - no writes or git mutations
//! - canonical hashing over sorted facts

use std::path::Path;
use std::process::Command;

use admit_core::provider_trait::Provider;
use admit_core::provider_types::*;
use admit_core::witness::{
    DisplacementMode, DisplacementTrace, Fact, Severity, Verdict, WitnessBuilder, WitnessProgram,
};
use admit_core::{ModuleId, ScopeId, Span};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::backend::{GIT_WORKING_TREE_SCHEMA_ID, GIT_WORKING_TREE_SCOPE_ID};

const RULE_BRANCH: &str = "git/branch";
const RULE_DIRTY: &str = "git/dirty_state";
const RULE_MODIFIED: &str = "git/modified_file";
const RULE_ADDED: &str = "git/added_file";
const RULE_DELETED: &str = "git/deleted_file";
const RULE_RENAMED: &str = "git/renamed_file";
const RULE_UNTRACKED: &str = "git/untracked_file";
const RULE_STAGED: &str = "git/staged_file";

const DIRTY_RULE_IDS: [&str; 6] = [
    RULE_MODIFIED,
    RULE_ADDED,
    RULE_DELETED,
    RULE_RENAMED,
    RULE_UNTRACKED,
    RULE_STAGED,
];

#[derive(Debug, Clone)]
struct GitStatusSnapshot {
    branch: String,
    head_commit: String,
    repo_toplevel: String,
    upstream: Option<String>,
    ahead: Option<i64>,
    behind: Option<i64>,
    entries: Vec<GitStatusEntry>,
}

#[derive(Debug, Clone)]
enum GitStatusEntry {
    Tracked {
        xy: String,
        path: String,
        old_path: Option<String>,
    },
    Untracked {
        path: String,
    },
}

/// Provider for Git working-tree observation facts.
pub struct GitWorkingTreeProvider;

impl GitWorkingTreeProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for GitWorkingTreeProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Provider for GitWorkingTreeProvider {
    fn describe(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            scope_id: ScopeId(GIT_WORKING_TREE_SCOPE_ID.to_string()),
            version: 1,
            schema_ids: vec![GIT_WORKING_TREE_SCHEMA_ID.to_string()],
            supported_phases: vec![ProviderPhase::Describe, ProviderPhase::Snapshot],
            deterministic: true,
            closure: ClosureRequirements {
                requires_process: true,
                ..ClosureRequirements::default()
            },
            required_approvals: vec![],
            predicates: vec![
                PredicateDescriptor {
                    name: "dirty_state".to_string(),
                    doc: "Triggers when facts indicate any tracked/untracked working-tree change."
                        .to_string(),
                    param_schema: Some(serde_json::json!({
                        "type": "object",
                        "required": ["facts"],
                        "properties": { "facts": { "type": "array" } }
                    })),
                },
                PredicateDescriptor {
                    name: "untracked_file".to_string(),
                    doc: "Triggers when untracked file facts are present.".to_string(),
                    param_schema: Some(serde_json::json!({
                        "type": "object",
                        "required": ["facts"],
                        "properties": { "facts": { "type": "array" } }
                    })),
                },
                PredicateDescriptor {
                    name: "staged_file".to_string(),
                    doc: "Triggers when staged file facts are present.".to_string(),
                    param_schema: Some(serde_json::json!({
                        "type": "object",
                        "required": ["facts"],
                        "properties": { "facts": { "type": "array" } }
                    })),
                },
                PredicateDescriptor {
                    name: "modified_file".to_string(),
                    doc: "Triggers when modified file facts are present.".to_string(),
                    param_schema: Some(serde_json::json!({
                        "type": "object",
                        "required": ["facts"],
                        "properties": { "facts": { "type": "array" } }
                    })),
                },
            ],
        }
    }

    fn snapshot(&self, req: &SnapshotRequest) -> Result<SnapshotResult, ProviderError> {
        let scope_id = ScopeId(GIT_WORKING_TREE_SCOPE_ID.to_string());
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

        let parsed = git_status_snapshot(root, &scope_id)?;
        let mut facts = status_to_facts(&parsed);
        facts.sort_by(|a, b| fact_sort_key(a).cmp(&fact_sort_key(b)));

        let facts_value = serde_json::to_value(&facts).map_err(|err| ProviderError {
            scope: scope_id.clone(),
            phase: ProviderPhase::Snapshot,
            message: format!("facts serialization failed: {}", err),
        })?;
        let cbor =
            admit_core::encode_canonical_value(&facts_value).map_err(|err| ProviderError {
                scope: scope_id.clone(),
                phase: ProviderPhase::Snapshot,
                message: format!("facts canonical encoding failed: {}", err),
            })?;
        let mut hasher = Sha256::new();
        hasher.update(cbor);
        let snapshot_hash = Sha256Hex::new(format!("{:x}", hasher.finalize()));

        let created_at = req
            .params
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(now_rfc3339);

        let facts_bundle = FactsBundle {
            schema_id: GIT_WORKING_TREE_SCHEMA_ID.to_string(),
            scope_id: scope_id.clone(),
            facts: facts.clone(),
            snapshot_hash,
            created_at: Rfc3339Timestamp::new(created_at),
        };

        let witness_program = WitnessProgram {
            module: ModuleId(format!("provider/{}", GIT_WORKING_TREE_SCOPE_ID)),
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
    ) -> Result<PredicateResult, ProviderError> {
        let scope_id = ScopeId(GIT_WORKING_TREE_SCOPE_ID.to_string());
        let facts = decode_facts(params, &scope_id)?;
        match name {
            "dirty_state" => {
                let mut findings = Vec::new();
                for rule_id in DIRTY_RULE_IDS {
                    findings.extend(findings_for_rule(&facts, rule_id));
                }
                if findings.is_empty() && is_dirty_from_marker(&facts) {
                    findings.push(admit_core::LintFinding {
                        rule_id: RULE_DIRTY.to_string(),
                        severity: Severity::Error,
                        invariant: Some("git.clean_tree".to_string()),
                        path: ".".to_string(),
                        span: Span {
                            file: ".".to_string(),
                            start: None,
                            end: None,
                            line: None,
                            col: None,
                        },
                        message: "working tree is dirty".to_string(),
                        evidence: None,
                    });
                }
                sort_findings(&mut findings);
                Ok(PredicateResult {
                    triggered: !findings.is_empty(),
                    findings,
                })
            }
            "untracked_file" => {
                let mut findings = findings_for_rule(&facts, RULE_UNTRACKED);
                sort_findings(&mut findings);
                Ok(PredicateResult {
                    triggered: !findings.is_empty(),
                    findings,
                })
            }
            "staged_file" => {
                let mut findings = findings_for_rule(&facts, RULE_STAGED);
                sort_findings(&mut findings);
                Ok(PredicateResult {
                    triggered: !findings.is_empty(),
                    findings,
                })
            }
            "modified_file" => {
                let mut findings = findings_for_rule(&facts, RULE_MODIFIED);
                sort_findings(&mut findings);
                Ok(PredicateResult {
                    triggered: !findings.is_empty(),
                    findings,
                })
            }
            _ => Err(ProviderError {
                scope: scope_id,
                phase: ProviderPhase::Snapshot,
                message: format!("predicate '{}' not supported", name),
            }),
        }
    }
}

fn decode_facts(
    params: &serde_json::Value,
    scope_id: &ScopeId,
) -> Result<Vec<Fact>, ProviderError> {
    let value = params.get("facts").cloned().ok_or_else(|| ProviderError {
        scope: scope_id.clone(),
        phase: ProviderPhase::Snapshot,
        message: "predicate requires params.facts".to_string(),
    })?;
    serde_json::from_value(value).map_err(|err| ProviderError {
        scope: scope_id.clone(),
        phase: ProviderPhase::Snapshot,
        message: format!("decode params.facts: {}", err),
    })
}

fn findings_for_rule(facts: &[Fact], rule_id: &str) -> Vec<admit_core::LintFinding> {
    facts
        .iter()
        .filter_map(|fact| match fact {
            Fact::LintFinding {
                rule_id: found_rule_id,
                severity,
                invariant,
                path,
                span,
                message,
                evidence,
            } if found_rule_id == rule_id => Some(admit_core::LintFinding {
                rule_id: found_rule_id.clone(),
                severity: severity.clone(),
                invariant: invariant.clone(),
                path: path.clone(),
                span: span.clone(),
                message: message.clone(),
                evidence: evidence.clone(),
            }),
            _ => None,
        })
        .collect()
}

fn is_dirty_from_marker(facts: &[Fact]) -> bool {
    facts.iter().any(|fact| match fact {
        Fact::LintFinding {
            rule_id, evidence, ..
        } if rule_id == RULE_DIRTY => evidence
            .as_ref()
            .and_then(|v| v.get("dirty"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false),
        _ => false,
    })
}

fn sort_findings(findings: &mut [admit_core::LintFinding]) {
    findings.sort_by(|a, b| {
        a.rule_id
            .cmp(&b.rule_id)
            .then(severity_rank(&a.severity).cmp(&severity_rank(&b.severity)))
            .then(a.path.cmp(&b.path))
            .then(a.span.file.cmp(&b.span.file))
            .then(a.span.line.unwrap_or(0).cmp(&b.span.line.unwrap_or(0)))
            .then(a.span.col.unwrap_or(0).cmp(&b.span.col.unwrap_or(0)))
            .then(a.message.cmp(&b.message))
    });
}

fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Error => 2,
    }
}

fn status_to_facts(status: &GitStatusSnapshot) -> Vec<Fact> {
    let mut facts = Vec::new();
    let branch = if status.branch.is_empty() {
        "(unknown)".to_string()
    } else {
        status.branch.clone()
    };
    let head_commit = if status.head_commit.is_empty() {
        "(unknown)".to_string()
    } else {
        status.head_commit.clone()
    };
    let repo_toplevel = if status.repo_toplevel.is_empty() {
        "(unknown)".to_string()
    } else {
        status.repo_toplevel.clone()
    };
    let head_state = classify_head_state(&branch, &head_commit);
    let receipt = serde_json::json!({
        "branch": branch,
        "head_commit": head_commit,
        "head_state": head_state,
        "repo_toplevel": repo_toplevel,
        "upstream": status.upstream.clone(),
        "ahead": status.ahead,
        "behind": status.behind
    });

    facts.push(Fact::LintFinding {
        rule_id: RULE_BRANCH.to_string(),
        severity: Severity::Info,
        invariant: None,
        path: ".".to_string(),
        span: span_for_path("."),
        message: format!("branch {} ({})", branch, head_state),
        evidence: Some(receipt.clone()),
    });

    let mut dirty_count = 0usize;
    for entry in &status.entries {
        match entry {
            GitStatusEntry::Untracked { path } => {
                dirty_count += 1;
                facts.push(Fact::LintFinding {
                    rule_id: RULE_UNTRACKED.to_string(),
                    severity: Severity::Info,
                    invariant: None,
                    path: path.clone(),
                    span: span_for_path(path),
                    message: "untracked file".to_string(),
                    evidence: Some(with_receipt(
                        &receipt,
                        serde_json::json!({
                            "entry_kind": "untracked"
                        }),
                    )),
                });
            }
            GitStatusEntry::Tracked { xy, path, old_path } => {
                let index = xy.chars().next().unwrap_or('.');
                let worktree = xy.chars().nth(1).unwrap_or('.');

                if index != '.' {
                    dirty_count += 1;
                    facts.push(Fact::LintFinding {
                        rule_id: RULE_STAGED.to_string(),
                        severity: Severity::Info,
                        invariant: None,
                        path: path.clone(),
                        span: span_for_path(path),
                        message: "staged file".to_string(),
                        evidence: Some(with_receipt(
                            &receipt,
                            serde_json::json!({
                                "xy": xy,
                                "index_status": index.to_string(),
                                "worktree_status": worktree.to_string(),
                                "old_path": old_path
                            }),
                        )),
                    });
                }
                if has_status(xy, 'M') || has_status(xy, 'T') {
                    dirty_count += 1;
                    facts.push(Fact::LintFinding {
                        rule_id: RULE_MODIFIED.to_string(),
                        severity: Severity::Info,
                        invariant: None,
                        path: path.clone(),
                        span: span_for_path(path),
                        message: "modified file".to_string(),
                        evidence: Some(with_receipt(
                            &receipt,
                            serde_json::json!({
                                "xy": xy,
                                "index_status": index.to_string(),
                                "worktree_status": worktree.to_string()
                            }),
                        )),
                    });
                }
                if has_status(xy, 'A') {
                    dirty_count += 1;
                    facts.push(Fact::LintFinding {
                        rule_id: RULE_ADDED.to_string(),
                        severity: Severity::Info,
                        invariant: None,
                        path: path.clone(),
                        span: span_for_path(path),
                        message: "added file".to_string(),
                        evidence: Some(with_receipt(
                            &receipt,
                            serde_json::json!({
                                "xy": xy,
                                "index_status": index.to_string(),
                                "worktree_status": worktree.to_string()
                            }),
                        )),
                    });
                }
                if has_status(xy, 'D') {
                    dirty_count += 1;
                    facts.push(Fact::LintFinding {
                        rule_id: RULE_DELETED.to_string(),
                        severity: Severity::Info,
                        invariant: None,
                        path: path.clone(),
                        span: span_for_path(path),
                        message: "deleted file".to_string(),
                        evidence: Some(with_receipt(
                            &receipt,
                            serde_json::json!({
                                "xy": xy,
                                "index_status": index.to_string(),
                                "worktree_status": worktree.to_string()
                            }),
                        )),
                    });
                }
                if old_path.is_some() || has_status(xy, 'R') {
                    dirty_count += 1;
                    facts.push(Fact::LintFinding {
                        rule_id: RULE_RENAMED.to_string(),
                        severity: Severity::Info,
                        invariant: None,
                        path: path.clone(),
                        span: span_for_path(path),
                        message: "renamed file".to_string(),
                        evidence: Some(with_receipt(
                            &receipt,
                            serde_json::json!({
                                "xy": xy,
                                "old_path": old_path
                            }),
                        )),
                    });
                }
            }
        }
    }

    facts.push(Fact::LintFinding {
        rule_id: RULE_DIRTY.to_string(),
        severity: Severity::Info,
        invariant: None,
        path: ".".to_string(),
        span: span_for_path("."),
        message: if dirty_count == 0 {
            "working tree is clean".to_string()
        } else {
            "working tree is dirty".to_string()
        },
        evidence: Some(with_receipt(
            &receipt,
            serde_json::json!({
                "dirty": dirty_count > 0,
                "change_fact_count": dirty_count
            }),
        )),
    });

    facts
}

fn with_receipt(receipt: &Value, extra: Value) -> Value {
    let mut obj = match receipt {
        Value::Object(map) => map.clone(),
        _ => Map::new(),
    };
    if let Value::Object(extra_obj) = extra {
        for (k, v) in extra_obj {
            obj.insert(k, v);
        }
    }
    Value::Object(obj)
}

fn classify_head_state(branch: &str, head_commit: &str) -> &'static str {
    if head_commit == "(initial)" || head_commit == "(unborn)" {
        "unborn"
    } else if branch == "(detached)" {
        "detached"
    } else if branch == "(unknown)" {
        "unknown"
    } else {
        "attached"
    }
}

fn has_status(xy: &str, ch: char) -> bool {
    let mut chars = xy.chars();
    chars.next() == Some(ch) || chars.next() == Some(ch)
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

fn git_status_snapshot(
    root: &Path,
    scope_id: &ScopeId,
) -> Result<GitStatusSnapshot, ProviderError> {
    let repo_toplevel = git_repo_toplevel(root, scope_id)?;
    let output = Command::new("git")
        .arg("-C")
        .arg(path_for_git(root))
        .args([
            "status",
            "--porcelain=v2",
            "--branch",
            "--untracked-files=all",
            "--ignored=no",
        ])
        .output()
        .map_err(|err| ProviderError {
            scope: scope_id.clone(),
            phase: ProviderPhase::Snapshot,
            message: format!("git status execution failed: {}", err),
        })?;
    if !output.status.success() {
        return Err(ProviderError {
            scope: scope_id.clone(),
            phase: ProviderPhase::Snapshot,
            message: format!(
                "git status failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        });
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut snapshot = GitStatusSnapshot {
        branch: String::new(),
        head_commit: String::new(),
        repo_toplevel,
        upstream: None,
        ahead: None,
        behind: None,
        entries: Vec::new(),
    };
    for line in stdout.lines() {
        parse_status_line(line, &mut snapshot);
    }
    snapshot
        .entries
        .sort_by(|a, b| status_entry_sort_key(a).cmp(&status_entry_sort_key(b)));
    Ok(snapshot)
}

fn parse_status_line(line: &str, snapshot: &mut GitStatusSnapshot) {
    if let Some(head) = line.strip_prefix("# branch.head ") {
        snapshot.branch = head.trim().to_string();
        return;
    }
    if let Some(oid) = line.strip_prefix("# branch.oid ") {
        snapshot.head_commit = oid.trim().to_string();
        return;
    }
    if let Some(upstream) = line.strip_prefix("# branch.upstream ") {
        snapshot.upstream = Some(upstream.trim().to_string());
        return;
    }
    if let Some(ab) = line.strip_prefix("# branch.ab ") {
        for token in ab.split_whitespace() {
            if let Some(rest) = token.strip_prefix('+') {
                snapshot.ahead = rest.parse::<i64>().ok();
            } else if let Some(rest) = token.strip_prefix('-') {
                snapshot.behind = rest.parse::<i64>().ok();
            }
        }
        return;
    }
    if let Some(path) = line.strip_prefix("? ") {
        snapshot.entries.push(GitStatusEntry::Untracked {
            path: normalize_status_path(path),
        });
        return;
    }
    if let Some(rest) = line.strip_prefix("1 ") {
        parse_type_1(rest, snapshot);
        return;
    }
    if let Some(rest) = line.strip_prefix("2 ") {
        parse_type_2(rest, snapshot);
        return;
    }
    if let Some(rest) = line.strip_prefix("u ") {
        parse_unmerged(rest, snapshot);
    }
}

fn parse_type_1(rest: &str, snapshot: &mut GitStatusSnapshot) {
    let mut parts = rest.splitn(8, ' ');
    let xy = match parts.next() {
        Some(v) => v.to_string(),
        None => return,
    };
    for _ in 0..6 {
        if parts.next().is_none() {
            return;
        }
    }
    let path = match parts.next() {
        Some(v) => normalize_status_path(v),
        None => return,
    };
    snapshot.entries.push(GitStatusEntry::Tracked {
        xy,
        path,
        old_path: None,
    });
}

fn parse_type_2(rest: &str, snapshot: &mut GitStatusSnapshot) {
    let mut parts = rest.splitn(9, ' ');
    let xy = match parts.next() {
        Some(v) => v.to_string(),
        None => return,
    };
    for _ in 0..7 {
        if parts.next().is_none() {
            return;
        }
    }
    let path_pair = match parts.next() {
        Some(v) => v,
        None => return,
    };
    let (path_raw, old_raw) = match path_pair.split_once('\t') {
        Some((new_path, old_path)) => (new_path, Some(old_path)),
        None => (path_pair, None),
    };
    snapshot.entries.push(GitStatusEntry::Tracked {
        xy,
        path: normalize_status_path(path_raw),
        old_path: old_raw.map(normalize_status_path),
    });
}

fn parse_unmerged(rest: &str, snapshot: &mut GitStatusSnapshot) {
    let mut parts = rest.split_whitespace();
    let xy = match parts.next() {
        Some(v) => v.to_string(),
        None => return,
    };
    let path = match rest.split_whitespace().last() {
        Some(v) => normalize_status_path(v),
        None => return,
    };
    snapshot.entries.push(GitStatusEntry::Tracked {
        xy,
        path,
        old_path: None,
    });
}

fn normalize_status_path(path: &str) -> String {
    let trimmed = path.trim();
    let unquoted = if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        trimmed[1..trimmed.len() - 1].replace("\\\\", "\\")
    } else {
        trimmed.to_string()
    };
    unquoted.replace('\\', "/")
}

fn git_repo_toplevel(root: &Path, scope_id: &ScopeId) -> Result<String, ProviderError> {
    let output = Command::new("git")
        .arg("-C")
        .arg(path_for_git(root))
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|err| ProviderError {
            scope: scope_id.clone(),
            phase: ProviderPhase::Snapshot,
            message: format!("git rev-parse --show-toplevel failed: {}", err),
        })?;
    if !output.status.success() {
        return Err(ProviderError {
            scope: scope_id.clone(),
            phase: ProviderPhase::Snapshot,
            message: format!(
                "git rev-parse --show-toplevel failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        });
    }
    let path = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if path.is_empty() {
        return Err(ProviderError {
            scope: scope_id.clone(),
            phase: ProviderPhase::Snapshot,
            message: "git rev-parse --show-toplevel returned empty path".to_string(),
        });
    }
    Ok(normalize_status_path(&path))
}

fn status_entry_sort_key(entry: &GitStatusEntry) -> (u8, String, String, String) {
    match entry {
        GitStatusEntry::Tracked { xy, path, old_path } => (
            0,
            path.clone(),
            old_path.clone().unwrap_or_default(),
            xy.clone(),
        ),
        GitStatusEntry::Untracked { path } => (1, path.clone(), String::new(), String::new()),
    }
}

/// Minimal sort key for facts (mirrors other scope providers).
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

fn now_rfc3339() -> String {
    use std::time::SystemTime;
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}Z", dur.as_secs())
}

#[cfg(windows)]
fn path_for_git(path: &Path) -> std::path::PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        return std::path::PathBuf::from(stripped);
    }
    path.to_path_buf()
}

#[cfg(not(windows))]
fn path_for_git(path: &Path) -> std::path::PathBuf {
    path.to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git_available() -> bool {
        Command::new("git").arg("--version").output().is_ok()
    }

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("admit-scope-git-{}-{}", label, nanos));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn run_git(root: &Path, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .expect("run git");
        assert!(
            status.success(),
            "git command failed: git -C {:?} {:?}",
            root,
            args
        );
    }

    #[test]
    fn describe_returns_expected_scope() {
        let provider = GitWorkingTreeProvider::new();
        let desc = provider.describe();
        assert_eq!(desc.scope_id.0, GIT_WORKING_TREE_SCOPE_ID);
        assert!(desc.deterministic);
        assert!(desc.closure.requires_process);
        assert!(!desc.closure.requires_fs);
        assert_eq!(desc.schema_ids, vec![GIT_WORKING_TREE_SCHEMA_ID]);
    }

    #[test]
    fn snapshot_rejects_missing_root() {
        let provider = GitWorkingTreeProvider::new();
        let req = SnapshotRequest {
            scope_id: ScopeId(GIT_WORKING_TREE_SCOPE_ID.to_string()),
            params: serde_json::Value::Null,
        };
        let err = provider
            .snapshot(&req)
            .expect_err("missing root should fail");
        assert_eq!(err.phase, ProviderPhase::Snapshot);
        assert!(err.message.contains("params.root"));
    }

    #[test]
    fn snapshot_rejects_non_repo_root() {
        if !git_available() {
            return;
        }
        let root = temp_dir("non-repo");
        let provider = GitWorkingTreeProvider::new();
        let req = SnapshotRequest {
            scope_id: ScopeId(GIT_WORKING_TREE_SCOPE_ID.to_string()),
            params: serde_json::json!({ "root": root.to_string_lossy() }),
        };
        let err = provider.snapshot(&req).expect_err("non-repo should fail");
        assert_eq!(err.phase, ProviderPhase::Snapshot);
        assert!(
            err.message.contains("git rev-parse --show-toplevel failed")
                || err.message.contains("git status failed")
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn snapshot_emits_dirty_and_untracked_facts() {
        if !git_available() {
            return;
        }

        let root = temp_dir("dirty");
        run_git(&root, &["init", "-q"]);
        std::fs::write(root.join("tracked.txt"), "v1\n").expect("write tracked");
        run_git(&root, &["add", "tracked.txt"]);
        run_git(
            &root,
            &[
                "-c",
                "user.email=test@example.com",
                "-c",
                "user.name=Test",
                "commit",
                "-m",
                "init",
                "-q",
            ],
        );

        std::fs::write(root.join("tracked.txt"), "v2\n").expect("modify tracked");
        std::fs::write(root.join("new.txt"), "new\n").expect("write untracked");

        let provider = GitWorkingTreeProvider::new();
        let req = SnapshotRequest {
            scope_id: ScopeId(GIT_WORKING_TREE_SCOPE_ID.to_string()),
            params: serde_json::json!({
                "root": root.to_string_lossy(),
                "created_at": "2026-02-11T00:00:00Z"
            }),
        };
        let out = provider.snapshot(&req).expect("snapshot");

        assert_eq!(out.facts_bundle.created_at.0, "2026-02-11T00:00:00Z");
        assert!(out
            .facts_bundle
            .facts
            .iter()
            .any(|f| matches!(f, Fact::LintFinding { rule_id, .. } if rule_id == RULE_MODIFIED)));
        assert!(out
            .facts_bundle
            .facts
            .iter()
            .any(|f| matches!(f, Fact::LintFinding { rule_id, .. } if rule_id == RULE_UNTRACKED)));
        assert!(out.facts_bundle.facts.iter().any(|f| matches!(
            f,
            Fact::LintFinding { rule_id, evidence: Some(e), .. }
                if rule_id == RULE_DIRTY && e.get("dirty").and_then(|v| v.as_bool()) == Some(true)
        )));
        assert!(
            out.facts_bundle.facts.iter().any(|f| matches!(
                f,
                Fact::LintFinding { rule_id, evidence: Some(e), .. }
                    if rule_id == RULE_BRANCH
                        && e.get("head_commit").and_then(|v| v.as_str()).is_some()
                        && e.get("repo_toplevel").and_then(|v| v.as_str()).is_some()
                        && e.get("head_state").and_then(|v| v.as_str()).is_some()
            )),
            "expected branch fact with repo/head receipt fields"
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn dirty_state_predicate_uses_fact_input() {
        let provider = GitWorkingTreeProvider::new();
        let facts = vec![Fact::LintFinding {
            rule_id: RULE_UNTRACKED.to_string(),
            severity: Severity::Info,
            invariant: None,
            path: "new.txt".to_string(),
            span: Span {
                file: "new.txt".to_string(),
                start: None,
                end: None,
                line: None,
                col: None,
            },
            message: "untracked file".to_string(),
            evidence: None,
        }];
        let out = provider
            .eval_predicate("dirty_state", &serde_json::json!({ "facts": facts }))
            .expect("predicate");
        assert!(out.triggered);
        assert!(!out.findings.is_empty());
    }
}
