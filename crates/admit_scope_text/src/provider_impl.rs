//! Provider implementation for the `text.metrics` scope.
//!
//! Snapshot is pure filesystem observation with deterministic ordering.

use std::path::{Path, PathBuf};

use admit_core::provider_trait::Provider;
use admit_core::provider_types::*;
use admit_core::witness::{
    DisplacementMode, DisplacementTrace, Fact, Severity, Verdict, WitnessBuilder, WitnessProgram,
};
use admit_core::{ModuleId, ScopeId, Span};
use sha2::{Digest, Sha256};

use crate::backend::{TEXT_METRICS_SCHEMA_ID, TEXT_METRICS_SCOPE_ID};

const RULE_FILE_METRICS: &str = "text/file_metrics";
const RULE_TODO_COUNT: &str = "text/todo_count";
const RULE_LINES_EXCEED: &str = "text/lines_exceed";
const RULE_BYTES_EXCEED: &str = "text/bytes_exceed";
const RULE_LINE_LENGTH_EXCEED: &str = "text/line_length_exceed";
const RULE_TODO_PRESENT: &str = "text/todo_present";

#[derive(Debug, Clone)]
struct FileMetrics {
    path: String,
    bytes: u64,
    lines: u64,
    nonempty_lines: u64,
    max_line_len: u64,
    todo_count: u64,
}

/// Provider for deterministic text metrics extraction.
pub struct TextMetricsProvider;

impl TextMetricsProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for TextMetricsProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Provider for TextMetricsProvider {
    fn describe(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            scope_id: ScopeId(TEXT_METRICS_SCOPE_ID.to_string()),
            version: 1,
            schema_ids: vec![TEXT_METRICS_SCHEMA_ID.to_string()],
            supported_phases: vec![ProviderPhase::Describe, ProviderPhase::Snapshot],
            deterministic: true,
            closure: ClosureRequirements {
                requires_fs: true,
                ..ClosureRequirements::default()
            },
            required_approvals: vec![],
            predicates: vec![
                PredicateDescriptor {
                    name: "lines_exceed".to_string(),
                    doc: "Triggers for files where line count exceeds params.max_lines."
                        .to_string(),
                    param_schema: Some(serde_json::json!({
                        "type": "object",
                        "required": ["facts", "max_lines"],
                        "properties": {
                            "facts": { "type": "array" },
                            "max_lines": { "type": "integer", "minimum": 0 }
                        }
                    })),
                },
                PredicateDescriptor {
                    name: "bytes_exceed".to_string(),
                    doc: "Triggers for files where byte size exceeds params.max_bytes."
                        .to_string(),
                    param_schema: Some(serde_json::json!({
                        "type": "object",
                        "required": ["facts", "max_bytes"],
                        "properties": {
                            "facts": { "type": "array" },
                            "max_bytes": { "type": "integer", "minimum": 0 }
                        }
                    })),
                },
                PredicateDescriptor {
                    name: "line_length_exceed".to_string(),
                    doc: "Triggers for files where max line length exceeds params.max_line_len."
                        .to_string(),
                    param_schema: Some(serde_json::json!({
                        "type": "object",
                        "required": ["facts", "max_line_len"],
                        "properties": {
                            "facts": { "type": "array" },
                            "max_line_len": { "type": "integer", "minimum": 0 }
                        }
                    })),
                },
                PredicateDescriptor {
                    name: "todo_present".to_string(),
                    doc: "Triggers for files where TODO markers are present.".to_string(),
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
        let scope_id = ScopeId(TEXT_METRICS_SCOPE_ID.to_string());
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

        let paths = walk_files(root).map_err(|err| ProviderError {
            scope: scope_id.clone(),
            phase: ProviderPhase::Snapshot,
            message: err,
        })?;
        let mut metrics = Vec::with_capacity(paths.len());
        for path in &paths {
            let rel = to_rel_path(root, path).map_err(|err| ProviderError {
                scope: scope_id.clone(),
                phase: ProviderPhase::Snapshot,
                message: err,
            })?;
            let bytes = std::fs::read(path).map_err(|err| ProviderError {
                scope: scope_id.clone(),
                phase: ProviderPhase::Snapshot,
                message: format!("read file '{}': {}", rel, err),
            })?;
            metrics.push(compute_file_metrics(&rel, &bytes));
        }
        metrics.sort_by(|a, b| a.path.cmp(&b.path));

        let mut facts: Vec<Fact> = Vec::new();
        for metric in &metrics {
            facts.push(file_metrics_fact(metric));
            if metric.todo_count > 0 {
                facts.push(todo_count_fact(metric));
            }
        }
        facts.sort_by(|a, b| fact_sort_key(a).cmp(&fact_sort_key(b)));

        let facts_value = serde_json::to_value(&facts).map_err(|err| ProviderError {
            scope: scope_id.clone(),
            phase: ProviderPhase::Snapshot,
            message: format!("facts serialization failed: {}", err),
        })?;
        let cbor = admit_core::encode_canonical_value(&facts_value).map_err(|err| ProviderError {
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
            schema_id: TEXT_METRICS_SCHEMA_ID.to_string(),
            scope_id: scope_id.clone(),
            facts: facts.clone(),
            snapshot_hash,
            created_at: Rfc3339Timestamp::new(created_at),
        };

        let witness_program = WitnessProgram {
            module: ModuleId(format!("provider/{}", TEXT_METRICS_SCOPE_ID)),
            scope: scope_id,
            ruleset_id: None,
            ruleset_version: None,
            content_id: None,
            program_hash: None,
            snapshot_hash: Some(facts_bundle.snapshot_hash.0.clone()),
            facts_bundle_hash: None,
            ruleset_hash: None,
        };
        let witness = WitnessBuilder::new(witness_program, Verdict::Admissible, "snapshot complete")
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
        let scope_id = ScopeId(TEXT_METRICS_SCOPE_ID.to_string());
        let facts = decode_facts(params, &scope_id)?;
        let metrics = extract_metrics(&facts);

        match name {
            "lines_exceed" => {
                let max_lines = required_u64(params, "max_lines", &scope_id)?;
                let mut findings = Vec::new();
                for metric in &metrics {
                    if metric.lines > max_lines {
                        findings.push(metric_finding(
                            RULE_LINES_EXCEED,
                            metric,
                            format!("line count {} exceeds {}", metric.lines, max_lines),
                            Some(serde_json::json!({
                                "observed": metric.lines,
                                "threshold": max_lines
                            })),
                        ));
                    }
                }
                sort_findings(&mut findings);
                Ok(PredicateResult {
                    triggered: !findings.is_empty(),
                    findings,
                })
            }
            "bytes_exceed" => {
                let max_bytes = required_u64(params, "max_bytes", &scope_id)?;
                let mut findings = Vec::new();
                for metric in &metrics {
                    if metric.bytes > max_bytes {
                        findings.push(metric_finding(
                            RULE_BYTES_EXCEED,
                            metric,
                            format!("byte size {} exceeds {}", metric.bytes, max_bytes),
                            Some(serde_json::json!({
                                "observed": metric.bytes,
                                "threshold": max_bytes
                            })),
                        ));
                    }
                }
                sort_findings(&mut findings);
                Ok(PredicateResult {
                    triggered: !findings.is_empty(),
                    findings,
                })
            }
            "line_length_exceed" => {
                let max_line_len = required_u64(params, "max_line_len", &scope_id)?;
                let mut findings = Vec::new();
                for metric in &metrics {
                    if metric.max_line_len > max_line_len {
                        findings.push(metric_finding(
                            RULE_LINE_LENGTH_EXCEED,
                            metric,
                            format!(
                                "max line length {} exceeds {}",
                                metric.max_line_len, max_line_len
                            ),
                            Some(serde_json::json!({
                                "observed": metric.max_line_len,
                                "threshold": max_line_len
                            })),
                        ));
                    }
                }
                sort_findings(&mut findings);
                Ok(PredicateResult {
                    triggered: !findings.is_empty(),
                    findings,
                })
            }
            "todo_present" => {
                let mut findings = Vec::new();
                for metric in &metrics {
                    if metric.todo_count > 0 {
                        findings.push(metric_finding(
                            RULE_TODO_PRESENT,
                            metric,
                            format!("TODO markers present: {}", metric.todo_count),
                            Some(serde_json::json!({
                                "todo_count": metric.todo_count
                            })),
                        ));
                    }
                }
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

fn required_u64(
    params: &serde_json::Value,
    key: &str,
    scope_id: &ScopeId,
) -> Result<u64, ProviderError> {
    params
        .get(key)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| ProviderError {
            scope: scope_id.clone(),
            phase: ProviderPhase::Snapshot,
            message: format!("predicate requires params.{} (u64)", key),
        })
}

fn metric_finding(
    rule_id: &str,
    metric: &FileMetrics,
    message: String,
    extra_evidence: Option<serde_json::Value>,
) -> admit_core::LintFinding {
    let mut evidence = serde_json::json!({
        "bytes": metric.bytes,
        "lines": metric.lines,
        "nonempty_lines": metric.nonempty_lines,
        "max_line_len": metric.max_line_len,
        "todo_count": metric.todo_count,
    });
    if let (Some(extra), Some(base)) = (extra_evidence, evidence.as_object_mut()) {
        base.insert("detail".to_string(), extra);
    }
    admit_core::LintFinding {
        rule_id: rule_id.to_string(),
        severity: Severity::Error,
        invariant: Some("text.metrics".to_string()),
        path: metric.path.clone(),
        span: span_for_path(&metric.path),
        message,
        evidence: Some(evidence),
    }
}

fn extract_metrics(facts: &[Fact]) -> Vec<FileMetrics> {
    let mut out = Vec::new();
    for fact in facts {
        let Fact::LintFinding {
            rule_id,
            path,
            evidence: Some(evidence),
            ..
        } = fact
        else {
            continue;
        };
        if rule_id != RULE_FILE_METRICS {
            continue;
        }
        let Some(obj) = evidence.as_object() else {
            continue;
        };
        let to_u64 = |k: &str| obj.get(k).and_then(|v| v.as_u64()).unwrap_or(0);
        out.push(FileMetrics {
            path: path.clone(),
            bytes: to_u64("bytes"),
            lines: to_u64("lines"),
            nonempty_lines: to_u64("nonempty_lines"),
            max_line_len: to_u64("max_line_len"),
            todo_count: to_u64("todo_count"),
        });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

fn compute_file_metrics(path: &str, bytes: &[u8]) -> FileMetrics {
    let text = String::from_utf8_lossy(bytes);
    let mut lines: u64 = 0;
    let mut nonempty_lines: u64 = 0;
    let mut max_line_len: u64 = 0;
    let mut todo_count: u64 = 0;
    for line in text.lines() {
        lines += 1;
        if !line.trim().is_empty() {
            nonempty_lines += 1;
        }
        let len = line.chars().count() as u64;
        if len > max_line_len {
            max_line_len = len;
        }
        if line.contains("TODO") {
            todo_count += 1;
        }
    }
    if !text.is_empty() && text.ends_with('\n') && text.lines().count() == 0 {
        lines = 1;
    }
    FileMetrics {
        path: path.to_string(),
        bytes: bytes.len() as u64,
        lines,
        nonempty_lines,
        max_line_len,
        todo_count,
    }
}

fn file_metrics_fact(metric: &FileMetrics) -> Fact {
    Fact::LintFinding {
        rule_id: RULE_FILE_METRICS.to_string(),
        severity: Severity::Info,
        invariant: None,
        path: metric.path.clone(),
        span: span_for_path(&metric.path),
        message: "text file metrics".to_string(),
        evidence: Some(serde_json::json!({
            "bytes": metric.bytes,
            "lines": metric.lines,
            "nonempty_lines": metric.nonempty_lines,
            "max_line_len": metric.max_line_len,
            "todo_count": metric.todo_count,
        })),
    }
}

fn todo_count_fact(metric: &FileMetrics) -> Fact {
    Fact::LintFinding {
        rule_id: RULE_TODO_COUNT.to_string(),
        severity: Severity::Info,
        invariant: None,
        path: metric.path.clone(),
        span: span_for_path(&metric.path),
        message: format!("TODO markers: {}", metric.todo_count),
        evidence: Some(serde_json::json!({
            "todo_count": metric.todo_count
        })),
    }
}

fn walk_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir)
            .map_err(|err| format!("read_dir '{}': {}", dir.display(), err))?;
        for entry in entries {
            let entry = entry.map_err(|err| format!("read_dir entry: {}", err))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|err| format!("file_type '{}': {}", path.display(), err))?;
            if file_type.is_dir() {
                if should_skip_dir(&path) {
                    continue;
                }
                stack.push(path);
            } else if file_type.is_file() {
                files.push(path);
            }
        }
    }
    files.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
    Ok(files)
}

fn should_skip_dir(path: &Path) -> bool {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    matches!(
        name,
        ".git" | "target" | "out" | "node_modules" | ".venv" | ".mypy_cache" | "logs"
    )
}

fn to_rel_path(root: &Path, path: &Path) -> Result<String, String> {
    let rel = path
        .strip_prefix(root)
        .map_err(|err| format!("strip_prefix '{}': {}", path.display(), err))?;
    let mut out = Vec::new();
    for comp in rel.components() {
        let s = comp.as_os_str().to_str().ok_or_else(|| {
            format!(
                "non-utf8 path component under root: {}",
                path.display()
            )
        })?;
        out.push(s);
    }
    Ok(out.join("/"))
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
        Fact::LintFinding { .. } => 8,
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

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("admit-scope-text-{}-{}", label, nanos));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn describe_returns_expected_scope() {
        let provider = TextMetricsProvider::new();
        let desc = provider.describe();
        assert_eq!(desc.scope_id.0, TEXT_METRICS_SCOPE_ID);
        assert!(desc.deterministic);
        assert!(desc.closure.requires_fs);
        assert_eq!(desc.schema_ids, vec![TEXT_METRICS_SCHEMA_ID]);
    }

    #[test]
    fn snapshot_rejects_missing_root() {
        let provider = TextMetricsProvider::new();
        let req = SnapshotRequest {
            scope_id: ScopeId(TEXT_METRICS_SCOPE_ID.to_string()),
            params: serde_json::Value::Null,
        };
        let err = provider.snapshot(&req).expect_err("missing root should fail");
        assert_eq!(err.phase, ProviderPhase::Snapshot);
        assert!(err.message.contains("params.root"));
    }

    #[test]
    fn snapshot_emits_file_metrics() {
        let root = temp_dir("snapshot");
        std::fs::write(root.join("a.txt"), "one\nTODO two\nthree\n").expect("write file");
        let provider = TextMetricsProvider::new();
        let req = SnapshotRequest {
            scope_id: ScopeId(TEXT_METRICS_SCOPE_ID.to_string()),
            params: serde_json::json!({
                "root": root.to_string_lossy(),
                "created_at": "2026-02-11T00:00:00Z"
            }),
        };
        let out = provider.snapshot(&req).expect("snapshot");
        assert_eq!(out.facts_bundle.created_at.0, "2026-02-11T00:00:00Z");
        assert!(
            out.facts_bundle
                .facts
                .iter()
                .any(|f| matches!(f, Fact::LintFinding { rule_id, .. } if rule_id == RULE_FILE_METRICS))
        );
        assert!(
            out.facts_bundle
                .facts
                .iter()
                .any(|f| matches!(f, Fact::LintFinding { rule_id, .. } if rule_id == RULE_TODO_COUNT))
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn lines_exceed_predicate_uses_fact_input() {
        let provider = TextMetricsProvider::new();
        let facts = vec![Fact::LintFinding {
            rule_id: RULE_FILE_METRICS.to_string(),
            severity: Severity::Info,
            invariant: None,
            path: "src/lib.rs".to_string(),
            span: span_for_path("src/lib.rs"),
            message: "text file metrics".to_string(),
            evidence: Some(serde_json::json!({
                "bytes": 120,
                "lines": 12,
                "nonempty_lines": 11,
                "max_line_len": 40,
                "todo_count": 0
            })),
        }];
        let out = provider
            .eval_predicate(
                "lines_exceed",
                &serde_json::json!({
                    "facts": facts,
                    "max_lines": 10
                }),
            )
            .expect("predicate");
        assert!(out.triggered);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].rule_id, RULE_LINES_EXCEED);
    }

    #[test]
    fn todo_present_predicate_triggers() {
        let provider = TextMetricsProvider::new();
        let facts = vec![Fact::LintFinding {
            rule_id: RULE_FILE_METRICS.to_string(),
            severity: Severity::Info,
            invariant: None,
            path: "src/lib.rs".to_string(),
            span: span_for_path("src/lib.rs"),
            message: "text file metrics".to_string(),
            evidence: Some(serde_json::json!({
                "bytes": 120,
                "lines": 12,
                "nonempty_lines": 11,
                "max_line_len": 40,
                "todo_count": 2
            })),
        }];
        let out = provider
            .eval_predicate("todo_present", &serde_json::json!({ "facts": facts }))
            .expect("predicate");
        assert!(out.triggered);
        assert_eq!(out.findings.len(), 1);
        assert_eq!(out.findings[0].rule_id, RULE_TODO_PRESENT);
    }
}
