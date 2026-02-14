//! Provider implementation for the `ingest.dir` scope.
//!
//! Implements `describe()` + `snapshot()` using existing pure functions
//! (`walk_files`, `chunk_file_by_format`). Plan/execute/verify use default stubs.

use std::path::Path;

use admit_core::provider_trait::Provider;
use admit_core::provider_types::*;
use admit_core::witness::{
    DisplacementMode, DisplacementTrace, Fact, Severity, Verdict, WitnessBuilder, WitnessProgram,
};
use admit_core::{ModuleId, ScopeId, Span};

use crate::backend::INGEST_DIR_SCOPE_ID;
use crate::{
    chunk_file_by_format, infer_format_from_path, is_chunked_text_format, sha256_hex, to_rel_path,
    walk_files,
};

/// Provider for directory ingestion. Pure filesystem observation — no DB, no network.
pub struct IngestDirProvider;

impl IngestDirProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for IngestDirProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Provider for IngestDirProvider {
    fn describe(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            scope_id: ScopeId(INGEST_DIR_SCOPE_ID.to_string()),
            version: 1,
            schema_ids: vec![format!("facts-bundle/{}@1", INGEST_DIR_SCOPE_ID)],
            supported_phases: vec![ProviderPhase::Describe, ProviderPhase::Snapshot],
            deterministic: true,
            closure: ClosureRequirements {
                requires_fs: true,
                requires_process: true, // git ls-files
                ..ClosureRequirements::default()
            },
            required_approvals: vec![],
            predicates: vec![PredicateDescriptor {
                predicate_id: "ingest.dir/missing_path@1".to_string(),
                name: "missing_path".to_string(),
                doc: "Triggers when params.path does not exist.".to_string(),
                result_kind: PredicateResultKind::Bool,
                emits_findings: true,
                param_schema: Some(serde_json::json!({
                    "type": "object",
                    "required": ["path"],
                    "properties": {
                        "path": { "type": "string" }
                    }
                })),
                evidence_schema: None,
            }],
        }
    }

    fn snapshot(&self, req: &SnapshotRequest) -> Result<SnapshotResult, ProviderError> {
        let scope_id = ScopeId(INGEST_DIR_SCOPE_ID.to_string());

        let root_str = req
            .params
            .get("root")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ProviderError {
                scope: scope_id.clone(),
                phase: ProviderPhase::Snapshot,
                message: "params.root (string) is required".into(),
            })?;

        let root = Path::new(root_str);
        if !root.is_dir() {
            return Err(ProviderError {
                scope: scope_id.clone(),
                phase: ProviderPhase::Snapshot,
                message: format!("root path is not a directory: {}", root_str),
            });
        }

        let walk = walk_files(root).map_err(|e| ProviderError {
            scope: scope_id.clone(),
            phase: ProviderPhase::Snapshot,
            message: format!("walk_files failed: {}", e),
        })?;

        let mut facts: Vec<Fact> = Vec::new();

        // Emit lint findings for walk warnings.
        for w in &walk.warnings {
            facts.push(Fact::LintFinding {
                rule_id: format!("ingest/{}", w.kind),
                severity: Severity::Warning,
                invariant: None,
                path: w.rel_path.clone().unwrap_or_default(),
                span: Span {
                    file: w.rel_path.clone().unwrap_or_default(),
                    start: None,
                    end: None,
                    line: None,
                    col: None,
                },
                message: w.message.clone(),
                evidence: None,
            });
        }

        // Process each file: hash + chunk.
        for path in &walk.paths {
            let rel = to_rel_path(root, path).map_err(|e| ProviderError {
                scope: scope_id.clone(),
                phase: ProviderPhase::Snapshot,
                message: e,
            })?;

            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(e) => {
                    facts.push(Fact::LintFinding {
                        rule_id: "ingest/read_error".to_string(),
                        severity: Severity::Warning,
                        invariant: None,
                        path: rel.clone(),
                        span: Span {
                            file: rel.clone(),
                            start: None,
                            end: None,
                            line: None,
                            col: None,
                        },
                        message: format!("could not read file: {}", e),
                        evidence: None,
                    });
                    continue;
                }
            };

            let ext = infer_format_from_path(&rel);
            if !is_chunked_text_format(&ext) {
                continue;
            }

            match chunk_file_by_format(&rel, &ext, &content) {
                Ok(chunks) => {
                    for chunk in &chunks {
                        let chunk_hash = sha256_hex(chunk.text.as_bytes());
                        facts.push(Fact::LintFinding {
                            rule_id: "ingest/chunk".to_string(),
                            severity: Severity::Info,
                            invariant: None,
                            path: rel.clone(),
                            span: Span {
                                file: rel.clone(),
                                start: None,
                                end: None,
                                line: Some(chunk.start_line),
                                col: None,
                            },
                            message: format!(
                                "chunk {} L{}-L{} ({} bytes)",
                                chunk.chunk_kind,
                                chunk.start_line,
                                chunk.end_line,
                                chunk.text.len()
                            ),
                            evidence: Some(serde_json::json!({
                                "chunk_sha256": chunk_hash,
                                "format": chunk.format,
                                "chunk_kind": chunk.chunk_kind,
                            })),
                        });
                    }
                }
                Err(e) => {
                    facts.push(Fact::LintFinding {
                        rule_id: "ingest/chunk_error".to_string(),
                        severity: Severity::Warning,
                        invariant: None,
                        path: rel.clone(),
                        span: Span {
                            file: rel.clone(),
                            start: None,
                            end: None,
                            line: None,
                            col: None,
                        },
                        message: format!("chunking failed: {}", e),
                        evidence: None,
                    });
                }
            }
        }

        // Sort facts for deterministic hashing.
        facts.sort_by(|a, b| fact_sort_key(a).cmp(&fact_sort_key(b)));

        // Compute snapshot hash from canonical JSON of facts.
        let facts_json = serde_json::to_vec(&facts).map_err(|e| ProviderError {
            scope: scope_id.clone(),
            phase: ProviderPhase::Snapshot,
            message: format!("facts serialization failed: {}", e),
        })?;
        let snapshot_hash = Sha256Hex::new(sha256_hex(&facts_json));

        let created_at = req
            .params
            .get("created_at")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(now_rfc3339);

        let facts_bundle = FactsBundle {
            schema_id: format!("facts-bundle/{}@1", INGEST_DIR_SCOPE_ID),
            scope_id: scope_id.clone(),
            facts: facts.clone(),
            snapshot_hash,
            created_at: Rfc3339Timestamp::new(created_at),
        };

        // Build a minimal witness for the snapshot.
        let witness_program = WitnessProgram {
            module: ModuleId(format!("provider/{}", INGEST_DIR_SCOPE_ID)),
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
        _ctx: &PredicateEvalContext,
    ) -> Result<PredicateResult, ProviderError> {
        let scope_id = ScopeId(INGEST_DIR_SCOPE_ID.to_string());
        match name {
            "missing_path" => {
                let path =
                    params
                        .get("path")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| ProviderError {
                            scope: scope_id.clone(),
                            phase: ProviderPhase::Snapshot,
                            message: "missing_path requires params.path (string)".to_string(),
                        })?;
                let missing = !Path::new(path).exists();
                let findings = if missing {
                    vec![admit_core::LintFinding {
                        rule_id: "ingest/missing_path".to_string(),
                        severity: Severity::Error,
                        invariant: None,
                        path: path.to_string(),
                        span: Span {
                            file: path.to_string(),
                            start: None,
                            end: None,
                            line: None,
                            col: None,
                        },
                        message: format!("required path does not exist: {}", path),
                        evidence: None,
                    }]
                } else {
                    vec![]
                };
                Ok(PredicateResult {
                    triggered: missing,
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

/// Minimal sort key for facts (mirrors admit_core::witness::fact_sort_key logic).
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
    // Use a simple approach without pulling in chrono.
    // In production, the CLI would pass a proper timestamp.
    // For now, use a fixed format from SystemTime.
    use std::time::SystemTime;
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // Rough UTC formatting: sufficient for snapshot identification.
    format!("{}Z", secs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_test_dir(prefix: &str) -> PathBuf {
        let mut dir = std::env::temp_dir();
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        dir.push(format!("{}_{}", prefix, nanos));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn describe_returns_correct_scope() {
        let p = IngestDirProvider::new();
        let desc = p.describe();
        assert_eq!(desc.scope_id.0, INGEST_DIR_SCOPE_ID);
        assert_eq!(desc.version, 1);
        assert!(desc.deterministic);
        assert!(desc.closure.requires_fs);
        assert!(desc.closure.requires_process);
        assert!(!desc.closure.requires_db);
        assert!(!desc.closure.requires_network);
        assert!(desc.supported_phases.contains(&ProviderPhase::Describe));
        assert!(desc.supported_phases.contains(&ProviderPhase::Snapshot));
    }

    #[test]
    fn snapshot_rejects_missing_root() {
        let p = IngestDirProvider::new();
        let req = SnapshotRequest {
            scope_id: ScopeId(INGEST_DIR_SCOPE_ID.into()),
            params: serde_json::json!({}),
        };
        let err = p.snapshot(&req).unwrap_err();
        assert_eq!(err.phase, ProviderPhase::Snapshot);
        assert!(err.message.contains("params.root"));
    }

    #[test]
    fn snapshot_rejects_nonexistent_root() {
        let p = IngestDirProvider::new();
        let req = SnapshotRequest {
            scope_id: ScopeId(INGEST_DIR_SCOPE_ID.into()),
            params: serde_json::json!({ "root": "/nonexistent/path/that/does/not/exist" }),
        };
        let err = p.snapshot(&req).unwrap_err();
        assert_eq!(err.phase, ProviderPhase::Snapshot);
        assert!(err.message.contains("not a directory"));
    }

    #[test]
    fn default_plan_returns_error() {
        let p = IngestDirProvider::new();
        let err = p
            .plan(
                &PlanIntent {
                    scope_id: ScopeId(INGEST_DIR_SCOPE_ID.into()),
                    description: "test".into(),
                    params: serde_json::Value::Null,
                },
                &[],
            )
            .unwrap_err();
        assert_eq!(err.phase, ProviderPhase::Plan);
    }

    #[test]
    fn missing_path_predicate_triggers_when_absent() {
        let p = IngestDirProvider::new();
        let out = p
            .eval_predicate(
                "missing_path",
                &serde_json::json!({ "path": "/definitely/not/here" }),
                &PredicateEvalContext::default(),
            )
            .expect("predicate");
        assert!(out.triggered);
        assert!(!out.findings.is_empty());
    }

    #[test]
    fn missing_path_predicate_passes_when_present() {
        let root = temp_test_dir("ingest_provider_predicate");
        let p = IngestDirProvider::new();
        let out = p
            .eval_predicate(
                "missing_path",
                &serde_json::json!({ "path": root.to_string_lossy() }),
                &PredicateEvalContext::default(),
            )
            .expect("predicate");
        assert!(!out.triggered);
        assert!(out.findings.is_empty());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn snapshot_respects_created_at_override() {
        let root = temp_test_dir("ingest_provider_snapshot");
        let file_path = root.join("note.md");
        fs::write(&file_path, "# Title\n\ncontent\n").expect("write test file");

        let p = IngestDirProvider::new();
        let req = SnapshotRequest {
            scope_id: ScopeId(INGEST_DIR_SCOPE_ID.into()),
            params: serde_json::json!({
                "root": root.to_string_lossy(),
                "created_at": "2026-02-11T00:00:00Z"
            }),
        };
        let out = p.snapshot(&req).expect("snapshot");
        assert_eq!(out.facts_bundle.created_at.0, "2026-02-11T00:00:00Z");
        assert_eq!(
            out.witness.program.snapshot_hash.as_deref(),
            Some(out.facts_bundle.snapshot_hash.as_str())
        );

        let _ = fs::remove_dir_all(root);
    }
}
