//! Provider implementation for the `rust.structure` scope.
//!
//! Implements `describe()` + `snapshot()` using `syn`-based structural fact
//! extraction. Plan/execute/verify use default stubs.

use std::path::Path;

use admit_core::provider_trait::Provider;
use admit_core::provider_types::*;
use admit_core::witness::{
    DisplacementMode, DisplacementTrace, Fact, Severity, Verdict, WitnessBuilder, WitnessProgram,
};
use admit_core::{ModuleId, ScopeId};

use crate::backend::{RUST_SCOPE_ID, RUST_STRUCTURE_SCHEMA_ID};
use crate::extractor::extract_facts;
use crate::file_walker::{load_rust_sources, sha256_hex};

/// Provider for Rust structural analysis. Pure filesystem observation — no DB, no network.
pub struct RustStructureProvider;

impl RustStructureProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for RustStructureProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl Provider for RustStructureProvider {
    fn describe(&self) -> ProviderDescriptor {
        ProviderDescriptor {
            scope_id: ScopeId(RUST_SCOPE_ID.to_string()),
            version: 1,
            schema_ids: vec![RUST_STRUCTURE_SCHEMA_ID.to_string()],
            supported_phases: vec![ProviderPhase::Describe, ProviderPhase::Snapshot],
            deterministic: true,
            closure: ClosureRequirements {
                requires_fs: true,
                ..ClosureRequirements::default()
            },
            required_approvals: vec![],
            predicates: vec![PredicateDescriptor {
                name: "unsafe_without_justification".to_string(),
                doc: "Flags rust/unsafe_block facts without matching justification facts."
                    .to_string(),
                param_schema: Some(serde_json::json!({
                    "type": "object",
                    "required": ["facts"],
                    "properties": {
                        "facts": { "type": "array" },
                        "justification_rule_id": { "type": "string" }
                    }
                })),
            }],
        }
    }

    fn snapshot(&self, req: &SnapshotRequest) -> Result<SnapshotResult, ProviderError> {
        let scope_id = ScopeId(RUST_SCOPE_ID.to_string());

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
        if !root.exists() {
            return Err(ProviderError {
                scope: scope_id.clone(),
                phase: ProviderPhase::Snapshot,
                message: format!("root path does not exist: {}", root_str),
            });
        }

        let files = load_rust_sources(root).map_err(|e| ProviderError {
            scope: scope_id.clone(),
            phase: ProviderPhase::Snapshot,
            message: format!("load_rust_sources failed: {}", e),
        })?;

        let mut facts: Vec<Fact> = Vec::new();
        for file in &files {
            facts.extend(extract_facts(file));
        }

        // Sort facts for deterministic hashing.
        facts.sort_by_key(fact_sort_key);

        // Compute snapshot hash via canonical CBOR (RFC 8949), not JSON.
        let facts_value = serde_json::to_value(&facts).map_err(|e| ProviderError {
            scope: scope_id.clone(),
            phase: ProviderPhase::Snapshot,
            message: format!("facts serialization failed: {}", e),
        })?;
        let cbor_bytes =
            admit_core::encode_canonical_value(&facts_value).map_err(|e| ProviderError {
                scope: scope_id.clone(),
                phase: ProviderPhase::Snapshot,
                message: format!("canonical CBOR encoding failed: {}", e),
            })?;
        let snapshot_hash = Sha256Hex::new(sha256_hex(&cbor_bytes));

        let now = now_rfc3339();

        let facts_bundle = FactsBundle {
            schema_id: RUST_STRUCTURE_SCHEMA_ID.to_string(),
            scope_id: scope_id.clone(),
            facts: facts.clone(),
            snapshot_hash,
            created_at: Rfc3339Timestamp::new(now),
        };

        // Build a minimal witness for the snapshot.
        let witness_program = WitnessProgram {
            module: ModuleId(format!("provider/{}", RUST_SCOPE_ID)),
            scope: scope_id,
            ruleset_id: None,
            ruleset_version: None,
            content_id: None,
            program_hash: None,
            snapshot_hash: Some(facts_bundle.snapshot_hash.0.clone()),
            facts_bundle_hash: None,
            ruleset_hash: None,
        };

        // Snapshot is observation, not judgment — always admissible.
        let witness = WitnessBuilder::new(
            witness_program,
            Verdict::Admissible,
            "structural snapshot complete",
        )
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
        let scope_id = ScopeId(RUST_SCOPE_ID.to_string());
        match name {
            "unsafe_without_justification" => {
                let facts_value = params.get("facts").cloned().ok_or_else(|| ProviderError {
                    scope: scope_id.clone(),
                    phase: ProviderPhase::Snapshot,
                    message: "unsafe_without_justification requires params.facts".to_string(),
                })?;
                let facts: Vec<Fact> =
                    serde_json::from_value(facts_value).map_err(|err| ProviderError {
                        scope: scope_id.clone(),
                        phase: ProviderPhase::Snapshot,
                        message: format!("decode params.facts: {}", err),
                    })?;
                let justification_rule = params
                    .get("justification_rule_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("rust/unsafe_justification");

                let mut justified_keys = std::collections::BTreeSet::new();
                for fact in &facts {
                    if let Fact::LintFinding {
                        rule_id,
                        path,
                        span,
                        ..
                    } = fact
                    {
                        if rule_id == justification_rule {
                            justified_keys.insert((path.clone(), span.line.unwrap_or(0)));
                        }
                    }
                }

                let mut findings = Vec::new();
                for fact in &facts {
                    if let Fact::LintFinding {
                        rule_id,
                        path,
                        span,
                        message,
                        evidence,
                        ..
                    } = fact
                    {
                        if rule_id != "rust/unsafe_block" {
                            continue;
                        }
                        let key = (path.clone(), span.line.unwrap_or(0));
                        if justified_keys.contains(&key) {
                            continue;
                        }
                        let file_sha = evidence
                            .as_ref()
                            .and_then(|v| v.get("file_sha256"))
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();
                        findings.push(admit_core::LintFinding {
                            rule_id: "rust/unsafe_without_justification".to_string(),
                            severity: Severity::Error,
                            invariant: Some("governance".to_string()),
                            path: path.clone(),
                            span: span.clone(),
                            message: format!("unsafe usage without justification: {}", message),
                            evidence: Some(serde_json::json!({
                                "source_rule_id": rule_id,
                                "file_sha256": file_sha
                            })),
                        });
                    }
                }
                findings.sort_by(|a, b| {
                    a.path
                        .cmp(&b.path)
                        .then(a.span.line.unwrap_or(0).cmp(&b.span.line.unwrap_or(0)))
                        .then(a.span.col.unwrap_or(0).cmp(&b.span.col.unwrap_or(0)))
                        .then(a.message.cmp(&b.message))
                });
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

/// Minimal sort key for facts (mirrors admit_scope_ingest pattern).
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn describe_returns_correct_scope() {
        let p = RustStructureProvider::new();
        let desc = p.describe();
        assert_eq!(desc.scope_id.0, RUST_SCOPE_ID);
        assert_eq!(desc.version, 1);
        assert!(desc.deterministic);
        assert!(desc.closure.requires_fs);
        assert!(!desc.closure.requires_process);
        assert!(!desc.closure.requires_db);
        assert!(!desc.closure.requires_network);
        assert!(desc.supported_phases.contains(&ProviderPhase::Describe));
        assert!(desc.supported_phases.contains(&ProviderPhase::Snapshot));
        assert_eq!(desc.schema_ids, vec![RUST_STRUCTURE_SCHEMA_ID]);
    }

    #[test]
    fn snapshot_rejects_missing_root() {
        let p = RustStructureProvider::new();
        let req = SnapshotRequest {
            scope_id: ScopeId(RUST_SCOPE_ID.into()),
            params: serde_json::json!({}),
        };
        let err = p.snapshot(&req).unwrap_err();
        assert_eq!(err.phase, ProviderPhase::Snapshot);
        assert!(err.message.contains("params.root"));
    }

    #[test]
    fn snapshot_rejects_nonexistent_root() {
        let p = RustStructureProvider::new();
        let req = SnapshotRequest {
            scope_id: ScopeId(RUST_SCOPE_ID.into()),
            params: serde_json::json!({ "root": "/nonexistent/path/that/does/not/exist" }),
        };
        let err = p.snapshot(&req).unwrap_err();
        assert_eq!(err.phase, ProviderPhase::Snapshot);
        assert!(err.message.contains("does not exist"));
    }

    #[test]
    fn snapshot_produces_facts_from_rust_files() {
        let dir = temp_dir("snapshot");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(
            dir.join("src/lib.rs"),
            "pub fn hello() {}\npub struct Foo { x: i32 }\n",
        )
        .unwrap();

        let p = RustStructureProvider::new();
        let req = SnapshotRequest {
            scope_id: ScopeId(RUST_SCOPE_ID.into()),
            params: serde_json::json!({ "root": dir.to_str().unwrap() }),
        };
        let result = p.snapshot(&req).unwrap();

        assert_eq!(result.facts_bundle.schema_id, RUST_STRUCTURE_SCHEMA_ID);
        assert_eq!(result.facts_bundle.scope_id.0, RUST_SCOPE_ID);
        assert!(!result.facts_bundle.facts.is_empty());
        assert!(!result.facts_bundle.snapshot_hash.0.is_empty());
        assert_eq!(result.witness.verdict, Verdict::Admissible);
    }

    #[test]
    fn default_plan_returns_error() {
        let p = RustStructureProvider::new();
        let err = p
            .plan(
                &PlanIntent {
                    scope_id: ScopeId(RUST_SCOPE_ID.into()),
                    description: "test".into(),
                    params: serde_json::Value::Null,
                },
                &[],
            )
            .unwrap_err();
        assert_eq!(err.phase, ProviderPhase::Plan);
    }

    #[test]
    fn default_execute_returns_error() {
        let p = RustStructureProvider::new();
        let err = p
            .execute(&PlanRef {
                plan_hash: Sha256Hex::new("abc"),
                approval_witness_hash: None,
            })
            .unwrap_err();
        assert_eq!(err.phase, ProviderPhase::Execute);
    }

    #[test]
    fn default_verify_returns_error() {
        let p = RustStructureProvider::new();
        let err = p
            .verify(&VerifyRequest {
                artifact_hash: Sha256Hex::new("abc"),
                schema_id: "test".into(),
                scope_id: ScopeId(RUST_SCOPE_ID.into()),
            })
            .unwrap_err();
        assert_eq!(err.phase, ProviderPhase::Verify);
    }

    #[test]
    fn unsafe_without_justification_uses_fact_input() {
        let p = RustStructureProvider::new();
        let facts = vec![Fact::LintFinding {
            rule_id: "rust/unsafe_block".to_string(),
            severity: Severity::Info,
            invariant: None,
            path: "src/lib.rs".to_string(),
            span: admit_core::Span {
                file: "src/lib.rs".to_string(),
                start: None,
                end: None,
                line: Some(12),
                col: Some(3),
            },
            message: "unsafe block in x".to_string(),
            evidence: Some(serde_json::json!({ "file_sha256": "abc" })),
        }];
        let out = p
            .eval_predicate(
                "unsafe_without_justification",
                &serde_json::json!({ "facts": facts }),
            )
            .expect("predicate");
        assert!(out.triggered);
        assert_eq!(out.findings.len(), 1);
    }

    #[test]
    fn unsafe_without_justification_ignores_justified_fact() {
        let p = RustStructureProvider::new();
        let facts = vec![
            Fact::LintFinding {
                rule_id: "rust/unsafe_block".to_string(),
                severity: Severity::Info,
                invariant: None,
                path: "src/lib.rs".to_string(),
                span: admit_core::Span {
                    file: "src/lib.rs".to_string(),
                    start: None,
                    end: None,
                    line: Some(12),
                    col: Some(3),
                },
                message: "unsafe block in x".to_string(),
                evidence: Some(serde_json::json!({ "file_sha256": "abc" })),
            },
            Fact::LintFinding {
                rule_id: "rust/unsafe_justification".to_string(),
                severity: Severity::Info,
                invariant: None,
                path: "src/lib.rs".to_string(),
                span: admit_core::Span {
                    file: "src/lib.rs".to_string(),
                    start: None,
                    end: None,
                    line: Some(12),
                    col: Some(3),
                },
                message: "justified".to_string(),
                evidence: Some(serde_json::json!({ "file_sha256": "abc" })),
            },
        ];
        let out = p
            .eval_predicate(
                "unsafe_without_justification",
                &serde_json::json!({ "facts": facts }),
            )
            .expect("predicate");
        assert!(!out.triggered);
        assert!(out.findings.is_empty());
    }

    fn temp_dir(label: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("admit-scope-rust-provider-{}-{}", label, nanos))
    }
}
