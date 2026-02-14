use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::error::EvalError;
use crate::ir::LintFailOn;
use crate::provider_registry::ProviderRegistry;
use crate::provider_types::FactsBundle;
use crate::span::Span;
use crate::symbols::{ModuleId, ScopeId};
use crate::witness::{
    DisplacementMode, DisplacementTrace, Fact, Severity, Verdict, Witness, WitnessBuilder,
    WitnessProgram,
};

pub const RULESET_SCHEMA_ID_V1: &str = "ruleset/admit@1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RulePredicateBinding {
    pub scope_id: ScopeId,
    pub predicate: String,
    #[serde(default)]
    pub params: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleBinding {
    pub rule_id: String,
    #[serde(default = "default_severity_error")]
    pub severity: Severity,
    pub when: RulePredicateBinding,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleSet {
    pub schema_id: String,
    pub ruleset_id: String,
    #[serde(default)]
    pub enabled_rules: Vec<String>,
    #[serde(default)]
    pub bindings: Vec<RuleBinding>,
    #[serde(default = "default_fail_on_error")]
    pub fail_on: LintFailOn,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub module: Option<ModuleId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<ScopeId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleResult {
    pub rule_id: String,
    pub severity: Severity,
    pub triggered: bool,
    pub findings_count: usize,
    pub scope_id: ScopeId,
    pub predicate: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RuleEvaluationOutcome {
    pub ruleset_hash: String,
    pub rule_results: Vec<RuleResult>,
    pub witness: Witness,
}

fn default_fail_on_error() -> LintFailOn {
    LintFailOn::Error
}

fn default_severity_error() -> Severity {
    Severity::Error
}

fn severity_rank(severity: &Severity) -> u8 {
    match severity {
        Severity::Info => 0,
        Severity::Warning => 1,
        Severity::Error => 2,
    }
}

fn severity_meets_fail_on(severity: &Severity, fail_on: &LintFailOn) -> bool {
    match fail_on {
        LintFailOn::Error => matches!(severity, Severity::Error),
        LintFailOn::Warning => matches!(severity, Severity::Error | Severity::Warning),
        LintFailOn::Info => true,
    }
}

fn ruleset_span(ruleset_id: &str, rule_id: &str) -> Span {
    Span {
        file: format!("ruleset:{}#{}", ruleset_id, rule_id),
        start: None,
        end: None,
        line: None,
        col: None,
    }
}

pub fn canonical_ruleset_hash(ruleset: &RuleSet) -> Result<String, EvalError> {
    let value = serde_json::to_value(ruleset)
        .map_err(|err| EvalError(format!("ruleset encode: {}", err)))?;
    let bytes = crate::encode_canonical_value(&value)?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    Ok(format!("{:x}", hasher.finalize()))
}

pub fn evaluate_ruleset(
    ruleset: &RuleSet,
    registry: &ProviderRegistry,
) -> Result<RuleEvaluationOutcome, EvalError> {
    evaluate_ruleset_with_inputs(ruleset, registry, None, None)
}

pub fn evaluate_ruleset_with_inputs(
    ruleset: &RuleSet,
    registry: &ProviderRegistry,
    input_bundles: Option<&BTreeMap<ScopeId, FactsBundle>>,
    runtime_overlays: Option<&BTreeMap<String, Value>>,
) -> Result<RuleEvaluationOutcome, EvalError> {
    if ruleset.schema_id != RULESET_SCHEMA_ID_V1 {
        return Err(EvalError(format!(
            "unsupported ruleset schema_id '{}', expected '{}'",
            ruleset.schema_id, RULESET_SCHEMA_ID_V1
        )));
    }

    let enabled: BTreeSet<&str> = if ruleset.enabled_rules.is_empty() {
        ruleset
            .bindings
            .iter()
            .map(|b| b.rule_id.as_str())
            .collect()
    } else {
        ruleset.enabled_rules.iter().map(|r| r.as_str()).collect()
    };

    let mut selected: Vec<RuleBinding> = ruleset
        .bindings
        .iter()
        .filter(|binding| enabled.contains(binding.rule_id.as_str()))
        .cloned()
        .collect();
    selected.sort_by(|a, b| {
        let pa = serde_json::to_string(&a.when.params).unwrap_or_default();
        let pb = serde_json::to_string(&b.when.params).unwrap_or_default();
        a.rule_id
            .cmp(&b.rule_id)
            .then(severity_rank(&a.severity).cmp(&severity_rank(&b.severity)))
            .then(a.when.scope_id.0.cmp(&b.when.scope_id.0))
            .then(a.when.predicate.cmp(&b.when.predicate))
            .then(pa.cmp(&pb))
    });

    let mut rule_results: Vec<RuleResult> = Vec::with_capacity(selected.len());
    let mut facts: Vec<Fact> = Vec::new();
    let mut failed = false;

    for binding in selected {
        let provider = registry.get(&binding.when.scope_id).ok_or_else(|| {
            EvalError(format!(
                "ruleset binding '{}' references unregistered scope '{}'",
                binding.rule_id, binding.when.scope_id.0
            ))
        })?;
        let mut effective_params = binding.when.params.clone();
        if let Some(bundles) = input_bundles {
            if let Some(bundle) = bundles.get(&binding.when.scope_id) {
                let mut obj = match effective_params {
                    Value::Object(map) => map,
                    Value::Null => serde_json::Map::new(),
                    other => {
                        let mut map = serde_json::Map::new();
                        map.insert("value".to_string(), other);
                        map
                    }
                };
                obj.entry("facts".to_string()).or_insert(
                    serde_json::to_value(&bundle.facts).map_err(|err| {
                        EvalError(format!("ruleset params encode facts: {}", err))
                    })?,
                );
                obj.entry("snapshot_hash".to_string())
                    .or_insert(Value::String(bundle.snapshot_hash.0.clone()));
                obj.entry("facts_schema_id".to_string())
                    .or_insert(Value::String(bundle.schema_id.clone()));
                effective_params = Value::Object(obj);
            }
        }
        // Merge runtime overlays keyed by rule_id (e.g., injected changed_paths).
        if let Some(overlays) = runtime_overlays {
            if let Some(overlay) = overlays.get(&binding.rule_id) {
                if let Value::Object(overlay_obj) = overlay {
                    let obj = match &mut effective_params {
                        Value::Object(map) => map,
                        other => {
                            let mut map = serde_json::Map::new();
                            if !other.is_null() {
                                map.insert(
                                    "value".to_string(),
                                    std::mem::replace(other, Value::Null),
                                );
                            }
                            *other = Value::Object(serde_json::Map::new());
                            match &mut effective_params {
                                Value::Object(m) => {
                                    *m = map;
                                    m
                                }
                                _ => unreachable!(),
                            }
                        }
                    };
                    for (k, v) in overlay_obj {
                        obj.insert(k.clone(), v.clone());
                    }
                }
            }
        }
        let mut result = provider
            .eval_predicate(&binding.when.predicate, &effective_params)
            .map_err(|err| {
                EvalError(format!(
                    "ruleset binding '{}' predicate '{}.{}' failed: {}",
                    binding.rule_id, binding.when.scope_id.0, binding.when.predicate, err
                ))
            })?;
        result.findings.sort_by(|a, b| {
            a.rule_id
                .cmp(&b.rule_id)
                .then(severity_rank(&a.severity).cmp(&severity_rank(&b.severity)))
                .then(a.path.cmp(&b.path))
                .then(a.span.file.cmp(&b.span.file))
                .then(a.span.line.unwrap_or(0).cmp(&b.span.line.unwrap_or(0)))
                .then(a.span.col.unwrap_or(0).cmp(&b.span.col.unwrap_or(0)))
                .then(a.message.cmp(&b.message))
        });

        facts.push(Fact::PredicateEvaluated {
            predicate: format!(
                "provider:{}::{}",
                binding.when.scope_id.0, binding.when.predicate
            ),
            result: result.triggered,
            span: ruleset_span(&ruleset.ruleset_id, &binding.rule_id),
        });

        facts.push(Fact::RuleEvaluated {
            rule_id: binding.rule_id.clone(),
            severity: binding.severity.clone(),
            triggered: result.triggered,
            scope_id: binding.when.scope_id.clone(),
            predicate: binding.when.predicate.clone(),
            span: ruleset_span(&ruleset.ruleset_id, &binding.rule_id),
        });

        if result.triggered && severity_meets_fail_on(&binding.severity, &ruleset.fail_on) {
            failed = true;
        }
        for finding in &result.findings {
            if severity_meets_fail_on(&finding.severity, &ruleset.fail_on) {
                failed = true;
            }
            facts.push(Fact::LintFinding {
                rule_id: finding.rule_id.clone(),
                severity: finding.severity.clone(),
                invariant: finding.invariant.clone(),
                path: finding.path.clone(),
                span: finding.span.clone(),
                message: finding.message.clone(),
                evidence: finding.evidence.clone(),
            });
        }

        rule_results.push(RuleResult {
            rule_id: binding.rule_id,
            severity: binding.severity,
            triggered: result.triggered,
            findings_count: result.findings.len(),
            scope_id: binding.when.scope_id,
            predicate: binding.when.predicate,
        });
    }

    let ruleset_hash = canonical_ruleset_hash(ruleset)?;
    let verdict = if failed {
        Verdict::Inadmissible
    } else {
        Verdict::Admissible
    };
    let reason = if failed {
        format!("ruleset {} failed", ruleset.ruleset_id)
    } else {
        format!("ruleset {} passed", ruleset.ruleset_id)
    };

    let module = ruleset
        .module
        .clone()
        .unwrap_or_else(|| ModuleId("module:ruleset@1".to_string()));
    let scope = ruleset
        .scope
        .clone()
        .unwrap_or_else(|| ScopeId("scope:rules.check".to_string()));
    let snapshot_hash = input_bundles.and_then(|bundles| {
        if bundles.len() == 1 {
            bundles.values().next().map(|b| b.snapshot_hash.0.clone())
        } else {
            None
        }
    });
    let program = WitnessProgram {
        module,
        scope,
        ruleset_id: Some(ruleset.ruleset_id.clone()),
        ruleset_version: None,
        content_id: None,
        program_hash: None,
        snapshot_hash,
        facts_bundle_hash: None,
        ruleset_hash: Some(ruleset_hash.clone()),
    };

    let witness = WitnessBuilder::new(program, verdict, reason)
        .with_facts(facts)
        .with_displacement_trace(DisplacementTrace {
            mode: DisplacementMode::Potential,
            totals: Vec::new(),
            contributions: Vec::new(),
        })
        .build();

    Ok(RuleEvaluationOutcome {
        ruleset_hash,
        rule_results,
        witness,
    })
}

pub fn scope_rule_bindings(ruleset: &RuleSet) -> BTreeMap<ScopeId, Vec<String>> {
    let mut out: BTreeMap<ScopeId, Vec<String>> = BTreeMap::new();
    let enabled: BTreeSet<&str> = if ruleset.enabled_rules.is_empty() {
        ruleset
            .bindings
            .iter()
            .map(|b| b.rule_id.as_str())
            .collect()
    } else {
        ruleset.enabled_rules.iter().map(|r| r.as_str()).collect()
    };
    for b in &ruleset.bindings {
        if !enabled.contains(b.rule_id.as_str()) {
            continue;
        }
        out.entry(b.when.scope_id.clone())
            .or_default()
            .push(b.rule_id.clone());
    }
    for rules in out.values_mut() {
        rules.sort();
        rules.dedup();
    }
    out
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::provider_trait::Provider;
    use crate::provider_types::{
        ClosureRequirements, PredicateResult, ProviderDescriptor, ProviderError, ProviderPhase,
        Rfc3339Timestamp, Sha256Hex, SnapshotRequest, SnapshotResult,
    };
    use crate::symbols::ScopeId;

    use super::*;

    struct StubProvider {
        scope_id: ScopeId,
    }

    impl Provider for StubProvider {
        fn describe(&self) -> ProviderDescriptor {
            ProviderDescriptor {
                scope_id: self.scope_id.clone(),
                version: 1,
                schema_ids: vec![],
                supported_phases: vec![ProviderPhase::Describe, ProviderPhase::Snapshot],
                deterministic: true,
                closure: ClosureRequirements::default(),
                required_approvals: vec![],
                predicates: vec![],
            }
        }

        fn snapshot(&self, _req: &SnapshotRequest) -> Result<SnapshotResult, ProviderError> {
            Err(ProviderError {
                scope: self.scope_id.clone(),
                phase: ProviderPhase::Snapshot,
                message: "stub".to_string(),
            })
        }

        fn eval_predicate(
            &self,
            name: &str,
            params: &Value,
        ) -> Result<PredicateResult, ProviderError> {
            match name {
                "always_trigger" => Ok(PredicateResult {
                    triggered: true,
                    findings: vec![],
                }),
                "warn_only" => Ok(PredicateResult {
                    triggered: false,
                    findings: vec![crate::lint::LintFinding {
                        rule_id: "stub/warn".to_string(),
                        severity: Severity::Warning,
                        invariant: None,
                        path: "x".to_string(),
                        span: Span {
                            file: "x".to_string(),
                            start: None,
                            end: None,
                            line: None,
                            col: None,
                        },
                        message: "warning".to_string(),
                        evidence: None,
                    }],
                }),
                "overlay_flag" => {
                    let hit = params
                        .get("changed_paths")
                        .and_then(|v| v.as_array())
                        .is_some_and(|paths| {
                            paths.iter().any(|v| v.as_str() == Some("Cargo.toml"))
                        });
                    Ok(PredicateResult {
                        triggered: hit,
                        findings: vec![],
                    })
                }
                _ => Err(ProviderError {
                    scope: self.scope_id.clone(),
                    phase: ProviderPhase::Snapshot,
                    message: "unknown predicate".to_string(),
                }),
            }
        }
    }

    #[test]
    fn ruleset_fail_on_error_respects_binding_severity() {
        let mut reg = ProviderRegistry::new();
        reg.register(Arc::new(StubProvider {
            scope_id: ScopeId("stub.scope".to_string()),
        }))
        .unwrap();

        let ruleset = RuleSet {
            schema_id: RULESET_SCHEMA_ID_V1.to_string(),
            ruleset_id: "default".to_string(),
            enabled_rules: vec!["R-010".to_string()],
            bindings: vec![RuleBinding {
                rule_id: "R-010".to_string(),
                severity: Severity::Error,
                when: RulePredicateBinding {
                    scope_id: ScopeId("stub.scope".to_string()),
                    predicate: "always_trigger".to_string(),
                    params: Value::Null,
                },
            }],
            fail_on: LintFailOn::Error,
            module: None,
            scope: None,
        };

        let out = evaluate_ruleset(&ruleset, &reg).unwrap();
        assert_eq!(out.witness.verdict, Verdict::Inadmissible);
        assert!(out
            .witness
            .facts
            .iter()
            .any(|f| matches!(f, Fact::RuleEvaluated { rule_id, triggered, .. } if rule_id == "R-010" && *triggered)));
    }

    #[test]
    fn ruleset_fail_on_error_ignores_warning_findings() {
        let mut reg = ProviderRegistry::new();
        reg.register(Arc::new(StubProvider {
            scope_id: ScopeId("stub.scope".to_string()),
        }))
        .unwrap();

        let ruleset = RuleSet {
            schema_id: RULESET_SCHEMA_ID_V1.to_string(),
            ruleset_id: "default".to_string(),
            enabled_rules: vec!["R-020".to_string()],
            bindings: vec![RuleBinding {
                rule_id: "R-020".to_string(),
                severity: Severity::Warning,
                when: RulePredicateBinding {
                    scope_id: ScopeId("stub.scope".to_string()),
                    predicate: "warn_only".to_string(),
                    params: Value::Null,
                },
            }],
            fail_on: LintFailOn::Error,
            module: None,
            scope: None,
        };

        let out = evaluate_ruleset(&ruleset, &reg).unwrap();
        assert_eq!(out.witness.verdict, Verdict::Admissible);
    }

    #[test]
    fn ruleset_inputs_inject_facts_and_snapshot_hash() {
        let mut reg = ProviderRegistry::new();
        reg.register(Arc::new(StubProvider {
            scope_id: ScopeId("stub.scope".to_string()),
        }))
        .unwrap();

        let ruleset = RuleSet {
            schema_id: RULESET_SCHEMA_ID_V1.to_string(),
            ruleset_id: "default".to_string(),
            enabled_rules: vec!["R-100".to_string()],
            bindings: vec![RuleBinding {
                rule_id: "R-100".to_string(),
                severity: Severity::Error,
                when: RulePredicateBinding {
                    scope_id: ScopeId("stub.scope".to_string()),
                    predicate: "warn_only".to_string(),
                    params: Value::Null,
                },
            }],
            fail_on: LintFailOn::Error,
            module: None,
            scope: None,
        };

        let mut bundles = BTreeMap::new();
        bundles.insert(
            ScopeId("stub.scope".to_string()),
            FactsBundle {
                schema_id: "facts-bundle/stub.scope@1".to_string(),
                scope_id: ScopeId("stub.scope".to_string()),
                facts: vec![],
                snapshot_hash: Sha256Hex::new("abc123"),
                created_at: Rfc3339Timestamp::new("2026-02-11T00:00:00Z"),
            },
        );
        let out = evaluate_ruleset_with_inputs(&ruleset, &reg, Some(&bundles), None).unwrap();
        assert_eq!(out.witness.program.snapshot_hash.as_deref(), Some("abc123"));
    }

    #[test]
    fn ruleset_runtime_overlay_merges_params_by_rule_id() {
        let mut reg = ProviderRegistry::new();
        reg.register(Arc::new(StubProvider {
            scope_id: ScopeId("stub.scope".to_string()),
        }))
        .unwrap();

        let ruleset = RuleSet {
            schema_id: RULESET_SCHEMA_ID_V1.to_string(),
            ruleset_id: "default".to_string(),
            enabled_rules: vec!["R-CI-200".to_string()],
            bindings: vec![RuleBinding {
                rule_id: "R-CI-200".to_string(),
                severity: Severity::Error,
                when: RulePredicateBinding {
                    scope_id: ScopeId("stub.scope".to_string()),
                    predicate: "overlay_flag".to_string(),
                    params: Value::Object(serde_json::Map::new()),
                },
            }],
            fail_on: LintFailOn::Error,
            module: None,
            scope: None,
        };

        let no_overlay = evaluate_ruleset_with_inputs(&ruleset, &reg, None, None).unwrap();
        assert_eq!(no_overlay.witness.verdict, Verdict::Admissible);

        let mut overlays = BTreeMap::new();
        overlays.insert(
            "R-CI-200".to_string(),
            serde_json::json!({ "changed_paths": ["Cargo.toml"] }),
        );
        let with_overlay =
            evaluate_ruleset_with_inputs(&ruleset, &reg, None, Some(&overlays)).unwrap();
        assert_eq!(with_overlay.witness.verdict, Verdict::Inadmissible);
        assert!(with_overlay.witness.facts.iter().any(|fact| matches!(
            fact,
            Fact::RuleEvaluated {
                rule_id,
                triggered,
                ..
            } if rule_id == "R-CI-200" && *triggered
        )));
    }

    #[test]
    fn ruleset_runtime_overlay_does_not_change_ruleset_hash() {
        let mut reg = ProviderRegistry::new();
        reg.register(Arc::new(StubProvider {
            scope_id: ScopeId("stub.scope".to_string()),
        }))
        .unwrap();

        let ruleset = RuleSet {
            schema_id: RULESET_SCHEMA_ID_V1.to_string(),
            ruleset_id: "default".to_string(),
            enabled_rules: vec!["R-CI-200".to_string()],
            bindings: vec![RuleBinding {
                rule_id: "R-CI-200".to_string(),
                severity: Severity::Warning,
                when: RulePredicateBinding {
                    scope_id: ScopeId("stub.scope".to_string()),
                    predicate: "overlay_flag".to_string(),
                    params: Value::Object(serde_json::Map::new()),
                },
            }],
            fail_on: LintFailOn::Error,
            module: None,
            scope: None,
        };

        let base = evaluate_ruleset_with_inputs(&ruleset, &reg, None, None).unwrap();
        let mut overlays = BTreeMap::new();
        overlays.insert(
            "R-CI-200".to_string(),
            serde_json::json!({ "changed_paths": ["Cargo.toml"] }),
        );
        let overlaid = evaluate_ruleset_with_inputs(&ruleset, &reg, None, Some(&overlays)).unwrap();

        assert_eq!(base.ruleset_hash, overlaid.ruleset_hash);
        assert_eq!(base.ruleset_hash, canonical_ruleset_hash(&ruleset).unwrap());
    }
}
