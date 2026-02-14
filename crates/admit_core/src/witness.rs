use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ir::{CommitValue, Program, Quantity, ScopeMode};
use crate::span::Span;
use crate::symbols::{ModuleId, ScopeId, SymbolRef};
use crate::trace::Trace;

pub const DEFAULT_WITNESS_SCHEMA_ID: &str = "admissibility-witness/2";
pub const DEFAULT_LENS_DELTA_SCHEMA_ID: &str = "lens-delta-witness/0";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Witness {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        alias = "court_version"
    )]
    pub engine_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub lens_id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub lens_hash: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub lens_activation_event_id: String,
    pub verdict: Verdict,
    pub program: WitnessProgram,
    pub reason: String,
    pub facts: Vec<Fact>,
    pub displacement_trace: DisplacementTrace,
    #[serde(default, skip_serializing_if = "InvariantProfile::is_empty")]
    pub invariant_profile: InvariantProfile,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LensHandle {
    pub lens_id: String,
    pub lens_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LensDeltaRow {
    pub section: String,
    pub stable_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_file: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub col: Option<u32>,
    pub before: String,
    pub after: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LensDeltaWitness {
    pub schema_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_id: Option<String>,
    pub from_lens: LensHandle,
    pub to_lens: LensHandle,
    pub snapshot_hash: String,
    pub rows: Vec<LensDeltaRow>,
}

impl LensDeltaWitness {
    pub fn new(
        from_lens: LensHandle,
        to_lens: LensHandle,
        snapshot_hash: String,
        mut rows: Vec<LensDeltaRow>,
    ) -> Self {
        rows.sort_by(|a, b| {
            (
                &a.section,
                &a.stable_id,
                &a.source_file,
                a.line.unwrap_or(0),
                a.col.unwrap_or(0),
            )
                .cmp(&(
                    &b.section,
                    &b.stable_id,
                    &b.source_file,
                    b.line.unwrap_or(0),
                    b.col.unwrap_or(0),
                ))
        });
        Self {
            schema_id: DEFAULT_LENS_DELTA_SCHEMA_ID.to_string(),
            created_at: None,
            tool_version: None,
            input_id: None,
            from_lens,
            to_lens,
            snapshot_hash,
            rows,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct WitnessProgram {
    pub module: ModuleId,
    pub scope: ScopeId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ruleset_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ruleset_version: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub program_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facts_bundle_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ruleset_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Admissible,
    Inadmissible,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum Fact {
    #[serde(rename = "constraint_triggered")]
    ConstraintTriggered {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        constraint_id: Option<SymbolRef>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        invariant: Option<String>,
        span: Span,
    },
    #[serde(rename = "permission_used")]
    PermissionUsed {
        kind: PermissionKind,
        diff: SymbolRef,
        span: Span,
    },
    #[serde(rename = "erasure_rule_used")]
    ErasureRuleUsed {
        diff: SymbolRef,
        bucket: SymbolRef,
        cost: Quantity,
        span: Span,
    },
    #[serde(rename = "commit_used")]
    CommitUsed {
        diff: SymbolRef,
        value: CommitValue,
        span: Span,
    },
    #[serde(rename = "predicate_evaluated")]
    PredicateEvaluated {
        predicate: String,
        result: bool,
        span: Span,
    },
    #[serde(rename = "rule_evaluated")]
    RuleEvaluated {
        rule_id: String,
        severity: Severity,
        triggered: bool,
        scope_id: ScopeId,
        predicate: String,
        span: Span,
    },
    #[serde(rename = "scope_change_used")]
    ScopeChangeUsed {
        from: ScopeId,
        to: ScopeId,
        mode: ScopeMode,
        span: Span,
    },
    #[serde(rename = "unaccounted_boundary_change")]
    UnaccountedBoundaryChange {
        from: ScopeId,
        to: ScopeId,
        mode: ScopeMode,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        invariant: Option<String>,
        span: Span,
    },
    #[serde(rename = "lens_activated")]
    LensActivated {
        lens_id: String,
        lens_hash: String,
        lens_activation_event_id: String,
        span: Span,
    },
    #[serde(rename = "meta_change_checked")]
    MetaChangeChecked {
        kind: String,
        from_lens_id: String,
        from_lens_hash: String,
        to_lens_id: String,
        to_lens_hash: String,
        synthetic_diff_id: String,
        span: Span,
    },
    #[serde(rename = "lint_finding")]
    LintFinding {
        rule_id: String,
        severity: Severity,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        invariant: Option<String>,
        // Vault-relative path (or other domain-relative path) for deterministic output.
        path: String,
        // Span is best-effort: always include file; line/col may be None.
        span: Span,
        message: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        evidence: Option<Value>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PermissionKind {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DisplacementTrace {
    pub mode: DisplacementMode,
    pub totals: Vec<DisplacementTotal>,
    pub contributions: Vec<DisplacementContribution>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DisplacementMode {
    Potential,
    Actual,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DisplacementTotal {
    pub bucket: SymbolRef,
    pub total: Quantity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DisplacementContribution {
    pub diff: SymbolRef,
    pub bucket: SymbolRef,
    pub cost: Quantity,
    pub rule_span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct InvariantSummary {
    pub invariant: String,
    pub triggered_count: usize,
    pub finding_count: usize,
    pub constraint_ids: Vec<SymbolRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct InvariantProfile {
    pub summaries: Vec<InvariantSummary>,
}

impl InvariantProfile {
    pub fn is_empty(&self) -> bool {
        self.summaries.is_empty()
    }
}

impl Witness {
    /// Deduped, sorted list of invariant names touched in this witness.
    pub fn invariants_touched(&self) -> Vec<String> {
        self.invariant_profile
            .summaries
            .iter()
            .map(|s| s.invariant.clone())
            .collect()
    }

    pub fn new(
        program: WitnessProgram,
        trace: Trace,
        displacement_trace: DisplacementTrace,
        verdict: Verdict,
        reason: impl Into<String>,
    ) -> Self {
        WitnessBuilder::new(program, verdict, reason)
            .with_trace(trace)
            .with_displacement_trace(displacement_trace)
            .build()
    }

    pub fn has_activation_metadata(&self) -> bool {
        !self.lens_id.trim().is_empty()
            && !self.lens_hash.trim().is_empty()
            && !self.lens_activation_event_id.trim().is_empty()
    }
}

pub struct WitnessBuilder {
    program: WitnessProgram,
    verdict: Verdict,
    reason: String,
    facts: Vec<Fact>,
    displacement_trace: Option<DisplacementTrace>,
}

impl WitnessProgram {
    pub fn from_program(program: &Program) -> Self {
        Self {
            module: program.module.clone(),
            scope: program.scope.clone(),
            ruleset_id: None,
            ruleset_version: None,
            content_id: None,
            program_hash: None,
            snapshot_hash: None,
            facts_bundle_hash: None,
            ruleset_hash: None,
        }
    }
}

impl WitnessBuilder {
    pub fn new(program: WitnessProgram, verdict: Verdict, reason: impl Into<String>) -> Self {
        Self {
            program,
            verdict,
            reason: reason.into(),
            facts: Vec::new(),
            displacement_trace: None,
        }
    }

    pub fn canonical_predicate_strings(&self) -> Vec<String> {
        let mut facts = self.facts.clone();
        facts.sort_by(|a, b| fact_sort_key(a).cmp(&fact_sort_key(b)));
        facts
            .into_iter()
            .filter_map(|fact| match fact {
                Fact::PredicateEvaluated { predicate, .. } => Some(predicate),
                _ => None,
            })
            .collect()
    }

    pub fn canonical_predicate_string(&self) -> String {
        self.canonical_predicate_strings().join("\n")
    }

    pub fn with_trace(mut self, trace: Trace) -> Self {
        self.facts = trace.into_facts();
        self
    }

    pub fn with_facts(mut self, facts: Vec<Fact>) -> Self {
        self.facts = facts;
        self
    }

    pub fn with_displacement_trace(mut self, displacement_trace: DisplacementTrace) -> Self {
        self.displacement_trace = Some(displacement_trace);
        self
    }

    pub fn build(mut self) -> Witness {
        self.facts
            .sort_by(|a, b| fact_sort_key(a).cmp(&fact_sort_key(b)));

        let displacement_trace = self
            .displacement_trace
            .unwrap_or_else(|| DisplacementTrace {
                mode: DisplacementMode::Potential,
                totals: Vec::new(),
                contributions: Vec::new(),
            });

        let invariant_profile = compute_invariant_profile(&self.facts);

        Witness {
            schema_id: Some(DEFAULT_WITNESS_SCHEMA_ID.to_string()),
            created_at: None,
            engine_version: None,
            input_id: None,
            config_hash: None,
            lens_id: runtime_default_lens_id(),
            lens_hash: runtime_default_lens_hash(),
            lens_activation_event_id: runtime_default_lens_activation_event_id(),
            verdict: self.verdict,
            program: self.program,
            reason: self.reason,
            facts: self.facts,
            displacement_trace,
            invariant_profile,
        }
    }
}

/// Build an `InvariantProfile` purely from facts. Uses `BTreeMap`/`BTreeSet` for deterministic
/// ordering: same facts always produce the same profile regardless of insertion order.
fn compute_invariant_profile(facts: &[Fact]) -> InvariantProfile {
    // (triggered_count, finding_count, constraint_ids)
    let mut by_inv: BTreeMap<String, (usize, usize, BTreeSet<SymbolRef>)> = BTreeMap::new();
    for fact in facts {
        match fact {
            Fact::ConstraintTriggered {
                constraint_id,
                invariant: Some(inv),
                ..
            } => {
                let e = by_inv.entry(inv.clone()).or_default();
                e.0 += 1;
                if let Some(id) = constraint_id {
                    e.2.insert(id.clone());
                }
            }
            Fact::LintFinding {
                invariant: Some(inv),
                ..
            } => {
                by_inv.entry(inv.clone()).or_default().1 += 1;
            }
            Fact::UnaccountedBoundaryChange {
                invariant: Some(inv),
                ..
            } => {
                by_inv.entry(inv.clone()).or_default().0 += 1;
            }
            _ => {}
        }
    }
    InvariantProfile {
        summaries: by_inv
            .into_iter()
            .map(|(inv, (tc, fc, ids))| InvariantSummary {
                invariant: inv,
                triggered_count: tc,
                finding_count: fc,
                constraint_ids: ids.into_iter().collect(),
            })
            .collect(),
    }
}

/// Normalize an invariant tag to lowercase, trimmed, whitespace replaced with underscores.
/// Prevents "Governance", " governance ", "GOVERNANCE" from being treated as different invariants.
pub fn normalize_invariant(s: &str) -> String {
    let trimmed = s.trim().to_lowercase();
    trimmed
        .chars()
        .map(|c| if c.is_whitespace() { '_' } else { c })
        .collect()
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
        Fact::ConstraintTriggered { span, .. } => span,
        Fact::PermissionUsed { span, .. } => span,
        Fact::ErasureRuleUsed { span, .. } => span,
        Fact::CommitUsed { span, .. } => span,
        Fact::PredicateEvaluated { span, .. } => span,
        Fact::RuleEvaluated { span, .. } => span,
        Fact::ScopeChangeUsed { span, .. } => span,
        Fact::UnaccountedBoundaryChange { span, .. } => span,
        Fact::LensActivated { span, .. } => span,
        Fact::MetaChangeChecked { span, .. } => span,
        Fact::LintFinding { span, .. } => span,
    };
    (
        type_rank,
        aux,
        span.file.clone(),
        span.line.unwrap_or(0),
        span.col.unwrap_or(0),
    )
}

fn runtime_default_lens_id() -> String {
    "lens:default@0".to_string()
}

fn runtime_default_lens_hash() -> String {
    "lens:default:pending".to_string()
}

fn runtime_default_lens_activation_event_id() -> String {
    "pending:lens_activation".to_string()
}
