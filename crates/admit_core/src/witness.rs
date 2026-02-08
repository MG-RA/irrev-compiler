use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::ir::{CommitValue, Program, Quantity, ScopeMode};
use crate::span::Span;
use crate::symbols::{ModuleId, ScopeId, SymbolRef};
use crate::trace::Trace;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Witness {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "court_version")]
    pub engine_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
    pub verdict: Verdict,
    pub program: WitnessProgram,
    pub reason: String,
    pub facts: Vec<Fact>,
    pub displacement_trace: DisplacementTrace,
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

impl Witness {
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

        Witness {
            schema_id: None,
            created_at: None,
            engine_version: None,
            input_id: None,
            config_hash: None,
            verdict: self.verdict,
            program: self.program,
            reason: self.reason,
            facts: self.facts,
            displacement_trace,
        }
    }
}

fn fact_sort_key(fact: &Fact) -> (u8, String, String, u32, u32) {
    let type_rank = match fact {
        Fact::ConstraintTriggered { .. } => 0,
        Fact::PermissionUsed { .. } => 1,
        Fact::ErasureRuleUsed { .. } => 2,
        Fact::CommitUsed { .. } => 3,
        Fact::PredicateEvaluated { .. } => 4,
        Fact::ScopeChangeUsed { .. } => 5,
        Fact::UnaccountedBoundaryChange { .. } => 6,
        Fact::LintFinding { .. } => 7,
    };
    let aux = match fact {
        Fact::LintFinding { rule_id, .. } => rule_id.clone(),
        _ => String::new(),
    };
    let span = match fact {
        Fact::ConstraintTriggered { span, .. } => span,
        Fact::PermissionUsed { span, .. } => span,
        Fact::ErasureRuleUsed { span, .. } => span,
        Fact::CommitUsed { span, .. } => span,
        Fact::PredicateEvaluated { span, .. } => span,
        Fact::ScopeChangeUsed { span, .. } => span,
        Fact::UnaccountedBoundaryChange { span, .. } => span,
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
