use serde::{Deserialize, Serialize};

use crate::error::EvalError;
use crate::span::Span;
use crate::symbols::{ModuleId, ScopeId, SymbolRef};

pub type UnitRef = String;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Quantity {
    pub value: f64,
    pub unit: UnitRef,
}

impl Quantity {
    pub fn ensure_compatible(&self, other: &Self) -> Result<(), EvalError> {
        if self.unit != other.unit {
            Err(EvalError(format!(
                "unit mismatch: {} vs {}",
                self.unit, other.unit
            )))
        } else {
            Ok(())
        }
    }

    pub fn add(&self, other: &Self) -> Result<Self, EvalError> {
        self.ensure_compatible(other)?;
        Ok(Quantity {
            value: self.value + other.value,
            unit: self.unit.clone(),
        })
    }

    pub fn compare(&self, other: &Self) -> Result<std::cmp::Ordering, EvalError> {
        self.ensure_compatible(other)?;
        Ok(self
            .value
            .partial_cmp(&other.value)
            .ok_or_else(|| EvalError("cannot compare NaN quantities".to_string()))?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Program {
    pub module: ModuleId,
    pub scope: ScopeId,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dependencies: Vec<ModuleId>,
    pub statements: Vec<Stmt>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScopeMode {
    Widen,
    Narrow,
    Translate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum Stmt {
    #[serde(rename = "DeclareDifference")]
    DeclareDifference {
        diff: SymbolRef,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        unit: Option<UnitRef>,
        span: Span,
    },
    #[serde(rename = "DeclareTransform")]
    DeclareTransform { transform: SymbolRef, span: Span },
    #[serde(rename = "Persist")]
    Persist {
        diff: SymbolRef,
        under: Vec<SymbolRef>,
        span: Span,
    },
    #[serde(rename = "ErasureRule")]
    ErasureRule {
        diff: SymbolRef,
        cost: Quantity,
        displaced_to: SymbolRef,
        span: Span,
    },
    #[serde(rename = "AllowErase")]
    AllowErase { diff: SymbolRef, span: Span },
    #[serde(rename = "DenyErase")]
    DenyErase { diff: SymbolRef, span: Span },
    #[serde(rename = "ScopeChange")]
    ScopeChange {
        from: ScopeId,
        to: ScopeId,
        mode: ScopeMode,
        span: Span,
    },
    #[serde(rename = "Constraint")]
    Constraint {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        id: Option<SymbolRef>,
        expr: BoolExpr,
        span: Span,
    },
    #[serde(rename = "ConstraintMeta")]
    ConstraintMeta {
        id: SymbolRef,
        key: String,
        value: String,
        span: Span,
    },
    #[serde(rename = "Commit")]
    Commit {
        diff: SymbolRef,
        value: CommitValue,
        span: Span,
    },
    #[serde(rename = "Query")]
    Query { query: Query, span: Span },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum CommitValue {
    Quantity(Quantity),
    Text(String),
    Bool(bool),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Query {
    Admissible,
    Witness,
    Delta,
    Lint { fail_on: LintFailOn },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LintFailOn {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum BoolExpr {
    #[serde(rename = "And")]
    And { items: Vec<BoolExpr> },
    #[serde(rename = "Or")]
    Or { items: Vec<BoolExpr> },
    #[serde(rename = "Not")]
    Not { item: Box<BoolExpr> },
    #[serde(rename = "Pred")]
    Pred { pred: Predicate },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type")]
pub enum Predicate {
    #[serde(rename = "EraseAllowed")]
    EraseAllowed { diff: SymbolRef },
    #[serde(rename = "DisplacedTotal")]
    DisplacedTotal {
        bucket: SymbolRef,
        op: CmpOp,
        value: Quantity,
    },
    #[serde(rename = "HasCommit")]
    HasCommit { diff: SymbolRef },
    #[serde(rename = "CommitEquals")]
    CommitEquals { diff: SymbolRef, value: CommitValue },
    #[serde(rename = "CommitCmp")]
    CommitCmp {
        diff: SymbolRef,
        op: CmpOp,
        value: Quantity,
    },
    /// Generic provider-delegated predicate. Replaces hardcoded extension
    /// predicates (ObsidianVaultRule, CalcWitness). The provider is resolved
    /// from the registry by `scope_id` and dispatched via `eval_predicate`.
    #[serde(rename = "ProviderPredicate")]
    ProviderPredicate {
        scope_id: ScopeId,
        name: String,
        #[serde(default)]
        params: serde_json::Value,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CmpOp {
    Eq,
    Neq,
    Gt,
    Gte,
    Lt,
    Lte,
}
