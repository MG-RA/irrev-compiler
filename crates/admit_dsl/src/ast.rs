use serde::{Deserialize, Serialize};

use crate::span::Span;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ModuleDecl {
    pub name: String,
    pub major: u32,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DependsDecl {
    pub modules: Vec<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ScopeDecl {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScopeMode {
    Widen,
    Narrow,
    Translate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScopeChangeStmt {
    pub from: String,
    pub to: String,
    pub mode: ScopeMode,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AllowScopeChangeStmt {
    pub from: String,
    pub to: String,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ScopeChangeRuleStmt {
    pub from: String,
    pub to: String,
    pub cost_value: f64,
    pub cost_unit: String,
    pub bucket: String,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DifferenceDecl {
    pub name: String,
    pub unit: Option<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransformDecl {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BucketDecl {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ConstraintDecl {
    pub name: String,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PersistStmt {
    pub diff: String,
    pub under: Vec<String>,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ErasureRuleStmt {
    pub diff: String,
    pub cost_value: f64,
    pub cost_unit: String,
    pub bucket: String,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PermissionKind {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PermissionStmt {
    pub kind: PermissionKind,
    pub diff: String,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum CommitValue {
    Number { value: f64, unit: Option<String> },
    Text(String),
    Bool(bool),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CommitStmt {
    pub diff: String,
    pub value: CommitValue,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum QueryKind {
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueryStmt {
    pub kind: QueryKind,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum BoolExpr {
    And(Vec<BoolExpr>),
    Or(Vec<BoolExpr>),
    Not(Box<BoolExpr>),
    Pred(Predicate),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum CmpOp {
    Eq,
    Neq,
    Gt,
    Gte,
    Lt,
    Lte,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Predicate {
    EraseAllowed {
        diff: String,
    },
    DisplacedTotal {
        bucket: String,
        op: CmpOp,
        value: f64,
        unit: String,
    },
    HasCommit {
        diff: String,
    },
    CommitEquals {
        diff: String,
        value: CommitValue,
    },
    CommitCmp {
        diff: String,
        op: CmpOp,
        value: f64,
        unit: String,
    },
    #[serde(rename = "ObsidianVaultRule", alias = "VaultRule")]
    ObsidianVaultRule {
        rule_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TagStmt {
    pub key: String,
    pub value: String,
    pub span: Span,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Stmt {
    Module(ModuleDecl),
    Depends(DependsDecl),
    Scope(ScopeDecl),
    ScopeChange(ScopeChangeStmt),
    AllowScopeChange(AllowScopeChangeStmt),
    ScopeChangeRule(ScopeChangeRuleStmt),
    Difference(DifferenceDecl),
    Transform(TransformDecl),
    Bucket(BucketDecl),
    Constraint(ConstraintDecl),
    Persist(PersistStmt),
    ErasureRule(ErasureRuleStmt),
    Permission(PermissionStmt),
    Commit(CommitStmt),
    Tag(TagStmt),
    InadmissibleIf { expr: BoolExpr, span: Span },
    Query(QueryStmt),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Program {
    pub statements: Vec<Stmt>,
}
