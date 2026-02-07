use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::span::Span;
use crate::witness::Severity;

/// A single lint finding produced by an external predicate provider (e.g. Obsidian vault lint).
///
/// This is converted into `Fact::LintFinding` for witness emission.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LintFinding {
    pub rule_id: String,
    pub severity: Severity,
    pub invariant: Option<String>,
    /// Domain-relative path (e.g. Obsidian-vault-relative) for deterministic output.
    pub path: String,
    pub span: Span,
    pub message: String,
    pub evidence: Option<Value>,
}
