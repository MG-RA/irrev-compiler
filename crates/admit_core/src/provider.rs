use crate::error::EvalError;
use crate::lint::LintFinding;

/// External predicate surface used to keep admit_core pure while allowing domain predicates.
///
/// v0: only supports `vault_rule("<rule-id>")` and returns a set of findings.
/// In boolean positions, the findings set is implicitly coerced via `exists(findings)`.
pub trait PredicateProvider {
    fn eval_vault_rule(&self, rule_id: &str) -> Result<Vec<LintFinding>, EvalError>;
}

