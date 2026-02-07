use crate::error::EvalError;
use crate::lint::LintFinding;

/// External predicate surface used to keep admit_core pure while allowing domain predicates.
///
/// v0: supports `obsidian_vault_rule("<rule-id>")` with `vault_rule` as an alias.
/// In boolean positions, the findings set is implicitly coerced via `exists(findings)`.
pub trait PredicateProvider {
    fn eval_domain_rule(&self, domain: &str, rule_id: &str) -> Result<Vec<LintFinding>, EvalError> {
        match domain {
            "obsidian_vault" | "vault" => self.eval_obsidian_vault_rule(rule_id),
            _ => Err(EvalError(format!(
                "domain_rule unsupported domain '{}'",
                domain
            ))),
        }
    }

    fn eval_obsidian_vault_rule(&self, rule_id: &str) -> Result<Vec<LintFinding>, EvalError> {
        self.eval_vault_rule(rule_id)
    }

    /// Back-compat alias. New providers should prefer `eval_obsidian_vault_rule`.
    fn eval_vault_rule(&self, rule_id: &str) -> Result<Vec<LintFinding>, EvalError>;
}
