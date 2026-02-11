use crate::bool_expr::eval_bool_with_provider;
use crate::env::Env;
use crate::error::EvalError;
use crate::provider_registry::ProviderRegistry;
use crate::span::Span;
use crate::trace::Trace;
use crate::witness::{normalize_invariant, Fact, Severity};

pub fn evaluate_constraints(env: &Env, trace: &mut Trace) -> Result<bool, EvalError> {
    evaluate_constraints_with_provider(env, trace, None)
}

pub fn evaluate_constraints_with_provider(
    env: &Env,
    trace: &mut Trace,
    provider: Option<&ProviderRegistry>,
) -> Result<bool, EvalError> {
    // Emit diagnostics for any constraint metadata conflicts detected during env construction.
    for (cid, key, prev, new) in &env.meta_conflicts {
        trace.record(Fact::LintFinding {
            rule_id: "meta-conflict".to_string(),
            severity: Severity::Warning,
            invariant: Some("governance".to_string()),
            path: String::new(),
            span: Span {
                file: String::new(),
                start: None,
                end: None,
                line: None,
                col: None,
            },
            message: format!(
                "constraint {:?} has conflicting values for tag '{}': '{}' vs '{}' (last-write-wins)",
                cid, key, prev, new
            ),
            evidence: None,
        });
    }

    let mut triggered = false;
    for (id, expr, span) in &env.constraints {
        if eval_bool_with_provider(expr, env, trace, span, provider)? {
            triggered = true;
            let invariant = id
                .as_ref()
                .and_then(|cid| env.constraint_meta.get(cid))
                .and_then(|meta| meta.get("invariant"))
                .map(|s| normalize_invariant(s));
            trace.record(Fact::ConstraintTriggered {
                constraint_id: id.clone(),
                invariant,
                span: span.clone(),
            });
        }
    }
    Ok(triggered)
}
