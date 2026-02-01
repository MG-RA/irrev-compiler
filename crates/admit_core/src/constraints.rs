use crate::bool_expr::eval_bool_with_provider;
use crate::env::Env;
use crate::error::EvalError;
use crate::provider::PredicateProvider;
use crate::trace::Trace;
use crate::witness::Fact;

pub fn evaluate_constraints(
    env: &Env,
    trace: &mut Trace,
) -> Result<bool, EvalError> {
    evaluate_constraints_with_provider(env, trace, None)
}

pub fn evaluate_constraints_with_provider(
    env: &Env,
    trace: &mut Trace,
    provider: Option<&dyn PredicateProvider>,
) -> Result<bool, EvalError> {
    let mut triggered = false;
    for (id, expr, span) in &env.constraints {
        if eval_bool_with_provider(expr, env, trace, span, provider)? {
            triggered = true;
            trace.record(Fact::ConstraintTriggered {
                constraint_id: id.clone(),
                span: span.clone(),
            });
        }
    }
    Ok(triggered)
}
