use crate::bool_expr::eval_bool;
use crate::env::Env;
use crate::error::EvalError;
use crate::trace::Trace;
use crate::witness::Fact;

pub fn evaluate_constraints(env: &Env, trace: &mut Trace) -> Result<bool, EvalError> {
    let mut triggered = false;
    for (id, expr, span) in &env.constraints {
        if eval_bool(expr, env, trace, span)? {
            triggered = true;
            trace.record(Fact::ConstraintTriggered {
                constraint_id: id.clone(),
                span: span.clone(),
            });
        }
    }
    Ok(triggered)
}
