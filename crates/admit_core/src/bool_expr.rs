use crate::env::Env;
use crate::error::EvalError;
use crate::ir::BoolExpr;
use crate::predicates::{eval_pred_with_provider, predicate_to_string};
use crate::provider::PredicateProvider;
use crate::span::Span;
use crate::trace::Trace;
use crate::witness::Fact;

pub fn eval_bool(
    expr: &BoolExpr,
    env: &Env,
    trace: &mut Trace,
    span: &Span,
) -> Result<bool, EvalError> {
    eval_bool_with_provider(expr, env, trace, span, None)
}

pub fn eval_bool_with_provider(
    expr: &BoolExpr,
    env: &Env,
    trace: &mut Trace,
    span: &Span,
    provider: Option<&dyn PredicateProvider>,
) -> Result<bool, EvalError> {
    match expr {
        BoolExpr::And { items } => {
            for item in items {
                if !eval_bool_with_provider(item, env, trace, span, provider)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        BoolExpr::Or { items } => {
            for item in items {
                if eval_bool_with_provider(item, env, trace, span, provider)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        BoolExpr::Not { item } => Ok(!eval_bool_with_provider(item, env, trace, span, provider)?),
        BoolExpr::Pred { pred } => {
            let result = eval_pred_with_provider(pred, env, trace, span, provider)?;
            trace.record(Fact::PredicateEvaluated {
                predicate: predicate_to_string(pred),
                result,
                span: span.clone(),
            });
            Ok(result)
        }
    }
}
