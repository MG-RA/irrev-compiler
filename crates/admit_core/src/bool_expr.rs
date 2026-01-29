use crate::env::Env;
use crate::error::EvalError;
use crate::ir::BoolExpr;
use crate::predicates::{eval_pred, predicate_to_string};
use crate::span::Span;
use crate::trace::Trace;
use crate::witness::Fact;

pub fn eval_bool(
    expr: &BoolExpr,
    env: &Env,
    trace: &mut Trace,
    span: &Span,
) -> Result<bool, EvalError> {
    match expr {
        BoolExpr::And { items } => {
            for item in items {
                if !eval_bool(item, env, trace, span)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        BoolExpr::Or { items } => {
            for item in items {
                if eval_bool(item, env, trace, span)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        BoolExpr::Not { item } => Ok(!eval_bool(item, env, trace, span)?),
        BoolExpr::Pred { pred } => {
            let result = eval_pred(pred, env, trace, span)?;
            trace.record(Fact::PredicateEvaluated {
                predicate: predicate_to_string(pred),
                result,
                span: span.clone(),
            });
            Ok(result)
        }
    }
}
