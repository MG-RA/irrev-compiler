use std::cmp::Ordering;

use crate::env::Env;
use crate::error::EvalError;
use crate::ir::{CmpOp, Predicate};
use crate::provider_registry::ProviderRegistry;
use crate::span::Span;
use crate::symbols::{SymbolNamespace, SymbolRef};
use crate::trace::Trace;
use crate::witness::Fact;

pub fn eval_pred(
    pred: &Predicate,
    env: &Env,
    trace: &mut Trace,
    span: &Span,
) -> Result<bool, EvalError> {
    eval_pred_with_provider(pred, env, trace, span, None)
}

pub fn eval_pred_with_provider(
    pred: &Predicate,
    env: &Env,
    trace: &mut Trace,
    span: &Span,
    registry: Option<&ProviderRegistry>,
) -> Result<bool, EvalError> {
    match pred {
        Predicate::EraseAllowed { diff } => Ok(env.is_allowed(diff)),
        Predicate::DisplacedTotal { bucket, op, value } => {
            let total = bucket_total(env, bucket, &value.unit)?;
            let cmp = total.compare(value)?;
            Ok(matches_op(cmp, op))
        }
        Predicate::HasCommit { diff } => Ok(env.commits.contains_key(diff)),
        Predicate::CommitEquals { diff, value } => match env.commits.get(diff) {
            Some(commit) => {
                trace.record(Fact::CommitUsed {
                    diff: diff.clone(),
                    value: commit.clone(),
                    span: span.clone(),
                });
                compare_commit(commit, value)
            }
            None => Ok(false),
        },
        Predicate::CommitCmp { diff, op, value } => {
            let commit = env
                .commits
                .get(diff)
                .ok_or_else(|| EvalError("missing commit".into()))?;
            trace.record(Fact::CommitUsed {
                diff: diff.clone(),
                value: commit.clone(),
                span: span.clone(),
            });
            if let crate::ir::CommitValue::Quantity(commit_qty) = commit {
                let cmp = commit_qty.compare(value)?;
                Ok(matches_op(cmp, op))
            } else {
                Err(EvalError("commit is not a quantity".into()))
            }
        }
        Predicate::ProviderPredicate {
            scope_id,
            name,
            params,
        } => {
            let registry = registry.ok_or_else(|| {
                EvalError(format!(
                    "provider predicate '{}.{}' requires a provider registry",
                    scope_id.0, name
                ))
            })?;
            let provider = registry.get(scope_id).ok_or_else(|| {
                EvalError(format!("no provider registered for scope '{}'", scope_id.0))
            })?;
            let result = provider
                .eval_predicate(
                    name,
                    params,
                    &crate::provider_types::PredicateEvalContext::default(),
                )
                .map_err(|e| EvalError(e.message))?;

            for f in &result.findings {
                trace.record(Fact::LintFinding {
                    rule_id: f.rule_id.clone(),
                    severity: f.severity.clone(),
                    invariant: f.invariant.clone(),
                    path: f.path.clone(),
                    span: f.span.clone(),
                    message: f.message.clone(),
                    evidence: f.evidence.clone(),
                });
            }

            Ok(result.triggered)
        }
    }
}

fn bucket_total(
    env: &Env,
    bucket: &SymbolRef,
    unit: &str,
) -> Result<crate::ir::Quantity, EvalError> {
    let mut total: Option<crate::ir::Quantity> = None;
    for (diff, (cost, target_bucket, _)) in &env.erasure_rules {
        if target_bucket == bucket && env.is_allowed(diff) {
            if cost.unit != unit {
                return Err(EvalError(format!(
                    "bucket unit mismatch: {} vs {}",
                    cost.unit, unit
                )));
            }
            total = Some(if let Some(acc) = total {
                acc.add(cost)?
            } else {
                cost.clone()
            });
        }
    }
    Ok(total.unwrap_or(crate::ir::Quantity {
        value: 0.0,
        unit: unit.to_string(),
    }))
}

fn matches_op(ordering: Ordering, op: &CmpOp) -> bool {
    match op {
        CmpOp::Eq => ordering == Ordering::Equal,
        CmpOp::Neq => ordering != Ordering::Equal,
        CmpOp::Gt => ordering == Ordering::Greater,
        CmpOp::Gte => ordering >= Ordering::Greater,
        CmpOp::Lt => ordering == Ordering::Less,
        CmpOp::Lte => ordering <= Ordering::Less,
    }
}

fn compare_commit(
    commit: &crate::ir::CommitValue,
    target: &crate::ir::CommitValue,
) -> Result<bool, EvalError> {
    match (commit, target) {
        (
            crate::ir::CommitValue::Quantity(commit_qty),
            crate::ir::CommitValue::Quantity(target_qty),
        ) => Ok(commit_qty == target_qty),
        (crate::ir::CommitValue::Text(c), crate::ir::CommitValue::Text(t)) => Ok(c == t),
        (crate::ir::CommitValue::Bool(c), crate::ir::CommitValue::Bool(t)) => Ok(c == t),
        _ => Err(EvalError("mismatched commit value types".into())),
    }
}

pub fn predicate_to_string(pred: &Predicate) -> String {
    match pred {
        Predicate::EraseAllowed { diff } => format!("erase_allowed {}", symbol_ref_repr(diff)),
        Predicate::DisplacedTotal { bucket, op, value } => format!(
            "displaced_total {} {} {}",
            symbol_ref_repr(bucket),
            cmp_op_repr(op),
            quantity_repr(value)
        ),
        Predicate::HasCommit { diff } => format!("has_commit {}", symbol_ref_repr(diff)),
        Predicate::CommitEquals { diff, value } => format!(
            "commit_equals {} {}",
            symbol_ref_repr(diff),
            commit_value_repr(value)
        ),
        Predicate::CommitCmp { diff, op, value } => format!(
            "commit_cmp {} {} {}",
            symbol_ref_repr(diff),
            cmp_op_repr(op),
            quantity_repr(value)
        ),
        Predicate::ProviderPredicate {
            scope_id,
            name,
            params,
        } => {
            format!("{}.{}({})", scope_id.0, name, params)
        }
    }
}

fn symbol_ref_repr(sym: &SymbolRef) -> String {
    format!("{}:{}", namespace_repr(&sym.ns), sym.name)
}

fn namespace_repr(ns: &SymbolNamespace) -> &'static str {
    match ns {
        SymbolNamespace::Difference => "difference",
        SymbolNamespace::Transform => "transform",
        SymbolNamespace::Bucket => "bucket",
        SymbolNamespace::Constraint => "constraint",
        SymbolNamespace::Scope => "scope",
        SymbolNamespace::Module => "module",
    }
}

fn cmp_op_repr(op: &CmpOp) -> &'static str {
    match op {
        CmpOp::Eq => "==",
        CmpOp::Neq => "!=",
        CmpOp::Gt => ">",
        CmpOp::Gte => ">=",
        CmpOp::Lt => "<",
        CmpOp::Lte => "<=",
    }
}

fn quantity_repr(q: &crate::ir::Quantity) -> String {
    format!("{} {}", q.value, q.unit)
}

fn commit_value_repr(value: &crate::ir::CommitValue) -> String {
    match value {
        crate::ir::CommitValue::Quantity(quantity) => quantity_repr(quantity),
        crate::ir::CommitValue::Text(text) => format!("\"{}\"", text),
        crate::ir::CommitValue::Bool(b) => format!("{}", b),
    }
}
