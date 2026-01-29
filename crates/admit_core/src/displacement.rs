use std::collections::BTreeMap;

use crate::env::Env;
use crate::error::EvalError;
use crate::symbols::SymbolRef;
use crate::trace::Trace;
use crate::witness::{
    DisplacementContribution, DisplacementMode, DisplacementTotal, DisplacementTrace, Fact,
    PermissionKind,
};

pub fn build_displacement_trace(
    env: &Env,
    trace: &mut Trace,
    mode: DisplacementMode,
) -> Result<DisplacementTrace, EvalError> {
    let mut totals: BTreeMap<SymbolRef, crate::ir::Quantity> = BTreeMap::new();
    let mut contributions = Vec::new();

    for (diff, (kind, span)) in &env.permissions {
        trace.record(Fact::PermissionUsed {
            kind: kind.clone(),
            diff: diff.clone(),
            span: span.clone(),
        });
        if *kind == PermissionKind::Allow && !env.erasure_rules.contains_key(diff) {
            return Err(EvalError(format!(
                "allow_erase requires erasure_rule for {}",
                diff.name
            )));
        }
    }

    for (diff, (cost, bucket, span)) in &env.erasure_rules {
        if env.is_allowed(diff) {
            if let Some(existing) = totals.get_mut(bucket) {
                *existing = existing.add(cost)?;
            } else {
                totals.insert(bucket.clone(), cost.clone());
            }
            contributions.push(DisplacementContribution {
                diff: diff.clone(),
                bucket: bucket.clone(),
                cost: cost.clone(),
                rule_span: span.clone(),
            });
            trace.record(Fact::ErasureRuleUsed {
                diff: diff.clone(),
                bucket: bucket.clone(),
                cost: cost.clone(),
                span: span.clone(),
            });
        }
    }

    let mut totals: Vec<DisplacementTotal> = totals
        .into_iter()
        .map(|(bucket, total)| DisplacementTotal { bucket, total })
        .collect();
    totals.sort_by(|a, b| a.bucket.cmp(&b.bucket));

    let mut contributions = contributions;
    contributions.sort_by(|a, b| match a.bucket.cmp(&b.bucket) {
        core::cmp::Ordering::Equal => a.diff.cmp(&b.diff),
        other => other,
    });

    Ok(DisplacementTrace {
        mode,
        totals,
        contributions,
    })
}
