use std::collections::BTreeSet;

use crate::boundary_loss_diff;
use crate::constraints::evaluate_constraints_with_provider;
use crate::displacement::build_displacement_trace;
use crate::env::Env;
use crate::error::EvalError;
use crate::ir::{Program, Query, ScopeMode};
use crate::provider_registry::ProviderRegistry;
use crate::trace::Trace;
use crate::witness::Fact;
use crate::witness::{DisplacementMode, Verdict, Witness, WitnessProgram};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone)]
pub enum FloatPolicy {
    Ban,
    Normalize,
}

#[derive(Debug, Clone)]
pub struct EvalOpts {
    pub displacement_mode: DisplacementMode,
    pub float_policy: FloatPolicy,
}

pub fn eval(program: &Program, query: Query, opts: EvalOpts) -> Result<Witness, EvalError> {
    eval_with_provider(program, query, opts, None)
}

pub fn eval_with_provider(
    program: &Program,
    query: Query,
    opts: EvalOpts,
    provider: Option<&ProviderRegistry>,
) -> Result<Witness, EvalError> {
    let env = Env::from_program(program)?;
    let mut trace = Trace::new();
    let lens_activation_event_id = pending_lens_activation_event_id(
        &env.active_lens.lens_id,
        &env.active_lens.lens_hash,
        &program.module.0,
        &program.scope.0,
    );

    match query {
        Query::Lint { fail_on } => {
            // v0 lint: evaluate constraints to collect lint findings, then gate by fail_on.
            // Scope changes and displacement are irrelevant for lint programs.
            let meta_triggered = evaluate_meta_changes(&env, &mut trace);
            let _ = evaluate_constraints_with_provider(&env, &mut trace, provider)?;

            let (errors, warnings, infos) = lint_counts(&trace);
            let should_fail = match fail_on {
                crate::ir::LintFailOn::Error => errors > 0,
                crate::ir::LintFailOn::Warning => errors > 0 || warnings > 0,
                crate::ir::LintFailOn::Info => errors > 0 || warnings > 0 || infos > 0,
            };
            let verdict = if should_fail || meta_triggered {
                Verdict::Inadmissible
            } else {
                Verdict::Admissible
            };
            let touched = collect_invariants_from_trace(&trace);
            let inv_suffix = if touched.is_empty() {
                String::new()
            } else {
                format!(" [{}]", touched.join(", "))
            };
            let reason = format!(
                "lint: {} error(s), {} warning(s), {} info(s){}",
                errors, warnings, infos, inv_suffix
            );
            let mut witness = Witness::new(
                WitnessProgram::from_program(program),
                trace,
                crate::witness::DisplacementTrace {
                    mode: DisplacementMode::Potential,
                    totals: Vec::new(),
                    contributions: Vec::new(),
                },
                verdict,
                reason,
            );
            witness.lens_id = env.active_lens.lens_id.clone();
            witness.lens_hash = env.active_lens.lens_hash.clone();
            witness.lens_activation_event_id = lens_activation_event_id;
            Ok(witness)
        }
        Query::Admissible | Query::Witness | Query::Delta | Query::InterpretationDelta { .. } => {
            let meta_triggered = evaluate_meta_changes(&env, &mut trace);
            let boundary_triggered = evaluate_scope_changes(&env, &mut trace);
            let displacement_trace =
                build_displacement_trace(&env, &mut trace, opts.displacement_mode.clone())?;
            let constraints_triggered =
                evaluate_constraints_with_provider(&env, &mut trace, provider)?;
            let triggered = boundary_triggered || constraints_triggered || meta_triggered;
            let verdict = if triggered {
                Verdict::Inadmissible
            } else {
                Verdict::Admissible
            };
            let touched = collect_invariants_from_trace(&trace);
            let inv_suffix = if touched.is_empty() {
                String::new()
            } else {
                format!(" [{}]", touched.join(", "))
            };
            let reason = if meta_triggered && (boundary_triggered || constraints_triggered) {
                format!(
                    "meta changes blocked; constraints triggered; unaccounted boundary change{}",
                    inv_suffix
                )
            } else if meta_triggered {
                format!("meta changes blocked{}", inv_suffix)
            } else if boundary_triggered && constraints_triggered {
                format!(
                    "constraints triggered; unaccounted boundary change{}",
                    inv_suffix
                )
            } else if boundary_triggered {
                format!("unaccounted boundary change{}", inv_suffix)
            } else if constraints_triggered {
                format!("constraints triggered{}", inv_suffix)
            } else {
                "admissible".to_string()
            };
            let mut witness = Witness::new(
                WitnessProgram::from_program(program),
                trace,
                displacement_trace,
                verdict,
                reason,
            );
            witness.lens_id = env.active_lens.lens_id.clone();
            witness.lens_hash = env.active_lens.lens_hash.clone();
            witness.lens_activation_event_id = lens_activation_event_id;
            Ok(witness)
        }
    }
}

fn evaluate_scope_changes(env: &Env, trace: &mut Trace) -> bool {
    let mut triggered = false;

    for (from, to, mode, span) in &env.scope_changes {
        trace.record(Fact::ScopeChangeUsed {
            from: from.clone(),
            to: to.clone(),
            mode: mode.clone(),
            span: span.clone(),
        });

        if matches!(mode, ScopeMode::Widen | ScopeMode::Translate) {
            let diff = boundary_loss_diff(from, to);
            let accounted = env.is_allowed(&diff) && env.erasure_rules.contains_key(&diff);
            if !accounted {
                triggered = true;
                trace.record(Fact::UnaccountedBoundaryChange {
                    from: from.clone(),
                    to: to.clone(),
                    mode: mode.clone(),
                    invariant: Some("irreversibility".to_string()),
                    span: span.clone(),
                });
            }
        }
    }

    triggered
}

fn evaluate_meta_changes(env: &Env, trace: &mut Trace) -> bool {
    let mut triggered = false;
    for change in &env.meta_changes {
        trace.record(Fact::MetaChangeChecked {
            kind: change.kind.clone(),
            from_lens_id: change.from_lens.lens_id.clone(),
            from_lens_hash: change.from_lens.lens_hash.clone(),
            to_lens_id: change.to_lens.lens_id.clone(),
            to_lens_hash: change.to_lens.lens_hash.clone(),
            synthetic_diff_id: change.synthetic_diff_id.clone(),
            span: change.span.clone(),
        });

        if !env
            .lenses
            .get(&change.from_lens.lens_id)
            .is_some_and(|hash| hash == &change.from_lens.lens_hash)
        {
            triggered = true;
            trace.record(Fact::ConstraintTriggered {
                constraint_id: None,
                invariant: Some("governance".to_string()),
                span: change.span.clone(),
            });
            continue;
        }

        if change.kind.trim().is_empty() || change.routes.is_empty() {
            triggered = true;
            trace.record(Fact::ConstraintTriggered {
                constraint_id: None,
                invariant: Some("governance".to_string()),
                span: change.span.clone(),
            });
            continue;
        }

        for route in &change.routes {
            if !env.buckets.contains(&route.bucket) {
                triggered = true;
                trace.record(Fact::ConstraintTriggered {
                    constraint_id: None,
                    invariant: Some("governance".to_string()),
                    span: change.span.clone(),
                });
            }
        }
    }
    triggered
}

fn collect_invariants_from_trace(trace: &Trace) -> Vec<String> {
    let mut set = BTreeSet::new();
    for fact in trace.facts() {
        match fact {
            Fact::ConstraintTriggered {
                invariant: Some(inv),
                ..
            }
            | Fact::LintFinding {
                invariant: Some(inv),
                ..
            }
            | Fact::UnaccountedBoundaryChange {
                invariant: Some(inv),
                ..
            } => {
                set.insert(inv.clone());
            }
            _ => {}
        }
    }
    set.into_iter().collect()
}

fn lint_counts(trace: &Trace) -> (usize, usize, usize) {
    let facts = trace.facts();
    let mut errors = 0usize;
    let mut warnings = 0usize;
    let mut infos = 0usize;
    for fact in facts {
        if let crate::witness::Fact::LintFinding { severity, .. } = fact {
            match severity {
                crate::witness::Severity::Error => errors += 1,
                crate::witness::Severity::Warning => warnings += 1,
                crate::witness::Severity::Info => infos += 1,
            }
        }
    }
    (errors, warnings, infos)
}

fn pending_lens_activation_event_id(
    lens_id: &str,
    lens_hash: &str,
    module: &str,
    scope: &str,
) -> String {
    let payload = serde_json::json!({
        "lens_hash": lens_hash,
        "lens_id": lens_id,
        "module": module,
        "scope": scope,
    });
    let mut hasher = Sha256::new();
    hasher.update(payload.to_string().as_bytes());
    format!("pending:lens_activation:{:x}", hasher.finalize())
}
