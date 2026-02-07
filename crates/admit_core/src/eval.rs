use crate::boundary_loss_diff;
use crate::constraints::evaluate_constraints_with_provider;
use crate::displacement::build_displacement_trace;
use crate::env::Env;
use crate::error::EvalError;
use crate::ir::{Program, Query, ScopeMode};
use crate::provider::PredicateProvider;
use crate::trace::Trace;
use crate::witness::Fact;
use crate::witness::{DisplacementMode, Verdict, Witness, WitnessProgram};

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
    provider: Option<&dyn PredicateProvider>,
) -> Result<Witness, EvalError> {
    let env = Env::from_program(program)?;
    let mut trace = Trace::new();

    match query {
        Query::Lint { fail_on } => {
            // v0 lint: evaluate constraints to collect lint findings, then gate by fail_on.
            // Scope changes and displacement are irrelevant for lint programs.
            let _ = evaluate_constraints_with_provider(&env, &mut trace, provider)?;

            let (errors, warnings, infos) = lint_counts(&trace);
            let should_fail = match fail_on {
                crate::ir::LintFailOn::Error => errors > 0,
                crate::ir::LintFailOn::Warning => errors > 0 || warnings > 0,
                crate::ir::LintFailOn::Info => errors > 0 || warnings > 0 || infos > 0,
            };
            let verdict = if should_fail {
                Verdict::Inadmissible
            } else {
                Verdict::Admissible
            };
            let reason = format!(
                "lint: {} error(s), {} warning(s), {} info(s)",
                errors, warnings, infos
            );
            let witness = Witness::new(
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
            Ok(witness)
        }
        _ => {
            let boundary_triggered = evaluate_scope_changes(&env, &mut trace);
            let displacement_trace =
                build_displacement_trace(&env, &mut trace, opts.displacement_mode.clone())?;
            let constraints_triggered =
                evaluate_constraints_with_provider(&env, &mut trace, provider)?;
            let triggered = boundary_triggered || constraints_triggered;
            let verdict = if triggered {
                Verdict::Inadmissible
            } else {
                Verdict::Admissible
            };
            let reason = if boundary_triggered && constraints_triggered {
                "constraints triggered; unaccounted boundary change".to_string()
            } else if boundary_triggered {
                "unaccounted boundary change".to_string()
            } else if constraints_triggered {
                "constraints triggered".to_string()
            } else {
                "admissible".to_string()
            };
            let witness = Witness::new(
                WitnessProgram::from_program(program),
                trace,
                displacement_trace,
                verdict,
                reason,
            );
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
                    span: span.clone(),
                });
            }
        }
    }

    triggered
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
