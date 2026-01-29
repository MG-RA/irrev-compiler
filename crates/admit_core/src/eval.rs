use crate::boundary_loss_diff;
use crate::constraints::evaluate_constraints;
use crate::displacement::build_displacement_trace;
use crate::env::Env;
use crate::error::EvalError;
use crate::ir::{Program, Query, ScopeMode};
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

pub fn eval(program: &Program, _query: Query, opts: EvalOpts) -> Result<Witness, EvalError> {
    let env = Env::from_program(program)?;
    let mut trace = Trace::new();
    let boundary_triggered = evaluate_scope_changes(&env, &mut trace);
    let displacement_trace =
        build_displacement_trace(&env, &mut trace, opts.displacement_mode.clone())?;
    let constraints_triggered = evaluate_constraints(&env, &mut trace)?;
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
