mod bool_expr;
mod boundary;
pub mod cbor;
mod constraints;
mod displacement;
mod env;
mod error;
mod eval;
mod ir;
mod predicates;
mod span;
mod symbols;
mod trace;
pub mod witness;

#[cfg(test)]
mod tests;

pub use bool_expr::*;
pub use boundary::{boundary_loss_diff, boundary_loss_diff_name};
pub use cbor::encode_canonical;
pub use constraints::evaluate_constraints;
pub use displacement::build_displacement_trace;
pub use env::Env;
pub use error::EvalError;
pub use eval::{eval, EvalOpts, FloatPolicy};
pub use ir::*;
pub use predicates::eval_pred;
pub use span::Span;
pub use symbols::*;
pub use trace::Trace;
pub use witness::*;
