mod bool_expr;
mod boundary;
pub mod calc_ast;
pub mod calc_eval;
pub mod calc_witness;
pub mod cbor;
mod constraints;
mod displacement;
mod env;
mod error;
mod eval;
pub mod exact_types;
pub mod git_operations;
pub mod git_witness;
pub mod hash_operations;
pub mod hash_witness;
pub mod identity_operations;
pub mod identity_witness;
mod ir;
mod lint;
pub mod plan;
mod predicates;
mod provider;
pub mod provider_registry;
pub mod provider_trait;
pub mod provider_types;
pub mod refs;
mod rules;
pub mod select_path;
mod span;
mod symbols;
mod trace;
pub mod witness;

#[cfg(test)]
mod tests;

pub use bool_expr::*;
pub use boundary::{boundary_loss_diff, boundary_loss_diff_name};
pub use cbor::{encode_canonical, encode_canonical_value};
pub use constraints::evaluate_constraints;
pub use displacement::build_displacement_trace;
pub use env::Env;
pub use error::EvalError;
pub use eval::{eval, EvalOpts, FloatPolicy};
pub use git_operations::*;
pub use git_witness::*;
pub use hash_operations::*;
pub use hash_witness::*;
pub use identity_operations::*;
pub use identity_witness::*;
pub use ir::*;
pub use lint::LintFinding;
pub use plan::*;
pub use predicates::eval_pred;
pub use provider_registry::ProviderRegistry;
pub use provider_trait::Provider;
pub use provider_types::{
    provider_pack_hash, PredicateDescriptor, PredicateEvalContext, PredicateResult,
    PredicateResultKind,
};
pub use refs::*;
pub use rules::*;
pub use select_path::*;
pub use span::Span;
pub use symbols::*;
pub use trace::Trace;
pub use witness::*;
