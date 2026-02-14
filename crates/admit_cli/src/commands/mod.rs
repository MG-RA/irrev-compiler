//! Command implementations for admit-cli

pub mod ci_check;
pub mod engine;
pub mod git;
pub mod lint;
pub mod projection;
pub mod vault;
pub mod visualize;

pub(crate) fn current_utc_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}
