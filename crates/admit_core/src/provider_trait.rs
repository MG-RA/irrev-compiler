//! The Provider trait — the first-class ceremony contract.
//!
//! Every scope implements this trait to participate in the provider protocol.
//! Default implementations for `plan`, `execute`, and `verify` return
//! "not supported" errors, allowing phased adoption: a provider that only
//! implements `describe` + `snapshot` compiles and works immediately.

use crate::provider_types::*;

/// First-class provider protocol. Every scope implements this.
///
/// # Contract invariants
///
/// - `execute()` MUST refuse without a valid `plan_hash`.
/// - `plan()` MUST produce a witness alongside the plan bundle.
/// - All returned artifacts use canonical encoding and are content-addressable.
/// - Providers never return strings as truth — typed artifacts only.
///
/// # Phase mapping
///
/// | Method     | Phase | Description                            |
/// |------------|-------|----------------------------------------|
/// | `describe` | —     | Identity + capability declaration      |
/// | `snapshot` | P0    | Observe world state into facts bundle  |
/// | `plan`     | P3    | Declare intent + proposed effects      |
/// | `execute`  | P3    | Execute against approved plan hash     |
/// | `verify`   | P4    | Re-check artifacts without trust       |
pub trait Provider: Send + Sync {
    /// Returns the provider's identity, capabilities, and schema versions.
    fn describe(&self) -> ProviderDescriptor;

    /// Observes world state and returns a content-addressed facts bundle.
    fn snapshot(&self, req: &SnapshotRequest) -> Result<SnapshotResult, ProviderError>;

    /// Generates a plan artifact from intent + prior snapshots.
    /// Default: returns "plan not supported".
    fn plan(
        &self,
        _intent: &PlanIntent,
        _inputs: &[SnapshotResult],
    ) -> Result<PlanResult, ProviderError> {
        Err(ProviderError {
            scope: self.describe().scope_id,
            phase: ProviderPhase::Plan,
            message: "plan not supported".into(),
        })
    }

    /// Executes against an approved plan hash.
    /// Default: returns "execute not supported".
    fn execute(&self, _plan_ref: &PlanRef) -> Result<ExecutionResult, ProviderError> {
        Err(ProviderError {
            scope: self.describe().scope_id,
            phase: ProviderPhase::Execute,
            message: "execute not supported".into(),
        })
    }

    /// Re-checks an artifact's hashes/encoding/signatures without trust.
    /// Default: returns "verify not supported".
    fn verify(&self, _req: &VerifyRequest) -> Result<VerifyResult, ProviderError> {
        Err(ProviderError {
            scope: self.describe().scope_id,
            phase: ProviderPhase::Verify,
            message: "verify not supported".into(),
        })
    }

    /// Evaluates a provider-declared predicate by name.
    ///
    /// The provider returns `PredicateResult` with a boolean and optional findings.
    /// The evaluator is responsible for recording findings into the trace.
    /// Default: returns "predicate not supported".
    fn eval_predicate(
        &self,
        name: &str,
        _params: &serde_json::Value,
    ) -> Result<PredicateResult, ProviderError> {
        Err(ProviderError {
            scope: self.describe().scope_id,
            phase: ProviderPhase::Snapshot,
            message: format!("predicate '{}' not supported by this provider", name),
        })
    }
}
