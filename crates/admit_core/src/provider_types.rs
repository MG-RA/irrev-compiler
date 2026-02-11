//! Vocabulary types for the Provider protocol.
//!
//! These are the shared nouns every provider speaks: descriptors, facts bundles,
//! plan bundles, execution results, and verification results. All types are pure
//! data with Serialize/Deserialize — no behaviour beyond construction.
//!
//! Design choices:
//! - Hashes and timestamps are newtypes, not bare strings, to prevent stringly-typed truth.
//! - `ProviderError` is serializable for JSON-RPC / LSP transport.
//! - `ProviderDescriptor` declares closure assumptions so `deterministic: true` is auditable.
//! - `FactsBundle.schema_id` is scope-namespaced (e.g. `"facts-bundle/ingest.dir@1"`).

use serde::{Deserialize, Serialize};

use crate::lint::LintFinding;
use crate::symbols::ScopeId;
use crate::witness::{Fact, Witness};

// ---------------------------------------------------------------------------
// Typed primitives
// ---------------------------------------------------------------------------

/// SHA-256 hex digest. Newtype prevents accidental mixing with other strings.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Sha256Hex(pub String);

impl Sha256Hex {
    pub fn new(hex: impl Into<String>) -> Self {
        Self(hex.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Sha256Hex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// RFC-3339 UTC timestamp. Newtype for type safety.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Rfc3339Timestamp(pub String);

impl Rfc3339Timestamp {
    pub fn new(ts: impl Into<String>) -> Self {
        Self(ts.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Rfc3339Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

// ---------------------------------------------------------------------------
// Phase
// ---------------------------------------------------------------------------

/// The five phases of the provider ceremony.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderPhase {
    Describe,
    Snapshot,
    Plan,
    Execute,
    Verify,
}

// ---------------------------------------------------------------------------
// Error (serializable for JSON-RPC / LSP transport)
// ---------------------------------------------------------------------------

/// Error returned by any provider method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderError {
    pub scope: ScopeId,
    pub phase: ProviderPhase,
    pub message: String,
}

impl std::fmt::Display for ProviderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "provider error [{}] in {:?}: {}",
            self.scope.0, self.phase, self.message
        )
    }
}

impl std::error::Error for ProviderError {}

// ---------------------------------------------------------------------------
// Closure assumptions
// ---------------------------------------------------------------------------

/// Declares what external resources a provider requires.
/// Makes `deterministic: true` auditable instead of vibes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClosureRequirements {
    pub requires_fs: bool,
    pub requires_network: bool,
    pub requires_db: bool,
    pub requires_process: bool,
}

// ---------------------------------------------------------------------------
// Describe
// ---------------------------------------------------------------------------

/// Declares a predicate that a provider can evaluate.
///
/// Providers declare their predicates in `ProviderDescriptor` so the kernel
/// can dispatch generically without hardcoding extension predicates in the IR.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredicateDescriptor {
    pub name: String,
    pub doc: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param_schema: Option<serde_json::Value>,
}

/// Result of evaluating a provider predicate.
///
/// The provider returns findings; the evaluator records them into the trace.
/// `triggered` is the boolean result used in constraint evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredicateResult {
    pub triggered: bool,
    pub findings: Vec<LintFinding>,
}

/// Identity and capability declaration returned by `Provider::describe()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderDescriptor {
    pub scope_id: ScopeId,
    pub version: u32,
    /// Scope-namespaced schema IDs (e.g. `"facts-bundle/ingest.dir@1"`).
    pub schema_ids: Vec<String>,
    pub supported_phases: Vec<ProviderPhase>,
    pub deterministic: bool,
    pub closure: ClosureRequirements,
    pub required_approvals: Vec<String>,
    /// Predicates this provider can evaluate via `eval_predicate`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub predicates: Vec<PredicateDescriptor>,
}

// ---------------------------------------------------------------------------
// Snapshot (P0 — Observe)
// ---------------------------------------------------------------------------

/// Request passed to `Provider::snapshot()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotRequest {
    pub scope_id: ScopeId,
    #[serde(default)]
    pub params: serde_json::Value,
}

/// A content-addressed bundle of facts produced by a snapshot.
///
/// `schema_id` is scope-namespaced (e.g. `"facts-bundle/ingest.dir@1"`).
/// `snapshot_hash` is the SHA-256 of the canonical (identity) encoding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FactsBundle {
    pub schema_id: String,
    pub scope_id: ScopeId,
    pub facts: Vec<Fact>,
    pub snapshot_hash: Sha256Hex,
    pub created_at: Rfc3339Timestamp,
}

/// Result of `Provider::snapshot()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotResult {
    pub facts_bundle: FactsBundle,
    pub witness: Witness,
}

// ---------------------------------------------------------------------------
// Plan (P3 prep — declare intent before execution)
// ---------------------------------------------------------------------------

/// Intent declaration passed to `Provider::plan()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanIntent {
    pub scope_id: ScopeId,
    pub description: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

/// A single step within a plan bundle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanStep {
    pub step_id: String,
    pub description: String,
    pub reversible: bool,
    #[serde(default)]
    pub params: serde_json::Value,
}

/// A plan artifact — describes proposed effects, hashable and witnessable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanBundle {
    pub schema_id: String,
    pub scope_id: ScopeId,
    pub intent_hash: Sha256Hex,
    pub steps: Vec<PlanStep>,
    pub plan_hash: Sha256Hex,
    pub created_at: Rfc3339Timestamp,
}

/// Result of `Provider::plan()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanResult {
    pub plan_bundle: PlanBundle,
    pub witness: Witness,
}

// ---------------------------------------------------------------------------
// Execute (P3 — effect against approved plan)
// ---------------------------------------------------------------------------

/// Reference to an approved plan for execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanRef {
    pub plan_hash: Sha256Hex,
    pub approval_witness_hash: Option<Sha256Hex>,
}

/// Status of an execution.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Complete,
    Partial,
    Failed,
    RolledBack,
}

/// Result of `Provider::execute()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    pub scope_id: ScopeId,
    pub plan_hash: Sha256Hex,
    pub status: ExecutionStatus,
    pub steps_completed: Vec<String>,
    pub artifact_hashes: Vec<Sha256Hex>,
    pub witness: Witness,
}

// ---------------------------------------------------------------------------
// Verify (P4 — re-check without trust)
// ---------------------------------------------------------------------------

/// Request passed to `Provider::verify()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyRequest {
    pub artifact_hash: Sha256Hex,
    pub schema_id: String,
    pub scope_id: ScopeId,
}

/// Result of `Provider::verify()`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyResult {
    pub valid: bool,
    pub hash_matches: bool,
    pub canonical_bytes_match: bool,
    pub signature_valid: Option<bool>,
    pub witness: Witness,
}
