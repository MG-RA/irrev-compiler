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
use sha2::{Digest, Sha256};

use crate::error::EvalError;
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
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Default)]
#[serde(rename_all = "snake_case")]
pub enum PredicateResultKind {
    #[default]
    Bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PredicateDescriptor {
    /// Stable contract ID, e.g. "text.metrics/lines_exceed@1".
    #[serde(default)]
    pub predicate_id: String,
    pub name: String,
    pub doc: String,
    #[serde(default)]
    pub result_kind: PredicateResultKind,
    #[serde(default = "default_true")]
    pub emits_findings: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub param_schema: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_schema: Option<serde_json::Value>,
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

/// Snapshot-bound context passed into provider predicate evaluation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PredicateEvalContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facts: Option<Vec<Fact>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub facts_schema_id: Option<String>,
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

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize)]
struct ProviderPackPredicateIdentity {
    predicate_id: String,
    name: String,
    result_kind: PredicateResultKind,
    emits_findings: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    param_schema: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    evidence_schema: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
struct ProviderPackIdentity {
    scope_id: ScopeId,
    version: u32,
    schema_ids: Vec<String>,
    supported_phases: Vec<ProviderPhase>,
    deterministic: bool,
    closure: ClosureRequirements,
    required_approvals: Vec<String>,
    predicates: Vec<ProviderPackPredicateIdentity>,
}

fn phase_rank(phase: ProviderPhase) -> u8 {
    match phase {
        ProviderPhase::Describe => 0,
        ProviderPhase::Snapshot => 1,
        ProviderPhase::Plan => 2,
        ProviderPhase::Execute => 3,
        ProviderPhase::Verify => 4,
    }
}

fn normalized_predicate_id(desc: &ProviderDescriptor, pred: &PredicateDescriptor) -> String {
    if pred.predicate_id.trim().is_empty() {
        format!("{}/{}@{}", desc.scope_id.0, pred.name, desc.version)
    } else {
        pred.predicate_id.clone()
    }
}

/// Deterministic provider pack hash over identity-bearing descriptor fields.
///
/// `doc` text is intentionally excluded so prose edits do not change identity.
pub fn provider_pack_hash(desc: &ProviderDescriptor) -> Result<String, EvalError> {
    let mut schema_ids = desc.schema_ids.clone();
    schema_ids.sort();

    let mut supported_phases = desc.supported_phases.clone();
    supported_phases.sort_by_key(|phase| phase_rank(*phase));

    let mut required_approvals = desc.required_approvals.clone();
    required_approvals.sort();

    let mut predicates = desc
        .predicates
        .iter()
        .map(|pred| ProviderPackPredicateIdentity {
            predicate_id: normalized_predicate_id(desc, pred),
            name: pred.name.clone(),
            result_kind: pred.result_kind,
            emits_findings: pred.emits_findings,
            param_schema: pred.param_schema.clone(),
            evidence_schema: pred.evidence_schema.clone(),
        })
        .collect::<Vec<_>>();
    predicates.sort_by(|a, b| a.predicate_id.cmp(&b.predicate_id).then(a.name.cmp(&b.name)));

    let identity = ProviderPackIdentity {
        scope_id: desc.scope_id.clone(),
        version: desc.version,
        schema_ids,
        supported_phases,
        deterministic: desc.deterministic,
        closure: desc.closure.clone(),
        required_approvals,
        predicates,
    };

    let value = serde_json::to_value(&identity)
        .map_err(|err| EvalError(format!("provider pack identity encode failed: {}", err)))?;
    let cbor = crate::encode_canonical_value(&value)?;
    let mut hasher = Sha256::new();
    hasher.update(cbor);
    Ok(format!("{:x}", hasher.finalize()))
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

#[cfg(test)]
mod tests {
    use super::*;

    fn descriptor() -> ProviderDescriptor {
        ProviderDescriptor {
            scope_id: ScopeId("text.metrics".to_string()),
            version: 1,
            schema_ids: vec![
                "facts-bundle/text.metrics@1".to_string(),
                "facts-bundle/common@1".to_string(),
            ],
            supported_phases: vec![ProviderPhase::Snapshot, ProviderPhase::Describe],
            deterministic: true,
            closure: ClosureRequirements {
                requires_fs: true,
                ..ClosureRequirements::default()
            },
            required_approvals: vec!["approval/b".to_string(), "approval/a".to_string()],
            predicates: vec![
                PredicateDescriptor {
                    predicate_id: "text.metrics/todo_present@1".to_string(),
                    name: "todo_present".to_string(),
                    doc: "Doc B".to_string(),
                    result_kind: PredicateResultKind::Bool,
                    emits_findings: true,
                    param_schema: Some(serde_json::json!({
                        "type": "object",
                        "properties": {}
                    })),
                    evidence_schema: None,
                },
                PredicateDescriptor {
                    predicate_id: "text.metrics/lines_exceed@1".to_string(),
                    name: "lines_exceed".to_string(),
                    doc: "Doc A".to_string(),
                    result_kind: PredicateResultKind::Bool,
                    emits_findings: true,
                    param_schema: Some(serde_json::json!({
                        "type": "object",
                        "properties": {
                            "max_lines": { "type": "integer" }
                        }
                    })),
                    evidence_schema: Some(serde_json::json!({
                        "type": "object"
                    })),
                },
            ],
        }
    }

    #[test]
    fn provider_pack_hash_is_order_independent_for_identity_lists() {
        let a = descriptor();
        let mut b = descriptor();
        b.schema_ids.reverse();
        b.supported_phases.reverse();
        b.required_approvals.reverse();
        b.predicates.reverse();
        assert_eq!(provider_pack_hash(&a).unwrap(), provider_pack_hash(&b).unwrap());
    }

    #[test]
    fn provider_pack_hash_ignores_doc_text() {
        let a = descriptor();
        let mut b = descriptor();
        b.predicates[0].doc = "Different prose".to_string();
        b.predicates[1].doc = "Another prose".to_string();
        assert_eq!(provider_pack_hash(&a).unwrap(), provider_pack_hash(&b).unwrap());
    }

    #[test]
    fn provider_pack_hash_changes_on_semantic_field_change() {
        let a = descriptor();
        let mut b = descriptor();
        b.predicates[1].param_schema = Some(serde_json::json!({
            "type": "object",
            "properties": {
                "max_lines": { "type": "integer", "minimum": 1 }
            }
        }));
        assert_ne!(provider_pack_hash(&a).unwrap(), provider_pack_hash(&b).unwrap());
    }
}
