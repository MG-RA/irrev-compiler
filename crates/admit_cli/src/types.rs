use std::fmt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum DeclareCostError {
    MissingWitnessInput,
    MultipleWitnessInputs,
    WitnessSha256Required,
    WitnessHashMismatch {
        expected: String,
        actual: String,
    },
    WitnessDecode(String),
    WitnessMissingLensMetadata,
    CborDecode(String),
    CanonicalEncode(String),
    SnapshotHashRequired,
    SnapshotHashMissing,
    SnapshotHashMismatch {
        witness: String,
        input: String,
    },
    SnapshotBytesRequired,
    MissingProgramRef,
    LedgerEventNotFound(String),
    LedgerEventTypeMismatch {
        event_id: String,
        found: String,
    },
    LedgerEventIdMismatch {
        expected: String,
        actual: String,
    },
    DuplicateEventId(String),
    CheckedEventNotFound(String),
    CheckedEventTypeMismatch {
        event_id: String,
        found: String,
    },
    CheckedEventIdMismatch {
        expected: String,
        actual: String,
    },
    ArtifactMissing {
        kind: String,
        sha256: String,
    },
    Io(String),
    Json(String),
    PlanAnswersFileNotFound(String),
    PlanAnswersMissingPrompt(String),
    PlanAnswersExtraPrompt(String),
    PlanAnswersDuplicatePrompt(String),
    PlanAnswersDecode(String),
    PlanMarkdownParse(String),
    PlanWitnessMissing(String),
    MetaRegistryMissing(String),
    MetaRegistryDecode(String),
    MetaRegistrySchemaMismatch {
        expected: String,
        found: String,
    },
    MetaRegistryMissingSchemaId(String),
    MetaRegistryMissingScopeId(String),
    MetaRegistryDuplicateSchemaId(String),
    MetaRegistryDuplicateScopeId(String),
    MetaRegistryDuplicateStdlibModule(String),
    MetaRegistryInvalidCanonicalEncoding(String),
    MetaRegistryMissingSelfSchema,
    MetaRegistrySchemaVersionMismatch {
        expected: u32,
        found: u32,
    },
    MetaRegistryMissingDefaultLens,
    MetaRegistryUnknownDefaultLens(String),
    MetaRegistryDuplicateLensId(String),
    MetaRegistryDuplicateLensHash(String),
    MetaRegistryDuplicateMetaChangeKind(String),
    MetaRegistryMissingCoreBucket(String),
    MetaRegistryDuplicateMetaBucket(String),
    MetaRegistryDuplicateScopePack {
        scope_id: String,
        version: u32,
    },
    MetaRegistryInvalidScopePackHash {
        scope_id: String,
        version: u32,
        hash: String,
    },
    MetaRegistryDuplicateScopePackPredicate {
        scope_id: String,
        version: u32,
        predicate_id: String,
    },
}

impl fmt::Display for DeclareCostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeclareCostError::MissingWitnessInput => {
                write!(f, "witness input missing (provide JSON or CBOR)")
            }
            DeclareCostError::MultipleWitnessInputs => {
                write!(f, "multiple witness inputs provided (JSON and CBOR)")
            }
            DeclareCostError::WitnessSha256Required => {
                write!(f, "witness_sha256 required when using JSON projection")
            }
            DeclareCostError::WitnessHashMismatch { expected, actual } => write!(
                f,
                "witness hash mismatch (expected {}, computed {})",
                expected, actual
            ),
            DeclareCostError::WitnessDecode(err) => write!(f, "witness decode error: {}", err),
            DeclareCostError::WitnessMissingLensMetadata => {
                write!(f, "witness missing required lens activation metadata")
            }
            DeclareCostError::CborDecode(err) => write!(f, "cbor decode error: {}", err),
            DeclareCostError::CanonicalEncode(err) => {
                write!(f, "canonical encoding error: {}", err)
            }
            DeclareCostError::SnapshotHashRequired => {
                write!(f, "snapshot_hash required")
            }
            DeclareCostError::SnapshotHashMissing => {
                write!(f, "snapshot_hash missing")
            }
            DeclareCostError::SnapshotHashMismatch { witness, input } => write!(
                f,
                "snapshot hash mismatch (witness {}, input {})",
                witness, input
            ),
            DeclareCostError::SnapshotBytesRequired => {
                write!(f, "snapshot canonical bytes required for artifact storage")
            }
            DeclareCostError::MissingProgramRef => {
                write!(f, "program module/scope required for CBOR-only input")
            }
            DeclareCostError::LedgerEventNotFound(event_id) => {
                write!(f, "ledger event not found: {}", event_id)
            }
            DeclareCostError::LedgerEventTypeMismatch { event_id, found } => write!(
                f,
                "ledger event type mismatch for {} (found {})",
                event_id, found
            ),
            DeclareCostError::LedgerEventIdMismatch { expected, actual } => write!(
                f,
                "ledger event id mismatch (expected {}, computed {})",
                expected, actual
            ),
            DeclareCostError::DuplicateEventId(event_id) => {
                write!(f, "event id already present in ledger: {}", event_id)
            }
            DeclareCostError::CheckedEventNotFound(event_id) => {
                write!(f, "admissibility.checked event not found: {}", event_id)
            }
            DeclareCostError::CheckedEventTypeMismatch { event_id, found } => write!(
                f,
                "admissibility.checked event type mismatch for {} (found {})",
                event_id, found
            ),
            DeclareCostError::CheckedEventIdMismatch { expected, actual } => write!(
                f,
                "admissibility.checked event id mismatch (expected {}, computed {})",
                expected, actual
            ),
            DeclareCostError::ArtifactMissing { kind, sha256 } => {
                write!(f, "artifact missing (kind {}, sha256 {})", kind, sha256)
            }
            DeclareCostError::Io(err) => write!(f, "io error: {}", err),
            DeclareCostError::Json(err) => write!(f, "json error: {}", err),
            DeclareCostError::PlanAnswersFileNotFound(path) => {
                write!(f, "plan answers file not found: {}", path)
            }
            DeclareCostError::PlanAnswersMissingPrompt(prompt_id) => {
                write!(f, "missing answer for prompt: {}", prompt_id)
            }
            DeclareCostError::PlanAnswersExtraPrompt(prompt_id) => {
                write!(f, "extra answer for unknown prompt: {}", prompt_id)
            }
            DeclareCostError::PlanAnswersDuplicatePrompt(prompt_id) => {
                write!(f, "duplicate answer for prompt: {}", prompt_id)
            }
            DeclareCostError::PlanAnswersDecode(err) => {
                write!(f, "plan answers decode error: {}", err)
            }
            DeclareCostError::PlanMarkdownParse(err) => {
                write!(f, "plan markdown parse error: {}", err)
            }
            DeclareCostError::PlanWitnessMissing(plan_id) => {
                write!(f, "plan witness not found: {}", plan_id)
            }
            DeclareCostError::MetaRegistryMissing(path) => {
                write!(f, "meta registry not found: {}", path)
            }
            DeclareCostError::MetaRegistryDecode(err) => {
                write!(f, "meta registry decode error: {}", err)
            }
            DeclareCostError::MetaRegistrySchemaMismatch { expected, found } => {
                write!(
                    f,
                    "meta registry schema_id mismatch (expected {}, found {})",
                    expected, found
                )
            }
            DeclareCostError::MetaRegistryMissingSchemaId(schema_id) => {
                write!(f, "meta registry missing schema_id: {}", schema_id)
            }
            DeclareCostError::MetaRegistryMissingScopeId(scope_id) => {
                write!(f, "meta registry missing scope_id: {}", scope_id)
            }
            DeclareCostError::MetaRegistryDuplicateSchemaId(schema_id) => {
                write!(f, "meta registry duplicate schema_id: {}", schema_id)
            }
            DeclareCostError::MetaRegistryDuplicateScopeId(scope_id) => {
                write!(f, "meta registry duplicate scope_id: {}", scope_id)
            }
            DeclareCostError::MetaRegistryDuplicateStdlibModule(module_id) => {
                write!(f, "meta registry duplicate stdlib module_id: {}", module_id)
            }
            DeclareCostError::MetaRegistryInvalidCanonicalEncoding(value) => {
                write!(f, "meta registry invalid canonical_encoding: {}", value)
            }
            DeclareCostError::MetaRegistryMissingSelfSchema => {
                write!(f, "meta registry missing self schema entry")
            }
            DeclareCostError::MetaRegistrySchemaVersionMismatch { expected, found } => {
                write!(
                    f,
                    "meta registry schema_version mismatch (expected {}, found {})",
                    expected, found
                )
            }
            DeclareCostError::MetaRegistryMissingDefaultLens => {
                write!(f, "meta registry missing default_lens")
            }
            DeclareCostError::MetaRegistryUnknownDefaultLens(lens_id) => {
                write!(
                    f,
                    "meta registry default_lens not found in lenses[]: {}",
                    lens_id
                )
            }
            DeclareCostError::MetaRegistryDuplicateLensId(lens_id) => {
                write!(f, "meta registry duplicate lens id: {}", lens_id)
            }
            DeclareCostError::MetaRegistryDuplicateLensHash(lens_hash) => {
                write!(f, "meta registry duplicate lens hash: {}", lens_hash)
            }
            DeclareCostError::MetaRegistryDuplicateMetaChangeKind(kind_id) => {
                write!(f, "meta registry duplicate meta_change kind: {}", kind_id)
            }
            DeclareCostError::MetaRegistryMissingCoreBucket(bucket_id) => {
                write!(f, "meta registry missing core bucket: {}", bucket_id)
            }
            DeclareCostError::MetaRegistryDuplicateMetaBucket(bucket_id) => {
                write!(f, "meta registry duplicate meta bucket: {}", bucket_id)
            }
            DeclareCostError::MetaRegistryDuplicateScopePack { scope_id, version } => {
                write!(
                    f,
                    "meta registry duplicate scope_pack entry for {}@{}",
                    scope_id, version
                )
            }
            DeclareCostError::MetaRegistryInvalidScopePackHash {
                scope_id,
                version,
                hash,
            } => {
                write!(
                    f,
                    "meta registry invalid scope_pack hash for {}@{}: {}",
                    scope_id, version, hash
                )
            }
            DeclareCostError::MetaRegistryDuplicateScopePackPredicate {
                scope_id,
                version,
                predicate_id,
            } => {
                write!(
                    f,
                    "meta registry duplicate scope_pack predicate for {}@{}: {}",
                    scope_id, version, predicate_id
                )
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public input / output structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DeclareCostInput {
    pub witness_json: Option<Vec<u8>>,
    pub witness_cbor: Option<Vec<u8>>,
    pub witness_sha256: Option<String>,
    pub witness_schema_id: Option<String>,
    pub compiler_build_id: Option<String>,
    pub snapshot_hash: Option<String>,
    pub snapshot_canonical_bytes: Option<Vec<u8>>,
    pub snapshot_schema_id: Option<String>,
    pub program_bundle_canonical_bytes: Option<Vec<u8>>,
    pub program_bundle_schema_id: Option<String>,
    pub program_module: Option<String>,
    pub program_scope: Option<String>,
    pub timestamp: String,
    pub artifacts_root: Option<PathBuf>,
    pub meta_registry_path: Option<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct VerifyWitnessInput {
    pub witness_json: Option<Vec<u8>>,
    pub witness_cbor: Option<Vec<u8>>,
    pub expected_sha256: Option<String>,
}

#[derive(Debug, Clone)]
pub struct VerifyWitnessOutput {
    pub sha256: String,
    pub cbor_bytes: Vec<u8>,
}

// ---------------------------------------------------------------------------
// Public event structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostDeclaredEvent {
    pub event_type: String,
    pub event_id: String,
    pub timestamp: String,
    pub witness: ArtifactRef,
    pub compiler: CompilerRef,
    pub snapshot_ref: ArtifactRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_bundle_ref: Option<ArtifactRef>,
    pub program: ProgramRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissibilityCheckedEvent {
    pub event_type: String,
    pub event_id: String,
    pub timestamp: String,
    pub cost_declared_event_id: String,
    pub witness: ArtifactRef,
    pub compiler: CompilerRef,
    pub snapshot_ref: ArtifactRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_bundle_ref: Option<ArtifactRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facts_bundle_ref: Option<ArtifactRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facts_bundle_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lens_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lens_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lens_activation_event_id: Option<String>,
    pub program: ProgramRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmissibilityExecutedEvent {
    pub event_type: String,
    pub event_id: String,
    pub timestamp: String,
    pub cost_declared_event_id: String,
    pub admissibility_checked_event_id: String,
    pub witness: ArtifactRef,
    pub compiler: CompilerRef,
    pub snapshot_ref: ArtifactRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_bundle_ref: Option<ArtifactRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facts_bundle_ref: Option<ArtifactRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facts_bundle_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lens_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lens_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lens_activation_event_id: Option<String>,
    pub program: ProgramRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LensActivatedEvent {
    pub event_type: String,
    pub event_id: String,
    pub timestamp: String,
    pub lens_id: String,
    pub lens_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activation_reason: Option<String>,
    pub program: ProgramRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaChangeCheckedEvent {
    pub event_type: String,
    pub event_id: String,
    pub timestamp: String,
    pub kind: String,
    pub from_lens_id: String,
    pub from_lens_hash: String,
    pub to_lens_id: String,
    pub to_lens_hash: String,
    pub payload_ref: String,
    pub synthetic_diff_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaInterpretationDeltaEvent {
    pub event_type: String,
    pub event_id: String,
    pub timestamp: String,
    pub from_lens_id: String,
    pub from_lens_hash: String,
    pub to_lens_id: String,
    pub to_lens_hash: String,
    pub witness: ArtifactRef,
    pub snapshot_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanCreatedEvent {
    pub event_type: String,
    pub event_id: String,
    pub timestamp: String,
    pub plan_witness: ArtifactRef,
    pub producer: PlanProducerRef,
    pub template_id: String,
    pub repro: PlanReproRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustIrLintEvent {
    pub event_type: String,
    pub event_id: String,
    pub timestamp: String,
    pub witness: ArtifactRef,
    pub scope_id: String,
    pub rule_pack: String,
    pub rules: Vec<String>,
    pub files_scanned: u64,
    pub violations: u64,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectionEvent {
    pub event_type: String,
    pub event_id: String,
    pub timestamp: String,
    pub projection_run_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projector_version: Option<String>,
    /// Optional structured metadata for projection-* admin/diagnostic events.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestEvent {
    pub event_type: String,
    pub event_id: String,
    pub timestamp: String,
    pub ingest_run_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<ArtifactRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<ArtifactRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingest_run: Option<ArtifactRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunks: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EngineEvent {
    pub event_type: String,
    pub event_id: String,
    pub timestamp: String,
    pub artifact_kind: String,
    pub artifact: ArtifactRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lang: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RustIrLintWitness {
    pub schema_id: String,
    pub schema_version: u32,
    pub created_at: String,
    pub scope_id: String,
    #[serde(alias = "court_version")]
    pub engine_version: String,
    pub input_root: String,
    pub input_id: String,
    pub input_ids: Vec<String>,
    pub config_hash: String,
    pub rule_pack: String,
    pub rules: Vec<String>,
    pub files_scanned: u64,
    pub violations: Vec<RustIrLintViolation>,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RustIrLintViolation {
    pub rule_id: String,
    pub severity: String,
    pub file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    pub message: String,
}

// ---------------------------------------------------------------------------
// Public reference / entry structs
// ---------------------------------------------------------------------------

// Re-export from admit_core for backward compatibility
pub use admit_core::{ArtifactRef, CompilerRef, ProgramRef};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanProducerRef {
    pub surface: String,
    pub tool_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanReproRef {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_hash: Option<String>,
    pub template_hash: String,
    pub answers_file_hash: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LedgerIssue {
    pub line: usize,
    pub event_id: Option<String>,
    pub event_type: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct LedgerReport {
    pub total: usize,
    pub issues: Vec<LedgerIssue>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ArtifactEntry {
    pub kind: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct ArtifactInput {
    pub kind: String,
    pub schema_id: String,
    pub bytes: Vec<u8>,
    pub ext: String,
}

// ---------------------------------------------------------------------------
// Meta registry types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaRegistryV1 {
    pub schema_id: String,
    pub schema_version: u32,
    pub registry_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    #[serde(default = "default_registry_default_lens")]
    pub default_lens: MetaRegistryDefaultLens,
    #[serde(default)]
    pub lenses: Vec<MetaRegistryLens>,
    #[serde(default)]
    pub meta_change_kinds: Vec<MetaRegistryMetaChangeKind>,
    #[serde(default)]
    pub meta_buckets: Vec<MetaRegistryMetaBucket>,
    #[serde(default)]
    pub stdlib: Vec<MetaRegistryStdlib>,
    #[serde(default)]
    pub schemas: Vec<MetaRegistrySchema>,
    #[serde(default)]
    pub scopes: Vec<MetaRegistryScope>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub scope_packs: Vec<MetaRegistryScopePack>,
}

pub type MetaRegistryV0 = MetaRegistryV1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaRegistryDefaultLens {
    pub lens_id: String,
    pub lens_hash: String,
}

fn default_registry_default_lens() -> MetaRegistryDefaultLens {
    MetaRegistryDefaultLens {
        lens_id: "lens:default@0".to_string(),
        lens_hash: "lens:default:pending".to_string(),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaRegistryLens {
    pub lens_id: String,
    pub lens_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaRegistryMetaChangeKind {
    pub kind_id: String,
    pub may_change_transform_space: bool,
    pub may_change_constraints: bool,
    pub may_change_accounting_routes: bool,
    pub may_change_permissions: bool,
    pub requires_manual_approval: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaRegistryMetaBucket {
    pub bucket_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaRegistryStdlib {
    pub module_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaRegistrySchema {
    pub id: String,
    pub schema_version: u32,
    pub kind: String,
    pub canonical_encoding: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaRegistryScope {
    // Phase 1 (required)
    // CRITICAL: id MUST NOT contain @version - version is separate field
    // Format: "scope:domain.name" (no @version suffix)
    pub id: String,
    pub version: u32,

    // Phase 2 (optional, forward-compatible)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_schema_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<ScopePhase>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub deterministic: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub foundational: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub emits: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub consumes: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub deps: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<ScopeRole>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub contract_ref: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MetaRegistryScopePack {
    pub scope_id: String,
    pub version: u32,
    pub provider_pack_hash: String,
    pub deterministic: bool,
    #[serde(default)]
    pub predicate_ids: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ScopePhase {
    P0,
    P1,
    P2,
    P3,
    P4,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScopeRole {
    Foundation,
    Transform,
    Verification,
    Governance,
    Integration,
    Application,
}

// ---------------------------------------------------------------------------
// Scope gate mode
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeGateMode {
    Warn,
    Error,
}

// ---------------------------------------------------------------------------
// Scope validation types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ScopeValidationSeverity {
    Error, // Blocks addition
    Warn,  // Doesn't block (unless strict mode)
    Info,  // Informational only
}

impl std::fmt::Display for ScopeValidationSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScopeValidationSeverity::Error => write!(f, "error"),
            ScopeValidationSeverity::Warn => write!(f, "warning"),
            ScopeValidationSeverity::Info => write!(f, "info"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeValidation {
    pub check: String,
    pub severity: ScopeValidationSeverity,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeAdditionWitness {
    pub schema_id: String, // "scope-addition-witness/0"
    pub schema_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>, // Optional canonical creation timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(alias = "court_version")]
    pub engine_version: Option<String>, // Optional producer/tool version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_id: Option<String>, // Optional canonical input identity
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>, // Optional config hash for reproducibility
    pub scope_id: String, // "scope:domain.name" (no @version)
    pub scope_version: u32,
    pub validation_timestamp: String, // ISO-8601 UTC, excluded from witness_id
    pub validations: Vec<ScopeValidation>,
    pub registry_version_before: u32,
    pub registry_version_after: u32,
    pub registry_hash_before: String, // CRITICAL: hash before mutation
    pub registry_hash_after: String,  // Hash after mutation
}

// Witness identity payload (for deterministic witness_id calculation)
// Excludes validation_timestamp and freeform messages for stable IDs
#[derive(Debug, Clone, Serialize)]
pub(crate) struct ScopeAdditionWitnessIdPayload {
    pub scope_id: String,
    pub scope_version: u32,
    pub validation_checks: Vec<String>, // Just check names, not messages
    pub registry_version_before: u32,
    pub registry_version_after: u32,
    pub registry_hash_before: String,
    pub registry_hash_after: String,
}

// ---------------------------------------------------------------------------
// Plan input
// ---------------------------------------------------------------------------

pub struct PlanNewInput {
    pub answers_path: PathBuf,
    pub scope: String,
    pub target: String,
    pub surface: String,
    pub tool_version: String,
    pub snapshot_hash: Option<String>,
    pub timestamp: String,
    pub artifacts_root: Option<PathBuf>,
    pub meta_registry_path: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Private payload structs (pub(crate) — used by witness, verify, and plan)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CostDeclaredPayload {
    pub event_type: String,
    pub timestamp: String,
    pub witness: ArtifactRef,
    pub compiler: CompilerRef,
    pub snapshot_ref: ArtifactRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_bundle_ref: Option<ArtifactRef>,
    pub program: ProgramRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct CheckedPayload {
    pub event_type: String,
    pub timestamp: String,
    pub cost_declared_event_id: String,
    pub witness: ArtifactRef,
    pub compiler: CompilerRef,
    pub snapshot_ref: ArtifactRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_bundle_ref: Option<ArtifactRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facts_bundle_ref: Option<ArtifactRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facts_bundle_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lens_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lens_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lens_activation_event_id: Option<String>,
    pub program: ProgramRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ExecutedPayload {
    pub event_type: String,
    pub timestamp: String,
    pub cost_declared_event_id: String,
    pub admissibility_checked_event_id: String,
    pub witness: ArtifactRef,
    pub compiler: CompilerRef,
    pub snapshot_ref: ArtifactRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub program_bundle_ref: Option<ArtifactRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facts_bundle_ref: Option<ArtifactRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub facts_bundle_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lens_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lens_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lens_activation_event_id: Option<String>,
    pub program: ProgramRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct LensActivatedPayload {
    pub event_type: String,
    pub timestamp: String,
    pub lens_id: String,
    pub lens_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub activation_reason: Option<String>,
    pub program: ProgramRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MetaChangeCheckedPayload {
    pub event_type: String,
    pub timestamp: String,
    pub kind: String,
    pub from_lens_id: String,
    pub from_lens_hash: String,
    pub to_lens_id: String,
    pub to_lens_hash: String,
    pub payload_ref: String,
    pub synthetic_diff_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct MetaInterpretationDeltaPayload {
    pub event_type: String,
    pub timestamp: String,
    pub from_lens_id: String,
    pub from_lens_hash: String,
    pub to_lens_id: String,
    pub to_lens_hash: String,
    pub witness: ArtifactRef,
    pub snapshot_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PlanCreatedPayload {
    pub event_type: String,
    pub timestamp: String,
    pub plan_witness: ArtifactRef,
    pub producer: PlanProducerRef,
    pub template_id: String,
    pub repro: PlanReproRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RustIrLintPayload {
    pub event_type: String,
    pub timestamp: String,
    pub witness: ArtifactRef,
    pub scope_id: String,
    pub rule_pack: String,
    pub rules: Vec<String>,
    pub files_scanned: u64,
    pub violations: u64,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct ProjectionEventPayload {
    pub event_type: String,
    pub timestamp: String,
    pub projection_run_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phase: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projector_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct IngestEventPayload {
    pub event_type: String,
    pub timestamp: String,
    pub ingest_run_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<ArtifactRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub coverage: Option<ArtifactRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingest_run: Option<ArtifactRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parse_sha256: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub files: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chunks: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct EngineEventPayload {
    pub event_type: String,
    pub timestamp: String,
    pub artifact_kind: String,
    pub artifact: ArtifactRef,
    pub name: Option<String>,
    pub lang: Option<String>,
    pub tags: Option<Vec<String>>,
}

// ---------------------------------------------------------------------------
// Registry gate error type (separate from DeclareCostError)
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum RegistryGateError {
    ScopeIdMalformed {
        scope_id: String,
        reason: String,
    },
    ScopeIdContainsVersion {
        scope_id: String,
    },
    ScopeVersionMismatch {
        id_version: u32,
        field_version: u32,
    },
    ScopeSnapshotSchemaMissing {
        scope_id: String,
        schema_id: String,
    },
    ScopeSnapshotSchemaWrongKind {
        scope_id: String,
        schema_id: String,
        found_kind: String,
    },
    ScopeEmitsSchemaUnknown {
        scope_id: String,
        schema_id: String,
    },
    ScopeConsumesSchemaUnknown {
        scope_id: String,
        schema_id: String,
    },
    ScopeDependencyCycle {
        scope_id: String,
        cycle: Vec<String>,
    },
    ScopeDependencyMissing {
        scope_id: String,
        dep_id: String,
    },
    MetaScopeMustBeComplete {
        scope_id: String,
        missing_field: String,
    },
    ValidationFailed {
        scope_id: String,
        errors: Vec<String>,
    },
    InvalidValidationLevel(String),
    Io(String),
    Json(String),
}

impl fmt::Display for RegistryGateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryGateError::ScopeIdMalformed { scope_id, reason } => {
                write!(f, "scope id malformed '{}': {}", scope_id, reason)
            }
            RegistryGateError::ScopeIdContainsVersion { scope_id } => {
                write!(
                    f,
                    "scope id '{}' contains @version (version must be in separate field)",
                    scope_id
                )
            }
            RegistryGateError::ScopeVersionMismatch {
                id_version,
                field_version,
            } => {
                write!(
                    f,
                    "scope version mismatch (id has @{}, field has {})",
                    id_version, field_version
                )
            }
            RegistryGateError::ScopeSnapshotSchemaMissing {
                scope_id,
                schema_id,
            } => {
                write!(
                    f,
                    "scope '{}' references unknown snapshot schema '{}'",
                    scope_id, schema_id
                )
            }
            RegistryGateError::ScopeSnapshotSchemaWrongKind {
                scope_id,
                schema_id,
                found_kind,
            } => {
                write!(
                    f,
                    "scope '{}' references schema '{}' as snapshot but it has kind '{}'",
                    scope_id, schema_id, found_kind
                )
            }
            RegistryGateError::ScopeEmitsSchemaUnknown {
                scope_id,
                schema_id,
            } => {
                write!(
                    f,
                    "scope '{}' emits unknown schema '{}'",
                    scope_id, schema_id
                )
            }
            RegistryGateError::ScopeConsumesSchemaUnknown {
                scope_id,
                schema_id,
            } => {
                write!(
                    f,
                    "scope '{}' consumes unknown schema '{}'",
                    scope_id, schema_id
                )
            }
            RegistryGateError::ScopeDependencyCycle { scope_id, cycle } => {
                write!(
                    f,
                    "scope '{}' creates dependency cycle: {}",
                    scope_id,
                    cycle.join(" -> ")
                )
            }
            RegistryGateError::ScopeDependencyMissing { scope_id, dep_id } => {
                write!(
                    f,
                    "scope '{}' depends on unknown scope '{}'",
                    scope_id, dep_id
                )
            }
            RegistryGateError::MetaScopeMustBeComplete {
                scope_id,
                missing_field,
            } => {
                write!(
                    f,
                    "meta scope '{}' must have all Phase 2 fields (missing: {})",
                    scope_id, missing_field
                )
            }
            RegistryGateError::ValidationFailed { scope_id, errors } => {
                write!(
                    f,
                    "scope '{}' validation failed: {}",
                    scope_id,
                    errors.join("; ")
                )
            }
            RegistryGateError::InvalidValidationLevel(level) => {
                write!(f, "invalid validation level: {}", level)
            }
            RegistryGateError::Io(err) => write!(f, "io error: {}", err),
            RegistryGateError::Json(err) => write!(f, "json error: {}", err),
        }
    }
}

impl std::error::Error for RegistryGateError {}
