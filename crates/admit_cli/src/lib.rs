use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use admit_core::cbor::encode_canonical;
use admit_core::witness::Witness;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DEFAULT_WITNESS_SCHEMA_ID: &str = "admissibility-witness/1";
const DEFAULT_ARTIFACT_ROOT: &str = "out/artifacts";
const META_REGISTRY_SCHEMA_ID: &str = "meta-registry/0";
const META_REGISTRY_KIND: &str = "meta_registry";
const META_REGISTRY_ENV: &str = "ADMIT_META_REGISTRY";

#[derive(Debug)]
pub enum DeclareCostError {
    MissingWitnessInput,
    MultipleWitnessInputs,
    WitnessSha256Required,
    WitnessHashMismatch { expected: String, actual: String },
    WitnessDecode(String),
    CborDecode(String),
    CanonicalEncode(String),
    SnapshotHashRequired,
    SnapshotHashMissing,
    SnapshotHashMismatch { witness: String, input: String },
    SnapshotBytesRequired,
    MissingProgramRef,
    LedgerEventNotFound(String),
    LedgerEventTypeMismatch { event_id: String, found: String },
    LedgerEventIdMismatch { expected: String, actual: String },
    DuplicateEventId(String),
    CheckedEventNotFound(String),
    CheckedEventTypeMismatch { event_id: String, found: String },
    CheckedEventIdMismatch { expected: String, actual: String },
    ArtifactMissing { kind: String, sha256: String },
    Io(String),
    Json(String),
    PlanAnswersFileNotFound(String),
    PlanAnswersMissingPrompt(String),
    PlanAnswersExtraPrompt(String),
    PlanAnswersDuplicatePrompt(String),
    PlanAnswersDecode(String),
    PlanWitnessMissing(String),
    MetaRegistryMissing(String),
    MetaRegistryDecode(String),
    MetaRegistrySchemaMismatch { expected: String, found: String },
    MetaRegistryMissingSchemaId(String),
    MetaRegistryMissingScopeId(String),
    MetaRegistryDuplicateSchemaId(String),
    MetaRegistryDuplicateScopeId(String),
    MetaRegistryDuplicateStdlibModule(String),
    MetaRegistryInvalidCanonicalEncoding(String),
    MetaRegistryMissingSelfSchema,
    MetaRegistrySchemaVersionMismatch { expected: u32, found: u32 },
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
            DeclareCostError::ArtifactMissing { kind, sha256 } => write!(
                f,
                "artifact missing (kind {}, sha256 {})",
                kind, sha256
            ),
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
        }
    }
}

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
pub struct ArtifactRef {
    pub kind: String,
    pub schema_id: String,
    pub sha256: String,
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerRef {
    pub build_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramRef {
    pub module: String,
    pub scope: String,
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
    pub program: ProgramRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_hash: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetaRegistryV0 {
    pub schema_id: String,
    pub schema_version: u32,
    pub registry_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generated_at: Option<String>,
    #[serde(default)]
    pub stdlib: Vec<MetaRegistryStdlib>,
    #[serde(default)]
    pub schemas: Vec<MetaRegistrySchema>,
    #[serde(default)]
    pub scopes: Vec<MetaRegistryScope>,
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
    pub id: String,
    pub version: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeGateMode {
    Warn,
    Error,
}

#[derive(Debug, Clone)]
struct MetaRegistryResolved {
    registry: MetaRegistryV0,
    hash: String,
}

#[derive(Debug, Clone, Serialize)]
struct CostDeclaredPayload {
    event_type: String,
    timestamp: String,
    witness: ArtifactRef,
    compiler: CompilerRef,
    snapshot_ref: ArtifactRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    program_bundle_ref: Option<ArtifactRef>,
    program: ProgramRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    registry_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct CheckedPayload {
    event_type: String,
    timestamp: String,
    cost_declared_event_id: String,
    witness: ArtifactRef,
    compiler: CompilerRef,
    snapshot_ref: ArtifactRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    program_bundle_ref: Option<ArtifactRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    facts_bundle_ref: Option<ArtifactRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    facts_bundle_hash: Option<String>,
    program: ProgramRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    registry_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct ExecutedPayload {
    event_type: String,
    timestamp: String,
    cost_declared_event_id: String,
    admissibility_checked_event_id: String,
    witness: ArtifactRef,
    compiler: CompilerRef,
    snapshot_ref: ArtifactRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    snapshot_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    program_bundle_ref: Option<ArtifactRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    facts_bundle_ref: Option<ArtifactRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    facts_bundle_hash: Option<String>,
    program: ProgramRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    registry_hash: Option<String>,
}

struct WitnessInput {
    cbor_bytes: Vec<u8>,
    witness: Option<Witness>,
    program_module: String,
    program_scope: String,
    snapshot_hash: Option<String>,
}

impl WitnessInput {
    fn from_witness(witness: Witness, cbor_bytes: Vec<u8>) -> Self {
        Self {
            cbor_bytes,
            witness: Some(witness.clone()),
            program_module: witness.program.module.0,
            program_scope: witness.program.scope.0,
            snapshot_hash: witness.program.snapshot_hash,
        }
    }

    fn from_cbor_only(
        input: &DeclareCostInput,
        cbor_bytes: Vec<u8>,
    ) -> Result<Self, DeclareCostError> {
        let module = input
            .program_module
            .clone()
            .ok_or(DeclareCostError::MissingProgramRef)?;
        let scope = input
            .program_scope
            .clone()
            .ok_or(DeclareCostError::MissingProgramRef)?;
        let witness = decode_cbor_to_value(&cbor_bytes)
            .and_then(|val| {
                serde_json::from_value::<Witness>(val)
                    .map_err(|err| DeclareCostError::WitnessDecode(err.to_string()))
            })?;
        let snapshot_hash = input
            .snapshot_hash
            .clone()
            .or_else(|| witness.program.snapshot_hash.clone());

        Ok(Self {
            cbor_bytes,
            witness: Some(witness),
            program_module: module,
            program_scope: scope,
            snapshot_hash,
        })
    }
}

pub fn declare_cost(input: DeclareCostInput) -> Result<CostDeclaredEvent, DeclareCostError> {
    let witness_input = load_witness(&input)?;
    let registry_resolved = resolve_meta_registry(input.meta_registry_path.as_deref())?;
    let registry_ref = registry_resolved.as_ref().map(|r| &r.registry);
    let registry_hash = registry_resolved.as_ref().map(|r| r.hash.clone());
    let computed_hash = sha256_hex(&witness_input.cbor_bytes);
    if let Some(expected) = &input.witness_sha256 {
        if expected != &computed_hash {
            return Err(DeclareCostError::WitnessHashMismatch {
                expected: expected.clone(),
                actual: computed_hash.clone(),
            });
        }
    }

    let snapshot_hash = match (&input.snapshot_hash, &witness_input.snapshot_hash) {
        (Some(input_hash), Some(witness_hash)) if input_hash != witness_hash => {
            return Err(DeclareCostError::SnapshotHashMismatch {
                witness: witness_hash.clone(),
                input: input_hash.clone(),
            })
        }
        (Some(input_hash), _) => Some(input_hash.clone()),
        (None, Some(witness_hash)) => Some(witness_hash.clone()),
        (None, None) => return Err(DeclareCostError::SnapshotHashRequired),
    };

    let schema_id = input
        .witness_schema_id
        .unwrap_or_else(|| DEFAULT_WITNESS_SCHEMA_ID.to_string());
    let artifacts_root = input
        .artifacts_root
        .unwrap_or_else(default_artifacts_dir);
    let projection = match &witness_input.witness {
        Some(witness) => Some(witness_projection_json(witness, &schema_id, &computed_hash)?),
        None => None,
    };
    let witness_ref = store_artifact(
        &artifacts_root,
        "witness",
        &schema_id,
        &witness_input.cbor_bytes,
        "cbor",
        projection,
        registry_ref,
    )?;
    let snapshot_bytes = input
        .snapshot_canonical_bytes
        .ok_or(DeclareCostError::SnapshotBytesRequired)?;
    let snapshot_schema_id = input
        .snapshot_schema_id
        .unwrap_or_else(|| "vault-snapshot/0".to_string());
    let snapshot_ref = store_artifact(
        &artifacts_root,
        "snapshot",
        &snapshot_schema_id,
        &snapshot_bytes,
        "json",
        None,
        registry_ref,
    )?;
    let program_bundle_ref = match (
        input.program_bundle_canonical_bytes,
        input.program_bundle_schema_id,
    ) {
        (Some(bytes), Some(schema_id)) => Some(store_artifact(
            &artifacts_root,
            "program_bundle",
            &schema_id,
            &bytes,
            "json",
            None,
            registry_ref,
        )?),
        (Some(_), None) => {
            return Err(DeclareCostError::Json(
                "program_bundle schema_id required".to_string(),
            ))
        }
        _ => None,
    };

    let compiler = CompilerRef {
        build_id: input
            .compiler_build_id
            .unwrap_or_else(|| "unknown".to_string()),
    };

    let program = ProgramRef {
        module: witness_input.program_module,
        scope: witness_input.program_scope,
    };

    let payload = CostDeclaredPayload {
        event_type: "cost.declared".to_string(),
        timestamp: input.timestamp.clone(),
        witness: witness_ref.clone(),
        compiler: compiler.clone(),
        snapshot_ref: snapshot_ref.clone(),
        snapshot_hash,
        program_bundle_ref: program_bundle_ref.clone(),
        program,
        registry_hash: registry_hash.clone(),
    };

    let payload_bytes =
        serde_json::to_vec(&payload).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    let event_id = sha256_hex(&payload_bytes);

    Ok(CostDeclaredEvent {
        event_type: payload.event_type,
        event_id,
        timestamp: payload.timestamp,
        witness: payload.witness,
        compiler: payload.compiler,
        snapshot_ref: payload.snapshot_ref,
        snapshot_hash: payload.snapshot_hash,
        program_bundle_ref: payload.program_bundle_ref,
        program: payload.program,
        registry_hash,
    })
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

pub fn verify_witness(input: VerifyWitnessInput) -> Result<VerifyWitnessOutput, DeclareCostError> {
    match (input.witness_json, input.witness_cbor) {
        (None, None) => Err(DeclareCostError::MissingWitnessInput),
        (Some(_), Some(_)) => Err(DeclareCostError::MultipleWitnessInputs),
        (Some(json_bytes), None) => {
            let witness = serde_json::from_slice::<Witness>(&json_bytes)
                .map_err(|err| DeclareCostError::WitnessDecode(err.to_string()))?;
            let canonical = encode_canonical(&witness)
                .map_err(|err| DeclareCostError::CanonicalEncode(err.0))?;
            let hash = sha256_hex(&canonical);
            if let Some(expected) = input.expected_sha256 {
                if expected != hash {
                    return Err(DeclareCostError::WitnessHashMismatch {
                        expected,
                        actual: hash.clone(),
                    });
                }
            }
            Ok(VerifyWitnessOutput {
                sha256: hash,
                cbor_bytes: canonical,
            })
        }
        (None, Some(cbor_bytes)) => {
            let hash = sha256_hex(&cbor_bytes);
            if let Some(expected) = input.expected_sha256 {
                if expected != hash {
                    return Err(DeclareCostError::WitnessHashMismatch {
                        expected,
                        actual: hash.clone(),
                    });
                }
            }
            Ok(VerifyWitnessOutput {
                sha256: hash,
                cbor_bytes,
            })
        }
    }
}

pub fn append_event(
    ledger_path: &Path,
    event: &CostDeclaredEvent,
) -> Result<(), DeclareCostError> {
    if let Some(parent) = ledger_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        }
    }

    if ledger_path.exists() {
        let contents =
            fs::read_to_string(ledger_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        for line in contents.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let value: serde_json::Value =
                serde_json::from_str(line).map_err(|err| DeclareCostError::Json(err.to_string()))?;
            if value
                .get("event_id")
                .and_then(|v| v.as_str())
                .is_some_and(|id| id == event.event_id)
            {
                return Err(DeclareCostError::DuplicateEventId(event.event_id.clone()));
            }
        }
    }

    let line =
        serde_json::to_string(event).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(ledger_path)
        .and_then(|mut file| {
            use std::io::Write;
            writeln!(file, "{}", line)
        })
        .map_err(|err| DeclareCostError::Io(err.to_string()))?;

    Ok(())
}

pub fn append_checked_event(
    ledger_path: &Path,
    event: &AdmissibilityCheckedEvent,
) -> Result<(), DeclareCostError> {
    if let Some(parent) = ledger_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        }
    }

    if ledger_path.exists() {
        let contents =
            fs::read_to_string(ledger_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        for line in contents.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let value: serde_json::Value =
                serde_json::from_str(line).map_err(|err| DeclareCostError::Json(err.to_string()))?;
            if value
                .get("event_id")
                .and_then(|v| v.as_str())
                .is_some_and(|id| id == event.event_id)
            {
                return Err(DeclareCostError::DuplicateEventId(event.event_id.clone()));
            }
        }
    }

    let line =
        serde_json::to_string(event).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(ledger_path)
        .and_then(|mut file| {
            use std::io::Write;
            writeln!(file, "{}", line)
        })
        .map_err(|err| DeclareCostError::Io(err.to_string()))?;

    Ok(())
}

pub fn append_executed_event(
    ledger_path: &Path,
    event: &AdmissibilityExecutedEvent,
) -> Result<(), DeclareCostError> {
    if let Some(parent) = ledger_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        }
    }

    if ledger_path.exists() {
        let contents =
            fs::read_to_string(ledger_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        for line in contents.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let value: serde_json::Value =
                serde_json::from_str(line).map_err(|err| DeclareCostError::Json(err.to_string()))?;
            if value
                .get("event_id")
                .and_then(|v| v.as_str())
                .is_some_and(|id| id == event.event_id)
            {
                return Err(DeclareCostError::DuplicateEventId(event.event_id.clone()));
            }
        }
    }

    let line =
        serde_json::to_string(event).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(ledger_path)
        .and_then(|mut file| {
            use std::io::Write;
            writeln!(file, "{}", line)
        })
        .map_err(|err| DeclareCostError::Io(err.to_string()))?;

    Ok(())
}

pub fn read_file_bytes(path: &Path) -> Result<Vec<u8>, DeclareCostError> {
    fs::read(path).map_err(|err| DeclareCostError::Io(err.to_string()))
}

pub fn default_ledger_path() -> PathBuf {
    PathBuf::from("out/ledger.jsonl")
}

pub fn default_artifacts_dir() -> PathBuf {
    PathBuf::from(DEFAULT_ARTIFACT_ROOT)
}

fn artifact_rel_path(kind: &str, sha256: &str, ext: &str) -> String {
    format!("{}/{}.{}", kind, sha256, ext)
}

fn artifact_disk_path(root: &Path, kind: &str, sha256: &str, ext: &str) -> PathBuf {
    root.join(kind).join(format!("{}.{}", sha256, ext))
}

fn artifact_path_from_ref(root: &Path, reference: &ArtifactRef) -> PathBuf {
    if let Some(path) = &reference.path {
        return root.join(path);
    }
    root.join(&reference.kind)
        .join(format!("{}.cbor", reference.sha256))
}

fn write_bytes_if_missing(path: &Path, bytes: &[u8]) -> Result<(), DeclareCostError> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        }
    }
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, bytes).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    fs::rename(&tmp_path, path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    Ok(())
}

fn store_artifact(
    root: &Path,
    kind: &str,
    schema_id: &str,
    bytes: &[u8],
    ext: &str,
    json_projection: Option<Vec<u8>>,
    registry: Option<&MetaRegistryV0>,
) -> Result<ArtifactRef, DeclareCostError> {
    if let Some(registry) = registry {
        if !registry_allows_schema(registry, schema_id) {
            return Err(DeclareCostError::MetaRegistryMissingSchemaId(
                schema_id.to_string(),
            ));
        }
    }
    let sha256 = sha256_hex(bytes);
    let data_path = artifact_disk_path(root, kind, &sha256, ext);
    write_bytes_if_missing(&data_path, bytes)?;
    if let Some(json_bytes) = json_projection {
        let json_path = artifact_disk_path(root, kind, &sha256, "json");
        write_bytes_if_missing(&json_path, &json_bytes)?;
    }
    Ok(ArtifactRef {
        kind: kind.to_string(),
        schema_id: schema_id.to_string(),
        sha256: sha256.clone(),
        size_bytes: bytes.len() as u64,
        path: Some(artifact_rel_path(kind, &sha256, ext)),
    })
}

fn registry_allows_schema(registry: &MetaRegistryV0, schema_id: &str) -> bool {
    registry.schemas.iter().any(|entry| entry.id == schema_id)
}

fn registry_allows_scope(registry: &MetaRegistryV0, scope_id: &str) -> bool {
    registry.scopes.iter().any(|entry| entry.id == scope_id)
}

fn enforce_scope_gate(
    registry: Option<&MetaRegistryV0>,
    scope_id: &str,
    mode: ScopeGateMode,
) -> Result<(), DeclareCostError> {
    if let Some(registry) = registry {
        if !registry_allows_scope(registry, scope_id) {
            if mode == ScopeGateMode::Error {
                return Err(DeclareCostError::MetaRegistryMissingScopeId(
                    scope_id.to_string(),
                ));
            }
        }
    }
    Ok(())
}

fn resolve_meta_registry(
    path: Option<&Path>,
) -> Result<Option<MetaRegistryResolved>, DeclareCostError> {
    let resolved_path = match path {
        Some(path) => Some(path.to_path_buf()),
        None => std::env::var(META_REGISTRY_ENV).ok().map(PathBuf::from),
    };
    let path = match resolved_path {
        Some(path) => path,
        None => return Ok(None),
    };
    if !path.exists() {
        return Err(DeclareCostError::MetaRegistryMissing(path.display().to_string()));
    }
    let bytes = fs::read(&path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    let registry_raw: MetaRegistryV0 =
        serde_json::from_slice(&bytes).map_err(|err| DeclareCostError::MetaRegistryDecode(err.to_string()))?;
    if registry_raw.schema_id != META_REGISTRY_SCHEMA_ID {
        return Err(DeclareCostError::MetaRegistrySchemaMismatch {
            expected: META_REGISTRY_SCHEMA_ID.to_string(),
            found: registry_raw.schema_id.clone(),
        });
    }
    let registry = normalize_meta_registry(registry_raw)?;
    let value =
        serde_json::to_value(&registry).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    let cbor_bytes = admit_core::encode_canonical_value(&value)
        .map_err(|err| DeclareCostError::CanonicalEncode(err.0))?;
    let hash = sha256_hex(&cbor_bytes);
    Ok(Some(MetaRegistryResolved {
        registry,
        hash,
    }))
}

fn load_meta_registry_by_hash(
    artifacts_root: &Path,
    hash: &str,
) -> Result<MetaRegistryV0, DeclareCostError> {
    let cbor_path = artifact_disk_path(artifacts_root, META_REGISTRY_KIND, hash, "cbor");
    if !cbor_path.exists() {
        return Err(DeclareCostError::ArtifactMissing {
            kind: META_REGISTRY_KIND.to_string(),
            sha256: hash.to_string(),
        });
    }
    let bytes = fs::read(&cbor_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    let value = decode_cbor_to_value(&bytes)?;
    let registry_raw = serde_json::from_value::<MetaRegistryV0>(value)
        .map_err(|err| DeclareCostError::MetaRegistryDecode(err.to_string()))?;
    if registry_raw.schema_id != META_REGISTRY_SCHEMA_ID {
        return Err(DeclareCostError::MetaRegistrySchemaMismatch {
            expected: META_REGISTRY_SCHEMA_ID.to_string(),
            found: registry_raw.schema_id,
        });
    }
    normalize_meta_registry(registry_raw)
}

fn load_registry_cached(
    cache: &mut std::collections::HashMap<String, MetaRegistryV0>,
    artifacts_root: &Path,
    hash: &str,
) -> Result<MetaRegistryV0, DeclareCostError> {
    if let Some(existing) = cache.get(hash) {
        return Ok(existing.clone());
    }
    let registry = load_meta_registry_by_hash(artifacts_root, hash)?;
    cache.insert(hash.to_string(), registry.clone());
    Ok(registry)
}

pub fn registry_init(out_path: &Path) -> Result<(), DeclareCostError> {
    if let Some(parent) = out_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        }
    }

    let registry = MetaRegistryV0 {
        schema_id: META_REGISTRY_SCHEMA_ID.to_string(),
        schema_version: 0,
        registry_version: 0,
        generated_at: None,
        stdlib: vec![MetaRegistryStdlib {
            module_id: "module:irrev_std@1".to_string(),
        }],
        schemas: vec![
            MetaRegistrySchema {
                id: META_REGISTRY_SCHEMA_ID.to_string(),
                schema_version: 0,
                kind: META_REGISTRY_KIND.to_string(),
                canonical_encoding: "canonical-cbor".to_string(),
            },
            MetaRegistrySchema {
                id: "admissibility-witness/1".to_string(),
                schema_version: 1,
                kind: "witness".to_string(),
                canonical_encoding: "canonical-cbor".to_string(),
            },
            MetaRegistrySchema {
                id: "vault-snapshot/0".to_string(),
                schema_version: 0,
                kind: "snapshot".to_string(),
                canonical_encoding: "canonical-json".to_string(),
            },
            MetaRegistrySchema {
                id: "program-bundle/0".to_string(),
                schema_version: 0,
                kind: "program_bundle".to_string(),
                canonical_encoding: "canonical-json".to_string(),
            },
            MetaRegistrySchema {
                id: "facts-bundle/0".to_string(),
                schema_version: 0,
                kind: "facts_bundle".to_string(),
                canonical_encoding: "canonical-json".to_string(),
            },
            MetaRegistrySchema {
                id: "plan-witness/1".to_string(),
                schema_version: 1,
                kind: "plan_witness".to_string(),
                canonical_encoding: "canonical-cbor".to_string(),
            },
        ],
        scopes: vec![
            MetaRegistryScope {
                id: "scope:meta.registry".to_string(),
                version: 0,
            },
            MetaRegistryScope {
                id: "scope:main".to_string(),
                version: 0,
            },
        ],
    };

    let json =
        serde_json::to_string_pretty(&registry).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    fs::write(out_path, json).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    Ok(())
}

pub fn registry_build(
    input_path: &Path,
    artifacts_root: &Path,
) -> Result<ArtifactRef, DeclareCostError> {
    let bytes = fs::read(input_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    let registry_raw: MetaRegistryV0 =
        serde_json::from_slice(&bytes).map_err(|err| DeclareCostError::MetaRegistryDecode(err.to_string()))?;
    if registry_raw.schema_id != META_REGISTRY_SCHEMA_ID {
        return Err(DeclareCostError::MetaRegistrySchemaMismatch {
            expected: META_REGISTRY_SCHEMA_ID.to_string(),
            found: registry_raw.schema_id.clone(),
        });
    }
    let registry = normalize_meta_registry(registry_raw)?;

    let value =
        serde_json::to_value(&registry).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    let cbor_bytes = admit_core::encode_canonical_value(&value)
        .map_err(|err| DeclareCostError::CanonicalEncode(err.0))?;
    let json_projection =
        serde_json::to_vec(&registry).map_err(|err| DeclareCostError::Json(err.to_string()))?;

    store_artifact(
        artifacts_root,
        META_REGISTRY_KIND,
        META_REGISTRY_SCHEMA_ID,
        &cbor_bytes,
        "cbor",
        Some(json_projection),
        Some(&registry),
    )
}

fn normalize_meta_registry(
    mut registry: MetaRegistryV0,
) -> Result<MetaRegistryV0, DeclareCostError> {
    let mut stdlib_ids = std::collections::HashSet::new();
    for entry in &registry.stdlib {
        if !stdlib_ids.insert(entry.module_id.as_str()) {
            return Err(DeclareCostError::MetaRegistryDuplicateStdlibModule(
                entry.module_id.clone(),
            ));
        }
    }
    registry
        .stdlib
        .sort_by(|a, b| a.module_id.cmp(&b.module_id));

    let mut schema_ids = std::collections::HashSet::new();
    let mut has_self_schema = false;
    for entry in &registry.schemas {
        if !schema_ids.insert(entry.id.as_str()) {
            return Err(DeclareCostError::MetaRegistryDuplicateSchemaId(
                entry.id.clone(),
            ));
        }
        if entry.canonical_encoding != "canonical-cbor"
            && entry.canonical_encoding != "canonical-json"
        {
            return Err(DeclareCostError::MetaRegistryInvalidCanonicalEncoding(
                entry.canonical_encoding.clone(),
            ));
        }
        if entry.id == registry.schema_id {
            has_self_schema = true;
            if entry.schema_version != registry.schema_version {
                return Err(DeclareCostError::MetaRegistrySchemaVersionMismatch {
                    expected: registry.schema_version,
                    found: entry.schema_version,
                });
            }
        }
    }
    if !has_self_schema {
        return Err(DeclareCostError::MetaRegistryMissingSelfSchema);
    }
    registry.schemas.sort_by(|a, b| a.id.cmp(&b.id));

    let mut scope_ids = std::collections::HashSet::new();
    for entry in &registry.scopes {
        if !scope_ids.insert(entry.id.as_str()) {
            return Err(DeclareCostError::MetaRegistryDuplicateScopeId(
                entry.id.clone(),
            ));
        }
    }
    registry.scopes.sort_by(|a, b| a.id.cmp(&b.id));

    Ok(registry)
}

pub fn list_artifacts(root: &Path) -> Result<Vec<ArtifactEntry>, DeclareCostError> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut entries = Vec::new();
    for kind_entry in fs::read_dir(root).map_err(|err| DeclareCostError::Io(err.to_string()))? {
        let kind_entry = kind_entry.map_err(|err| DeclareCostError::Io(err.to_string()))?;
        if !kind_entry.file_type().map_err(|err| DeclareCostError::Io(err.to_string()))?.is_dir() {
            continue;
        }
        let kind = kind_entry
            .file_name()
            .into_string()
            .unwrap_or_else(|_| "unknown".to_string());
        for file in fs::read_dir(kind_entry.path())
            .map_err(|err| DeclareCostError::Io(err.to_string()))?
        {
            let file = file.map_err(|err| DeclareCostError::Io(err.to_string()))?;
            let path = file.path();
            let ext = match path.extension().and_then(|e| e.to_str()) {
                Some(ext) => ext,
                None => continue,
            };
            if ext != "cbor" && ext != "json" {
                continue;
            }
            let metadata =
                fs::metadata(&path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
            let sha256 = path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_string();
            if sha256.is_empty() {
                continue;
            }
            let rel_path = artifact_rel_path(&kind, &sha256, ext);
            entries.push(ArtifactEntry {
                kind: kind.clone(),
                sha256,
                size_bytes: metadata.len(),
                path: rel_path,
            });
        }
    }
    entries.sort_by(|a, b| a.kind.cmp(&b.kind).then(a.sha256.cmp(&b.sha256)));
    Ok(entries)
}

pub fn read_artifact_projection(
    root: &Path,
    kind: &str,
    sha256: &str,
) -> Result<Option<Vec<u8>>, DeclareCostError> {
    let json_path = artifact_disk_path(root, kind, sha256, "json");
    if !json_path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(&json_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    Ok(Some(bytes))
}

fn witness_projection_json(
    witness: &Witness,
    schema_id: &str,
    sha256: &str,
) -> Result<Vec<u8>, DeclareCostError> {
    #[derive(Serialize)]
    struct Projection<'a> {
        schema_id: &'a str,
        sha256: &'a str,
        witness: &'a Witness,
    }

    let projection = Projection {
        schema_id,
        sha256,
        witness,
    };
    serde_json::to_vec(&projection).map_err(|err| DeclareCostError::Json(err.to_string()))
}

fn load_witness(input: &DeclareCostInput) -> Result<WitnessInput, DeclareCostError> {
    match (&input.witness_json, &input.witness_cbor) {
        (None, None) => Err(DeclareCostError::MissingWitnessInput),
        (Some(_), Some(_)) => Err(DeclareCostError::MultipleWitnessInputs),
        (Some(json_bytes), None) => {
            if input.witness_sha256.is_none() {
                return Err(DeclareCostError::WitnessSha256Required);
            }
            let witness = serde_json::from_slice::<Witness>(json_bytes)
                .map_err(|err| DeclareCostError::WitnessDecode(err.to_string()))?;
            let canonical = encode_canonical(&witness)
                .map_err(|err| DeclareCostError::CanonicalEncode(err.0))?;
            Ok(WitnessInput::from_witness(witness, canonical))
        }
        (None, Some(cbor_bytes)) => WitnessInput::from_cbor_only(input, cbor_bytes.clone()),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

fn decode_cbor_to_value(bytes: &[u8]) -> Result<serde_json::Value, DeclareCostError> {
    let mut idx = 0usize;
    let value = decode_cbor_value(bytes, &mut idx)?;
    if idx != bytes.len() {
        return Err(DeclareCostError::CborDecode(
            "trailing bytes after CBOR value".to_string(),
        ));
    }
    Ok(value)
}

fn decode_cbor_value(
    bytes: &[u8],
    idx: &mut usize,
) -> Result<serde_json::Value, DeclareCostError> {
    let byte = read_byte(bytes, idx)?;
    let major = byte >> 5;
    let ai = byte & 0x1f;

    let val = read_ai(bytes, idx, ai)?;
    match major {
        0 => Ok(serde_json::Value::Number(
            serde_json::Number::from(val),
        )),
        1 => {
            let n = -1i64 - (val as i64);
            let num = serde_json::Number::from(n);
            Ok(serde_json::Value::Number(num))
        }
        3 => {
            let len = val as usize;
            let s = read_bytes(bytes, idx, len)?;
            let text = std::str::from_utf8(s)
                .map_err(|err| DeclareCostError::CborDecode(err.to_string()))?;
            Ok(serde_json::Value::String(text.to_string()))
        }
        4 => {
            let len = val as usize;
            let mut items = Vec::with_capacity(len);
            for _ in 0..len {
                items.push(decode_cbor_value(bytes, idx)?);
            }
            Ok(serde_json::Value::Array(items))
        }
        5 => {
            let len = val as usize;
            let mut map = serde_json::Map::new();
            for _ in 0..len {
                let key_val = decode_cbor_value(bytes, idx)?;
                let key = match key_val {
                    serde_json::Value::String(s) => s,
                    _ => {
                        return Err(DeclareCostError::CborDecode(
                            "map key is not a string".to_string(),
                        ))
                    }
                };
                let value = decode_cbor_value(bytes, idx)?;
                map.insert(key, value);
            }
            Ok(serde_json::Value::Object(map))
        }
        7 => match ai {
            20 => Ok(serde_json::Value::Bool(false)),
            21 => Ok(serde_json::Value::Bool(true)),
            22 => Ok(serde_json::Value::Null),
            _ => Err(DeclareCostError::CborDecode(
                "unsupported simple value".to_string(),
            )),
        },
        _ => Err(DeclareCostError::CborDecode(
            "unsupported CBOR major type".to_string(),
        )),
    }
}

fn verify_artifact_ref(
    root: &Path,
    reference: &ArtifactRef,
    line_no: usize,
    event_id: &Option<String>,
    event_type: &Option<String>,
    issues: &mut Vec<LedgerIssue>,
    label: &str,
) -> Option<Vec<u8>> {
    if let Some(path) = &reference.path {
        let path_obj = Path::new(path);
        let stem = path_obj.file_stem().and_then(|s| s.to_str());
        let parent = path_obj.parent().and_then(|p| p.to_str());
        if stem != Some(reference.sha256.as_str()) || parent != Some(reference.kind.as_str()) {
            issues.push(LedgerIssue {
                line: line_no,
                event_id: event_id.clone(),
                event_type: event_type.clone(),
                message: format!("{} path mismatch", label),
            });
        }
    }

    let artifact_path = artifact_path_from_ref(root, reference);
    if !artifact_path.exists() {
        issues.push(LedgerIssue {
            line: line_no,
            event_id: event_id.clone(),
            event_type: event_type.clone(),
            message: format!("{} artifact missing", label),
        });
        return None;
    }
    match fs::read(&artifact_path) {
        Ok(bytes) => {
            let hash = sha256_hex(&bytes);
            if hash != reference.sha256 {
                issues.push(LedgerIssue {
                    line: line_no,
                    event_id: event_id.clone(),
                    event_type: event_type.clone(),
                    message: format!(
                        "{} hash mismatch (expected {}, computed {})",
                        label, reference.sha256, hash
                    ),
                });
            }
            if reference.size_bytes != bytes.len() as u64 {
                issues.push(LedgerIssue {
                    line: line_no,
                    event_id: event_id.clone(),
                    event_type: event_type.clone(),
                    message: format!("{} size mismatch", label),
                });
            }
            Some(bytes)
        }
        Err(err) => {
            issues.push(LedgerIssue {
                line: line_no,
                event_id: event_id.clone(),
                event_type: event_type.clone(),
                message: format!("{} artifact read failed: {}", label, err),
            });
            None
        }
    }
}

fn read_ai(bytes: &[u8], idx: &mut usize, ai: u8) -> Result<u64, DeclareCostError> {
    match ai {
        0..=23 => Ok(ai as u64),
        24 => Ok(read_uint(bytes, idx, 1)?),
        25 => Ok(read_uint(bytes, idx, 2)?),
        26 => Ok(read_uint(bytes, idx, 4)?),
        27 => Ok(read_uint(bytes, idx, 8)?),
        _ => Err(DeclareCostError::CborDecode(
            "indefinite lengths not supported".to_string(),
        )),
    }
}

fn read_uint(bytes: &[u8], idx: &mut usize, len: usize) -> Result<u64, DeclareCostError> {
    let slice = read_bytes(bytes, idx, len)?;
    let mut value = 0u64;
    for &b in slice {
        value = (value << 8) | b as u64;
    }
    Ok(value)
}

fn read_byte(bytes: &[u8], idx: &mut usize) -> Result<u8, DeclareCostError> {
    if *idx >= bytes.len() {
        return Err(DeclareCostError::CborDecode(
            "unexpected end of input".to_string(),
        ));
    }
    let b = bytes[*idx];
    *idx += 1;
    Ok(b)
}

fn read_bytes<'a>(
    bytes: &'a [u8],
    idx: &mut usize,
    len: usize,
) -> Result<&'a [u8], DeclareCostError> {
    if *idx + len > bytes.len() {
        return Err(DeclareCostError::CborDecode(
            "unexpected end of input".to_string(),
        ));
    }
    let slice = &bytes[*idx..*idx + len];
    *idx += len;
    Ok(slice)
}

fn payload_hash<T: Serialize>(payload: &T) -> Result<String, DeclareCostError> {
    let payload_bytes =
        serde_json::to_vec(payload).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    Ok(sha256_hex(&payload_bytes))
}

fn payload_for_event(event: &CostDeclaredEvent) -> CostDeclaredPayload {
    CostDeclaredPayload {
        event_type: event.event_type.clone(),
        timestamp: event.timestamp.clone(),
        witness: event.witness.clone(),
        compiler: event.compiler.clone(),
        snapshot_ref: event.snapshot_ref.clone(),
        snapshot_hash: event.snapshot_hash.clone(),
        program_bundle_ref: event.program_bundle_ref.clone(),
        program: event.program.clone(),
        registry_hash: event.registry_hash.clone(),
    }
}

pub fn read_cost_declared_event(
    ledger_path: &Path,
    event_id: &str,
) -> Result<CostDeclaredEvent, DeclareCostError> {
    let contents =
        fs::read_to_string(ledger_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    for line in contents.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|err| DeclareCostError::Json(err.to_string()))?;
        let found_id = value.get("event_id").and_then(|v| v.as_str());
        if found_id.is_some_and(|id| id == event_id) {
            let found_type = value
                .get("event_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            if found_type != "cost.declared" {
                return Err(DeclareCostError::LedgerEventTypeMismatch {
                    event_id: event_id.to_string(),
                    found: found_type.to_string(),
                });
            }
            return serde_json::from_value::<CostDeclaredEvent>(value)
                .map_err(|err| DeclareCostError::Json(err.to_string()));
        }
    }
    Err(DeclareCostError::LedgerEventNotFound(event_id.to_string()))
}

pub fn read_checked_event(
    ledger_path: &Path,
    event_id: &str,
) -> Result<AdmissibilityCheckedEvent, DeclareCostError> {
    let contents =
        fs::read_to_string(ledger_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    for line in contents.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value =
            serde_json::from_str(line).map_err(|err| DeclareCostError::Json(err.to_string()))?;
        let found_id = value.get("event_id").and_then(|v| v.as_str());
        if found_id.is_some_and(|id| id == event_id) {
            let found_type = value
                .get("event_type")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            if found_type != "admissibility.checked" {
                return Err(DeclareCostError::CheckedEventTypeMismatch {
                    event_id: event_id.to_string(),
                    found: found_type.to_string(),
                });
            }
            return serde_json::from_value::<AdmissibilityCheckedEvent>(value)
                .map_err(|err| DeclareCostError::Json(err.to_string()));
        }
    }
    Err(DeclareCostError::CheckedEventNotFound(event_id.to_string()))
}

pub fn check_cost_declared(
    ledger_path: &Path,
    artifacts_root: Option<&Path>,
    event_id: &str,
    timestamp: String,
    compiler_build_id: Option<String>,
    facts_bundle_input: Option<ArtifactInput>,
    meta_registry_path: Option<&Path>,
    scope_gate_mode: ScopeGateMode,
) -> Result<AdmissibilityCheckedEvent, DeclareCostError> {
    let cost_event = read_cost_declared_event(ledger_path, event_id)?;
    let registry_resolved = resolve_meta_registry(meta_registry_path)?;
    let registry_ref = registry_resolved.as_ref().map(|r| &r.registry);
    let registry_hash = registry_resolved.as_ref().map(|r| r.hash.clone());
    enforce_scope_gate(registry_ref, &cost_event.program.scope, scope_gate_mode)?;
    if cost_event.snapshot_hash.is_none() {
        return Err(DeclareCostError::SnapshotHashMissing);
    }
    let payload = payload_for_event(&cost_event);
    let computed = payload_hash(&payload)?;
    if computed != cost_event.event_id {
        return Err(DeclareCostError::LedgerEventIdMismatch {
            expected: cost_event.event_id.clone(),
            actual: computed,
        });
    }

    let artifacts_root = artifacts_root
        .map(|p| p.to_path_buf())
        .unwrap_or_else(default_artifacts_dir);
    let cbor_path = artifact_disk_path(
        &artifacts_root,
        &cost_event.witness.kind,
        &cost_event.witness.sha256,
        "cbor",
    );
    if !cbor_path.exists() {
        return Err(DeclareCostError::ArtifactMissing {
            kind: cost_event.witness.kind.clone(),
            sha256: cost_event.witness.sha256.clone(),
        });
    }
    let cbor_bytes = fs::read(&cbor_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    let hash = sha256_hex(&cbor_bytes);
    if hash != cost_event.witness.sha256 {
        return Err(DeclareCostError::WitnessHashMismatch {
            expected: cost_event.witness.sha256.clone(),
            actual: hash,
        });
    }

    let witness = cost_event.witness.clone();
    let compiler = CompilerRef {
        build_id: compiler_build_id.unwrap_or_else(|| "unknown".to_string()),
    };
    let facts_bundle_ref = match facts_bundle_input {
        Some(input) => Some(store_artifact(
            &artifacts_root,
            &input.kind,
            &input.schema_id,
            &input.bytes,
            &input.ext,
            None,
            registry_ref,
        )?),
        None => None,
    };
    let facts_bundle_hash = facts_bundle_ref
        .as_ref()
        .map(|reference| reference.sha256.clone());
    let checked_payload = CheckedPayload {
        event_type: "admissibility.checked".to_string(),
        timestamp: timestamp.clone(),
        cost_declared_event_id: cost_event.event_id.clone(),
        witness,
        compiler: compiler.clone(),
        snapshot_ref: cost_event.snapshot_ref.clone(),
        snapshot_hash: cost_event.snapshot_hash.clone(),
        program_bundle_ref: cost_event.program_bundle_ref.clone(),
        facts_bundle_ref: facts_bundle_ref.clone(),
        facts_bundle_hash: facts_bundle_hash.clone(),
        program: cost_event.program.clone(),
        registry_hash: registry_hash.clone(),
    };
    let checked_event_id = payload_hash(&checked_payload)?;

    Ok(AdmissibilityCheckedEvent {
        event_type: checked_payload.event_type,
        event_id: checked_event_id,
        timestamp,
        cost_declared_event_id: checked_payload.cost_declared_event_id,
        witness: checked_payload.witness,
        compiler,
        snapshot_ref: checked_payload.snapshot_ref,
        snapshot_hash: checked_payload.snapshot_hash,
        program_bundle_ref: checked_payload.program_bundle_ref,
        facts_bundle_ref: checked_payload.facts_bundle_ref,
        facts_bundle_hash: checked_payload.facts_bundle_hash,
        program: checked_payload.program,
        registry_hash,
    })
}

pub fn execute_checked(
    ledger_path: &Path,
    artifacts_root: Option<&Path>,
    checked_event_id: &str,
    timestamp: String,
    compiler_build_id: Option<String>,
    meta_registry_path: Option<&Path>,
    scope_gate_mode: ScopeGateMode,
) -> Result<AdmissibilityExecutedEvent, DeclareCostError> {
    let checked_event = read_checked_event(ledger_path, checked_event_id)?;
    let registry_resolved = resolve_meta_registry(meta_registry_path)?;
    let registry_hash = registry_resolved.as_ref().map(|r| r.hash.clone());
    if checked_event.snapshot_hash.is_none() {
        return Err(DeclareCostError::SnapshotHashMissing);
    }
    let cost_event = read_cost_declared_event(ledger_path, &checked_event.cost_declared_event_id)?;
    let registry_ref = registry_resolved.as_ref().map(|r| &r.registry);
    enforce_scope_gate(registry_ref, &cost_event.program.scope, scope_gate_mode)?;
    if cost_event.snapshot_hash.is_none() {
        return Err(DeclareCostError::SnapshotHashMissing);
    }

    let checked_payload = CheckedPayload {
        event_type: checked_event.event_type.clone(),
        timestamp: checked_event.timestamp.clone(),
        cost_declared_event_id: checked_event.cost_declared_event_id.clone(),
        witness: checked_event.witness.clone(),
        compiler: checked_event.compiler.clone(),
        snapshot_ref: checked_event.snapshot_ref.clone(),
        snapshot_hash: checked_event.snapshot_hash.clone(),
        program_bundle_ref: checked_event.program_bundle_ref.clone(),
        facts_bundle_ref: checked_event.facts_bundle_ref.clone(),
        facts_bundle_hash: checked_event.facts_bundle_hash.clone(),
        program: checked_event.program.clone(),
        registry_hash: checked_event.registry_hash.clone(),
    };
    let checked_hash = payload_hash(&checked_payload)?;
    if checked_hash != checked_event.event_id {
        return Err(DeclareCostError::CheckedEventIdMismatch {
            expected: checked_event.event_id.clone(),
            actual: checked_hash,
        });
    }

    let cost_payload = payload_for_event(&cost_event);
    let cost_hash = payload_hash(&cost_payload)?;
    if cost_hash != cost_event.event_id {
        return Err(DeclareCostError::LedgerEventIdMismatch {
            expected: cost_event.event_id.clone(),
            actual: cost_hash,
        });
    }

    let artifacts_root = artifacts_root
        .map(|p| p.to_path_buf())
        .unwrap_or_else(default_artifacts_dir);
    let cbor_path = artifact_disk_path(
        &artifacts_root,
        &cost_event.witness.kind,
        &cost_event.witness.sha256,
        "cbor",
    );
    if !cbor_path.exists() {
        return Err(DeclareCostError::ArtifactMissing {
            kind: cost_event.witness.kind.clone(),
            sha256: cost_event.witness.sha256.clone(),
        });
    }
    let cbor_bytes = fs::read(&cbor_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    let hash = sha256_hex(&cbor_bytes);
    if hash != cost_event.witness.sha256 {
        return Err(DeclareCostError::WitnessHashMismatch {
            expected: cost_event.witness.sha256.clone(),
            actual: hash,
        });
    }

    let witness = cost_event.witness.clone();
    let compiler = CompilerRef {
        build_id: compiler_build_id.unwrap_or_else(|| "unknown".to_string()),
    };
    let executed_payload = ExecutedPayload {
        event_type: "admissibility.executed".to_string(),
        timestamp: timestamp.clone(),
        cost_declared_event_id: cost_event.event_id.clone(),
        admissibility_checked_event_id: checked_event.event_id.clone(),
        witness,
        compiler: compiler.clone(),
        snapshot_ref: cost_event.snapshot_ref.clone(),
        snapshot_hash: cost_event.snapshot_hash.clone(),
        program_bundle_ref: cost_event.program_bundle_ref.clone(),
        facts_bundle_ref: checked_event.facts_bundle_ref.clone(),
        facts_bundle_hash: checked_event.facts_bundle_hash.clone(),
        program: cost_event.program.clone(),
        registry_hash: registry_hash.clone(),
    };
    let event_id = payload_hash(&executed_payload)?;

    Ok(AdmissibilityExecutedEvent {
        event_type: executed_payload.event_type,
        event_id,
        timestamp,
        cost_declared_event_id: executed_payload.cost_declared_event_id,
        admissibility_checked_event_id: executed_payload.admissibility_checked_event_id,
        witness: executed_payload.witness,
        compiler,
        snapshot_ref: executed_payload.snapshot_ref,
        snapshot_hash: executed_payload.snapshot_hash,
        program_bundle_ref: executed_payload.program_bundle_ref,
        facts_bundle_ref: executed_payload.facts_bundle_ref,
        facts_bundle_hash: executed_payload.facts_bundle_hash,
        program: executed_payload.program,
        registry_hash,
    })
}

pub fn verify_ledger(
    ledger_path: &Path,
    artifacts_root: Option<&Path>,
) -> Result<LedgerReport, DeclareCostError> {
    let contents =
        fs::read_to_string(ledger_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    let artifacts_root = artifacts_root
        .map(|p| p.to_path_buf())
        .unwrap_or_else(default_artifacts_dir);
    let mut issues = Vec::new();
    let mut event_ids = std::collections::HashSet::new();
    let mut index_by_id = std::collections::HashMap::new();
    let mut cost_by_id: std::collections::HashMap<String, CostDeclaredEvent> = Default::default();
    let mut checked_by_id: std::collections::HashMap<String, AdmissibilityCheckedEvent> =
        Default::default();
    let mut executed_by_id: std::collections::HashMap<String, AdmissibilityExecutedEvent> =
        Default::default();
    let mut registry_cache: std::collections::HashMap<String, MetaRegistryV0> = Default::default();

    for (i, line) in contents.lines().enumerate() {
        let line_no = i + 1;
        if line.trim().is_empty() {
            continue;
        }
        let value: serde_json::Value = match serde_json::from_str(line) {
            Ok(val) => val,
            Err(err) => {
                issues.push(LedgerIssue {
                    line: line_no,
                    event_id: None,
                    event_type: None,
                    message: format!("invalid json: {}", err),
                });
                continue;
            }
        };
        let event_id = value
            .get("event_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let event_type = value
            .get("event_type")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        if let Some(id) = &event_id {
            if !event_ids.insert(id.clone()) {
                issues.push(LedgerIssue {
                    line: line_no,
                    event_id: event_id.clone(),
                    event_type: event_type.clone(),
                    message: "duplicate event_id".to_string(),
                });
            }
            index_by_id.insert(id.clone(), line_no);
        } else {
            issues.push(LedgerIssue {
                line: line_no,
                event_id: None,
                event_type: event_type.clone(),
                message: "missing event_id".to_string(),
            });
        }

        match event_type.as_deref() {
            Some("cost.declared") => match serde_json::from_value::<CostDeclaredEvent>(value) {
                Ok(event) => {
                    if event.snapshot_hash.is_none() {
                        issues.push(LedgerIssue {
                            line: line_no,
                            event_id: event_id.clone(),
                            event_type: event_type.clone(),
                            message: "snapshot_hash missing".to_string(),
                        });
                    }
                    let payload = payload_for_event(&event);
                    if let Ok(hash) = payload_hash(&payload) {
                        if hash != event.event_id {
                            issues.push(LedgerIssue {
                                line: line_no,
                                event_id: event_id.clone(),
                                event_type: event_type.clone(),
                                message: format!(
                                    "event_id mismatch (expected {}, computed {})",
                                    event.event_id, hash
                                ),
                            });
                        }
                    }
                    let witness_bytes = verify_artifact_ref(
                        &artifacts_root,
                        &event.witness,
                        line_no,
                        &event_id,
                        &event_type,
                        &mut issues,
                        "witness",
                    );
                    if let Some(bytes) = witness_bytes {
                        match decode_cbor_to_value(&bytes)
                            .and_then(|val| {
                                serde_json::from_value::<Witness>(val).map_err(|err| {
                                    DeclareCostError::WitnessDecode(err.to_string())
                                })
                            }) {
                            Ok(witness) => {
                                if let (Some(witness_hash), Some(event_hash)) =
                                    (&witness.program.snapshot_hash, &event.snapshot_hash)
                                {
                                    if witness_hash != event_hash {
                                        issues.push(LedgerIssue {
                                            line: line_no,
                                            event_id: event_id.clone(),
                                            event_type: event_type.clone(),
                                            message: format!(
                                                "snapshot hash mismatch (witness {}, event {})",
                                                witness_hash, event_hash
                                            ),
                                        });
                                    }
                                }
                                if witness.program.module.0 != event.program.module {
                                    issues.push(LedgerIssue {
                                        line: line_no,
                                        event_id: event_id.clone(),
                                        event_type: event_type.clone(),
                                        message: "program module mismatch".to_string(),
                                    });
                                }
                                if witness.program.scope.0 != event.program.scope {
                                    issues.push(LedgerIssue {
                                        line: line_no,
                                        event_id: event_id.clone(),
                                        event_type: event_type.clone(),
                                        message: "program scope mismatch".to_string(),
                                    });
                                }
                            }
                            Err(err) => {
                                issues.push(LedgerIssue {
                                    line: line_no,
                                    event_id: event_id.clone(),
                                    event_type: event_type.clone(),
                                    message: format!("witness cbor decode failed: {}", err),
                                });
                            }
                        }
                    }

                    let _ = verify_artifact_ref(
                        &artifacts_root,
                        &event.snapshot_ref,
                        line_no,
                        &event_id,
                        &event_type,
                        &mut issues,
                        "snapshot",
                    );
                    if let Some(hash) = &event.snapshot_hash {
                        if hash != &event.snapshot_ref.sha256 {
                            issues.push(LedgerIssue {
                                line: line_no,
                                event_id: event_id.clone(),
                                event_type: event_type.clone(),
                                message: "snapshot hash mismatch vs ref".to_string(),
                            });
                        }
                    }
                    if let Some(program_ref) = &event.program_bundle_ref {
                        let _ = verify_artifact_ref(
                            &artifacts_root,
                            program_ref,
                            line_no,
                            &event_id,
                            &event_type,
                            &mut issues,
                            "program_bundle",
                        );
                    }
                    if let Some(registry_hash) = &event.registry_hash {
                        match load_registry_cached(&mut registry_cache, &artifacts_root, registry_hash)
                        {
                            Ok(registry) => {
                            if !registry_allows_schema(&registry, &event.witness.schema_id) {
                                issues.push(LedgerIssue {
                                    line: line_no,
                                    event_id: event_id.clone(),
                                    event_type: event_type.clone(),
                                    message: format!(
                                        "registry missing schema_id for witness: {}",
                                        event.witness.schema_id
                                    ),
                                });
                            }
                            if !registry_allows_schema(&registry, &event.snapshot_ref.schema_id) {
                                issues.push(LedgerIssue {
                                    line: line_no,
                                    event_id: event_id.clone(),
                                    event_type: event_type.clone(),
                                    message: format!(
                                        "registry missing schema_id for snapshot: {}",
                                        event.snapshot_ref.schema_id
                                    ),
                                });
                            }
                            if let Some(program_ref) = &event.program_bundle_ref {
                                if !registry_allows_schema(&registry, &program_ref.schema_id) {
                                    issues.push(LedgerIssue {
                                        line: line_no,
                                        event_id: event_id.clone(),
                                        event_type: event_type.clone(),
                                        message: format!(
                                            "registry missing schema_id for program bundle: {}",
                                            program_ref.schema_id
                                        ),
                                    });
                                }
                            }
                            if !registry_allows_scope(&registry, &event.program.scope) {
                                issues.push(LedgerIssue {
                                    line: line_no,
                                    event_id: event_id.clone(),
                                    event_type: event_type.clone(),
                                    message: format!(
                                        "registry missing scope_id for program: {}",
                                        event.program.scope
                                    ),
                                });
                            }
                            }
                            Err(err) => {
                                issues.push(LedgerIssue {
                                    line: line_no,
                                    event_id: event_id.clone(),
                                    event_type: event_type.clone(),
                                    message: format!(
                                        "registry load failed (hash {}): {}",
                                        registry_hash, err
                                    ),
                                });
                            }
                        }
                    }
                    cost_by_id.insert(event.event_id.clone(), event);
                }
                Err(err) => {
                    issues.push(LedgerIssue {
                        line: line_no,
                        event_id: event_id.clone(),
                        event_type: event_type.clone(),
                        message: format!("cost.declared decode failed: {}", err),
                    });
                }
            },
            Some("admissibility.checked") => {
                match serde_json::from_value::<AdmissibilityCheckedEvent>(value) {
                    Ok(event) => {
                        if event.snapshot_hash.is_none() {
                            issues.push(LedgerIssue {
                                line: line_no,
                                event_id: event_id.clone(),
                                event_type: event_type.clone(),
                                message: "snapshot_hash missing".to_string(),
                            });
                        }
                        let payload = CheckedPayload {
                            event_type: event.event_type.clone(),
                            timestamp: event.timestamp.clone(),
                            cost_declared_event_id: event.cost_declared_event_id.clone(),
                            witness: event.witness.clone(),
                            compiler: event.compiler.clone(),
                            snapshot_ref: event.snapshot_ref.clone(),
                            snapshot_hash: event.snapshot_hash.clone(),
                            program_bundle_ref: event.program_bundle_ref.clone(),
                            facts_bundle_ref: event.facts_bundle_ref.clone(),
                            facts_bundle_hash: event.facts_bundle_hash.clone(),
                            program: event.program.clone(),
                            registry_hash: event.registry_hash.clone(),
                        };
                        if let Ok(hash) = payload_hash(&payload) {
                            if hash != event.event_id {
                                issues.push(LedgerIssue {
                                    line: line_no,
                                    event_id: event_id.clone(),
                                    event_type: event_type.clone(),
                                    message: format!(
                                        "event_id mismatch (expected {}, computed {})",
                                        event.event_id, hash
                                    ),
                                });
                            }
                        }
                        if let Some(facts_ref) = &event.facts_bundle_ref {
                            let _ = verify_artifact_ref(
                                &artifacts_root,
                                facts_ref,
                                line_no,
                                &event_id,
                                &event_type,
                                &mut issues,
                                "facts_bundle",
                            );
                        }
                        if let Some(registry_hash) = &event.registry_hash {
                            match load_registry_cached(
                                &mut registry_cache,
                                &artifacts_root,
                                registry_hash,
                            ) {
                                Ok(registry) => {
                                    if !registry_allows_schema(&registry, &event.witness.schema_id)
                                    {
                                        issues.push(LedgerIssue {
                                            line: line_no,
                                            event_id: event_id.clone(),
                                            event_type: event_type.clone(),
                                            message: format!(
                                                "registry missing schema_id for witness: {}",
                                                event.witness.schema_id
                                            ),
                                        });
                                    }
                                    if !registry_allows_schema(
                                        &registry,
                                        &event.snapshot_ref.schema_id,
                                    ) {
                                        issues.push(LedgerIssue {
                                            line: line_no,
                                            event_id: event_id.clone(),
                                            event_type: event_type.clone(),
                                            message: format!(
                                                "registry missing schema_id for snapshot: {}",
                                                event.snapshot_ref.schema_id
                                            ),
                                        });
                                    }
                                    if let Some(program_ref) = &event.program_bundle_ref {
                                        if !registry_allows_schema(
                                            &registry,
                                            &program_ref.schema_id,
                                        ) {
                                            issues.push(LedgerIssue {
                                                line: line_no,
                                                event_id: event_id.clone(),
                                                event_type: event_type.clone(),
                                                message: format!(
                                                    "registry missing schema_id for program bundle: {}",
                                                    program_ref.schema_id
                                                ),
                                            });
                                        }
                                    }
                                    if let Some(facts_ref) = &event.facts_bundle_ref {
                                        if !registry_allows_schema(
                                            &registry,
                                            &facts_ref.schema_id,
                                        ) {
                                            issues.push(LedgerIssue {
                                                line: line_no,
                                                event_id: event_id.clone(),
                                                event_type: event_type.clone(),
                                                message: format!(
                                                    "registry missing schema_id for facts bundle: {}",
                                                    facts_ref.schema_id
                                                ),
                                            });
                                        }
                                    }
                                    if !registry_allows_scope(&registry, &event.program.scope) {
                                        issues.push(LedgerIssue {
                                            line: line_no,
                                            event_id: event_id.clone(),
                                            event_type: event_type.clone(),
                                            message: format!(
                                                "registry missing scope_id for program: {}",
                                                event.program.scope
                                            ),
                                        });
                                    }
                                }
                                Err(err) => {
                                    issues.push(LedgerIssue {
                                        line: line_no,
                                        event_id: event_id.clone(),
                                        event_type: event_type.clone(),
                                        message: format!(
                                            "registry load failed (hash {}): {}",
                                            registry_hash, err
                                        ),
                                    });
                                }
                            }
                        }
                        checked_by_id.insert(event.event_id.clone(), event);
                    }
                    Err(err) => issues.push(LedgerIssue {
                        line: line_no,
                        event_id: event_id.clone(),
                        event_type: event_type.clone(),
                        message: format!("admissibility.checked decode failed: {}", err),
                    }),
                }
            }
            Some("admissibility.executed") => {
                match serde_json::from_value::<AdmissibilityExecutedEvent>(value) {
                    Ok(event) => {
                        if event.snapshot_hash.is_none() {
                            issues.push(LedgerIssue {
                                line: line_no,
                                event_id: event_id.clone(),
                                event_type: event_type.clone(),
                                message: "snapshot_hash missing".to_string(),
                            });
                        }
                        let payload = ExecutedPayload {
                            event_type: event.event_type.clone(),
                            timestamp: event.timestamp.clone(),
                            cost_declared_event_id: event.cost_declared_event_id.clone(),
                            admissibility_checked_event_id: event.admissibility_checked_event_id.clone(),
                            witness: event.witness.clone(),
                            compiler: event.compiler.clone(),
                            snapshot_ref: event.snapshot_ref.clone(),
                            snapshot_hash: event.snapshot_hash.clone(),
                            program_bundle_ref: event.program_bundle_ref.clone(),
                            facts_bundle_ref: event.facts_bundle_ref.clone(),
                            facts_bundle_hash: event.facts_bundle_hash.clone(),
                            program: event.program.clone(),
                            registry_hash: event.registry_hash.clone(),
                        };
                        if let Ok(hash) = payload_hash(&payload) {
                            if hash != event.event_id {
                                issues.push(LedgerIssue {
                                    line: line_no,
                                    event_id: event_id.clone(),
                                    event_type: event_type.clone(),
                                    message: format!(
                                        "event_id mismatch (expected {}, computed {})",
                                        event.event_id, hash
                                    ),
                                });
                            }
                        }
                        if let Some(registry_hash) = &event.registry_hash {
                            match load_registry_cached(
                                &mut registry_cache,
                                &artifacts_root,
                                registry_hash,
                            ) {
                                Ok(registry) => {
                                    if !registry_allows_schema(&registry, &event.witness.schema_id)
                                    {
                                        issues.push(LedgerIssue {
                                            line: line_no,
                                            event_id: event_id.clone(),
                                            event_type: event_type.clone(),
                                            message: format!(
                                                "registry missing schema_id for witness: {}",
                                                event.witness.schema_id
                                            ),
                                        });
                                    }
                                    if !registry_allows_schema(
                                        &registry,
                                        &event.snapshot_ref.schema_id,
                                    ) {
                                        issues.push(LedgerIssue {
                                            line: line_no,
                                            event_id: event_id.clone(),
                                            event_type: event_type.clone(),
                                            message: format!(
                                                "registry missing schema_id for snapshot: {}",
                                                event.snapshot_ref.schema_id
                                            ),
                                        });
                                    }
                                    if let Some(program_ref) = &event.program_bundle_ref {
                                        if !registry_allows_schema(
                                            &registry,
                                            &program_ref.schema_id,
                                        ) {
                                            issues.push(LedgerIssue {
                                                line: line_no,
                                                event_id: event_id.clone(),
                                                event_type: event_type.clone(),
                                                message: format!(
                                                    "registry missing schema_id for program bundle: {}",
                                                    program_ref.schema_id
                                                ),
                                            });
                                        }
                                    }
                                    if let Some(facts_ref) = &event.facts_bundle_ref {
                                        if !registry_allows_schema(
                                            &registry,
                                            &facts_ref.schema_id,
                                        ) {
                                            issues.push(LedgerIssue {
                                                line: line_no,
                                                event_id: event_id.clone(),
                                                event_type: event_type.clone(),
                                                message: format!(
                                                    "registry missing schema_id for facts bundle: {}",
                                                    facts_ref.schema_id
                                                ),
                                            });
                                        }
                                    }
                                    if !registry_allows_scope(&registry, &event.program.scope) {
                                        issues.push(LedgerIssue {
                                            line: line_no,
                                            event_id: event_id.clone(),
                                            event_type: event_type.clone(),
                                            message: format!(
                                                "registry missing scope_id for program: {}",
                                                event.program.scope
                                            ),
                                        });
                                    }
                                }
                                Err(err) => {
                                    issues.push(LedgerIssue {
                                        line: line_no,
                                        event_id: event_id.clone(),
                                        event_type: event_type.clone(),
                                        message: format!(
                                            "registry load failed (hash {}): {}",
                                            registry_hash, err
                                        ),
                                    });
                                }
                            }
                        }
                        executed_by_id.insert(event.event_id.clone(), event);
                    }
                    Err(err) => issues.push(LedgerIssue {
                        line: line_no,
                        event_id: event_id.clone(),
                        event_type: event_type.clone(),
                        message: format!("admissibility.executed decode failed: {}", err),
                    }),
                }
            }
            Some("plan.created") => {
                match serde_json::from_value::<PlanCreatedEvent>(value) {
                    Ok(event) => {
                        if event.plan_witness.schema_id != PLAN_WITNESS_SCHEMA_ID {
                            issues.push(LedgerIssue {
                                line: line_no,
                                event_id: event_id.clone(),
                                event_type: event_type.clone(),
                                message: format!(
                                    "plan witness schema_id mismatch (expected {}, found {})",
                                    PLAN_WITNESS_SCHEMA_ID, event.plan_witness.schema_id
                                ),
                            });
                        }
                        let payload = PlanCreatedPayload {
                            event_type: event.event_type.clone(),
                            timestamp: event.timestamp.clone(),
                            plan_witness: event.plan_witness.clone(),
                            producer: event.producer.clone(),
                            template_id: event.template_id.clone(),
                            repro: event.repro.clone(),
                            registry_hash: event.registry_hash.clone(),
                        };
                        if let Ok(hash) = payload_hash(&payload) {
                            if hash != event.event_id {
                                issues.push(LedgerIssue {
                                    line: line_no,
                                    event_id: event_id.clone(),
                                    event_type: event_type.clone(),
                                    message: format!(
                                        "event_id mismatch (expected {}, computed {})",
                                        event.event_id, hash
                                    ),
                                });
                            }
                        }
                        let witness_bytes = verify_artifact_ref(
                            &artifacts_root,
                            &event.plan_witness,
                            line_no,
                            &event_id,
                            &event_type,
                            &mut issues,
                            "plan_witness",
                        );
                        if let Some(bytes) = witness_bytes {
                            match decode_cbor_to_value(&bytes)
                                .and_then(|val| {
                                    serde_json::from_value::<admit_core::PlanWitness>(val)
                                        .map_err(|err| DeclareCostError::Json(err.to_string()))
                                }) {
                                Ok(witness) => {
                                    if witness.schema_id != PLAN_WITNESS_SCHEMA_ID {
                                        issues.push(LedgerIssue {
                                            line: line_no,
                                            event_id: event_id.clone(),
                                            event_type: event_type.clone(),
                                            message: format!(
                                                "plan witness schema_id mismatch (expected {}, found {})",
                                                PLAN_WITNESS_SCHEMA_ID, witness.schema_id
                                            ),
                                        });
                                    }
                                    if witness.schema_id != event.plan_witness.schema_id {
                                        issues.push(LedgerIssue {
                                            line: line_no,
                                            event_id: event_id.clone(),
                                            event_type: event_type.clone(),
                                            message: "plan witness schema_id mismatch vs ref"
                                                .to_string(),
                                        });
                                    }
                                }
                                Err(err) => {
                                    issues.push(LedgerIssue {
                                        line: line_no,
                                        event_id: event_id.clone(),
                                        event_type: event_type.clone(),
                                        message: format!(
                                            "plan witness cbor decode failed: {}",
                                            err
                                        ),
                                    });
                                }
                            }
                        }
                        if let Some(registry_hash) = &event.registry_hash {
                            match load_registry_cached(
                                &mut registry_cache,
                                &artifacts_root,
                                registry_hash,
                            ) {
                                Ok(registry) => {
                                if !registry_allows_schema(&registry, &event.plan_witness.schema_id)
                                {
                                    issues.push(LedgerIssue {
                                        line: line_no,
                                        event_id: event_id.clone(),
                                        event_type: event_type.clone(),
                                        message: format!(
                                            "registry missing schema_id for plan witness: {}",
                                            event.plan_witness.schema_id
                                        ),
                                    });
                                }
                                }
                                Err(err) => {
                                    issues.push(LedgerIssue {
                                        line: line_no,
                                        event_id: event_id.clone(),
                                        event_type: event_type.clone(),
                                        message: format!(
                                            "registry load failed (hash {}): {}",
                                            registry_hash, err
                                        ),
                                    });
                                }
                            }
                        }
                    }
                    Err(err) => {
                        issues.push(LedgerIssue {
                            line: line_no,
                            event_id: event_id.clone(),
                            event_type: event_type.clone(),
                            message: format!("plan.created decode failed: {}", err),
                        });
                    }
                }
            }
            Some(other) => issues.push(LedgerIssue {
                line: line_no,
                event_id: event_id.clone(),
                event_type: Some(other.to_string()),
                message: "unknown event_type".to_string(),
            }),
            None => issues.push(LedgerIssue {
                line: line_no,
                event_id: event_id.clone(),
                event_type: None,
                message: "missing event_type".to_string(),
            }),
        }
    }

    for checked in checked_by_id.values() {
        if let Some(idx) = index_by_id.get(&checked.event_id) {
            if let Some(cost_idx) = index_by_id.get(&checked.cost_declared_event_id) {
                if cost_idx >= idx {
                    issues.push(LedgerIssue {
                        line: *idx,
                        event_id: Some(checked.event_id.clone()),
                        event_type: Some("admissibility.checked".to_string()),
                        message: "cost.declared appears after admissibility.checked".to_string(),
                    });
                }
            } else {
                issues.push(LedgerIssue {
                    line: *idx,
                    event_id: Some(checked.event_id.clone()),
                    event_type: Some("admissibility.checked".to_string()),
                    message: "missing cost.declared reference".to_string(),
                });
            }
        }
        if let Some(cost) = cost_by_id.get(&checked.cost_declared_event_id) {
            if checked.witness.sha256 != cost.witness.sha256 {
                issues.push(LedgerIssue {
                    line: index_by_id
                        .get(&checked.event_id)
                        .copied()
                        .unwrap_or(0),
                    event_id: Some(checked.event_id.clone()),
                    event_type: Some("admissibility.checked".to_string()),
                    message: "witness hash mismatch vs cost.declared".to_string(),
                });
            }
            if checked.snapshot_ref.sha256 != cost.snapshot_ref.sha256 {
                issues.push(LedgerIssue {
                    line: index_by_id
                        .get(&checked.event_id)
                        .copied()
                        .unwrap_or(0),
                    event_id: Some(checked.event_id.clone()),
                    event_type: Some("admissibility.checked".to_string()),
                    message: "snapshot ref mismatch vs cost.declared".to_string(),
                });
            }
            if checked.program_bundle_ref.as_ref().map(|r| &r.sha256)
                != cost.program_bundle_ref.as_ref().map(|r| &r.sha256)
            {
                issues.push(LedgerIssue {
                    line: index_by_id
                        .get(&checked.event_id)
                        .copied()
                        .unwrap_or(0),
                    event_id: Some(checked.event_id.clone()),
                    event_type: Some("admissibility.checked".to_string()),
                    message: "program bundle ref mismatch vs cost.declared".to_string(),
                });
            }
            if checked.snapshot_hash != cost.snapshot_hash {
                issues.push(LedgerIssue {
                    line: index_by_id
                        .get(&checked.event_id)
                        .copied()
                        .unwrap_or(0),
                    event_id: Some(checked.event_id.clone()),
                    event_type: Some("admissibility.checked".to_string()),
                    message: "snapshot hash mismatch vs cost.declared".to_string(),
                });
            }
            if let Some(facts_ref) = &checked.facts_bundle_ref {
                if let Some(hash) = &checked.facts_bundle_hash {
                    if hash != &facts_ref.sha256 {
                        issues.push(LedgerIssue {
                            line: index_by_id
                                .get(&checked.event_id)
                                .copied()
                                .unwrap_or(0),
                            event_id: Some(checked.event_id.clone()),
                            event_type: Some("admissibility.checked".to_string()),
                            message: "facts bundle hash mismatch vs ref".to_string(),
                        });
                    }
                }
            }
        }
    }

    for executed in executed_by_id.values() {
        let idx = index_by_id.get(&executed.event_id).copied().unwrap_or(0);
        if let Some(checked_idx) = index_by_id.get(&executed.admissibility_checked_event_id) {
            if checked_idx >= &idx {
                issues.push(LedgerIssue {
                    line: idx,
                    event_id: Some(executed.event_id.clone()),
                    event_type: Some("admissibility.executed".to_string()),
                    message: "admissibility.checked appears after admissibility.executed".to_string(),
                });
            }
        } else {
            issues.push(LedgerIssue {
                line: idx,
                event_id: Some(executed.event_id.clone()),
                event_type: Some("admissibility.executed".to_string()),
                message: "missing admissibility.checked reference".to_string(),
            });
        }
        if let Some(cost_idx) = index_by_id.get(&executed.cost_declared_event_id) {
            if cost_idx >= &idx {
                issues.push(LedgerIssue {
                    line: idx,
                    event_id: Some(executed.event_id.clone()),
                    event_type: Some("admissibility.executed".to_string()),
                    message: "cost.declared appears after admissibility.executed".to_string(),
                });
            }
        } else {
            issues.push(LedgerIssue {
                line: idx,
                event_id: Some(executed.event_id.clone()),
                event_type: Some("admissibility.executed".to_string()),
                message: "missing cost.declared reference".to_string(),
            });
        }
        if let Some(checked) = checked_by_id.get(&executed.admissibility_checked_event_id) {
            if executed.cost_declared_event_id != checked.cost_declared_event_id {
                issues.push(LedgerIssue {
                    line: idx,
                    event_id: Some(executed.event_id.clone()),
                    event_type: Some("admissibility.executed".to_string()),
                    message: "cost.declared id mismatch vs admissibility.checked".to_string(),
                });
            }
            if executed.witness.sha256 != checked.witness.sha256 {
                issues.push(LedgerIssue {
                    line: idx,
                    event_id: Some(executed.event_id.clone()),
                    event_type: Some("admissibility.executed".to_string()),
                    message: "witness hash mismatch vs admissibility.checked".to_string(),
                });
            }
            if executed.snapshot_ref.sha256 != checked.snapshot_ref.sha256 {
                issues.push(LedgerIssue {
                    line: idx,
                    event_id: Some(executed.event_id.clone()),
                    event_type: Some("admissibility.executed".to_string()),
                    message: "snapshot ref mismatch vs admissibility.checked".to_string(),
                });
            }
            if executed.program_bundle_ref.as_ref().map(|r| &r.sha256)
                != checked.program_bundle_ref.as_ref().map(|r| &r.sha256)
            {
                issues.push(LedgerIssue {
                    line: idx,
                    event_id: Some(executed.event_id.clone()),
                    event_type: Some("admissibility.executed".to_string()),
                    message: "program bundle ref mismatch vs admissibility.checked".to_string(),
                });
            }
            if executed.snapshot_hash != checked.snapshot_hash {
                issues.push(LedgerIssue {
                    line: idx,
                    event_id: Some(executed.event_id.clone()),
                    event_type: Some("admissibility.executed".to_string()),
                    message: "snapshot hash mismatch vs admissibility.checked".to_string(),
                });
            }
            if executed.facts_bundle_ref.as_ref().map(|r| &r.sha256)
                != checked.facts_bundle_ref.as_ref().map(|r| &r.sha256)
            {
                issues.push(LedgerIssue {
                    line: idx,
                    event_id: Some(executed.event_id.clone()),
                    event_type: Some("admissibility.executed".to_string()),
                    message: "facts bundle ref mismatch vs admissibility.checked".to_string(),
                });
            }
            if executed.facts_bundle_hash != checked.facts_bundle_hash {
                issues.push(LedgerIssue {
                    line: idx,
                    event_id: Some(executed.event_id.clone()),
                    event_type: Some("admissibility.executed".to_string()),
                    message: "facts bundle hash mismatch vs admissibility.checked".to_string(),
                });
            }
        }
    }

    Ok(LedgerReport {
        total: contents.lines().filter(|l| !l.trim().is_empty()).count(),
        issues,
    })
}

// ---------------------------------------------------------------------------
// Plan witness types and functions
// ---------------------------------------------------------------------------

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

#[derive(Debug, Clone, Serialize)]
struct PlanCreatedPayload {
    event_type: String,
    timestamp: String,
    plan_witness: ArtifactRef,
    producer: PlanProducerRef,
    template_id: String,
    repro: PlanReproRef,
    #[serde(skip_serializing_if = "Option::is_none")]
    registry_hash: Option<String>,
}

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

const PLAN_WITNESS_SCHEMA_ID: &str = "plan-witness/1";
const PLAN_TEMPLATE_ID: &str = "plan:diagnostic@1";

fn diagnostic_prompts() -> Vec<admit_core::PlanPrompt> {
    vec![
        admit_core::PlanPrompt {
            prompt_id: "action_definition".into(),
            section: 1,
            title: "Action Definition".into(),
            guidance: "What specific action is being performed? What system(s) or substrate(s) does it touch? What is the minimal description that distinguishes this action from similar ones?".into(),
        },
        admit_core::PlanPrompt {
            prompt_id: "boundary_declaration".into(),
            section: 2,
            title: "Boundary Declaration".into(),
            guidance: "What is allowed to change? What must not change? What files, records, artifacts, schemas, or external systems are in scope? What explicit paths/resources are out of bounds?".into(),
        },
        admit_core::PlanPrompt {
            prompt_id: "persistence_analysis".into(),
            section: 3,
            title: "Persistence Analysis".into(),
            guidance: "After the action completes, what differences remain even if no one uses the result? Which changes persist by default? Which changes would require active effort to undo?".into(),
        },
        admit_core::PlanPrompt {
            prompt_id: "erasure_cost".into(),
            section: 4,
            title: "Erasure Cost".into(),
            guidance: "If you attempted to undo this action, what would be lost? Classify the erasure cost: Grade 0 (fully reversible, no loss), Grade 1 (reversible with routine effort), Grade 2 (costly or lossy to reverse), Grade 3 (irreversible or externally irreversible). Describe the cost in concrete terms.".into(),
        },
        admit_core::PlanPrompt {
            prompt_id: "displacement_ownership".into(),
            section: 5,
            title: "Displacement & Ownership".into(),
            guidance: "Who absorbs the cost if reversal is required? Is the cost borne by the actor, future maintainers, users, or external systems or people? Is this displacement explicit and accepted?".into(),
        },
        admit_core::PlanPrompt {
            prompt_id: "preconditions".into(),
            section: 6,
            title: "Preconditions".into(),
            guidance: "What facts must be true before execution? What evidence is required to prove those facts? How are those facts snapshotted or attested? If a precondition cannot be witnessed, it must not be assumed.".into(),
        },
        admit_core::PlanPrompt {
            prompt_id: "execution_constraints".into(),
            section: 7,
            title: "Execution Constraints".into(),
            guidance: "What constraints must hold during execution? What failure modes are acceptable? What failures must abort the action immediately?".into(),
        },
        admit_core::PlanPrompt {
            prompt_id: "postconditions".into(),
            section: 8,
            title: "Postconditions".into(),
            guidance: "What evidence will prove what actually happened? How will success be distinguished from partial or failed execution? What artifacts or records must be produced?".into(),
        },
        admit_core::PlanPrompt {
            prompt_id: "accountability".into(),
            section: 9,
            title: "Accountability".into(),
            guidance: "Who is the acting entity? Under what authority is the action performed? What identifier ties this action to a responsible actor or system?".into(),
        },
        admit_core::PlanPrompt {
            prompt_id: "acceptance_criteria".into(),
            section: 10,
            title: "Acceptance Criteria".into(),
            guidance: "Under what conditions is the action considered done? What would count as unacceptable even if execution technically succeeded?".into(),
        },
        admit_core::PlanPrompt {
            prompt_id: "refusal_conditions".into(),
            section: 11,
            title: "Refusal Conditions".into(),
            guidance: "List conditions under which the plan must not be executed. What missing evidence or ambiguity should cause a hard stop?".into(),
        },
        admit_core::PlanPrompt {
            prompt_id: "final_check".into(),
            section: 12,
            title: "Final Check".into(),
            guidance: "Answer yes/no: Are all irreversible effects bounded? Is erasure cost explicitly declared and accepted? Is responsibility assigned without ambiguity? Could a future reader reconstruct why this action happened? If any answer is no, the plan is not admissible.".into(),
        },
    ]
}

fn derive_risks(answers: &[admit_core::PlanAnswer]) -> admit_core::DerivedRisks {
    let erasure_answer = answers
        .iter()
        .find(|a| a.prompt_id == "erasure_cost")
        .map(|a| a.answer.to_lowercase())
        .unwrap_or_default();

    let erasure_grade = match max_erasure_grade(&erasure_answer) {
        3 => admit_core::ErasureGrade::Grade3,
        2 => admit_core::ErasureGrade::Grade2,
        1 => admit_core::ErasureGrade::Grade1,
        _ => admit_core::ErasureGrade::Grade0,
    };

    let risk_label = match &erasure_grade {
        admit_core::ErasureGrade::Grade3 => "mutation_destructive",
        admit_core::ErasureGrade::Grade1 | admit_core::ErasureGrade::Grade2 => {
            "mutation_non_destructive"
        }
        admit_core::ErasureGrade::Grade0 => "none",
    }
    .to_string();

    let keywords = [
        "governance",
        "irreversibility",
        "decomposition",
        "attribution",
    ];
    let mut invariants_touched: Vec<String> = keywords
        .iter()
        .filter(|kw| {
            answers
                .iter()
                .any(|a| a.answer.to_lowercase().contains(*kw))
        })
        .map(|kw| kw.to_string())
        .collect();
    invariants_touched.sort();

    admit_core::DerivedRisks {
        erasure_grade,
        risk_label,
        invariants_touched,
    }
}

fn max_erasure_grade(answer: &str) -> u8 {
    let bytes = answer.as_bytes();
    let mut max_grade = 0u8;
    let mut i = 0usize;
    while i + 5 <= bytes.len() {
        if &bytes[i..i + 5] == b"grade" {
            let left_ok = i == 0 || !is_word_char(bytes[i - 1]);
            let mut j = i + 5;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if left_ok && j < bytes.len() && bytes[j].is_ascii_digit() {
                let digit = bytes[j] - b'0';
                let right_ok = j + 1 == bytes.len() || !is_word_char(bytes[j + 1]);
                if right_ok && digit <= 3 && digit > max_grade {
                    max_grade = digit;
                }
            }
        }
        i += 1;
    }
    max_grade
}

fn is_word_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

pub fn create_plan(input: PlanNewInput) -> Result<PlanCreatedEvent, DeclareCostError> {
    let answers_raw = fs::read(&input.answers_path).map_err(|_| {
        DeclareCostError::PlanAnswersFileNotFound(
            input.answers_path.display().to_string(),
        )
    })?;
    let answers_file_hash = sha256_hex(&answers_raw);
    let registry_resolved = resolve_meta_registry(input.meta_registry_path.as_deref())?;
    let registry_ref = registry_resolved.as_ref().map(|r| &r.registry);
    let registry_hash = registry_resolved.as_ref().map(|r| r.hash.clone());

    #[derive(Deserialize)]
    struct RawAnswer {
        prompt_id: String,
        answer: String,
    }

    let raw_answers: Vec<RawAnswer> = serde_json::from_slice(&answers_raw)
        .map_err(|err| DeclareCostError::PlanAnswersDecode(err.to_string()))?;

    let prompts = diagnostic_prompts();
    let prompt_ids: std::collections::HashSet<&str> =
        prompts.iter().map(|p| p.prompt_id.as_str()).collect();

    let mut seen_answers = std::collections::HashSet::new();
    for ra in &raw_answers {
        if !seen_answers.insert(ra.prompt_id.clone()) {
            return Err(DeclareCostError::PlanAnswersDuplicatePrompt(
                ra.prompt_id.clone(),
            ));
        }
    }

    // Check for extra answers (not in template)
    for ra in &raw_answers {
        if !prompt_ids.contains(ra.prompt_id.as_str()) {
            return Err(DeclareCostError::PlanAnswersExtraPrompt(
                ra.prompt_id.clone(),
            ));
        }
    }

    // Build answer map from input
    let answer_map: std::collections::HashMap<&str, &str> = raw_answers
        .iter()
        .map(|ra| (ra.prompt_id.as_str(), ra.answer.as_str()))
        .collect();

    // Check for missing answers and build ordered list
    let mut answers = Vec::with_capacity(prompts.len());
    for prompt in &prompts {
        let answer_text = answer_map
            .get(prompt.prompt_id.as_str())
            .ok_or_else(|| {
                DeclareCostError::PlanAnswersMissingPrompt(prompt.prompt_id.clone())
            })?;
        answers.push(admit_core::PlanAnswer {
            prompt_id: prompt.prompt_id.clone(),
            answer: answer_text.to_string(),
        });
    }

    let derived = derive_risks(&answers);

    // Compute template hash from the canonical prompts list
    let prompts_value =
        serde_json::to_value(&prompts).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    let template_bytes = admit_core::encode_canonical_value(&prompts_value)
        .map_err(|err| DeclareCostError::CanonicalEncode(err.0))?;
    let template_hash = sha256_hex(&template_bytes);

    let witness = admit_core::PlanWitness {
        schema_id: PLAN_WITNESS_SCHEMA_ID.to_string(),
        created_at: input.timestamp.clone(),
        producer: admit_core::PlanProducer {
            surface: input.surface.clone(),
            tool_version: input.tool_version.clone(),
        },
        inputs: admit_core::PlanInputs {
            template_id: PLAN_TEMPLATE_ID.to_string(),
            scope: input.scope.clone(),
            target: input.target.clone(),
        },
        template: admit_core::PlanTemplate {
            template_id: PLAN_TEMPLATE_ID.to_string(),
            template_hash: template_hash.clone(),
            prompts,
        },
        answers,
        derived,
        repro: admit_core::PlanRepro {
            snapshot_hash: input.snapshot_hash.clone(),
            template_hash: template_hash.clone(),
            answers_file_hash: answers_file_hash.clone(),
        },
    };

    let witness_value = serde_json::to_value(&witness)
        .map_err(|err| DeclareCostError::Json(err.to_string()))?;
    let cbor_bytes = admit_core::encode_canonical_value(&witness_value)
        .map_err(|err| DeclareCostError::Json(err.0))?;

    let json_projection =
        serde_json::to_vec(&witness).map_err(|err| DeclareCostError::Json(err.to_string()))?;

    let artifacts_root = input.artifacts_root.unwrap_or_else(default_artifacts_dir);
    let witness_ref = store_artifact(
        &artifacts_root,
        "plan_witness",
        PLAN_WITNESS_SCHEMA_ID,
        &cbor_bytes,
        "cbor",
        Some(json_projection),
        registry_ref,
    )?;

    let producer_ref = PlanProducerRef {
        surface: input.surface,
        tool_version: input.tool_version,
    };
    let repro_ref = PlanReproRef {
        snapshot_hash: input.snapshot_hash,
        template_hash,
        answers_file_hash,
    };

    let payload = PlanCreatedPayload {
        event_type: "plan.created".to_string(),
        timestamp: input.timestamp.clone(),
        plan_witness: witness_ref.clone(),
        producer: producer_ref.clone(),
        template_id: PLAN_TEMPLATE_ID.to_string(),
        repro: repro_ref.clone(),
        registry_hash: registry_hash.clone(),
    };
    let event_id = payload_hash(&payload)?;

    Ok(PlanCreatedEvent {
        event_type: payload.event_type,
        event_id,
        timestamp: input.timestamp,
        plan_witness: witness_ref,
        producer: producer_ref,
        template_id: PLAN_TEMPLATE_ID.to_string(),
        repro: repro_ref,
        registry_hash,
    })
}

pub fn append_plan_created_event(
    ledger_path: &Path,
    event: &PlanCreatedEvent,
) -> Result<(), DeclareCostError> {
    if let Some(parent) = ledger_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        }
    }

    if ledger_path.exists() {
        let contents =
            fs::read_to_string(ledger_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        for line in contents.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let value: serde_json::Value =
                serde_json::from_str(line).map_err(|err| DeclareCostError::Json(err.to_string()))?;
            if value
                .get("event_id")
                .and_then(|v| v.as_str())
                .is_some_and(|id| id == event.event_id)
            {
                return Err(DeclareCostError::DuplicateEventId(event.event_id.clone()));
            }
        }
    }

    let line =
        serde_json::to_string(event).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(ledger_path)
        .and_then(|mut file| {
            use std::io::Write;
            writeln!(file, "{}", line)
        })
        .map_err(|err| DeclareCostError::Io(err.to_string()))?;

    Ok(())
}

fn load_plan_witness(
    artifacts_root: &Path,
    plan_id: &str,
) -> Result<admit_core::PlanWitness, DeclareCostError> {
    // Try CBOR first
    let cbor_path = artifact_disk_path(artifacts_root, "plan_witness", plan_id, "cbor");
    if cbor_path.exists() {
        let bytes =
            fs::read(&cbor_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        let value = decode_cbor_to_value(&bytes)?;
        return serde_json::from_value::<admit_core::PlanWitness>(value)
            .map_err(|err| DeclareCostError::Json(err.to_string()));
    }
    // Fall back to JSON projection
    let json_path = artifact_disk_path(artifacts_root, "plan_witness", plan_id, "json");
    if json_path.exists() {
        let bytes =
            fs::read(&json_path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
        return serde_json::from_slice::<admit_core::PlanWitness>(&bytes)
            .map_err(|err| DeclareCostError::Json(err.to_string()));
    }
    Err(DeclareCostError::PlanWitnessMissing(plan_id.to_string()))
}

pub fn render_plan_text(
    artifacts_root: &Path,
    plan_id: &str,
) -> Result<String, DeclareCostError> {
    let witness = load_plan_witness(artifacts_root, plan_id)?;
    let mut out = String::new();

    out.push_str(&format!("plan_id={}\n", plan_id));
    out.push_str(&format!("schema_id={}\n", witness.schema_id));
    out.push_str(&format!("created_at={}\n", witness.created_at));
    out.push_str(&format!(
        "producer={}/{}\n",
        witness.producer.surface, witness.producer.tool_version
    ));
    out.push_str(&format!("scope={}\n", witness.inputs.scope));
    out.push_str(&format!("target={}\n", witness.inputs.target));
    out.push_str(&format!(
        "erasure_grade={:?}\n",
        witness.derived.erasure_grade
    ));
    out.push_str(&format!("risk_label={}\n", witness.derived.risk_label));
    out.push_str(&format!(
        "invariants_touched={}\n",
        witness.derived.invariants_touched.join(",")
    ));

    for prompt in &witness.template.prompts {
        let answer_text = witness
            .answers
            .iter()
            .find(|a| a.prompt_id == prompt.prompt_id)
            .map(|a| a.answer.as_str())
            .unwrap_or("");
        out.push_str(&format!(
            "\n--- Section {}: {} ---\n{}\n",
            prompt.section, prompt.title, answer_text
        ));
    }

    Ok(out)
}

pub fn export_plan_markdown(
    artifacts_root: &Path,
    plan_id: &str,
) -> Result<String, DeclareCostError> {
    let witness = load_plan_witness(artifacts_root, plan_id)?;
    let mut out = String::new();

    // Repro header as HTML comment (survives Markdown rendering)
    out.push_str("<!-- plan-projection\n");
    out.push_str(&format!("plan_id: {}\n", plan_id));
    out.push_str(&format!("witness_created_at: {}\n", witness.created_at));
    out.push_str(&format!("witness_hash: {}\n", plan_id));
    out.push_str("identity: plan_id == sha256(canonical_cbor(plan_witness))\n");
    out.push_str("repro: plan_witness includes created_at; to reproduce plan_id, pass the same created_at and identical answers bytes.\n");
    out.push_str(&format!("template_id: {}\n", witness.template.template_id));
    out.push_str("source: plan_witness artifact (canonical CBOR)\n");
    out.push_str(
        "NOTE: This is a projection. The CBOR artifact is the source of truth.\n",
    );
    out.push_str("-->\n\n");

    out.push_str("## Irreversibility-First Plan Design Prompt\n\n");

    for prompt in &witness.template.prompts {
        let answer_text = witness
            .answers
            .iter()
            .find(|a| a.prompt_id == prompt.prompt_id)
            .map(|a| a.answer.as_str())
            .unwrap_or("");

        out.push_str(&format!(
            "### {}. {}\n\n{}\n\n---\n\n",
            prompt.section, prompt.title, answer_text
        ));
    }

    Ok(out)
}
