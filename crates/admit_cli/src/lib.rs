use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};

use admit_core::cbor::encode_canonical;
use admit_core::witness::Witness;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DEFAULT_WITNESS_SCHEMA_ID: &str = "admissibility-witness/1";
const DEFAULT_ARTIFACT_ROOT: &str = "out/artifacts";

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
) -> Result<ArtifactRef, DeclareCostError> {
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
) -> Result<AdmissibilityCheckedEvent, DeclareCostError> {
    let cost_event = read_cost_declared_event(ledger_path, event_id)?;
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
    })
}

pub fn execute_checked(
    ledger_path: &Path,
    artifacts_root: Option<&Path>,
    checked_event_id: &str,
    timestamp: String,
    compiler_build_id: Option<String>,
) -> Result<AdmissibilityExecutedEvent, DeclareCostError> {
    let checked_event = read_checked_event(ledger_path, checked_event_id)?;
    if checked_event.snapshot_hash.is_none() {
        return Err(DeclareCostError::SnapshotHashMissing);
    }
    let cost_event = read_cost_declared_event(ledger_path, &checked_event.cost_declared_event_id)?;
    if cost_event.snapshot_hash.is_none() {
        return Err(DeclareCostError::SnapshotHashMissing);
    }

    let checked_payload = CheckedPayload {
        event_type: checked_event.event_type.clone(),
        timestamp: checked_event.timestamp.clone(),
        cost_declared_event_id: checked_event.cost_declared_event_id.clone(),
        witness: checked_event.witness.clone(),
        compiler: checked_event.compiler.clone(),
        snapshot_hash: checked_event.snapshot_hash.clone(),
        facts_bundle_hash: checked_event.facts_bundle_hash.clone(),
        program: checked_event.program.clone(),
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
