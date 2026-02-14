use std::fs;
use std::path::Path;

use admit_core::cbor::encode_canonical;
use admit_core::witness::Witness;
use serde::Serialize;

use super::artifact::{default_artifacts_dir, store_artifact};
use super::internal::{
    artifact_disk_path, decode_cbor_to_value, payload_hash, sha256_hex, DEFAULT_WITNESS_SCHEMA_ID,
};
use super::ledger::{read_checked_event, read_cost_declared_event};
use super::registry::{enforce_scope_gate, resolve_meta_registry};
use super::types::{
    AdmissibilityCheckedEvent, AdmissibilityExecutedEvent, ArtifactInput, CheckedPayload,
    CompilerRef, CostDeclaredEvent, CostDeclaredPayload, DeclareCostError, DeclareCostInput,
    ExecutedPayload, LensActivatedPayload, ProgramRef, VerifyWitnessInput, VerifyWitnessOutput,
};

// ---------------------------------------------------------------------------
// Internal witness input representation
// ---------------------------------------------------------------------------

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
        let witness = decode_cbor_to_value(&cbor_bytes).and_then(|val| {
            serde_json::from_value::<Witness>(val)
                .map_err(|err| DeclareCostError::WitnessDecode(err.to_string()))
        })?;
        ensure_witness_lens_metadata(&witness)?;
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
            ensure_witness_lens_metadata(&witness)?;
            let canonical = encode_canonical(&witness)
                .map_err(|err| DeclareCostError::CanonicalEncode(err.0))?;
            Ok(WitnessInput::from_witness(witness, canonical))
        }
        (None, Some(cbor_bytes)) => WitnessInput::from_cbor_only(input, cbor_bytes.clone()),
    }
}

fn ensure_witness_lens_metadata(witness: &Witness) -> Result<(), DeclareCostError> {
    if witness.has_activation_metadata()
        || witness
            .schema_id
            .as_deref()
            .is_some_and(|schema| schema == "admissibility-witness/1")
    {
        Ok(())
    } else {
        Err(DeclareCostError::WitnessMissingLensMetadata)
    }
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

// ---------------------------------------------------------------------------
// Public: verify witness
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Public: declare cost
// ---------------------------------------------------------------------------

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
    let artifacts_root = input.artifacts_root.unwrap_or_else(default_artifacts_dir);
    let projection = match &witness_input.witness {
        Some(witness) => Some(witness_projection_json(
            witness,
            &schema_id,
            &computed_hash,
        )?),
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

// ---------------------------------------------------------------------------
// Public: payload_for_event (used by verify.rs to recompute cost event IDs)
// ---------------------------------------------------------------------------

pub(crate) fn payload_for_event(event: &CostDeclaredEvent) -> CostDeclaredPayload {
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

// ---------------------------------------------------------------------------
// Public: check cost declared
// ---------------------------------------------------------------------------

pub fn check_cost_declared(
    ledger_path: &Path,
    artifacts_root: Option<&Path>,
    event_id: &str,
    timestamp: String,
    compiler_build_id: Option<String>,
    facts_bundle_input: Option<ArtifactInput>,
    meta_registry_path: Option<&Path>,
    scope_gate_mode: super::types::ScopeGateMode,
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
    let witness_model = decode_cbor_to_value(&cbor_bytes).and_then(|val| {
        serde_json::from_value::<Witness>(val)
            .map_err(|err| DeclareCostError::WitnessDecode(err.to_string()))
    })?;
    ensure_witness_lens_metadata(&witness_model)?;
    let requires_lens_activation = cost_event.witness.schema_id == "admissibility-witness/2"
        || witness_model
            .schema_id
            .as_deref()
            .is_some_and(|schema| schema == "admissibility-witness/2");
    let (lens_id, lens_hash, lens_activation_event_id) = if requires_lens_activation {
        let lens_id_value = if witness_model.lens_id.trim().is_empty() {
            "lens:default@0".to_string()
        } else {
            witness_model.lens_id.clone()
        };
        let lens_hash_value = if witness_model.lens_hash.trim().is_empty() {
            "lens:legacy".to_string()
        } else {
            witness_model.lens_hash.clone()
        };
        let activation_id = payload_hash(&LensActivatedPayload {
            event_type: "lens.activated".to_string(),
            timestamp: timestamp.clone(),
            lens_id: lens_id_value.clone(),
            lens_hash: lens_hash_value.clone(),
            activation_reason: Some("check".to_string()),
            program: cost_event.program.clone(),
            registry_hash: registry_hash.clone(),
        })?;
        (
            Some(lens_id_value),
            Some(lens_hash_value),
            Some(activation_id),
        )
    } else {
        (None, None, None)
    };

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
        lens_id: lens_id.clone(),
        lens_hash: lens_hash.clone(),
        lens_activation_event_id: lens_activation_event_id.clone(),
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
        lens_id,
        lens_hash,
        lens_activation_event_id,
        program: checked_payload.program,
        registry_hash,
    })
}

// ---------------------------------------------------------------------------
// Public: execute checked
// ---------------------------------------------------------------------------

pub fn execute_checked(
    ledger_path: &Path,
    artifacts_root: Option<&Path>,
    checked_event_id: &str,
    timestamp: String,
    compiler_build_id: Option<String>,
    meta_registry_path: Option<&Path>,
    scope_gate_mode: super::types::ScopeGateMode,
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
        lens_id: checked_event.lens_id.clone(),
        lens_hash: checked_event.lens_hash.clone(),
        lens_activation_event_id: checked_event.lens_activation_event_id.clone(),
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
        lens_id: checked_event.lens_id.clone(),
        lens_hash: checked_event.lens_hash.clone(),
        lens_activation_event_id: checked_event.lens_activation_event_id.clone(),
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
        lens_id: executed_payload.lens_id,
        lens_hash: executed_payload.lens_hash,
        lens_activation_event_id: executed_payload.lens_activation_event_id,
        program: executed_payload.program,
        registry_hash,
    })
}
