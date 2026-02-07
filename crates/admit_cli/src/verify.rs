use std::fs;
use std::path::Path;

use super::artifact::default_artifacts_dir;
use super::internal::{
    artifact_path_from_ref, decode_cbor_to_value, payload_hash, sha256_hex,
    PLAN_WITNESS_SCHEMA_IDS, RUST_IR_LINT_WITNESS_SCHEMA_ID,
};
use super::registry::{load_registry_cached, registry_allows_schema, registry_allows_scope};
use super::types::{
    AdmissibilityCheckedEvent, AdmissibilityExecutedEvent, ArtifactRef, CheckedPayload,
    CostDeclaredEvent, CourtEvent, CourtEventPayload, DeclareCostError, ExecutedPayload,
    IngestEvent, IngestEventPayload, LedgerIssue, LedgerReport, PlanCreatedEvent,
    PlanCreatedPayload, ProjectionEvent, ProjectionEventPayload, RustIrLintEvent,
    RustIrLintPayload, RustIrLintWitness,
};
use super::witness::payload_for_event;

// ---------------------------------------------------------------------------
// Artifact reference integrity check
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Full ledger verification
// ---------------------------------------------------------------------------

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
    let mut registry_cache: std::collections::HashMap<String, super::types::MetaRegistryV0> =
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
                        match decode_cbor_to_value(&bytes).and_then(|val| {
                            serde_json::from_value::<admit_core::Witness>(val)
                                .map_err(|err| DeclareCostError::WitnessDecode(err.to_string()))
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
                        match load_registry_cached(
                            &mut registry_cache,
                            &artifacts_root,
                            registry_hash,
                        ) {
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
                                if !registry_allows_schema(&registry, &event.snapshot_ref.schema_id)
                                {
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
                                        if !registry_allows_schema(&registry, &facts_ref.schema_id)
                                        {
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
                            admissibility_checked_event_id: event
                                .admissibility_checked_event_id
                                .clone(),
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
                                        if !registry_allows_schema(&registry, &facts_ref.schema_id)
                                        {
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
            Some("plan.created") => match serde_json::from_value::<PlanCreatedEvent>(value) {
                Ok(event) => {
                    let expected_plan_schema = PLAN_WITNESS_SCHEMA_IDS.join(", ");
                    if !PLAN_WITNESS_SCHEMA_IDS.contains(&event.plan_witness.schema_id.as_str()) {
                        issues.push(LedgerIssue {
                            line: line_no,
                            event_id: event_id.clone(),
                            event_type: event_type.clone(),
                            message: format!(
                                "plan witness schema_id mismatch (expected one of [{}], found {})",
                                expected_plan_schema, event.plan_witness.schema_id
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
                        match decode_cbor_to_value(&bytes).and_then(|val| {
                            serde_json::from_value::<admit_core::PlanWitness>(val)
                                .map_err(|err| DeclareCostError::Json(err.to_string()))
                        }) {
                            Ok(witness) => {
                                if !PLAN_WITNESS_SCHEMA_IDS.contains(&witness.schema_id.as_str()) {
                                    issues.push(LedgerIssue {
                                            line: line_no,
                                            event_id: event_id.clone(),
                                            event_type: event_type.clone(),
                                            message: format!(
                                                "plan witness schema_id mismatch (expected one of [{}], found {})",
                                                expected_plan_schema, witness.schema_id
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
                                    message: format!("plan witness cbor decode failed: {}", err),
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
            },
            Some("rust.ir_lint.completed") => {
                match serde_json::from_value::<RustIrLintEvent>(value) {
                    Ok(event) => {
                        if event.witness.schema_id != RUST_IR_LINT_WITNESS_SCHEMA_ID {
                            issues.push(LedgerIssue {
                                line: line_no,
                                event_id: event_id.clone(),
                                event_type: event_type.clone(),
                                message: format!(
                                    "rust ir lint witness schema_id mismatch (expected {}, found {})",
                                    RUST_IR_LINT_WITNESS_SCHEMA_ID, event.witness.schema_id
                                ),
                            });
                        }
                        let payload = RustIrLintPayload {
                            event_type: event.event_type.clone(),
                            timestamp: event.timestamp.clone(),
                            witness: event.witness.clone(),
                            scope_id: event.scope_id.clone(),
                            rule_pack: event.rule_pack.clone(),
                            rules: event.rules.clone(),
                            files_scanned: event.files_scanned,
                            violations: event.violations,
                            passed: event.passed,
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
                            &event.witness,
                            line_no,
                            &event_id,
                            &event_type,
                            &mut issues,
                            "rust ir lint witness",
                        );
                        if let Some(bytes) = witness_bytes {
                            match decode_cbor_to_value(&bytes).and_then(|val| {
                                serde_json::from_value::<RustIrLintWitness>(val)
                                    .map_err(|err| DeclareCostError::Json(err.to_string()))
                            }) {
                                Ok(witness) => {
                                    if witness.schema_id != RUST_IR_LINT_WITNESS_SCHEMA_ID {
                                        issues.push(LedgerIssue {
                                            line: line_no,
                                            event_id: event_id.clone(),
                                            event_type: event_type.clone(),
                                            message: format!(
                                                "rust ir lint witness schema_id mismatch (expected {}, found {})",
                                                RUST_IR_LINT_WITNESS_SCHEMA_ID, witness.schema_id
                                            ),
                                        });
                                    }
                                    if witness.schema_id != event.witness.schema_id {
                                        issues.push(LedgerIssue {
                                            line: line_no,
                                            event_id: event_id.clone(),
                                            event_type: event_type.clone(),
                                            message:
                                                "rust ir lint witness schema_id mismatch vs ref"
                                                    .to_string(),
                                        });
                                    }
                                    if witness.passed != event.passed {
                                        issues.push(LedgerIssue {
                                            line: line_no,
                                            event_id: event_id.clone(),
                                            event_type: event_type.clone(),
                                            message: "rust ir lint passed flag mismatch vs witness"
                                                .to_string(),
                                        });
                                    }
                                    if witness.files_scanned != event.files_scanned {
                                        issues.push(LedgerIssue {
                                            line: line_no,
                                            event_id: event_id.clone(),
                                            event_type: event_type.clone(),
                                            message:
                                                "rust ir lint files_scanned mismatch vs witness"
                                                    .to_string(),
                                        });
                                    }
                                    if witness.violations.len() as u64 != event.violations {
                                        issues.push(LedgerIssue {
                                            line: line_no,
                                            event_id: event_id.clone(),
                                            event_type: event_type.clone(),
                                            message:
                                                "rust ir lint violation count mismatch vs witness"
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
                                            "rust ir lint witness cbor decode failed: {}",
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
                                    if !registry_allows_schema(&registry, &event.witness.schema_id)
                                    {
                                        issues.push(LedgerIssue {
                                            line: line_no,
                                            event_id: event_id.clone(),
                                            event_type: event_type.clone(),
                                            message: format!(
                                                "registry missing schema_id for rust ir lint witness: {}",
                                                event.witness.schema_id
                                            ),
                                        });
                                    }
                                    if !registry_allows_scope(&registry, &event.scope_id) {
                                        issues.push(LedgerIssue {
                                            line: line_no,
                                            event_id: event_id.clone(),
                                            event_type: event_type.clone(),
                                            message: format!(
                                                "registry missing scope_id for rust ir lint: {}",
                                                event.scope_id
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
                            message: format!("rust.ir_lint.completed decode failed: {}", err),
                        });
                    }
                }
            }
            Some(t) if t.starts_with("ingest.") => {
                match serde_json::from_value::<IngestEvent>(value) {
                    Ok(event) => {
                        let payload = IngestEventPayload {
                            event_type: event.event_type.clone(),
                            timestamp: event.timestamp.clone(),
                            ingest_run_id: event.ingest_run_id.clone(),
                            root: event.root.clone(),
                            status: event.status.clone(),
                            duration_ms: event.duration_ms,
                            error: event.error.clone(),
                            config: event.config.clone(),
                            coverage: event.coverage.clone(),
                            ingest_run: event.ingest_run.clone(),
                            snapshot_sha256: event.snapshot_sha256.clone(),
                            parse_sha256: event.parse_sha256.clone(),
                            files: event.files,
                            chunks: event.chunks,
                            total_bytes: event.total_bytes,
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

                        if let Some(config) = &event.config {
                            verify_artifact_ref(
                                &artifacts_root,
                                config,
                                line_no,
                                &event_id,
                                &event_type,
                                &mut issues,
                                "ingest config",
                            );
                        }
                        if let Some(coverage) = &event.coverage {
                            verify_artifact_ref(
                                &artifacts_root,
                                coverage,
                                line_no,
                                &event_id,
                                &event_type,
                                &mut issues,
                                "ingest coverage",
                            );
                        }
                        if let Some(run) = &event.ingest_run {
                            verify_artifact_ref(
                                &artifacts_root,
                                run,
                                line_no,
                                &event_id,
                                &event_type,
                                &mut issues,
                                "ingest run record",
                            );
                        }
                    }
                    Err(err) => {
                        issues.push(LedgerIssue {
                            line: line_no,
                            event_id: event_id.clone(),
                            event_type: event_type.clone(),
                            message: format!("ingest event decode failed: {}", err),
                        });
                    }
                }
            }
            Some(t) if t.starts_with("projection.") => {
                match serde_json::from_value::<ProjectionEvent>(value) {
                    Ok(event) => {
                        let payload = ProjectionEventPayload {
                            event_type: event.event_type.clone(),
                            timestamp: event.timestamp.clone(),
                            projection_run_id: event.projection_run_id.clone(),
                            trace_sha256: event.trace_sha256.clone(),
                            phase: event.phase.clone(),
                            status: event.status.clone(),
                            duration_ms: event.duration_ms,
                            error: event.error.clone(),
                            config_hash: event.config_hash.clone(),
                            projector_version: event.projector_version.clone(),
                            meta: event.meta.clone(),
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
                    }
                    Err(err) => {
                        issues.push(LedgerIssue {
                            line: line_no,
                            event_id: event_id.clone(),
                            event_type: event_type.clone(),
                            message: format!("projection event decode failed: {}", err),
                        });
                    }
                }
            }
            Some(t) if t.starts_with("court.") => {
                match serde_json::from_value::<CourtEvent>(value) {
                    Ok(event) => {
                        let payload = CourtEventPayload {
                            event_type: event.event_type.clone(),
                            timestamp: event.timestamp.clone(),
                            artifact_kind: event.artifact_kind.clone(),
                            artifact: event.artifact.clone(),
                            name: event.name.clone(),
                            lang: event.lang.clone(),
                            tags: event.tags.clone(),
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

                        verify_artifact_ref(
                            &artifacts_root,
                            &event.artifact,
                            line_no,
                            &event_id,
                            &event_type,
                            &mut issues,
                            "court artifact",
                        );
                    }
                    Err(err) => {
                        issues.push(LedgerIssue {
                            line: line_no,
                            event_id: event_id.clone(),
                            event_type: event_type.clone(),
                            message: format!("court event decode failed: {}", err),
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

    // Cross-event consistency: checked -> cost
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
                    line: index_by_id.get(&checked.event_id).copied().unwrap_or(0),
                    event_id: Some(checked.event_id.clone()),
                    event_type: Some("admissibility.checked".to_string()),
                    message: "witness hash mismatch vs cost.declared".to_string(),
                });
            }
            if checked.snapshot_ref.sha256 != cost.snapshot_ref.sha256 {
                issues.push(LedgerIssue {
                    line: index_by_id.get(&checked.event_id).copied().unwrap_or(0),
                    event_id: Some(checked.event_id.clone()),
                    event_type: Some("admissibility.checked".to_string()),
                    message: "snapshot ref mismatch vs cost.declared".to_string(),
                });
            }
            if checked.program_bundle_ref.as_ref().map(|r| &r.sha256)
                != cost.program_bundle_ref.as_ref().map(|r| &r.sha256)
            {
                issues.push(LedgerIssue {
                    line: index_by_id.get(&checked.event_id).copied().unwrap_or(0),
                    event_id: Some(checked.event_id.clone()),
                    event_type: Some("admissibility.checked".to_string()),
                    message: "program bundle ref mismatch vs cost.declared".to_string(),
                });
            }
            if checked.snapshot_hash != cost.snapshot_hash {
                issues.push(LedgerIssue {
                    line: index_by_id.get(&checked.event_id).copied().unwrap_or(0),
                    event_id: Some(checked.event_id.clone()),
                    event_type: Some("admissibility.checked".to_string()),
                    message: "snapshot hash mismatch vs cost.declared".to_string(),
                });
            }
            if let Some(facts_ref) = &checked.facts_bundle_ref {
                if let Some(hash) = &checked.facts_bundle_hash {
                    if hash != &facts_ref.sha256 {
                        issues.push(LedgerIssue {
                            line: index_by_id.get(&checked.event_id).copied().unwrap_or(0),
                            event_id: Some(checked.event_id.clone()),
                            event_type: Some("admissibility.checked".to_string()),
                            message: "facts bundle hash mismatch vs ref".to_string(),
                        });
                    }
                }
            }
        }
    }

    // Cross-event consistency: executed -> checked -> cost
    for executed in executed_by_id.values() {
        let idx = index_by_id.get(&executed.event_id).copied().unwrap_or(0);
        if let Some(checked_idx) = index_by_id.get(&executed.admissibility_checked_event_id) {
            if checked_idx >= &idx {
                issues.push(LedgerIssue {
                    line: idx,
                    event_id: Some(executed.event_id.clone()),
                    event_type: Some("admissibility.executed".to_string()),
                    message: "admissibility.checked appears after admissibility.executed"
                        .to_string(),
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
