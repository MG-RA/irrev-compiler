//! Projection command implementations (vacuum and retry operations)

use admit_cli::{
    append_projection_event, build_projection_event, default_artifacts_dir, default_ledger_path,
};
use admit_surrealdb::projection_store::ProjectionStoreOps;
use admit_surrealdb::projection_run::{PhaseResult, PhaseStatus, RunStatus};
use admit_surrealdb::ProjectionEventRow;

use crate::{
    obsidian_adapter, ProjectionCoordinator, ProjectionVacuumArgs, ProjectionRetryArgs,
    sha256_hex,
};

pub fn run_projection_vacuum(
    args: ProjectionVacuumArgs,
    projection: &ProjectionCoordinator,
) -> Result<(), String> {
    let store = projection.require_store("projection vacuum")?;
    let store_ops: &dyn ProjectionStoreOps = store;
    if !store
        .is_ready()
        .map_err(|e| format!("surrealdb is-ready failed: {}", e))?
    {
        return Err("surrealdb endpoint not ready".to_string());
    }
    store_ops
        .ensure_schemas()
        .map_err(|err| format!("surrealdb ensure schemas failed: {}", err))?;

    let ledger_path = args.ledger.clone().unwrap_or_else(default_ledger_path);
    let artifacts_dir = args
        .artifacts_dir
        .clone()
        .unwrap_or_else(default_artifacts_dir);

    let run_ids = if let Some(run_id) = args.run.clone() {
        vec![run_id]
    } else if let Some(before_run) = args.before_run.as_ref() {
        let Some(started_at) = store
            .projection_run_started_at(before_run)
            .map_err(|e| format!("lookup projection run {}: {}", before_run, e))?
        else {
            return Err(format!("projection run not found: {}", before_run));
        };
        store
            .projection_run_ids_before(&started_at)
            .map_err(|e| format!("list projection runs before {}: {}", before_run, e))?
    } else {
        return Err("projection vacuum requires --before-run or --run".to_string());
    };

    if run_ids.is_empty() {
        if args.json {
            let value = serde_json::json!({
                "before_run": args.before_run,
                "run": args.run,
                "dry_run": args.dry_run,
                "runs": run_ids,
            });
            println!(
                "{}",
                serde_json::to_string(&value).map_err(|err| format!("json encode: {}", err))?
            );
        } else {
            println!("projection_vacuum_runs=0");
        }
        return Ok(());
    }

    let before_run = args.before_run.clone();
    let run = args.run.clone();

    let op_started_at = chrono::Utc::now().to_rfc3339();
    let op_id = sha256_hex(&format!(
        "projection.vacuum.v1|{}|{}|{}|{}|{}|{}|{}",
        op_started_at,
        before_run.clone().unwrap_or_default(),
        run.clone().unwrap_or_default(),
        args.dry_run,
        store.config().endpoint,
        store.config().namespace.clone().unwrap_or_default(),
        store.config().database.clone().unwrap_or_default(),
    ));

    let meta_base = serde_json::json!({
        "before_run": before_run.clone(),
        "run": run.clone(),
        "dry_run": args.dry_run,
        "runs": run_ids.clone(),
        "runs_deleted": run_ids.len(),
        "surrealdb": {
            "endpoint": store.config().endpoint,
            "namespace": store.config().namespace,
            "database": store.config().database,
        },
    });

    let ev_started = build_projection_event(
        "projection.vacuum.started",
        &op_id,
        op_started_at.clone(),
        None,
        None,
        Some("running".to_string()),
        None,
        None,
        None,
        None,
        Some(meta_base.clone()),
    )
    .map_err(|e| e.to_string())?;
    if !args.no_ledger {
        append_projection_event(&ledger_path, &ev_started).map_err(|e| e.to_string())?;
    }
    store_ops
        .project_projection_events(&[to_projection_event_row(&ev_started)])
        .map_err(|err| format!("surrealdb project events failed: {}", err))?;

    let start = std::time::Instant::now();
    if !args.dry_run {
        store
            .vacuum_projection_runs(&run_ids)
            .map_err(|e| format!("projection vacuum failed: {}", e))?;
    }
    let duration_ms = start.elapsed().as_millis() as u64;

    let vacuum_value = serde_json::json!({
        "schema_id": "projection-vacuum/1",
        "created_at_utc": chrono::Utc::now().to_rfc3339(),
        "op_id": op_id,
        "before_run": before_run.clone(),
        "run": run.clone(),
        "dry_run": args.dry_run,
        "runs_deleted": run_ids.len(),
        "runs": run_ids.clone(),
        "surrealdb": {
            "endpoint": store.config().endpoint,
            "namespace": store.config().namespace,
            "database": store.config().database,
        },
    });
    let vacuum_artifact = admit_cli::store_value_artifact(
        &artifacts_dir,
        "projection_vacuum",
        "projection-vacuum/1",
        &vacuum_value,
    )
    .map_err(|e| e.to_string())?;

    let completed_at = chrono::Utc::now().to_rfc3339();
    let ev_completed = build_projection_event(
        "projection.vacuum.completed",
        &op_id,
        completed_at.clone(),
        None,
        None,
        Some(if args.dry_run {
            "dry_run".to_string()
        } else {
            "complete".to_string()
        }),
        Some(duration_ms),
        None,
        None,
        None,
        Some(serde_json::json!({
            "artifact": vacuum_artifact,
            "details": meta_base,
        })),
    )
    .map_err(|e| e.to_string())?;
    if !args.no_ledger {
        append_projection_event(&ledger_path, &ev_completed).map_err(|e| e.to_string())?;
    }
    store_ops
        .project_projection_events(&[to_projection_event_row(&ev_completed)])
        .map_err(|err| format!("surrealdb project events failed: {}", err))?;

    if args.json {
        let value = serde_json::json!({
            "before_run": before_run,
            "run": run,
            "dry_run": args.dry_run,
            "runs": ev_started.meta.as_ref().and_then(|m| m.get("runs")).cloned().unwrap_or_else(|| serde_json::json!([])),
            "runs_deleted": run_ids.len(),
            "ledger": ledger_path,
            "artifacts_dir": artifacts_dir,
            "artifact": vacuum_artifact,
            "events": [ev_started, ev_completed],
        });
        println!(
            "{}",
            serde_json::to_string(&value).map_err(|err| format!("json encode: {}", err))?
        );
    } else {
        println!("projection_vacuum_runs={}", run_ids.len());
        for run_id in &run_ids {
            println!("run_id={}", run_id);
        }
    }

    Ok(())
}

pub fn run_projection_retry(
    args: ProjectionRetryArgs,
    projection: &ProjectionCoordinator,
) -> Result<(), String> {
    let store = projection.require_store("projection retry")?;
    let store_ops: &dyn ProjectionStoreOps = store;
    if !store
        .is_ready()
        .map_err(|e| format!("surrealdb is-ready failed: {}", e))?
    {
        return Err("surrealdb endpoint not ready".to_string());
    }
    store_ops
        .ensure_schemas()
        .map_err(|err| format!("surrealdb ensure schemas failed: {}", err))?;

    let ledger_path = args.ledger.clone().unwrap_or_else(default_ledger_path);

    let run_value = store
        .projection_run_record(&args.run)
        .map_err(|e| format!("load projection run {}: {}", args.run, e))?
        .ok_or_else(|| format!("projection run not found: {}", args.run))?;

    let trace_sha256 = run_value
        .get("trace_sha256")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "projection run missing trace_sha256".to_string())?
        .to_string();

    let phases_enabled: Vec<String> = run_value
        .get("phases_enabled")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let phase_results_value = run_value
        .get("phase_results")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    let phase_results_value = if let serde_json::Value::String(s) = &phase_results_value {
        serde_json::from_str::<serde_json::Value>(s)
            .map_err(|e| format!("parse phase_results: {}", e))?
    } else {
        phase_results_value
    };

    let mut phase_results: std::collections::BTreeMap<String, PhaseResult> =
        serde_json::from_value(phase_results_value)
            .map_err(|e| format!("decode phase_results: {}", e))?;

    let mut target_phases: Vec<String> = if let Some(phase) = args.phase.clone() {
        vec![phase]
    } else {
        phase_results
            .iter()
            .filter(|(_, r)| r.status == PhaseStatus::Failed || !r.failed_batches.is_empty())
            .map(|(k, _)| k.clone())
            .collect()
    };
    target_phases = target_phases
        .into_iter()
        .map(|p| obsidian_adapter::normalize_obsidian_vault_links_phase(&p))
        .collect();
    target_phases.sort();
    target_phases.dedup();

    if let Some(batch_hash) = args.batch.as_ref() {
        let mut found_phase = None;
        for (phase, result) in phase_results.iter() {
            if result
                .failed_batches
                .iter()
                .any(|b| &b.batch_hash == batch_hash)
            {
                found_phase = Some(phase.clone());
                break;
            }
        }
        if let Some(phase) = found_phase {
            target_phases = vec![phase];
        } else {
            return Err(format!("batch hash not found in run {}", args.run));
        }
    }

    if target_phases.is_empty() {
        if args.json {
            let value = serde_json::json!({
                "run": args.run,
                "dry_run": args.dry_run,
                "phases": [],
            });
            println!(
                "{}",
                serde_json::to_string(&value).map_err(|err| format!("json encode: {}", err))?
            );
        } else {
            println!("projection_retry_phases=0");
        }
        return Ok(());
    }

    let artifacts_dir = args
        .artifacts_dir
        .clone()
        .unwrap_or_else(default_artifacts_dir);

    let mut retry_plan: Vec<(String, usize)> = Vec::new();
    for phase in &target_phases {
        if let Some(result) = phase_results.get(phase) {
            let mut count = result.failed_batches.len();
            if let Some(batch_hash) = args.batch.as_ref() {
                count = result
                    .failed_batches
                    .iter()
                    .filter(|b| &b.batch_hash == batch_hash)
                    .count();
            }
            retry_plan.push((phase.clone(), count));
        }
    }

    if args.dry_run {
        if args.json {
            let value = serde_json::json!({
                "run": args.run,
                "dry_run": true,
                "phases": retry_plan.iter().map(|(p, c)| serde_json::json!({"phase": p, "failed_batches": c})).collect::<Vec<_>>(),
            });
            println!(
                "{}",
                serde_json::to_string(&value).map_err(|err| format!("json encode: {}", err))?
            );
        } else {
            println!("projection_retry_phases={}", retry_plan.len());
            for (phase, count) in retry_plan {
                println!("phase={} failed_batches={}", phase, count);
            }
        }
        return Ok(());
    }

    let requested_phase = args.phase.clone();
    let requested_batch = args.batch.clone();

    let ev_started = build_projection_event(
        "projection.retry.started",
        &args.run,
        chrono::Utc::now().to_rfc3339(),
        Some(trace_sha256.clone()),
        requested_phase.clone(),
        Some("running".to_string()),
        None,
        None,
        None,
        None,
        Some(serde_json::json!({
            "requested_phase": requested_phase,
            "requested_batch": requested_batch,
            "retry_plan": retry_plan.iter().map(|(p, c)| serde_json::json!({"phase": p, "failed_batches": c})).collect::<Vec<_>>(),
        })),
    )
    .map_err(|e| e.to_string())?;
    if !args.no_ledger {
        append_projection_event(&ledger_path, &ev_started).map_err(|e| e.to_string())?;
    }
    store_ops
        .project_projection_events(&[to_projection_event_row(&ev_started)])
        .map_err(|err| format!("surrealdb project events failed: {}", err))?;

    let trace_bytes = store
        .dag_trace_bytes_for_trace(&trace_sha256)
        .map_err(|e| format!("load dag_trace {}: {}", trace_sha256, e))?;
    let trace_value: serde_json::Value = serde_cbor::from_slice(&trace_bytes)
        .map_err(|e| format!("decode dag_trace cbor: {}", e))?;
    let dag: admit_dag::GovernedDag =
        serde_json::from_value(trace_value).map_err(|e| format!("decode dag from trace: {}", e))?;

    for phase in target_phases.iter() {
        let Some(original) = phase_results.get(phase).cloned() else {
            continue;
        };

        let mut selected_batches: Vec<admit_surrealdb::projection_run::FailedBatch> =
            original.failed_batches.clone();
        if let Some(batch_hash) = args.batch.as_ref() {
            selected_batches = selected_batches
                .into_iter()
                .filter(|b| &b.batch_hash == batch_hash)
                .collect();
        }

        let start = std::time::Instant::now();
        let new_result = match phase.as_str() {
            "dag_trace" => {
                if selected_batches.is_empty() || original.status == PhaseStatus::Failed {
                    store_ops
                        .project_dag_trace(&trace_sha256, &trace_bytes, &dag, Some(&args.run))
                        .map_err(|e| e.to_string())?
                } else {
                    let (succeeded, still_failed) = store
                        .retry_dag_trace_batches(&dag, &args.run, &selected_batches)
                        .map_err(|e| format!("retry dag_trace: {}", e))?;
                    merge_retry_results(original.clone(), succeeded, still_failed, start.elapsed())
                }
            }
            "doc_files" => {
                if selected_batches.is_empty() || original.status == PhaseStatus::Failed {
                    store_ops
                        .project_doc_files(&dag, &artifacts_dir, Some(&args.run))
                        .map_err(|e| e.to_string())?
                } else {
                    let (succeeded, still_failed) = store
                        .retry_doc_files_batches(&dag, &artifacts_dir, &args.run, &selected_batches)
                        .map_err(|e| format!("retry doc_files: {}", e))?;
                    merge_retry_results(original.clone(), succeeded, still_failed, start.elapsed())
                }
            }
            "doc_chunks" => {
                if selected_batches.is_empty() || original.status == PhaseStatus::Failed {
                    store_ops
                        .project_doc_chunks(&dag, &artifacts_dir, &[], Some(&args.run))
                        .map_err(|e| e.to_string())?
                } else {
                    let (succeeded, still_failed) = store
                        .retry_doc_chunks_batches(
                            &dag,
                            &artifacts_dir,
                            &args.run,
                            &selected_batches,
                        )
                        .map_err(|e| format!("retry doc_chunks: {}", e))?;
                    merge_retry_results(original.clone(), succeeded, still_failed, start.elapsed())
                }
            }
            "chunk_repr" => {
                if selected_batches.is_empty() || original.status == PhaseStatus::Failed {
                    store_ops
                        .project_chunk_repr(&dag, &artifacts_dir, Some(&args.run))
                        .map_err(|e| e.to_string())?
                } else {
                    let (succeeded, still_failed) = store
                        .retry_chunk_repr_batches(
                            &dag,
                            &artifacts_dir,
                            &args.run,
                            &selected_batches,
                        )
                        .map_err(|e| format!("retry chunk_repr: {}", e))?;
                    merge_retry_results(original.clone(), succeeded, still_failed, start.elapsed())
                }
            }
            phase if obsidian_adapter::is_obsidian_vault_links_phase(phase) => {
                let (effective_vault_prefixes, _did_fallback, _doc_paths) =
                    obsidian_adapter::effective_vault_prefixes_for_dag(
                        &dag,
                        &store.projection_config().obsidian_vault_prefixes,
                    );
                let vault_prefix_refs: Vec<&str> = effective_vault_prefixes
                    .iter()
                    .map(|s| s.as_str())
                    .collect();
                obsidian_adapter::project_obsidian_vault_links(
                        store,
                        &dag,
                        &artifacts_dir,
                        &vault_prefix_refs,
                        None,
                        Some(&args.run),
                    )?
            }
            _ => {
                eprintln!("projection retry: unsupported phase '{}'", phase);
                original.clone()
            }
        };

        phase_results.insert(phase.clone(), new_result);
    }

    let new_status = compute_run_status(&phases_enabled, &phase_results);
    let finished_at = chrono::Utc::now().to_rfc3339();
    store
        .end_projection_run(&args.run, new_status, &finished_at, &phase_results)
        .map_err(|e| format!("update projection run after retry: {}", e))?;

    let phase_statuses: Vec<serde_json::Value> = phase_results
        .iter()
        .map(|(phase, result)| {
            let status = match result.status {
                PhaseStatus::Complete => "complete",
                PhaseStatus::Partial => "partial",
                PhaseStatus::Failed => "failed",
                PhaseStatus::Running => "running",
            };
            serde_json::json!({
                "phase": phase,
                "status": status,
                "failed_batches": result.failed_batches.len(),
                "successful_batches": result.successful_batches,
                "total_batches": result.total_batches,
            })
        })
        .collect();
    let ev_completed = build_projection_event(
        "projection.retry.completed",
        &args.run,
        chrono::Utc::now().to_rfc3339(),
        Some(trace_sha256.clone()),
        args.phase.clone(),
        Some(new_status.to_string()),
        None,
        None,
        None,
        None,
        Some(serde_json::json!({
            "phases": phase_statuses,
        })),
    )
    .map_err(|e| e.to_string())?;
    if !args.no_ledger {
        append_projection_event(&ledger_path, &ev_completed).map_err(|e| e.to_string())?;
    }
    store_ops
        .project_projection_events(&[to_projection_event_row(&ev_completed)])
        .map_err(|err| format!("surrealdb project events failed: {}", err))?;

    if args.json {
        let value = serde_json::json!({
            "run": args.run,
            "status": new_status.to_string(),
            "phases": phase_results,
        });
        println!(
            "{}",
            serde_json::to_string(&value).map_err(|err| format!("json encode: {}", err))?
        );
    } else {
        println!("projection_retry_run={}", args.run);
        println!("projection_retry_status={}", new_status);
        for (phase, result) in phase_results {
            println!(
                "phase={} status={} failed_batches={}",
                phase,
                match result.status {
                    PhaseStatus::Complete => "complete",
                    PhaseStatus::Partial => "partial",
                    PhaseStatus::Failed => "failed",
                    PhaseStatus::Running => "running",
                },
                result.failed_batches.len()
            );
        }
    }

    Ok(())
}

fn merge_retry_results(
    mut original: PhaseResult,
    retried_successes: usize,
    retried_failures: Vec<admit_surrealdb::projection_run::FailedBatch>,
    duration: std::time::Duration,
) -> PhaseResult {
    let mut failed_map: std::collections::BTreeMap<
        String,
        admit_surrealdb::projection_run::FailedBatch,
    > = retried_failures
        .into_iter()
        .map(|b| (b.batch_hash.clone(), b))
        .collect();

    let mut new_failed: Vec<admit_surrealdb::projection_run::FailedBatch> = Vec::new();
    let mut recovered = 0usize;
    for batch in original.failed_batches.iter() {
        if let Some(updated) = failed_map.remove(&batch.batch_hash) {
            new_failed.push(updated);
        } else {
            recovered += 1;
        }
    }

    original.successful_batches = original
        .successful_batches
        .saturating_add(retried_successes + recovered);
    original.failed_batches = new_failed;
    original.duration_ms = duration.as_millis() as u64;
    if original.failed_batches.is_empty() {
        original.status = PhaseStatus::Complete;
        original.error = None;
    } else if original.successful_batches == 0 {
        original.status = PhaseStatus::Failed;
        original.error = Some(format!(
            "{} of {} batches failed",
            original.failed_batches.len(),
            original.total_batches
        ));
    } else {
        original.status = PhaseStatus::Partial;
        original.error = Some(format!(
            "{} of {} batches failed",
            original.failed_batches.len(),
            original.total_batches
        ));
    }
    original
}

fn compute_run_status(
    phases_enabled: &[String],
    phase_results: &std::collections::BTreeMap<String, PhaseResult>,
) -> RunStatus {
    if phase_results.is_empty() {
        return RunStatus::Running;
    }

    let total_phases = if phases_enabled.is_empty() {
        phase_results.len()
    } else {
        phases_enabled.len()
    };

    let completed = phase_results
        .values()
        .filter(|r| r.status == PhaseStatus::Complete)
        .count();
    let failed = phase_results
        .values()
        .filter(|r| r.status == PhaseStatus::Failed)
        .count();
    let partial = phase_results
        .values()
        .filter(|r| r.status == PhaseStatus::Partial)
        .count();

    if failed == total_phases {
        RunStatus::Failed
    } else if completed == total_phases {
        RunStatus::Complete
    } else if completed > 0 || failed > 0 || partial > 0 {
        RunStatus::Partial
    } else {
        RunStatus::Running
    }
}

pub(crate) fn to_projection_event_row(event: &admit_cli::ProjectionEvent) -> ProjectionEventRow {
    ProjectionEventRow {
        event_id: event.event_id.clone(),
        event_type: event.event_type.clone(),
        timestamp: event.timestamp.clone(),
        projection_run_id: event.projection_run_id.clone(),
        phase: event.phase.clone(),
        status: event.status.clone(),
        duration_ms: event.duration_ms,
        error: event.error.clone(),
        trace_sha256: event.trace_sha256.clone(),
        config_hash: event.config_hash.clone(),
        projector_version: event.projector_version.clone(),
        meta: event.meta.clone(),
    }
}
