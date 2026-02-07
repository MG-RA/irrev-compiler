use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde_json::json;

use crate::artifact::{default_artifacts_dir, store_artifact};
use crate::internal::sha256_hex;
use crate::ledger::build_ingest_event;
use crate::types::{ArtifactRef, DeclareCostError, IngestEvent};

use crate::ingest_dir::{ingest_dir_with_cache, IngestDirOutput};

const INGEST_CONFIG_SCHEMA_ID: &str = "ingest-dir-config/0";
const INGEST_CONFIG_KIND: &str = "ingest_config";
const INGEST_COVERAGE_SCHEMA_ID: &str = "ingest-coverage/0";
const INGEST_COVERAGE_KIND: &str = "ingest_coverage";
const INGEST_RUN_SCHEMA_ID: &str = "ingest-run/0";
const INGEST_RUN_KIND: &str = "ingest_run";

#[derive(Debug, Clone)]
pub struct IngestDirProtocolOutput {
    pub ingest_run_id: String,
    pub config: ArtifactRef,
    pub events: Vec<IngestEvent>,
    #[allow(dead_code)]
    pub status: String,
    pub error: Option<String>,
    pub out: Option<IngestDirOutput>,
    pub coverage: Option<ArtifactRef>,
    pub ingest_run: Option<ArtifactRef>,
}

fn is_truthy_env(key: &str) -> bool {
    std::env::var_os(key)
        .and_then(|v| v.to_str().map(|s| s.to_string()))
        .is_some_and(|s| s == "1" || s.eq_ignore_ascii_case("true"))
}

fn ingest_config_artifact(
    root_abs: &Path,
    artifacts_root: &Path,
    incremental_cache: Option<&Path>,
) -> Result<ArtifactRef, DeclareCostError> {
    let config_value = json!({
        "schema_id": INGEST_CONFIG_SCHEMA_ID,
        "schema_version": 0,
        "ingest_kind": "dir",
        "root_abs": root_abs.to_string_lossy(),
        "artifacts_root": artifacts_root.to_string_lossy(),
        "disable_git": is_truthy_env("ADMIT_INGEST_DISABLE_GIT"),
        "incremental_cache": incremental_cache.map(|p| p.to_string_lossy().to_string()),
    });

    let cbor = admit_core::encode_canonical_value(&config_value)
        .map_err(|err| DeclareCostError::CanonicalEncode(err.0))?;
    let json_bytes = serde_json::to_vec_pretty(&config_value)
        .map_err(|err| DeclareCostError::Json(err.to_string()))?;

    store_artifact(
        artifacts_root,
        INGEST_CONFIG_KIND,
        INGEST_CONFIG_SCHEMA_ID,
        &cbor,
        "cbor",
        Some(json_bytes),
        None,
    )
}

fn ingest_coverage_artifact(
    ingest_run_id: &str,
    out: &IngestDirOutput,
    config: &ArtifactRef,
    artifacts_root: &Path,
) -> Result<ArtifactRef, DeclareCostError> {
    let mut warnings_by_kind: BTreeMap<String, u64> = BTreeMap::new();
    for w in &out.warnings {
        *warnings_by_kind.entry(w.kind.clone()).or_default() += 1;
    }

    let coverage_value = json!({
        "schema_id": INGEST_COVERAGE_SCHEMA_ID,
        "schema_version": 0,
        "ingest_run_id": ingest_run_id,
        "config_sha256": config.sha256,
        "root": ".",
        "walk_mode": out.walk_mode,
        "skipped_by_skip_dir": out.skipped_by_skip_dir,
        "included_files": out.files.len(),
        "included_chunks": out.chunks.len(),
        "total_bytes": out.total_bytes,
        "warnings_by_kind": warnings_by_kind,
        "warnings": out.warnings,
        "incremental": out.incremental.as_ref().map(|inc| json!({
            "enabled": inc.enabled,
            "cache_path": inc.cache_path.as_ref().map(|p| p.to_string_lossy().to_string()),
            "cache_reset": inc.cache_reset,
            "cache_reset_reason": inc.cache_reset_reason,
            "files_cached": inc.files_cached,
            "files_parsed": inc.files_parsed,
            "chunks_cached": inc.chunks_cached,
            "chunks_parsed": inc.chunks_parsed,
            "docs_to_resolve_links": inc.docs_to_resolve_links.len(),
        })),
    });

    let cbor = admit_core::encode_canonical_value(&coverage_value)
        .map_err(|err| DeclareCostError::CanonicalEncode(err.0))?;
    let json_bytes = serde_json::to_vec_pretty(&coverage_value)
        .map_err(|err| DeclareCostError::Json(err.to_string()))?;

    store_artifact(
        artifacts_root,
        INGEST_COVERAGE_KIND,
        INGEST_COVERAGE_SCHEMA_ID,
        &cbor,
        "cbor",
        Some(json_bytes),
        None,
    )
}

fn ingest_run_record_artifact(
    ingest_run_id: &str,
    started_at: &str,
    finished_at: &str,
    root_abs: &Path,
    out: &IngestDirOutput,
    config: &ArtifactRef,
    coverage: &ArtifactRef,
    artifacts_root: &Path,
) -> Result<ArtifactRef, DeclareCostError> {
    let run_value = json!({
        "schema_id": INGEST_RUN_SCHEMA_ID,
        "schema_version": 0,
        "ingest_run_id": ingest_run_id,
        "started_at": started_at,
        "finished_at": finished_at,
        "root": ".",
        "root_abs": root_abs.to_string_lossy(),
        "config": config,
        "snapshot": out.snapshot,
        "parse": out.parse,
        "coverage": coverage,
        "snapshot_sha256": out.snapshot_sha256,
        "parse_sha256": out.parse_sha256,
        "included_files": out.files.len(),
        "included_chunks": out.chunks.len(),
        "total_bytes": out.total_bytes,
        "warnings": out.warnings.len(),
    });

    let cbor = admit_core::encode_canonical_value(&run_value)
        .map_err(|err| DeclareCostError::CanonicalEncode(err.0))?;
    let json_bytes = serde_json::to_vec_pretty(&run_value)
        .map_err(|err| DeclareCostError::Json(err.to_string()))?;

    store_artifact(
        artifacts_root,
        INGEST_RUN_KIND,
        INGEST_RUN_SCHEMA_ID,
        &cbor,
        "cbor",
        Some(json_bytes),
        None,
    )
}

pub fn ingest_dir_protocol(
    root: &Path,
    artifacts_root: Option<&Path>,
) -> Result<IngestDirProtocolOutput, DeclareCostError> {
    ingest_dir_protocol_with_cache(root, artifacts_root, None)
}

pub fn ingest_dir_protocol_with_cache(
    root: &Path,
    artifacts_root: Option<&Path>,
    incremental_cache: Option<&Path>,
) -> Result<IngestDirProtocolOutput, DeclareCostError> {
    let started_at = chrono::Utc::now().to_rfc3339();
    let root_abs = root
        .canonicalize()
        .map_err(|err| DeclareCostError::Io(format!("canonicalize root: {}", err)))?;

    let artifacts_root_buf: PathBuf = artifacts_root
        .map(|p| p.to_path_buf())
        .unwrap_or_else(default_artifacts_dir);
    let artifacts_root = artifacts_root_buf.as_path();

    let config = ingest_config_artifact(&root_abs, artifacts_root, incremental_cache)?;

    let ingest_run_id_src = format!(
        "admit_ingest_run_v1|{}|{}|{}",
        root_abs.to_string_lossy(),
        started_at,
        config.sha256
    );
    let ingest_run_id = sha256_hex(ingest_run_id_src.as_bytes());

    let mut events: Vec<IngestEvent> = Vec::new();
    let started_ev = build_ingest_event(
        "ingest.run.started",
        &ingest_run_id,
        started_at.clone(),
        Some(root_abs.to_string_lossy().to_string()),
        Some("running".to_string()),
        None,
        None,
        Some(config.clone()),
        None,
        None,
        None,
        None,
        None,
        None,
        None,
    )?;
    events.push(started_ev);

    let t0 = std::time::Instant::now();
    let out = match ingest_dir_with_cache(&root_abs, Some(artifacts_root), incremental_cache) {
        Ok(out) => out,
        Err(err) => {
            let error_msg = err.to_string();
            let failed_ev = build_ingest_event(
                "ingest.run.completed",
                &ingest_run_id,
                chrono::Utc::now().to_rfc3339(),
                Some(root_abs.to_string_lossy().to_string()),
                Some("failed".to_string()),
                Some(t0.elapsed().as_millis() as u64),
                Some(error_msg.clone()),
                Some(config.clone()),
                None,
                None,
                None,
                None,
                None,
                None,
                None,
            )?;
            events.push(failed_ev);
            return Ok(IngestDirProtocolOutput {
                ingest_run_id,
                config,
                events,
                status: "failed".to_string(),
                error: Some(error_msg),
                out: None,
                coverage: None,
                ingest_run: None,
            });
        }
    };
    let duration_ms = t0.elapsed().as_millis() as u64;
    let finished_at = chrono::Utc::now().to_rfc3339();

    let coverage = ingest_coverage_artifact(&ingest_run_id, &out, &config, artifacts_root)?;
    let ingest_run = ingest_run_record_artifact(
        &ingest_run_id,
        &started_at,
        &finished_at,
        &root_abs,
        &out,
        &config,
        &coverage,
        artifacts_root,
    )?;

    let completed_ev = build_ingest_event(
        "ingest.run.completed",
        &ingest_run_id,
        finished_at,
        Some(root_abs.to_string_lossy().to_string()),
        Some("complete".to_string()),
        Some(duration_ms),
        None,
        Some(config.clone()),
        Some(coverage.clone()),
        Some(ingest_run.clone()),
        Some(out.snapshot_sha256.clone()),
        Some(out.parse_sha256.clone()),
        Some(out.files.len() as u64),
        Some(out.chunks.len() as u64),
        Some(out.total_bytes),
    )?;
    events.push(completed_ev);

    Ok(IngestDirProtocolOutput {
        ingest_run_id,
        config,
        events,
        status: "complete".to_string(),
        error: None,
        out: Some(out),
        coverage: Some(coverage),
        ingest_run: Some(ingest_run),
    })
}
