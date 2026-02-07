use std::io::Write;
use std::process::{Command, Stdio};
use std::path::Path;
use std::collections::{BTreeMap, BTreeSet};

use admit_core::ArtifactRef;
use admit_dag::{DagEdge, DagNode, EdgeType, GovernedDag, NodeKind, ProjectionStore};
use sha2::Digest;

// Projection configuration layer
pub mod projection_config;

// Projection run tracking primitive
pub mod projection_run;

// Projection observability events (queryable view)
pub mod projection_events;

// Ingestion run + events (queryable view)
pub mod ingest_run;
pub mod ingest_events;

// Projection store trait and implementations
pub mod projection_store;

// Pure link resolution logic (no database dependencies)
pub mod link_resolver;

// Re-export key types for convenience
pub use projection_store::{NullStore, ProjectionError, ProjectionResult, ProjectionStoreOps};
pub use link_resolver::{VaultLinkResolver, ObsidianLink, ResolutionResult, AssetResolution};
pub use projection_events::ProjectionEventRow;
pub use ingest_events::IngestEventRow;
pub use ingest_run::IngestRunRow;

#[derive(Debug, Clone)]
pub struct SurrealCliConfig {
    pub endpoint: String,
    pub namespace: Option<String>,
    pub database: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
    pub token: Option<String>,
    pub auth_level: Option<String>,
    pub surreal_bin: String,
}

impl Default for SurrealCliConfig {
    fn default() -> Self {
        Self {
            endpoint: "ws://localhost:8000".to_string(),
            namespace: None,
            database: None,
            username: None,
            password: None,
            token: None,
            auth_level: None,
            surreal_bin: "surreal".to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct SurrealCliProjectionStore {
    config: SurrealCliConfig,
    projection_config: projection_config::ProjectionConfig,
}

#[derive(Debug, Clone)]
pub struct DocChunkEmbeddingRow {
    pub node_id: String,
    pub doc_path: String,
    pub start_line: u32,
    pub chunk_sha256: String,
    pub model: String,
    pub dim_target: u32,
    pub embedding: Vec<f32>,
}

#[derive(Debug, Clone)]
pub struct DocEmbeddingRow {
    pub doc_path: String,
    pub model: String,
    pub dim_target: u32,
    pub embedding: Vec<f32>,
    pub chunk_count: u32,
}

#[derive(Debug, Clone)]
pub struct EmbedRunRow {
    pub run_id: String,
    pub kind: String, // e.g. "ollama_embed"
    pub trace_sha256: Option<String>,
    pub snapshot_sha256: Option<String>,
    pub parse_sha256: Option<String>,
    pub root: Option<String>,
    pub model: String,
    /// Requested embedding dimension target (Matryoshka truncation). 0 means "full length".
    pub dim_target: u32,
    /// Observed embedding dimension actually stored (after truncation).
    pub dim_actual: Option<u32>,
    pub doc_prefix: String,
    pub query_prefix: String,
    pub created_at_utc: String,
}

#[derive(Debug, Clone)]
pub struct DocTitleEmbeddingRow {
    pub doc_path: String,
    pub title: String,
    pub model: String,
    pub dim_target: u32,
    pub embedding: Vec<f32>,
    pub run_id: String,
}

#[derive(Debug, Clone)]
pub struct UnresolvedLinkRow {
    pub link_id: String,
    pub from_doc_path: String,
    pub raw_target: String,
    pub raw_heading: Option<String>,
    pub resolution_kind: String,
    pub candidates: Vec<String>,
    pub resolved_doc_path: Option<String>,
    pub line: u32,
    pub embed: bool,
}

#[derive(Debug, Clone)]
pub struct UnresolvedLinkSuggestionRow {
    pub suggestion_id: String,
    pub run_id: String,
    pub link_id: String,
    pub from_doc_path: String,
    pub line: u32,
    pub embed: bool,
    pub raw_target: String,
    pub raw_heading: Option<String>,
    pub resolution_kind: String,
    pub vault_prefix: String,
    pub model: String,
    pub dim_target: u32,
    pub recommended_doc_path: Option<String>,
    pub candidates: Vec<(String, f64)>,
}

#[derive(Debug, Clone)]
pub struct QueryArtifactRow {
    pub artifact_sha256: String,
    pub schema_id: String,
    pub name: String,
    pub lang: String,
    pub source: String,
    pub tags: Vec<String>,
    pub created_at_utc: String,
}

#[derive(Debug, Clone)]
pub struct FunctionArtifactRow {
    pub artifact_sha256: String,
    pub schema_id: String,
    pub name: String,
    pub lang: String,
    pub source: String,
    pub tags: Vec<String>,
    pub created_at_utc: String,
}

impl SurrealCliProjectionStore {
    pub fn new(config: SurrealCliConfig) -> Self {
        Self {
            config,
            projection_config: projection_config::ProjectionConfig::default(),
        }
    }

    pub fn with_projection_config(
        config: SurrealCliConfig,
        projection_config: projection_config::ProjectionConfig,
    ) -> Self {
        Self {
            config,
            projection_config,
        }
    }

    pub fn config(&self) -> &SurrealCliConfig {
        &self.config
    }

    pub fn projection_config(&self) -> &projection_config::ProjectionConfig {
        &self.projection_config
    }

    pub fn is_ready(&self) -> Result<bool, String> {
        let output = Command::new(&self.config.surreal_bin)
            .arg("is-ready")
            .arg("--endpoint")
            .arg(&self.config.endpoint)
            .output()
            .map_err(|err| format!("spawn surreal is-ready: {}", err))?;
        if !output.status.success() {
            return Ok(false);
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout.trim() == "OK")
    }

    fn run_sql_output(&self, sql: &str) -> Result<SqlRunOutput, String> {
        let mut cmd = Command::new(&self.config.surreal_bin);
        cmd.arg("sql")
            .arg("--hide-welcome")
            .arg("--endpoint")
            .arg(&self.config.endpoint)
            .arg("--json");

        if let Some(level) = &self.config.auth_level {
            cmd.arg("--auth-level").arg(level);
        }
        if let Some(ns) = &self.config.namespace {
            cmd.arg("--namespace").arg(ns);
        }
        if let Some(db) = &self.config.database {
            cmd.arg("--database").arg(db);
        }
        if let Some(user) = &self.config.username {
            cmd.arg("--username").arg(user);
        }
        if let Some(pass) = &self.config.password {
            cmd.arg("--password").arg(pass);
        }
        if let Some(token) = &self.config.token {
            cmd.arg("--token").arg(token);
        }

        let mut child = cmd
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| format!("spawn surreal sql: {}", err))?;

        child
            .stdin
            .as_mut()
            .ok_or_else(|| "failed to open surreal sql stdin".to_string())?
            .write_all(sql.as_bytes())
            .map_err(|err| format!("write surreal sql stdin: {}", err))?;

        let output = child
            .wait_with_output()
            .map_err(|err| format!("wait surreal sql: {}", err))?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !output.status.success() {
            return Err(format!(
                "surreal sql failed (exit={}):\nstdout:\n{}\nstderr:\n{}",
                output.status, stdout, stderr
            ));
        }

        // IMPORTANT: `surreal sql --json` may exit 0 even when statements fail.
        // Empirically, failures can surface as `null` entries or as an array of strings.
        let values = parse_json_stream(&stdout).map_err(|err| {
            format!(
                "surreal sql returned non-json output: {}\nstdout:\n{}\nstderr:\n{}",
                err, stdout, stderr
            )
        })?;
        Ok(SqlRunOutput {
            values,
            stdout: stdout.to_string(),
            stderr: stderr.to_string(),
        })
    }

    fn run_sql(&self, sql: &str) -> Result<(), String> {
        let output = self.run_sql_output(sql)?;
        check_surreal_json_stream(&output.values).map_err(|msg| {
            format!("{}\nstdout:\n{}\nstderr:\n{}", msg, output.stdout, output.stderr)
        })?;
        Ok(())
    }

    fn run_sql_allow_already_exists(&self, sql: &str) -> Result<(), String> {
        let output = self.run_sql_output(sql)?;
        check_surreal_json_stream_allow_already_exists(&output.values).map_err(|msg| {
            format!("{}\nstdout:\n{}\nstderr:\n{}", msg, output.stdout, output.stderr)
        })?;
        Ok(())
    }

    pub fn ensure_doc_chunk_schema(&self) -> Result<(), String> {
        // Keep this schema idempotent: tolerate "already exists" errors.
        let sql = r#"
DEFINE TABLE doc_chunk SCHEMALESS;
DEFINE ANALYZER doc_chunk_en TOKENIZERS blank FILTERS lowercase, ascii;
DEFINE INDEX doc_chunk_text_ft ON TABLE doc_chunk COLUMNS text SEARCH ANALYZER doc_chunk_en BM25;
DEFINE INDEX doc_chunk_doc_path ON TABLE doc_chunk COLUMNS doc_path;
"#;
        self.run_sql_allow_already_exists(sql)
    }

    pub fn ensure_doc_file_schema(&self) -> Result<(), String> {
        let sql = r#"
DEFINE TABLE doc_file SCHEMALESS;
DEFINE INDEX doc_file_path ON TABLE doc_file COLUMNS doc_path UNIQUE;
DEFINE INDEX doc_file_role ON TABLE doc_file COLUMNS fm_role;
DEFINE INDEX doc_file_type ON TABLE doc_file COLUMNS fm_type;
DEFINE INDEX doc_file_status_date ON TABLE doc_file COLUMNS fm_status_date;
DEFINE INDEX doc_file_canonical ON TABLE doc_file COLUMNS fm_canonical;
DEFINE INDEX doc_file_facets ON TABLE doc_file COLUMNS fm_facets;

DEFINE TABLE facet SCHEMALESS;
DEFINE INDEX facet_name ON TABLE facet COLUMNS name UNIQUE;

DEFINE TABLE has_facet SCHEMALESS;
DEFINE INDEX has_facet_doc_path ON TABLE has_facet COLUMNS doc_path;
DEFINE INDEX has_facet_name ON TABLE has_facet COLUMNS facet_name;
DEFINE INDEX has_facet_run ON TABLE has_facet COLUMNS projection_run_id;

DEFINE TABLE embed_run SCHEMALESS;
DEFINE INDEX embed_run_kind ON TABLE embed_run COLUMNS kind;
DEFINE INDEX embed_run_model ON TABLE embed_run COLUMNS model;
DEFINE INDEX embed_run_dim_target ON TABLE embed_run COLUMNS dim_target;
DEFINE INDEX embed_run_parse_sha256 ON TABLE embed_run COLUMNS parse_sha256;
DEFINE INDEX embed_run_snapshot_sha256 ON TABLE embed_run COLUMNS snapshot_sha256;
DEFINE INDEX embed_run_created_at ON TABLE embed_run COLUMNS created_at_utc;

DEFINE TABLE doc_embedding SCHEMALESS;
DEFINE INDEX doc_embedding_doc_path ON TABLE doc_embedding COLUMNS doc_path;
DEFINE INDEX doc_embedding_model ON TABLE doc_embedding COLUMNS model;
DEFINE INDEX doc_embedding_node ON TABLE doc_embedding COLUMNS node_id;
DEFINE INDEX doc_embedding_dim_target ON TABLE doc_embedding COLUMNS dim_target;

DEFINE TABLE doc_embedding_doc SCHEMALESS;
DEFINE INDEX doc_embedding_doc_path ON TABLE doc_embedding_doc COLUMNS doc_path;
DEFINE INDEX doc_embedding_doc_model ON TABLE doc_embedding_doc COLUMNS model;
DEFINE INDEX doc_embedding_doc_dim_target ON TABLE doc_embedding_doc COLUMNS dim_target;

DEFINE TABLE doc_title_embedding SCHEMALESS;
DEFINE INDEX doc_title_embedding_doc_path ON TABLE doc_title_embedding COLUMNS doc_path;
DEFINE INDEX doc_title_embedding_model ON TABLE doc_title_embedding COLUMNS model;
DEFINE INDEX doc_title_embedding_dim_target ON TABLE doc_title_embedding COLUMNS dim_target;
"#;
        self.run_sql_allow_already_exists(sql)
    }

    pub fn ensure_projection_run_schema(&self) -> Result<(), String> {
        let sql = r#"
DEFINE TABLE projection_run SCHEMALESS;
DEFINE INDEX projection_run_trace ON TABLE projection_run COLUMNS trace_sha256;
DEFINE INDEX projection_run_ingest ON TABLE projection_run COLUMNS ingest_run_id;
DEFINE INDEX projection_run_status ON TABLE projection_run COLUMNS status;
DEFINE INDEX projection_run_started ON TABLE projection_run COLUMNS started_at;
DEFINE INDEX projection_run_config ON TABLE projection_run COLUMNS config_hash;
"#;
        self.run_sql_allow_already_exists(sql)
    }

    pub fn ensure_projection_event_schema(&self) -> Result<(), String> {
        let sql = r#"
DEFINE TABLE projection_event SCHEMALESS;
DEFINE INDEX projection_event_run_id ON TABLE projection_event COLUMNS run_id;
DEFINE INDEX projection_event_run ON TABLE projection_event COLUMNS projection_run_id;
DEFINE INDEX projection_event_phase ON TABLE projection_event COLUMNS phase;
DEFINE INDEX projection_event_type ON TABLE projection_event COLUMNS event_type;
DEFINE INDEX projection_event_timestamp ON TABLE projection_event COLUMNS timestamp;
DEFINE INDEX projection_event_trace ON TABLE projection_event COLUMNS trace_sha256;
"#;
        self.run_sql_allow_already_exists(sql)
    }

    pub fn ensure_ingest_run_schema(&self) -> Result<(), String> {
        let sql = r#"
DEFINE TABLE ingest_run SCHEMALESS;
DEFINE INDEX ingest_run_started ON TABLE ingest_run COLUMNS started_at;
DEFINE INDEX ingest_run_status ON TABLE ingest_run COLUMNS status;
DEFINE INDEX ingest_run_root ON TABLE ingest_run COLUMNS root;
"#;
        self.run_sql_allow_already_exists(sql)
    }

    pub fn ensure_ingest_event_schema(&self) -> Result<(), String> {
        let sql = r#"
DEFINE TABLE ingest_event SCHEMALESS;
DEFINE INDEX ingest_event_run ON TABLE ingest_event COLUMNS ingest_run_id;
DEFINE INDEX ingest_event_type ON TABLE ingest_event COLUMNS event_type;
DEFINE INDEX ingest_event_timestamp ON TABLE ingest_event COLUMNS timestamp;
"#;
        self.run_sql_allow_already_exists(sql)
    }

    pub fn ensure_query_artifact_schema(&self) -> Result<(), String> {
        let sql = r#"
DEFINE TABLE query_artifact SCHEMALESS;
DEFINE INDEX query_artifact_sha ON TABLE query_artifact COLUMNS artifact_sha256;
DEFINE INDEX query_artifact_name ON TABLE query_artifact COLUMNS name;
DEFINE INDEX query_artifact_lang ON TABLE query_artifact COLUMNS lang;
DEFINE INDEX query_artifact_created ON TABLE query_artifact COLUMNS created_at_utc;
"#;
        self.run_sql_allow_already_exists(sql)
    }

    pub fn ensure_function_artifact_schema(&self) -> Result<(), String> {
        let sql = r#"
DEFINE TABLE fn_artifact SCHEMALESS;
DEFINE INDEX fn_artifact_sha ON TABLE fn_artifact COLUMNS artifact_sha256;
DEFINE INDEX fn_artifact_name ON TABLE fn_artifact COLUMNS name;
DEFINE INDEX fn_artifact_lang ON TABLE fn_artifact COLUMNS lang;
DEFINE INDEX fn_artifact_created ON TABLE fn_artifact COLUMNS created_at_utc;
"#;
        self.run_sql_allow_already_exists(sql)
    }

    /// Begin a new projection run, returns the run_id
    pub fn begin_projection_run(&self, run: &crate::projection_run::ProjectionRun) -> Result<String, String> {
        use crate::projection_run::RunStatus;

        let status_str = match run.status {
            RunStatus::Running => "running",
            RunStatus::Partial => "partial",
            RunStatus::Complete => "complete",
            RunStatus::Failed => "failed",
            RunStatus::Superseded => "superseded",
        };

        let phases_json = serde_json::to_string(&run.phases_enabled)
            .map_err(|e| format!("Failed to serialize phases: {}", e))?;

        let sql = format!(
            "INSERT INTO projection_run {{ \
                run_id: {}, \
                ingest_run_id: {}, \
                trace_sha256: {}, \
                started_at: {}, \
                projector_version: {}, \
                config_hash: {}, \
                phases_enabled: {}, \
                status: {}, \
                phase_results: {{}} \
            }};",
            json_string(&run.run_id),
            json_opt_string(run.ingest_run_id.as_deref()),
            json_string(&run.trace_sha256),
            json_string(&run.started_at),
            json_string(&run.projector_version),
            json_string(&run.config_hash),
            phases_json,
            json_string(status_str),
        );

        self.run_sql(&sql)?;
        Ok(run.run_id.clone())
    }

    /// End a projection run with final status
    pub fn end_projection_run(
        &self,
        run_id: &str,
        status: crate::projection_run::RunStatus,
        finished_at: &str,
        phase_results: &std::collections::BTreeMap<String, crate::projection_run::PhaseResult>,
    ) -> Result<(), String> {
        let status_str = match status {
            crate::projection_run::RunStatus::Running => "running",
            crate::projection_run::RunStatus::Partial => "partial",
            crate::projection_run::RunStatus::Complete => "complete",
            crate::projection_run::RunStatus::Failed => "failed",
            crate::projection_run::RunStatus::Superseded => "superseded",
        };

        let phase_results_json = serde_json::to_string(phase_results)
            .map_err(|e| format!("Failed to serialize phase results: {}", e))?;

        let sql = format!(
            "UPDATE projection_run SET \
                status = {}, \
                finished_at = {}, \
                phase_results = {} \
            WHERE run_id = {};",
            json_string(status_str),
            json_string(finished_at),
            phase_results_json,
            json_string(run_id),
        );

        self.run_sql(&sql)
    }

    /// Get the latest projection run for a given trace
    pub fn get_latest_projection_run(&self, trace_sha256: &str) -> Result<Option<serde_json::Value>, String> {
        let sql = format!(
            "SELECT * FROM projection_run \
            WHERE trace_sha256 = {} \
            ORDER BY started_at DESC \
            LIMIT 1;",
            json_string(trace_sha256),
        );

        let output = self.run_sql_output(&sql)?;
        if output.values.is_empty() {
            return Ok(None);
        }

        // Extract first result
        if let Some(serde_json::Value::Array(arr)) = output.values.first() {
            if let Some(result) = arr.first() {
                if let serde_json::Value::Object(obj) = result {
                    if let Some(result_val) = obj.get("result") {
                        if let serde_json::Value::Array(result_arr) = result_val {
                            return Ok(result_arr.first().cloned());
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    /// Find the newest complete run matching (trace_sha256, config_hash, phases_enabled).
    ///
    /// Used to skip projection work when an identical complete run already exists.
    pub fn find_complete_projection_run(
        &self,
        trace_sha256: &str,
        config_hash: &str,
        phases_enabled: &[String],
    ) -> Result<Option<serde_json::Value>, String> {
        let phases_json =
            serde_json::to_string(phases_enabled).unwrap_or_else(|_| "[]".to_string());
        let sql = format!(
            "SELECT * FROM projection_run \
            WHERE trace_sha256 = {} AND config_hash = {} AND phases_enabled = {} AND status = 'complete' \
            ORDER BY started_at DESC \
            LIMIT 1;",
            json_string(trace_sha256),
            json_string(config_hash),
            phases_json,
        );
        let output = self.run_sql_output(&sql)?;
        check_surreal_json_stream(&output.values).map_err(|msg| {
            format!("{}\nstdout:\n{}\nstderr:\n{}", msg, output.stdout, output.stderr)
        })?;
        let values = extract_result_array(&output.values)?;
        Ok(values.first().cloned())
    }

    pub fn projection_run_record(&self, run_id: &str) -> Result<Option<serde_json::Value>, String> {
        let sql = format!(
            "SELECT * FROM projection_run WHERE run_id = {} LIMIT 1;",
            json_string(run_id),
        );
        let output = self.run_sql_output(&sql)?;
        check_surreal_json_stream(&output.values).map_err(|msg| {
            format!("{}\nstdout:\n{}\nstderr:\n{}", msg, output.stdout, output.stderr)
        })?;
        let values = extract_result_array(&output.values)?;
        Ok(values.first().cloned())
    }

    pub fn dag_trace_bytes_for_trace(&self, trace_sha256: &str) -> Result<Vec<u8>, String> {
        let sql = format!(
            "SELECT bytes_cbor_hex FROM dag_trace WHERE trace_sha256 = {} LIMIT 1;",
            json_string(trace_sha256),
        );
        let output = self.run_sql_output(&sql)?;
        check_surreal_json_stream(&output.values).map_err(|msg| {
            format!("{}\nstdout:\n{}\nstderr:\n{}", msg, output.stdout, output.stderr)
        })?;
        let values = extract_result_array(&output.values)?;
        for value in values {
            if let serde_json::Value::Object(obj) = value {
                if let Some(serde_json::Value::String(hex_str)) = obj.get("bytes_cbor_hex") {
                    let bytes = hex::decode(hex_str)
                        .map_err(|e| format!("decode dag_trace cbor hex: {}", e))?;
                    return Ok(bytes);
                }
            }
        }
        Err(format!(
            "dag_trace bytes not found for trace_sha256 {}",
            trace_sha256
        ))
    }

    pub fn retry_dag_trace_batches(
        &self,
        dag: &GovernedDag,
        run_id: &str,
        failed_batches: &[crate::projection_run::FailedBatch],
    ) -> Result<(usize, Vec<crate::projection_run::FailedBatch>), String> {
        let phase = "dag_trace";
        let mut node_lookup: BTreeMap<String, DagNode> = BTreeMap::new();
        for (id, node) in dag.nodes() {
            node_lookup.insert(id.to_string(), node.clone());
        }
        let mut edge_lookup: BTreeMap<String, DagEdge> = BTreeMap::new();
        for edge in dag.edges() {
            let edge_id = edge_identity_sha256(edge)?;
            edge_lookup.insert(edge_id, edge.clone());
        }

        let mut successful = 0usize;
        let mut failed: Vec<crate::projection_run::FailedBatch> = Vec::new();

        for batch in failed_batches {
            let mut sql = String::new();
            let mut found = 0usize;
            for item_id in &batch.item_ids {
                if let Some(node) = node_lookup.get(item_id) {
                    sql.push_str(&node_upsert_sql_with_run(item_id, node, Some(run_id)));
                    found += 1;
                    continue;
                }
                if let Some(edge) = edge_lookup.get(item_id) {
                    sql.push_str(&edge_relate_sql_with_run(item_id, edge, Some(run_id)));
                    found += 1;
                    continue;
                }
            }
            if found == 0 {
                failed.push(crate::projection_run::FailedBatch {
                    attempt_count: batch.attempt_count.saturating_add(1),
                    error: "no matching items in dag trace for batch".to_string(),
                    ..batch.clone()
                });
                continue;
            }

            match self.run_sql(&sql) {
                Ok(()) => successful += 1,
                Err(err) => failed.push(crate::projection_run::FailedBatch {
                    attempt_count: batch.attempt_count.saturating_add(1),
                    error: format!("retry {} batch failed: {}", phase, err),
                    ..batch.clone()
                }),
            }
        }

        Ok((successful, failed))
    }

    pub fn retry_doc_files_batches(
        &self,
        dag: &GovernedDag,
        artifacts_root: &Path,
        run_id: &str,
        failed_batches: &[crate::projection_run::FailedBatch],
    ) -> Result<(usize, Vec<crate::projection_run::FailedBatch>), String> {
        let phase = "doc_files";
        self.ensure_doc_file_schema()?;

        let mut doc_index: BTreeMap<String, (String, ArtifactRef)> = BTreeMap::new();
        for (id, node) in dag.nodes() {
            let NodeKind::FileAtPath { path, .. } = &node.kind else {
                continue;
            };
            if !path.to_lowercase().ends_with(".md") {
                continue;
            }
            let Some(artifact_ref) = node.artifact_ref.as_ref() else {
                continue;
            };
            doc_index.insert(path.clone(), (id.to_string(), artifact_ref.clone()));
        }

        let mut successful = 0usize;
        let mut failed: Vec<crate::projection_run::FailedBatch> = Vec::new();

        for batch in failed_batches {
            let mut sql = String::new();
            let mut found = 0usize;
            for doc_path in &batch.item_ids {
                let Some((file_node_id, artifact_ref)) = doc_index.get(doc_path) else {
                    continue;
                };
                let Some(rel_path) = artifact_ref.path.as_ref() else {
                    continue;
                };
                let doc = VaultDoc {
                    doc_path: doc_path.clone(),
                    doc_id: sha256_hex_str(doc_path),
                    file_node_id: file_node_id.clone(),
                    title: file_stem_title(doc_path),
                    artifact_sha256: artifact_ref.sha256.clone(),
                    artifact_abs_path: artifacts_root.join(Path::new(rel_path)),
                };

                let mut doc_sql = String::new();
                doc_sql.push_str(&doc_file_upsert_sql_with_run(&doc, Some(run_id)));

                let bytes = std::fs::read(&doc.artifact_abs_path);
                if let Ok(bytes) = bytes {
                    if let Ok(text) = std::str::from_utf8(&bytes) {
                        let fm = extract_frontmatter(text);
                        doc_sql.push_str(&doc_file_update_frontmatter_sql(&doc, fm.as_ref()));

                        if let Some(fm) = fm.as_ref() {
                            for facet in fm.facets.iter() {
                                if facet.trim().is_empty() {
                                    continue;
                                }
                                doc_sql.push_str(&facet_upsert_sql(facet));
                                let edge_id = has_facet_edge_id(&doc.doc_path, facet)
                                    .map_err(|e| format!("facet edge id: {}", e))?;
                                doc_sql.push_str(&has_facet_relate_sql(&doc, facet, &edge_id, Some(run_id)));
                            }
                        }
                    }
                }

                sql.push_str(&doc_sql);
                found += 1;
            }

            if found == 0 {
                failed.push(crate::projection_run::FailedBatch {
                    attempt_count: batch.attempt_count.saturating_add(1),
                    error: "no matching doc_files for batch".to_string(),
                    ..batch.clone()
                });
                continue;
            }

            match self.run_sql(&sql) {
                Ok(()) => successful += 1,
                Err(err) => failed.push(crate::projection_run::FailedBatch {
                    attempt_count: batch.attempt_count.saturating_add(1),
                    error: format!("retry {} batch failed: {}", phase, err),
                    ..batch.clone()
                }),
            }
        }

        Ok((successful, failed))
    }

    pub fn retry_doc_chunks_batches(
        &self,
        dag: &GovernedDag,
        artifacts_root: &Path,
        run_id: &str,
        failed_batches: &[crate::projection_run::FailedBatch],
    ) -> Result<(usize, Vec<crate::projection_run::FailedBatch>), String> {
        let phase = "doc_chunks";
        self.ensure_doc_chunk_schema()?;
        self.ensure_doc_file_schema()?;

        let mut chunk_index: BTreeMap<String, (String, String, Vec<String>, u32, ArtifactRef)> =
            BTreeMap::new();
        for (id, node) in dag.nodes() {
            let NodeKind::TextChunk {
                chunk_sha256,
                doc_path,
                heading_path,
                start_line,
            } = &node.kind
            else {
                continue;
            };
            let Some(artifact_ref) = node.artifact_ref.as_ref() else {
                continue;
            };
            chunk_index.insert(
                id.to_string(),
                (
                    chunk_sha256.clone(),
                    doc_path.clone(),
                    heading_path.clone(),
                    *start_line,
                    artifact_ref.clone(),
                ),
            );
        }

        let mut successful = 0usize;
        let mut failed: Vec<crate::projection_run::FailedBatch> = Vec::new();

        for batch in failed_batches {
            let mut sql = String::new();
            let mut found = 0usize;
            for node_id in &batch.item_ids {
                let Some((chunk_sha256, doc_path, heading_path, start_line, artifact_ref)) = chunk_index.get(node_id)
                else {
                    continue;
                };
                let Some(rel_path) = artifact_ref.path.as_ref() else {
                    continue;
                };
                let abs_path = artifacts_root.join(Path::new(rel_path));
                let bytes = match std::fs::read(&abs_path) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                let text = String::from_utf8_lossy(&bytes);
                let doc_ref = Some(thing("doc_file", &sha256_hex_str(doc_path)));
                let sql_item = doc_chunk_upsert_sql_with_run(
                    node_id,
                    chunk_sha256,
                    doc_path,
                    heading_path,
                    *start_line,
                    &artifact_ref.sha256,
                    &text,
                    doc_ref.as_deref(),
                    Some(run_id),
                );
                sql.push_str(&sql_item);
                found += 1;
            }

            if found == 0 {
                failed.push(crate::projection_run::FailedBatch {
                    attempt_count: batch.attempt_count.saturating_add(1),
                    error: "no matching doc_chunks for batch".to_string(),
                    ..batch.clone()
                });
                continue;
            }

            match self.run_sql(&sql) {
                Ok(()) => successful += 1,
                Err(err) => failed.push(crate::projection_run::FailedBatch {
                    attempt_count: batch.attempt_count.saturating_add(1),
                    error: format!("retry {} batch failed: {}", phase, err),
                    ..batch.clone()
                }),
            }
        }

        Ok((successful, failed))
    }

    pub fn projection_run_started_at(&self, run_id: &str) -> Result<Option<String>, String> {
        let sql = format!(
            "SELECT VALUE started_at FROM projection_run WHERE run_id = {} LIMIT 1;",
            json_string(run_id),
        );
        let output = self.run_sql_output(&sql)?;
        check_surreal_json_stream(&output.values).map_err(|msg| {
            format!("{}\nstdout:\n{}\nstderr:\n{}", msg, output.stdout, output.stderr)
        })?;
        let values = extract_result_array(&output.values)?;
        for value in values {
            if let serde_json::Value::String(s) = value {
                return Ok(Some(s));
            }
        }
        Ok(None)
    }

    pub fn projection_run_ids_before(&self, started_at: &str) -> Result<Vec<String>, String> {
        let sql = format!(
            "SELECT run_id, started_at FROM projection_run WHERE started_at < {} ORDER BY started_at ASC;",
            json_string(started_at),
        );
        let output = self.run_sql_output(&sql)?;
        check_surreal_json_stream(&output.values).map_err(|msg| {
            format!("{}\nstdout:\n{}\nstderr:\n{}", msg, output.stdout, output.stderr)
        })?;
        let values = extract_result_array(&output.values)?;
        let mut out: Vec<String> = Vec::new();
        for value in values {
            match value {
                serde_json::Value::Object(obj) => {
                    if let Some(serde_json::Value::String(id)) = obj.get("run_id") {
                        out.push(id.clone());
                    }
                }
                serde_json::Value::String(s) => out.push(s),
                _ => {}
            }
        }
        Ok(out)
    }

    pub fn vacuum_projection_runs(&self, run_ids: &[String]) -> Result<(), String> {
        if run_ids.is_empty() {
            return Ok(());
        }
        let runs_json = serde_json::to_string(run_ids)
            .map_err(|e| format!("serialize run_ids: {}", e))?;
        let sql = format!(
            "LET $runs = {runs};\
DELETE node WHERE projection_run_id IN $runs RETURN NONE;\
DELETE edge WHERE projection_run_id IN $runs RETURN NONE;\
DELETE dag_trace WHERE projection_run_id IN $runs RETURN NONE;\
DELETE doc_file WHERE projection_run_id IN $runs RETURN NONE;\
DELETE doc_chunk WHERE projection_run_id IN $runs RETURN NONE;\
DELETE obsidian_link WHERE projection_run_id IN $runs RETURN NONE;\
DELETE obsidian_file_link WHERE projection_run_id IN $runs RETURN NONE;\
DELETE doc_link_unresolved WHERE projection_run_id IN $runs RETURN NONE;\
DELETE has_facet WHERE projection_run_id IN $runs RETURN NONE;\
DELETE projection_event WHERE projection_run_id IN $runs RETURN NONE;\
DELETE projection_run WHERE run_id IN $runs RETURN NONE;",
            runs = runs_json
        );
        self.run_sql(&sql)
    }

    pub fn project_doc_embeddings(
        &self,
        chunk_rows: &[DocChunkEmbeddingRow],
        doc_rows: &[DocEmbeddingRow],
    ) -> Result<(), String> {
        self.ensure_doc_file_schema()?;

        let batch_limit = self.projection_config.batch_sizes.embeddings;
        let max_sql_bytes = self.projection_config.batch_sizes.max_sql_bytes.max(1);
        let mut batch_count: usize = 0;
        let mut sql = String::new();

        for row in chunk_rows {
            let embed_id = sha256_hex_str(&format!(
                "{}|{}|{}|{}",
                row.model, row.dim_target, row.node_id, row.chunk_sha256
            ));
            let emb_json = serde_json::to_string(&row.embedding)
                .map_err(|err| format!("json encode embedding: {}", err))?;
            let dim = row.embedding.len() as u32;
            let doc_id = sha256_hex_str(&row.doc_path);
            sql.push_str(&format!(
                "UPSERT {thing_id} CONTENT {{ embed_id: {embed_id}, node_id: {node_id}, doc_path: {doc_path}, start_line: {start_line}, chunk_sha256: {chunk_sha256}, model: {model}, dim_target: {dim_target}, dim: {dim}, embedding: {embedding}, doc: {doc_ref}, chunk: {chunk_ref} }} RETURN NONE;",
                thing_id = thing("doc_embedding", &embed_id),
                embed_id = json_string(&embed_id),
                node_id = json_string(&row.node_id),
                doc_path = json_string(&row.doc_path),
                start_line = row.start_line,
                chunk_sha256 = json_string(&row.chunk_sha256),
                model = json_string(&row.model),
                dim_target = row.dim_target,
                dim = dim,
                embedding = emb_json,
                doc_ref = thing("doc_file", &doc_id),
                chunk_ref = thing("doc_chunk", &row.node_id),
            ));
            batch_count += 1;
            if batch_count >= batch_limit || sql.len() >= max_sql_bytes {
                self.run_sql(&sql)?;
                sql.clear();
                batch_count = 0;
            }
        }

        for row in doc_rows {
            let embed_id = sha256_hex_str(&format!("{}|{}|{}", row.model, row.dim_target, row.doc_path));
            let emb_json = serde_json::to_string(&row.embedding)
                .map_err(|err| format!("json encode embedding: {}", err))?;
            let dim = row.embedding.len() as u32;
            let doc_id = sha256_hex_str(&row.doc_path);
            sql.push_str(&format!(
                "UPSERT {thing_id} CONTENT {{ embed_id: {embed_id}, doc_path: {doc_path}, model: {model}, dim_target: {dim_target}, dim: {dim}, chunk_count: {chunk_count}, embedding: {embedding}, doc: {doc_ref} }} RETURN NONE;",
                thing_id = thing("doc_embedding_doc", &embed_id),
                embed_id = json_string(&embed_id),
                doc_path = json_string(&row.doc_path),
                model = json_string(&row.model),
                dim_target = row.dim_target,
                dim = dim,
                chunk_count = row.chunk_count,
                embedding = emb_json,
                doc_ref = thing("doc_file", &doc_id),
            ));
            batch_count += 1;
            if batch_count >= batch_limit || sql.len() >= max_sql_bytes {
                self.run_sql(&sql)?;
                sql.clear();
                batch_count = 0;
            }
        }

        if !sql.is_empty() {
            self.run_sql(&sql)?;
        }

        Ok(())
    }

    pub fn ensure_vault_link_schema(&self) -> Result<(), String> {
        // `doc_file` is a stable keyspace for Obsidian-style notes. It is keyed by doc_path hash,
        // so links remain stable across file content edits.
        let sql = r#"
DEFINE TABLE obsidian_link SCHEMALESS;
DEFINE INDEX obsidian_link_from ON TABLE obsidian_link COLUMNS from_doc_path;
DEFINE INDEX obsidian_link_to ON TABLE obsidian_link COLUMNS to_doc_path;
DEFINE INDEX obsidian_link_run ON TABLE obsidian_link COLUMNS projection_run_id;

DEFINE TABLE obsidian_file_link SCHEMALESS;
DEFINE INDEX obsidian_file_link_from ON TABLE obsidian_file_link COLUMNS from_doc_path;
DEFINE INDEX obsidian_file_link_to_path ON TABLE obsidian_file_link COLUMNS to_file_path;
DEFINE INDEX obsidian_file_link_run ON TABLE obsidian_file_link COLUMNS projection_run_id;

DEFINE TABLE doc_link_unresolved SCHEMALESS;
DEFINE INDEX doc_link_unresolved_from ON TABLE doc_link_unresolved COLUMNS from_doc_path;
DEFINE INDEX doc_link_unresolved_kind ON TABLE doc_link_unresolved COLUMNS resolution_kind;
DEFINE INDEX doc_link_unresolved_run ON TABLE doc_link_unresolved COLUMNS projection_run_id;

DEFINE TABLE unresolved_link_suggestion SCHEMALESS;
DEFINE INDEX unresolved_link_suggestion_link ON TABLE unresolved_link_suggestion COLUMNS link_id;
DEFINE INDEX unresolved_link_suggestion_run ON TABLE unresolved_link_suggestion COLUMNS run_id;
DEFINE INDEX unresolved_link_suggestion_kind ON TABLE unresolved_link_suggestion COLUMNS resolution_kind;
DEFINE INDEX unresolved_link_suggestion_from ON TABLE unresolved_link_suggestion COLUMNS from_doc_path;
DEFINE INDEX unresolved_link_suggestion_vault ON TABLE unresolved_link_suggestion COLUMNS vault_prefix;

DEFINE TABLE doc_heading SCHEMALESS;
DEFINE INDEX doc_heading_doc ON TABLE doc_heading COLUMNS doc_path;
DEFINE INDEX doc_heading_slug ON TABLE doc_heading COLUMNS heading_slug;

DEFINE TABLE doc_stats SCHEMALESS;
DEFINE INDEX doc_stats_path ON TABLE doc_stats COLUMNS doc_path UNIQUE;
"#;
        self.run_sql_allow_already_exists(sql)
    }

    pub fn project_embed_run(&self, run: &EmbedRunRow) -> Result<(), String> {
        self.ensure_doc_file_schema()?;
        let sql = format!(
            "UPSERT {thing_id} CONTENT {{ run_id: {run_id}, kind: {kind}, trace_sha256: {trace_sha256}, snapshot_sha256: {snapshot_sha256}, parse_sha256: {parse_sha256}, root: {root}, model: {model}, dim_target: {dim_target}, dim_actual: {dim_actual}, doc_prefix: {doc_prefix}, query_prefix: {query_prefix}, created_at_utc: {created_at} }} RETURN NONE;",
            thing_id = thing("embed_run", &run.run_id),
            run_id = json_string(&run.run_id),
            kind = json_string(&run.kind),
            trace_sha256 = json_opt_string(run.trace_sha256.as_deref()),
            snapshot_sha256 = json_opt_string(run.snapshot_sha256.as_deref()),
            parse_sha256 = json_opt_string(run.parse_sha256.as_deref()),
            root = json_opt_string(run.root.as_deref()),
            model = json_string(&run.model),
            dim_target = run.dim_target,
            dim_actual = run
                .dim_actual
                .map(|v| v.to_string())
                .unwrap_or_else(|| "NULL".to_string()),
            doc_prefix = json_string(&run.doc_prefix),
            query_prefix = json_string(&run.query_prefix),
            created_at = json_string(&run.created_at_utc),
        );
        self.run_sql(&sql)
    }

    pub fn project_doc_files_from_artifacts(
        &self,
        dag: &GovernedDag,
        artifacts_root: &Path,
    ) -> Result<(), String> {
        self.ensure_doc_file_schema()?;

        let batch_limit = self.projection_config.batch_sizes.doc_files;
        let mut batch_count: usize = 0;
        let mut sql = String::new();

        for (id, node) in dag.nodes() {
            let NodeKind::FileAtPath { path, .. } = &node.kind else {
                continue;
            };
            if !path.to_lowercase().ends_with(".md") {
                continue;
            }
            let Some(artifact_ref) = node.artifact_ref.as_ref() else {
                continue;
            };
            let Some(rel_path) = artifact_ref.path.as_ref() else {
                continue;
            };

            let doc = VaultDoc {
                doc_path: path.clone(),
                doc_id: sha256_hex_str(path),
                file_node_id: id.to_string(),
                title: file_stem_title(path),
                artifact_sha256: artifact_ref.sha256.clone(),
                artifact_abs_path: artifacts_root.join(Path::new(rel_path)),
            };

            sql.push_str(&doc_file_upsert_sql(&doc));
            batch_count += 1;
            if batch_count >= batch_limit {
                self.run_sql(&sql)?;
                sql.clear();
                batch_count = 0;
            }

            // Parse + project frontmatter when available.
            let bytes = match std::fs::read(&doc.artifact_abs_path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let text = match std::str::from_utf8(&bytes) {
                Ok(t) => t,
                Err(_) => continue,
            };
            let fm = extract_frontmatter(text);
            sql.push_str(&doc_file_update_frontmatter_sql(&doc, fm.as_ref()));
            batch_count += 1;
            if batch_count >= batch_limit {
                self.run_sql(&sql)?;
                sql.clear();
                batch_count = 0;
            }

            // Refresh facet relations (derived view).
            sql.push_str(&format!(
                "DELETE has_facet WHERE doc_path = {} RETURN NONE;",
                json_string(&doc.doc_path)
            ));
            batch_count += 1;
            if batch_count >= batch_limit {
                self.run_sql(&sql)?;
                sql.clear();
                batch_count = 0;
            }
            if let Some(fm) = fm.as_ref() {
                for facet in fm.facets.iter() {
                    if facet.trim().is_empty() {
                        continue;
                    }
                    sql.push_str(&facet_upsert_sql(facet));
                    let edge_id = has_facet_edge_id(&doc.doc_path, facet)?;
                    sql.push_str(&has_facet_relate_sql(&doc, facet, &edge_id, None));
                    batch_count += 2;
                    if batch_count >= batch_limit {
                        self.run_sql(&sql)?;
                        sql.clear();
                        batch_count = 0;
                    }
                }
            }
        }

        if !sql.is_empty() {
            self.run_sql(&sql)?;
        }

        Ok(())
    }

    pub fn select_doc_files(&self, prefixes: &[&str]) -> Result<Vec<(String, String)>, String> {
        self.ensure_doc_file_schema()?;
        if prefixes.is_empty() {
            return Ok(Vec::new());
        }
        let mut conds = Vec::new();
        for p in prefixes {
            conds.push(format!("string::starts_with(doc_path, {})", json_string(p)));
        }
        let where_sql = conds.join(" OR ");
        let sql = format!("SELECT doc_path, title FROM doc_file WHERE {} LIMIT 100000;", where_sql);
        let rows = self.select_rows_from_single_select(&sql)?;
        let mut out = Vec::new();
        for r in rows {
            let Some(obj) = r.as_object() else { continue };
            let doc_path = obj.get("doc_path").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let title = obj.get("title").and_then(|v| v.as_str()).unwrap_or("").to_string();
            if doc_path.is_empty() {
                continue;
            }
            out.push((doc_path, title));
        }
        Ok(out)
    }

    pub fn project_doc_title_embeddings(&self, rows: &[DocTitleEmbeddingRow]) -> Result<(), String> {
        self.ensure_doc_file_schema()?;
        let batch_limit = self.projection_config.batch_sizes.embeddings;
        let max_sql_bytes = self.projection_config.batch_sizes.max_sql_bytes.max(1);
        let mut batch_count: usize = 0;
        let mut sql = String::new();

        for row in rows {
            let embed_id = sha256_hex_str(&format!("{}|{}|{}", row.model, row.dim_target, row.doc_path));
            let emb_json = serde_json::to_string(&row.embedding)
                .map_err(|err| format!("json encode embedding: {}", err))?;
            let dim = row.embedding.len() as u32;
            let doc_id = sha256_hex_str(&row.doc_path);
            sql.push_str(&format!(
                "UPSERT {thing_id} CONTENT {{ embed_id: {embed_id}, run_id: {run_id}, doc_path: {doc_path}, title: {title}, model: {model}, dim_target: {dim_target}, dim: {dim}, embedding: {embedding}, doc: {doc_ref} }} RETURN NONE;",
                thing_id = thing("doc_title_embedding", &embed_id),
                embed_id = json_string(&embed_id),
                run_id = json_string(&row.run_id),
                doc_path = json_string(&row.doc_path),
                title = json_string(&row.title),
                model = json_string(&row.model),
                dim_target = row.dim_target,
                dim = dim,
                embedding = emb_json,
                doc_ref = thing("doc_file", &doc_id),
            ));
            batch_count += 1;
            if batch_count >= batch_limit || sql.len() >= max_sql_bytes {
                self.run_sql(&sql)?;
                sql.clear();
                batch_count = 0;
            }
        }
        if !sql.is_empty() {
            self.run_sql(&sql)?;
        }
        Ok(())
    }

    pub fn select_unresolved_links(
        &self,
        prefixes: &[&str],
        kinds: &[&str],
        limit: usize,
        projection_run_id: Option<&str>,
    ) -> Result<Vec<UnresolvedLinkRow>, String> {
        self.ensure_vault_link_schema()?;
        if prefixes.is_empty() || kinds.is_empty() {
            return Ok(Vec::new());
        }
        let mut conds = Vec::new();
        for p in prefixes {
            conds.push(format!("string::starts_with(from_doc_path, {})", json_string(p)));
        }
        let where_prefix = conds.join(" OR ");
        let kinds_json = serde_json::to_string(kinds).unwrap_or_else(|_| "[]".to_string());
        let lim = limit.max(1).min(100000);
        let run_filter = projection_run_id
            .map(|rid| format!(" AND projection_run_id = {}", json_string(rid)))
            .unwrap_or_default();
        let sql = format!(
            "SELECT link_id, from_doc_path, raw_target, raw_heading, resolution_kind, candidates, resolved_doc_path, line, embed FROM doc_link_unresolved WHERE ({}) AND resolution_kind IN {}{} LIMIT {};",
            where_prefix, kinds_json, run_filter, lim
        );
        let rows = self.select_rows_from_single_select(&sql)?;
        let mut out = Vec::new();
        for r in rows {
            let Some(obj) = r.as_object() else { continue };
            let link_id = obj.get("link_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let from_doc_path = obj.get("from_doc_path").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let raw_target = obj.get("raw_target").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let raw_heading = obj.get("raw_heading").and_then(|v| v.as_str()).map(|s| s.to_string());
            let resolution_kind = obj.get("resolution_kind").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let resolved_doc_path = obj.get("resolved_doc_path").and_then(|v| v.as_str()).map(|s| s.to_string());
            let line = obj.get("line").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
            let embed = obj.get("embed").and_then(|v| v.as_bool()).unwrap_or(false);
            let mut candidates: Vec<String> = Vec::new();
            if let Some(arr) = obj.get("candidates").and_then(|v| v.as_array()) {
                for c in arr {
                    if let Some(s) = c.as_str() {
                        candidates.push(s.to_string());
                    }
                }
            }
            if link_id.is_empty() || from_doc_path.is_empty() || raw_target.is_empty() || resolution_kind.is_empty() {
                continue;
            }
            out.push(UnresolvedLinkRow {
                link_id,
                from_doc_path,
                raw_target,
                raw_heading,
                resolution_kind,
                candidates,
                resolved_doc_path,
                line,
                embed,
            });
        }
        Ok(out)
    }

    pub fn search_doc_title_embeddings(
        &self,
        vault_prefix: &str,
        model: &str,
        dim_target: u32,
        query_embedding: &[f32],
        limit: usize,
    ) -> Result<Vec<(String, f64)>, String> {
        self.ensure_doc_file_schema()?;
        let emb_json =
            serde_json::to_string(query_embedding).map_err(|err| format!("json encode query embedding: {}", err))?;
        let lim = limit.max(1).min(50);
        let sql = format!(
            "SELECT doc_path, vector::similarity::cosine(embedding, {q}) AS sim FROM doc_title_embedding WHERE model={model} AND dim_target={dim} AND string::starts_with(doc_path, {prefix}) ORDER BY sim DESC LIMIT {lim};",
            q = emb_json,
            model = json_string(model),
            dim = dim_target,
            prefix = json_string(vault_prefix),
            lim = lim,
        );
        let rows = self.select_rows_from_single_select(&sql)?;
        let mut out = Vec::new();
        for r in rows {
            let Some(obj) = r.as_object() else { continue };
            let doc_path = obj.get("doc_path").and_then(|v| v.as_str()).unwrap_or("").to_string();
            let sim = obj.get("sim").and_then(|v| v.as_f64()).unwrap_or(0.0);
            if doc_path.is_empty() {
                continue;
            }
            out.push((doc_path, sim));
        }
        Ok(out)
    }

    pub fn project_unresolved_link_suggestions(
        &self,
        run_id: &str,
        rows: &[UnresolvedLinkSuggestionRow],
    ) -> Result<(), String> {
        self.ensure_vault_link_schema()?;
        let mut sql = String::new();
        sql.push_str(&format!(
            "DELETE unresolved_link_suggestion WHERE run_id = {} RETURN NONE;",
            json_string(run_id)
        ));

        let batch_limit = self.projection_config.batch_sizes.links;
        let max_sql_bytes = self.projection_config.batch_sizes.max_sql_bytes.max(1);
        let mut batch_count: usize = 0;

        for row in rows {
            let candidates_json = serde_json::to_string(
                &row
                    .candidates
                    .iter()
                    .map(|(p, s)| serde_json::json!({ "doc_path": p, "sim": s }))
                    .collect::<Vec<_>>(),
            )
            .unwrap_or_else(|_| "[]".to_string());

            sql.push_str(&format!(
                "UPSERT {thing_id} CONTENT {{ suggestion_id: {suggestion_id}, run_id: {run_id}, link_id: {link_id}, from_doc_path: {from_doc_path}, line: {line}, embed: {embed}, raw_target: {raw_target}, raw_heading: {raw_heading}, resolution_kind: {resolution_kind}, vault_prefix: {vault_prefix}, model: {model}, dim_target: {dim_target}, recommended_doc_path: {recommended_doc_path}, candidates: {candidates} }} RETURN NONE;",
                thing_id = thing("unresolved_link_suggestion", &row.suggestion_id),
                suggestion_id = json_string(&row.suggestion_id),
                run_id = json_string(&row.run_id),
                link_id = json_string(&row.link_id),
                from_doc_path = json_string(&row.from_doc_path),
                line = row.line,
                embed = if row.embed { "true" } else { "false" },
                raw_target = json_string(&row.raw_target),
                raw_heading = json_opt_string(row.raw_heading.as_deref()),
                resolution_kind = json_string(&row.resolution_kind),
                vault_prefix = json_string(&row.vault_prefix),
                model = json_string(&row.model),
                dim_target = row.dim_target,
                recommended_doc_path = json_opt_string(row.recommended_doc_path.as_deref()),
                candidates = candidates_json,
            ));
            batch_count += 1;
            if batch_count >= batch_limit || sql.len() >= max_sql_bytes {
                self.run_sql(&sql)?;
                sql.clear();
                batch_count = 0;
            }
        }
        if !sql.is_empty() {
            self.run_sql(&sql)?;
        }
        Ok(())
    }

    fn select_rows_from_single_select(&self, sql: &str) -> Result<Vec<serde_json::Value>, String> {
        let output = self.run_sql_output(sql)?;
        check_surreal_json_stream(&output.values).map_err(|msg| {
            format!("{}\nstdout:\n{}\nstderr:\n{}", msg, output.stdout, output.stderr)
        })?;
        let Some(first) = output.values.first() else {
            return Ok(Vec::new());
        };
        // Surreal JSON format for SELECT: [[{...}, ...]]
        let Some(top_arr) = first.as_array() else {
            return Ok(Vec::new());
        };
        let Some(inner) = top_arr.get(0).and_then(|v| v.as_array()) else {
            return Ok(Vec::new());
        };
        Ok(inner.clone())
    }

    pub fn project_doc_chunks_from_artifacts(
        &self,
        dag: &GovernedDag,
        artifacts_root: &Path,
        doc_file_prefixes: &[&str],
    ) -> Result<(), String> {
        self.ensure_doc_chunk_schema()?;
        self.ensure_doc_file_schema()?;

        let batch_limit = self.projection_config.batch_sizes.doc_chunks;
        let mut batch_count: usize = 0;
        let mut sql = String::new();

        for (id, node) in dag.nodes() {
            let NodeKind::TextChunk {
                chunk_sha256,
                doc_path,
                heading_path,
                start_line,
            } = &node.kind
            else {
                continue;
            };

            let Some(artifact_ref) = node.artifact_ref.as_ref() else {
                continue;
            };
            let Some(rel_path) = artifact_ref.path.as_ref() else {
                continue;
            };

            let abs_path = artifacts_root.join(Path::new(rel_path));
            let bytes = match std::fs::read(&abs_path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let text = String::from_utf8_lossy(&bytes);

            let record_id = id.to_string();
            let doc_ref = if doc_file_prefixes.is_empty() || doc_file_prefixes.iter().any(|p| doc_path.starts_with(p)) {
                Some(thing("doc_file", &sha256_hex_str(doc_path)))
            } else {
                None
            };
            sql.push_str(&doc_chunk_upsert_sql(
                &record_id,
                chunk_sha256,
                doc_path,
                heading_path,
                *start_line,
                &artifact_ref.sha256,
                &text,
                doc_ref.as_deref(),
            ));
            batch_count += 1;

            if batch_count >= batch_limit {
                self.run_sql(&sql)?;
                sql.clear();
                batch_count = 0;
            }
        }

        if !sql.is_empty() {
            self.run_sql(&sql)?;
        }

        Ok(())
    }

    pub fn project_vault_obsidian_links_from_artifacts(
        &self,
        dag: &GovernedDag,
        artifacts_root: &Path,
        vault_prefixes: &[&str],
        doc_filter: Option<&BTreeSet<String>>,
        run_id: Option<&str>,
    ) -> Result<crate::projection_run::PhaseResult, String> {
        let phase = "vault_links";
        let phase_start = std::time::Instant::now();
        self.ensure_doc_file_schema()?;
        self.ensure_vault_link_schema()?;

        // Index known vault markdown docs by path + stem for resolution.
        let mut vault_docs: BTreeMap<String, VaultDoc> = BTreeMap::new();
        let mut title_exact_index: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut title_casefold_index: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let heading_index = build_heading_index(dag, vault_prefixes);
        let vault_files = build_file_index(dag, vault_prefixes);

        for (id, node) in dag.nodes() {
            let NodeKind::FileAtPath { path, .. } = &node.kind else {
                continue;
            };
            if !vault_prefixes.iter().any(|p| path.starts_with(p)) {
                continue;
            }
            if !path.to_lowercase().ends_with(".md") {
                continue;
            }
            let Some(artifact_ref) = node.artifact_ref.as_ref() else {
                continue;
            };
            let Some(rel_path) = artifact_ref.path.as_ref() else {
                continue;
            };

            let title = file_stem_title(path);
            let abs_path = artifacts_root.join(Path::new(rel_path));
            vault_docs.insert(
                path.clone(),
                VaultDoc {
                    doc_path: path.clone(),
                    doc_id: sha256_hex_str(path),
                    file_node_id: id.to_string(),
                    title: title.clone(),
                    artifact_sha256: artifact_ref.sha256.clone(),
                    artifact_abs_path: abs_path,
                },
            );
            title_exact_index.entry(title.clone()).or_default().insert(path.clone());
            title_casefold_index
                .entry(title.to_lowercase())
                .or_default()
                .insert(path.clone());
        }

        // Upsert doc_file records for vault docs we saw.
        // In incremental mode, `doc_filter` narrows this to changed documents.
        let mut doc_file_batches = BatchAccumulator::new(
            self,
            phase,
            run_id,
            self.projection_config.batch_sizes.doc_files,
        );
        for doc in vault_docs.values() {
            if let Some(filter) = doc_filter {
                if !filter.contains(&doc.doc_path) {
                    continue;
                }
            }
            let sql = doc_file_upsert_sql_with_run(doc, run_id);
            doc_file_batches.push_item(doc.doc_path.clone(), &sql);
        }
        let doc_file_result = doc_file_batches.finish();

        // Project headings for vault docs (for observability + hygiene).
        // In incremental mode, `doc_filter` narrows this to changed documents.
        let mut heading_batches = BatchAccumulator::new(
            self,
            phase,
            run_id,
            self.projection_config.batch_sizes.headings,
        );
        for (_id, node) in dag.nodes() {
            let NodeKind::TextChunk {
                doc_path,
                heading_path,
                start_line,
                ..
            } = &node.kind
            else {
                continue;
            };
            if !vault_prefixes.iter().any(|p| doc_path.starts_with(p)) {
                continue;
            }
            if let Some(filter) = doc_filter {
                if !filter.contains(doc_path) {
                    continue;
                }
            }
            let Some(last) = heading_path.last() else {
                continue;
            };
            let heading_slug = obsidian_heading_slug(last);
            if heading_slug.is_empty() {
                continue;
            }
            let heading_id = sha256_hex_str(&format!("{}|{}|{}", doc_path, start_line, heading_slug));
            let sql = doc_heading_upsert_sql(
                &heading_id,
                doc_path,
                heading_path,
                *start_line,
                last,
                &heading_slug,
            );
            heading_batches.push_item(heading_id, &sql);
        }
        let heading_result = heading_batches.finish();

        // Build relation edges between doc_file records based on Obsidian wiki links.
        let mut stats_by_doc: BTreeMap<String, DocStatsAgg> = BTreeMap::new();
        let mut inbound_links: BTreeMap<String, u32> = BTreeMap::new();

        let mut doc_update_batches = BatchAccumulator::new(
            self,
            phase,
            run_id,
            self.projection_config.batch_sizes.doc_files,
        );
        let mut link_batches = BatchAccumulator::new(
            self,
            phase,
            run_id,
            self.projection_config.batch_sizes.links,
        );

        let mut files_read: u64 = 0;
        for doc in vault_docs.values() {
            if let Some(filter) = doc_filter {
                if !filter.contains(&doc.doc_path) {
                    continue;
                }
            }
            if run_id.is_none() {
                // Projection is derived; make it self-cleaning per source document so we don't accumulate ghosts
                // when notes change between ingestions.
                let mut delete_sql = String::new();
                delete_sql.push_str(&format!(
                    "DELETE obsidian_link WHERE from_doc_path = {} RETURN NONE;",
                    json_string(&doc.doc_path)
                ));
                delete_sql.push_str(&format!(
                    "DELETE obsidian_file_link WHERE from_doc_path = {} RETURN NONE;",
                    json_string(&doc.doc_path)
                ));
                delete_sql.push_str(&format!(
                    "DELETE doc_link_unresolved WHERE from_doc_path = {} RETURN NONE;",
                    json_string(&doc.doc_path)
                ));
                link_batches.push_item(format!("delete_links:{}", doc.doc_path), &delete_sql);
            }

            let mut stats = DocStatsAgg::default();

            let bytes = match std::fs::read(&doc.artifact_abs_path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            files_read = files_read.saturating_add(1);
            let text = match std::str::from_utf8(&bytes) {
                Ok(t) => t,
                Err(_) => continue,
            };

            let fm = extract_frontmatter(text);
            let doc_update_sql = doc_file_update_frontmatter_sql(doc, fm.as_ref());
            doc_update_batches.push_item(doc.doc_path.clone(), &doc_update_sql);

            for link in extract_obsidian_links(text) {
                if looks_like_asset_target(&link.target) {
                    let asset_res = resolve_obsidian_asset_target(
                        &doc.doc_path,
                        &link.target,
                        vault_prefixes,
                        &vault_files,
                    );
                    if let Some(asset_res) = asset_res {
                        stats.out_file_links = stats.out_file_links.saturating_add(1);
                        let edge_id = obsidian_file_link_edge_id(
                            &doc.doc_path,
                            &asset_res.to_file_path,
                            &link,
                            &asset_res.kind,
                        )?;
                        let link_sql = obsidian_file_link_relate_sql(
                            &doc.doc_path,
                            &doc.doc_id,
                            &asset_res.to_file_path,
                            &asset_res.to_file_node_id,
                            &edge_id,
                            &link,
                            &asset_res.kind,
                            run_id,
                        );
                        link_batches.push_item(format!("obsidian_file_link:{}", edge_id), &link_sql);
                        continue;
                    }
                    // If the asset can't be resolved, treat it as a missing link (unresolved).
                    stats.missing_out = stats.missing_out.saturating_add(1);
                    let resolution = ResolutionResult {
                        resolved: None,
                        kind: "missing".to_string(),
                        candidates: Vec::new(),
                        norm_target: normalize_target(&link.target),
                        norm_alias: normalize_optional(link.alias.as_deref()),
                        norm_heading: link
                            .heading
                            .as_deref()
                            .map(normalize_heading)
                            .filter(|s| !s.is_empty()),
                    };
                    let link_id = obsidian_unresolved_id(&doc.doc_path, &link)?;
                    let link_sql = doc_link_unresolved_upsert_sql(
                        &link_id,
                        &doc.doc_path,
                        &link,
                        &resolution,
                        None,
                        run_id,
                    );
                    link_batches.push_item(format!("doc_link_unresolved:{}", link_id), &link_sql);
                    continue;
                }

                let mut resolution = resolve_obsidian_target(
                    &doc.doc_path,
                    &link.target,
                    vault_prefixes,
                    &vault_docs,
                    &title_exact_index,
                    &title_casefold_index,
                );
                resolution.norm_alias = normalize_optional(link.alias.as_deref());
                resolution.norm_heading = link.heading.as_deref().map(normalize_heading).filter(|s| !s.is_empty());

                match resolution.kind.as_str() {
                    "missing" | "ambiguous" => {
                        if resolution.kind == "missing" {
                            stats.missing_out = stats.missing_out.saturating_add(1);
                        } else {
                            stats.ambiguous_out = stats.ambiguous_out.saturating_add(1);
                        }

                        if resolution.kind == "ambiguous" {
                            if let Some((chosen, kind)) =
                                choose_ambiguous_target(&doc.doc_path, &resolution.candidates)
                            {
                                resolution.resolved = Some(chosen.clone());
                                resolution.kind = kind;
                                // This is no longer ambiguous in practice; adjust the counters.
                                stats.ambiguous_out = stats.ambiguous_out.saturating_sub(1);
                            }
                        }

                        if resolution.resolved.is_some() {
                            let to_doc_path = resolution.resolved.as_ref().unwrap();

                            if let Some(h) = link.heading.as_ref() {
                                let wanted_norm = normalize_heading(h);
                                let wanted_slug = obsidian_heading_slug(h);
                                let ok = heading_index.get(to_doc_path).is_some_and(|set| {
                                    (!wanted_norm.is_empty() && set.contains(&wanted_norm))
                                        || (!wanted_slug.is_empty() && set.contains(&wanted_slug))
                                });
                                if !ok {
                                    stats.heading_missing_out = stats.heading_missing_out.saturating_add(1);
                                    let mut heading_miss = resolution.clone();
                                    heading_miss.kind = "heading_missing".to_string();
                                    let link_id = obsidian_unresolved_id(&doc.doc_path, &link)?;
                                    let link_sql = doc_link_unresolved_upsert_sql(
                                        &link_id,
                                        &doc.doc_path,
                                        &link,
                                        &heading_miss,
                                        Some(to_doc_path),
                                        run_id,
                                    );
                                    link_batches
                                        .push_item(format!("doc_link_unresolved:{}", link_id), &link_sql);
                                    continue;
                                }
                            }

                            stats.out_links = stats.out_links.saturating_add(1);
                            *inbound_links.entry(to_doc_path.clone()).or_insert(0) += 1;
                            let edge_id = obsidian_link_edge_id(
                                &doc.doc_path,
                                to_doc_path,
                                &link,
                                &resolution.kind,
                            )?;
                            let link_sql = obsidian_link_relate_sql(
                                &doc.doc_path,
                                to_doc_path,
                                &edge_id,
                                &link,
                                &resolution.kind,
                                run_id,
                            );
                            link_batches.push_item(format!("obsidian_link:{}", edge_id), &link_sql);
                            continue;
                        }

                        let link_id = obsidian_unresolved_id(&doc.doc_path, &link)?;
                        let link_sql = doc_link_unresolved_upsert_sql(
                            &link_id,
                            &doc.doc_path,
                            &link,
                            &resolution,
                            None,
                            run_id,
                        );
                        link_batches.push_item(format!("doc_link_unresolved:{}", link_id), &link_sql);
                    }
                    _ => {
                        let Some(to_doc_path) = resolution.resolved.as_ref() else {
                            stats.missing_out = stats.missing_out.saturating_add(1);
                            let link_id = obsidian_unresolved_id(&doc.doc_path, &link)?;
                            let link_sql = doc_link_unresolved_upsert_sql(
                                &link_id,
                                &doc.doc_path,
                                &link,
                                &resolution,
                                None,
                                run_id,
                            );
                            link_batches
                                .push_item(format!("doc_link_unresolved:{}", link_id), &link_sql);
                            continue;
                        };

                        if let Some(h) = link.heading.as_ref() {
                            let wanted_norm = normalize_heading(h);
                            let wanted_slug = obsidian_heading_slug(h);
                            let ok = heading_index.get(to_doc_path).is_some_and(|set| {
                                (!wanted_norm.is_empty() && set.contains(&wanted_norm))
                                    || (!wanted_slug.is_empty() && set.contains(&wanted_slug))
                            });
                            if !ok {
                                stats.heading_missing_out = stats.heading_missing_out.saturating_add(1);
                                let mut heading_miss = resolution.clone();
                                heading_miss.kind = "heading_missing".to_string();
                                let link_id = obsidian_unresolved_id(&doc.doc_path, &link)?;
                                let link_sql = doc_link_unresolved_upsert_sql(
                                    &link_id,
                                    &doc.doc_path,
                                    &link,
                                    &heading_miss,
                                    Some(to_doc_path),
                                    run_id,
                                );
                                link_batches
                                    .push_item(format!("doc_link_unresolved:{}", link_id), &link_sql);
                                continue;
                            }
                        }

                        stats.out_links = stats.out_links.saturating_add(1);
                        *inbound_links.entry(to_doc_path.clone()).or_insert(0) += 1;
                        let edge_id = obsidian_link_edge_id(&doc.doc_path, to_doc_path, &link, &resolution.kind)?;
                        let link_sql = obsidian_link_relate_sql(
                            &doc.doc_path,
                            to_doc_path,
                            &edge_id,
                            &link,
                            &resolution.kind,
                            run_id,
                        );
                        link_batches.push_item(format!("obsidian_link:{}", edge_id), &link_sql);
                    }
                }
            }

            stats_by_doc.insert(doc.doc_path.clone(), stats);
        }

        let doc_update_result = doc_update_batches.finish();
        let link_result = link_batches.finish();

        // Materialize doc-level stats so the UI can browse without heavy GROUP BY queries.
        let mut stats_batches = BatchAccumulator::new(
            self,
            phase,
            run_id,
            self.projection_config.batch_sizes.stats,
        );
        for doc in vault_docs.values() {
            if let Some(filter) = doc_filter {
                if !filter.contains(&doc.doc_path) {
                    continue;
                }
            }
            let stats = stats_by_doc.get(&doc.doc_path).cloned().unwrap_or_default();
            let in_links = inbound_links.get(&doc.doc_path).copied().unwrap_or(0);
            let sql = doc_stats_upsert_sql(doc, &stats, in_links);
            stats_batches.push_item(doc.doc_path.clone(), &sql);
        }
        let stats_result = stats_batches.finish();

        let total_batches = doc_file_result.total_batches
            + heading_result.total_batches
            + doc_update_result.total_batches
            + link_result.total_batches
            + stats_result.total_batches;
        let successful_batches = doc_file_result.successful_batches
            + heading_result.successful_batches
            + doc_update_result.successful_batches
            + link_result.successful_batches
            + stats_result.successful_batches;
        let mut failed_batches = doc_file_result.failed_batches;
        failed_batches.extend(heading_result.failed_batches);
        failed_batches.extend(doc_update_result.failed_batches);
        failed_batches.extend(link_result.failed_batches);
        failed_batches.extend(stats_result.failed_batches);

        let records_processed = doc_file_result.records_processed
            + heading_result.records_processed
            + doc_update_result.records_processed
            + link_result.records_processed
            + stats_result.records_processed;
        let bytes_written = doc_file_result.bytes_written
            + heading_result.bytes_written
            + doc_update_result.bytes_written
            + link_result.bytes_written
            + stats_result.bytes_written;
        let db_write_ms = doc_file_result.db_write_time_ms.unwrap_or(0)
            + heading_result.db_write_time_ms.unwrap_or(0)
            + doc_update_result.db_write_time_ms.unwrap_or(0)
            + link_result.db_write_time_ms.unwrap_or(0)
            + stats_result.db_write_time_ms.unwrap_or(0);

        let mut result = phase_result_from_batches(
            phase,
            total_batches,
            successful_batches,
            failed_batches,
            records_processed,
            bytes_written,
            db_write_ms,
        );
        let total_ms = phase_start.elapsed().as_millis() as u64;
        result.duration_ms = total_ms;
        result.files_read = Some(files_read);
        result.parse_time_ms = Some(total_ms.saturating_sub(db_write_ms));
        Ok(result)
    }
}

struct SqlRunOutput {
    values: Vec<serde_json::Value>,
    stdout: String,
    stderr: String,
}

fn phase_result_from_batches(
    phase: &str,
    total_batches: usize,
    successful_batches: usize,
    failed_batches: Vec<crate::projection_run::FailedBatch>,
    records_processed: u64,
    bytes_written: u64,
    db_write_time_ms: u64,
) -> crate::projection_run::PhaseResult {
    use crate::projection_run::PhaseStatus;

    let status = if total_batches == 0 || failed_batches.is_empty() {
        PhaseStatus::Complete
    } else if successful_batches == 0 {
        PhaseStatus::Failed
    } else {
        PhaseStatus::Partial
    };

    let error = if failed_batches.is_empty() {
        None
    } else {
        Some(format!(
            "{} of {} batches failed",
            failed_batches.len(),
            total_batches
        ))
    };

    let errors: Vec<String> = failed_batches
        .iter()
        .map(|b| format!("batch {}: {}", b.batch_index, b.error))
        .collect();

    crate::projection_run::PhaseResult {
        phase: phase.to_string(),
        status,
        total_batches,
        successful_batches,
        failed_batches,
        duration_ms: 0,
        records_processed,
        batches_executed: total_batches as u64,
        bytes_written,
        files_read: None,
        parse_time_ms: None,
        db_write_time_ms: Some(db_write_time_ms),
        errors,
        error,
    }
}

struct BatchAccumulator<'a> {
    store: &'a SurrealCliProjectionStore,
    phase: &'a str,
    run_id: String,
    batch_limit: usize,
    max_sql_bytes: usize,
    batch_index: usize,
    total_batches: usize,
    successful_batches: usize,
    failed_batches: Vec<crate::projection_run::FailedBatch>,
    records_processed: u64,
    bytes_written: u64,
    db_write_time_ms: u64,
    sql: String,
    item_ids: Vec<String>,
}

impl<'a> BatchAccumulator<'a> {
    fn new(
        store: &'a SurrealCliProjectionStore,
        phase: &'a str,
        run_id: Option<&str>,
        batch_limit: usize,
    ) -> Self {
        Self {
            store,
            phase,
            run_id: run_id.unwrap_or("unknown").to_string(),
            batch_limit: batch_limit.max(1),
            max_sql_bytes: store.projection_config.batch_sizes.max_sql_bytes.max(1),
            batch_index: 0,
            total_batches: 0,
            successful_batches: 0,
            failed_batches: Vec::new(),
            records_processed: 0,
            bytes_written: 0,
            db_write_time_ms: 0,
            sql: String::new(),
            item_ids: Vec::new(),
        }
    }

    fn push_item(&mut self, item_id: String, sql_fragment: &str) {
        self.sql.push_str(sql_fragment);
        self.item_ids.push(item_id);
        self.records_processed = self.records_processed.saturating_add(1);
        // Flush by count OR bytes. The bytes cap is the primary lever for reducing
        // `surreal sql` subprocess spawn overhead.
        if self.item_ids.len() >= self.batch_limit || self.sql.len() >= self.max_sql_bytes {
            self.flush();
        }
    }

    fn flush(&mut self) {
        if self.item_ids.is_empty() {
            return;
        }
        let sql = std::mem::take(&mut self.sql);
        let item_ids = std::mem::take(&mut self.item_ids);
        let batch_index = self.batch_index;
        self.batch_index = self.batch_index.saturating_add(1);
        self.total_batches = self.total_batches.saturating_add(1);
        self.bytes_written = self.bytes_written.saturating_add(sql.len() as u64);

        let start = std::time::Instant::now();
        match self.store.run_sql(&sql) {
            Ok(()) => {
                self.successful_batches = self.successful_batches.saturating_add(1);
            }
            Err(err) => {
                self.failed_batches.push(crate::projection_run::FailedBatch::new(
                    self.phase,
                    &self.run_id,
                    batch_index,
                    item_ids,
                    err,
                    1,
                ));
            }
        }
        self.db_write_time_ms = self
            .db_write_time_ms
            .saturating_add(start.elapsed().as_millis() as u64);
    }

    fn finish(mut self) -> crate::projection_run::PhaseResult {
        self.flush();
        phase_result_from_batches(
            self.phase,
            self.total_batches,
            self.successful_batches,
            self.failed_batches,
            self.records_processed,
            self.bytes_written,
            self.db_write_time_ms,
        )
    }
}

impl ProjectionStore for SurrealCliProjectionStore {
    fn project_dag_trace(
        &self,
        trace_sha256: &str,
        trace_cbor: &[u8],
        dag: &GovernedDag,
    ) -> Result<(), String> {
        let trace_cbor_hex = hex_lower(trace_cbor);

        // Store the trace envelope first.
        let trace_sql = format!(
            "UPSERT {} CONTENT {{ trace_sha256: {}, bytes_cbor_hex: {}, node_count: {}, edge_count: {} }} RETURN NONE;",
            thing("dag_trace", trace_sha256),
            json_string(trace_sha256),
            json_string(&trace_cbor_hex),
            dag.node_count(),
            dag.edge_count()
        );
        self.run_sql(&trace_sql)?;

        // Batch nodes / edges to avoid very large single SQL payloads.
        let batch_limit = self.projection_config.batch_sizes.nodes;
        let mut batch_count: usize = 0;
        let mut sql = String::new();

        for (id, node) in dag.nodes() {
            let record_id = id.to_string();
            sql.push_str(&node_upsert_sql(&record_id, node));
            batch_count += 1;
            if batch_count >= batch_limit {
                self.run_sql(&sql)?;
                sql.clear();
                batch_count = 0;
            }
        }
        if !sql.is_empty() {
            self.run_sql(&sql)?;
            sql.clear();
        }

        batch_count = 0;
        for edge in dag.edges() {
            let edge_id = edge_identity_sha256(edge)?;
            sql.push_str(&edge_relate_sql(&edge_id, edge));
            batch_count += 1;
            if batch_count >= batch_limit {
                self.run_sql(&sql)?;
                sql.clear();
                batch_count = 0;
            }
        }
        if !sql.is_empty() {
            self.run_sql(&sql)?;
        }

        Ok(())
    }
}

// Implementation of the new ProjectionStoreOps trait for SurrealCliProjectionStore
impl crate::projection_store::ProjectionStoreOps for SurrealCliProjectionStore {
    fn is_ready(&self) -> crate::projection_store::ProjectionResult<bool> {
        self.is_ready().map_err(|e| e.into())
    }

    fn store_name(&self) -> &str {
        "surreal-cli"
    }

    fn begin_run(
        &self,
        run: &crate::projection_run::ProjectionRun,
    ) -> crate::projection_store::ProjectionResult<String> {
        self.begin_projection_run(run).map_err(|e| e.into())
    }

    fn end_run(
        &self,
        run_id: &str,
        status: crate::projection_run::RunStatus,
        finished_at: &str,
        phase_results: &std::collections::BTreeMap<String, crate::projection_run::PhaseResult>,
    ) -> crate::projection_store::ProjectionResult<()> {
        self.end_projection_run(run_id, status, finished_at, phase_results)
            .map_err(|e| e.into())
    }

    fn get_latest_run(
        &self,
        trace_sha256: &str,
    ) -> crate::projection_store::ProjectionResult<Option<serde_json::Value>> {
        self.get_latest_projection_run(trace_sha256)
            .map_err(|e| e.into())
    }

    fn ensure_schemas(&self) -> crate::projection_store::ProjectionResult<()> {
        self.ensure_doc_chunk_schema()?;
        self.ensure_doc_file_schema()?;
        self.ensure_vault_link_schema()?;
        self.ensure_projection_run_schema()?;
        self.ensure_projection_event_schema()?;
        self.ensure_ingest_run_schema()?;
        self.ensure_ingest_event_schema()?;
        self.ensure_query_artifact_schema()?;
        self.ensure_function_artifact_schema()?;
        Ok(())
    }

    fn project_projection_events(
        &self,
        rows: &[crate::projection_events::ProjectionEventRow],
    ) -> crate::projection_store::ProjectionResult<()> {
        self.ensure_projection_event_schema()?;
        if rows.is_empty() {
            return Ok(());
        }

        // Batch to avoid huge SQL payloads (and to reduce `surreal sql` spawn overhead).
        let batch_limit = 200usize;
        let max_sql_bytes = self.projection_config.batch_sizes.max_sql_bytes.max(1);
        let mut sql = String::new();
        let mut count = 0usize;

        for row in rows {
            let thing_id = thing("projection_event", &row.event_id);
            let meta_json = if let Some(meta) = row.meta.as_ref() {
                serde_json::to_string(meta).unwrap_or_else(|_| "null".to_string())
            } else {
                "null".to_string()
            };
            sql.push_str(&format!(
                "UPSERT {} CONTENT {{ event_id: {}, event_type: {}, timestamp: {}, run_id: {}, projection_run_id: {}, phase: {}, status: {}, duration_ms: {}, error: {}, trace_sha256: {}, config_hash: {}, projector_version: {}, meta: {} }} RETURN NONE;\n",
                thing_id,
                json_string(&row.event_id),
                json_string(&row.event_type),
                json_string(&row.timestamp),
                json_string(&row.projection_run_id),
                json_string(&row.projection_run_id),
                json_opt_string(row.phase.as_deref()),
                json_opt_string(row.status.as_deref()),
                row.duration_ms.map(|v| v.to_string()).unwrap_or_else(|| "null".to_string()),
                json_opt_string(row.error.as_deref()),
                json_opt_string(row.trace_sha256.as_deref()),
                json_opt_string(row.config_hash.as_deref()),
                json_opt_string(row.projector_version.as_deref()),
                meta_json,
            ));
            count += 1;
            if count >= batch_limit || sql.len() >= max_sql_bytes {
                self.run_sql(&sql)?;
                sql.clear();
                count = 0;
            }
        }

        if !sql.is_empty() {
            self.run_sql(&sql)?;
        }

        Ok(())
    }

    fn project_ingest_run(
        &self,
        run: &crate::ingest_run::IngestRunRow,
    ) -> crate::projection_store::ProjectionResult<()> {
        self.ensure_ingest_run_schema()?;
        let sql = format!(
            "UPSERT {thing_id} CONTENT {{ ingest_run_id: {ingest_run_id}, started_at: {started_at}, finished_at: {finished_at}, status: {status}, root: {root}, config_sha256: {config_sha256}, coverage_sha256: {coverage_sha256}, ingest_run_sha256: {ingest_run_sha256}, snapshot_sha256: {snapshot_sha256}, parse_sha256: {parse_sha256}, files: {files}, chunks: {chunks}, total_bytes: {total_bytes} }} RETURN NONE;",
            thing_id = thing("ingest_run", &run.ingest_run_id),
            ingest_run_id = json_string(&run.ingest_run_id),
            started_at = json_string(&run.started_at),
            finished_at = json_opt_string(run.finished_at.as_deref()),
            status = json_string(&run.status),
            root = json_string(&run.root),
            config_sha256 = json_string(&run.config_sha256),
            coverage_sha256 = json_opt_string(run.coverage_sha256.as_deref()),
            ingest_run_sha256 = json_opt_string(run.ingest_run_sha256.as_deref()),
            snapshot_sha256 = json_opt_string(run.snapshot_sha256.as_deref()),
            parse_sha256 = json_opt_string(run.parse_sha256.as_deref()),
            files = run.files.map(|v| v.to_string()).unwrap_or_else(|| "null".to_string()),
            chunks = run.chunks.map(|v| v.to_string()).unwrap_or_else(|| "null".to_string()),
            total_bytes = run.total_bytes.map(|v| v.to_string()).unwrap_or_else(|| "null".to_string()),
        );
        self.run_sql(&sql).map_err(|e| e.into())
    }

    fn project_ingest_events(
        &self,
        rows: &[crate::ingest_events::IngestEventRow],
    ) -> crate::projection_store::ProjectionResult<()> {
        self.ensure_ingest_event_schema()?;
        if rows.is_empty() {
            return Ok(());
        }

        let batch_limit = 200usize;
        let mut sql = String::new();
        let mut count = 0usize;

        for row in rows {
            let thing_id = thing("ingest_event", &row.event_id);
            sql.push_str(&format!(
                "UPSERT {} CONTENT {{ event_id: {}, event_type: {}, timestamp: {}, ingest_run_id: {}, status: {}, duration_ms: {}, error: {}, root: {}, config_sha256: {}, coverage_sha256: {}, ingest_run_sha256: {}, snapshot_sha256: {}, parse_sha256: {}, files: {}, chunks: {}, total_bytes: {} }} RETURN NONE;\n",
                thing_id,
                json_string(&row.event_id),
                json_string(&row.event_type),
                json_string(&row.timestamp),
                json_string(&row.ingest_run_id),
                json_opt_string(row.status.as_deref()),
                row.duration_ms.map(|v| v.to_string()).unwrap_or_else(|| "null".to_string()),
                json_opt_string(row.error.as_deref()),
                json_opt_string(row.root.as_deref()),
                json_opt_string(row.config_sha256.as_deref()),
                json_opt_string(row.coverage_sha256.as_deref()),
                json_opt_string(row.ingest_run_sha256.as_deref()),
                json_opt_string(row.snapshot_sha256.as_deref()),
                json_opt_string(row.parse_sha256.as_deref()),
                row.files.map(|v| v.to_string()).unwrap_or_else(|| "null".to_string()),
                row.chunks.map(|v| v.to_string()).unwrap_or_else(|| "null".to_string()),
                row.total_bytes.map(|v| v.to_string()).unwrap_or_else(|| "null".to_string()),
            ));
            count += 1;
            if count >= batch_limit {
                self.run_sql(&sql)?;
                sql.clear();
                count = 0;
            }
        }

        if !sql.is_empty() {
            self.run_sql(&sql)?;
        }

        Ok(())
    }

    fn project_dag_trace(
        &self,
        trace_sha256: &str,
        trace_cbor: &[u8],
        dag: &GovernedDag,
        run_id: Option<&str>,
    ) -> crate::projection_store::ProjectionResult<crate::projection_run::PhaseResult> {
        let phase = "dag_trace";
        let phase_start = std::time::Instant::now();
        let trace_cbor_hex = hex_lower(trace_cbor);

        // Store the trace envelope first, with optional run_id stamping
        let run_id_field = if let Some(rid) = run_id {
            format!(", projection_run_id: {}", json_string(rid))
        } else {
            String::new()
        };

        let trace_sql = format!(
            "UPSERT {} CONTENT {{ trace_sha256: {}, bytes_cbor_hex: {}, node_count: {}, edge_count: {}{} }} RETURN NONE;",
            thing("dag_trace", trace_sha256),
            json_string(trace_sha256),
            json_string(&trace_cbor_hex),
            dag.node_count(),
            dag.edge_count(),
            run_id_field
        );
        let trace_sql_len = trace_sql.len() as u64;
        let trace_db_start = std::time::Instant::now();
        self.run_sql(&trace_sql)
            .map_err(|e| crate::projection_store::ProjectionError::new(e).with_phase(phase))?;
        let trace_db_ms = trace_db_start.elapsed().as_millis() as u64;

        // Batch nodes / edges to avoid very large single SQL payloads.
        let batch_limit = self.projection_config.batch_sizes.nodes;
        let mut node_batches = BatchAccumulator::new(self, phase, run_id, batch_limit);
        for (id, node) in dag.nodes() {
            let record_id = id.to_string();
            let sql = node_upsert_sql_with_run(&record_id, node, run_id);
            node_batches.push_item(record_id, &sql);
        }
        let node_result = node_batches.finish();

        let mut edge_batches = BatchAccumulator::new(self, phase, run_id, batch_limit);
        for edge in dag.edges() {
            let edge_id = edge_identity_sha256(edge).map_err(|e| {
                crate::projection_store::ProjectionError::new(e).with_phase(phase)
            })?;
            let sql = edge_relate_sql_with_run(&edge_id, edge, run_id);
            edge_batches.push_item(edge_id, &sql);
        }
        let edge_result = edge_batches.finish();

        let total_batches = node_result.total_batches + edge_result.total_batches;
        let successful_batches = node_result.successful_batches + edge_result.successful_batches;
        let mut failed_batches = node_result.failed_batches;
        failed_batches.extend(edge_result.failed_batches);
        let records_processed = node_result.records_processed + edge_result.records_processed;
        let bytes_written = trace_sql_len
            .saturating_add(node_result.bytes_written)
            .saturating_add(edge_result.bytes_written);
        let db_write_ms = trace_db_ms
            .saturating_add(node_result.db_write_time_ms.unwrap_or(0))
            .saturating_add(edge_result.db_write_time_ms.unwrap_or(0));
        let mut result = phase_result_from_batches(
            phase,
            total_batches,
            successful_batches,
            failed_batches,
            records_processed,
            bytes_written,
            db_write_ms,
        );
        let total_ms = phase_start.elapsed().as_millis() as u64;
        result.duration_ms = total_ms;
        result.parse_time_ms = Some(total_ms.saturating_sub(db_write_ms));
        Ok(result)
    }

    fn project_doc_files(
        &self,
        dag: &GovernedDag,
        artifacts_root: &Path,
        run_id: Option<&str>,
    ) -> crate::projection_store::ProjectionResult<crate::projection_run::PhaseResult> {
        let phase = "doc_files";
        let phase_start = std::time::Instant::now();
        self.ensure_doc_file_schema()
            .map_err(|e| crate::projection_store::ProjectionError::new(e).with_phase(phase))?;

        let batch_limit = self.projection_config.batch_sizes.doc_files;
        let mut batcher = BatchAccumulator::new(self, phase, run_id, batch_limit);
        let mut files_read: u64 = 0;

        for (id, node) in dag.nodes() {
            let NodeKind::FileAtPath { path, .. } = &node.kind else {
                continue;
            };
            if !path.to_lowercase().ends_with(".md") {
                continue;
            }
            let Some(artifact_ref) = node.artifact_ref.as_ref() else {
                continue;
            };
            let Some(rel_path) = artifact_ref.path.as_ref() else {
                continue;
            };

            let doc = VaultDoc {
                doc_path: path.clone(),
                doc_id: sha256_hex_str(path),
                file_node_id: id.to_string(),
                title: file_stem_title(path),
                artifact_sha256: artifact_ref.sha256.clone(),
                artifact_abs_path: artifacts_root.join(Path::new(rel_path)),
            };

            let mut doc_sql = String::new();
            doc_sql.push_str(&doc_file_upsert_sql_with_run(&doc, run_id));

            // Parse + project frontmatter when available.
            let bytes = match std::fs::read(&doc.artifact_abs_path) {
                Ok(b) => b,
                Err(_) => {
                    batcher.push_item(doc.doc_path.clone(), &doc_sql);
                    continue;
                }
            };
            files_read = files_read.saturating_add(1);
            let text = match std::str::from_utf8(&bytes) {
                Ok(t) => t,
                Err(_) => {
                    batcher.push_item(doc.doc_path.clone(), &doc_sql);
                    continue;
                }
            };
            let fm = extract_frontmatter(text);
            doc_sql.push_str(&doc_file_update_frontmatter_sql(&doc, fm.as_ref()));

            // Refresh facet relations (derived view).
            if run_id.is_none() {
                doc_sql.push_str(&format!(
                    "DELETE has_facet WHERE doc_path = {} RETURN NONE;",
                    json_string(&doc.doc_path)
                ));
            }
            if let Some(fm) = fm.as_ref() {
                for facet in fm.facets.iter() {
                    if facet.trim().is_empty() {
                        continue;
                    }
                    doc_sql.push_str(&facet_upsert_sql(facet));
                    let edge_id = has_facet_edge_id(&doc.doc_path, facet).map_err(|e| {
                        crate::projection_store::ProjectionError::new(e).with_phase(phase)
                    })?;
                    doc_sql.push_str(&has_facet_relate_sql(&doc, facet, &edge_id, run_id));
                }
            }

            batcher.push_item(doc.doc_path.clone(), &doc_sql);
        }

        let mut result = batcher.finish();
        let total_ms = phase_start.elapsed().as_millis() as u64;
        let db_write_ms = result.db_write_time_ms.unwrap_or(0);
        result.duration_ms = total_ms;
        result.files_read = Some(files_read);
        result.parse_time_ms = Some(total_ms.saturating_sub(db_write_ms));
        Ok(result)
    }

    fn project_doc_chunks(
        &self,
        dag: &GovernedDag,
        artifacts_root: &Path,
        doc_file_prefixes: &[&str],
        run_id: Option<&str>,
    ) -> crate::projection_store::ProjectionResult<crate::projection_run::PhaseResult> {
        let phase = "doc_chunks";
        let phase_start = std::time::Instant::now();
        self.ensure_doc_chunk_schema()
            .map_err(|e| crate::projection_store::ProjectionError::new(e).with_phase(phase))?;
        self.ensure_doc_file_schema()
            .map_err(|e| crate::projection_store::ProjectionError::new(e).with_phase(phase))?;

        let batch_limit = self.projection_config.batch_sizes.doc_chunks;
        let mut batcher = BatchAccumulator::new(self, phase, run_id, batch_limit);
        let mut files_read: u64 = 0;

        for (id, node) in dag.nodes() {
            let NodeKind::TextChunk {
                chunk_sha256,
                doc_path,
                heading_path,
                start_line,
            } = &node.kind
            else {
                continue;
            };

            let Some(artifact_ref) = node.artifact_ref.as_ref() else {
                continue;
            };
            let Some(rel_path) = artifact_ref.path.as_ref() else {
                continue;
            };

            let abs_path = artifacts_root.join(Path::new(rel_path));
            let bytes = match std::fs::read(&abs_path) {
                Ok(b) => b,
                Err(_) => continue,
            };
            files_read = files_read.saturating_add(1);
            let text = String::from_utf8_lossy(&bytes);

            let record_id = id.to_string();
            let doc_ref = if doc_file_prefixes.is_empty()
                || doc_file_prefixes.iter().any(|p| doc_path.starts_with(p))
            {
                Some(thing("doc_file", &sha256_hex_str(doc_path)))
            } else {
                None
            };
            let sql = doc_chunk_upsert_sql_with_run(
                &record_id,
                chunk_sha256,
                doc_path,
                heading_path,
                *start_line,
                &artifact_ref.sha256,
                &text,
                doc_ref.as_deref(),
                run_id,
            );
            batcher.push_item(record_id, &sql);
        }

        let mut result = batcher.finish();
        let total_ms = phase_start.elapsed().as_millis() as u64;
        let db_write_ms = result.db_write_time_ms.unwrap_or(0);
        result.duration_ms = total_ms;
        result.files_read = Some(files_read);
        result.parse_time_ms = Some(total_ms.saturating_sub(db_write_ms));
        Ok(result)
    }

    fn project_vault_links(
        &self,
        dag: &GovernedDag,
        artifacts_root: &Path,
        vault_prefixes: &[&str],
        doc_filter: Option<&BTreeSet<String>>,
        run_id: Option<&str>,
    ) -> crate::projection_store::ProjectionResult<crate::projection_run::PhaseResult> {
        // Delegate to existing implementation
        self.project_vault_obsidian_links_from_artifacts(
            dag,
            artifacts_root,
            vault_prefixes,
            doc_filter,
            run_id,
        )
            .map_err(|e| e.into())
    }

    fn project_embeddings(
        &self,
        chunk_rows: &[DocChunkEmbeddingRow],
        doc_rows: &[DocEmbeddingRow],
        _run_id: Option<&str>,
    ) -> crate::projection_store::ProjectionResult<()> {
        // Delegate to existing implementation
        // TODO: Add run_id stamping to embedding projection
        self.project_doc_embeddings(chunk_rows, doc_rows)
            .map_err(|e| e.into())
    }

    fn project_embed_run(&self, run: &EmbedRunRow) -> crate::projection_store::ProjectionResult<()> {
        SurrealCliProjectionStore::project_embed_run(self, run).map_err(|e| e.into())
    }

    fn project_title_embeddings(
        &self,
        rows: &[DocTitleEmbeddingRow],
        _run_id: Option<&str>,
    ) -> crate::projection_store::ProjectionResult<()> {
        // Delegate to existing implementation (already has run_id in rows)
        self.project_doc_title_embeddings(rows).map_err(|e| e.into())
    }

    fn project_unresolved_suggestions(
        &self,
        run_id: &str,
        rows: &[UnresolvedLinkSuggestionRow],
    ) -> crate::projection_store::ProjectionResult<()> {
        self.project_unresolved_link_suggestions(run_id, rows)
            .map_err(|e| e.into())
    }

    fn project_query_artifacts(
        &self,
        rows: &[QueryArtifactRow],
    ) -> crate::projection_store::ProjectionResult<()> {
        self.ensure_query_artifact_schema()?;
        if rows.is_empty() {
            return Ok(());
        }

        let batch_limit = 25usize;
        let mut sql = String::new();
        let mut count = 0usize;

        for row in rows {
            let thing_id = thing("query_artifact", &row.artifact_sha256);
            let tags_json = serde_json::to_string(&row.tags)
                .unwrap_or_else(|_| "[]".to_string());

            sql.push_str(&format!(
                "UPSERT {thing_id} CONTENT {{ artifact_sha256: {artifact_sha256}, schema_id: {schema_id}, name: {name}, lang: {lang}, source: {source}, tags: {tags}, created_at_utc: {created_at_utc} }} RETURN NONE;\n",
                thing_id = thing_id,
                artifact_sha256 = json_string(&row.artifact_sha256),
                schema_id = json_string(&row.schema_id),
                name = json_string(&row.name),
                lang = json_string(&row.lang),
                source = json_string(&row.source),
                tags = tags_json,
                created_at_utc = json_string(&row.created_at_utc),
            ));

            count += 1;
            if count >= batch_limit {
                self.run_sql(&sql)?;
                sql.clear();
                count = 0;
            }
        }

        if !sql.is_empty() {
            self.run_sql(&sql)?;
        }

        Ok(())
    }

    fn project_function_artifacts(
        &self,
        rows: &[FunctionArtifactRow],
    ) -> crate::projection_store::ProjectionResult<()> {
        self.ensure_function_artifact_schema()?;
        if rows.is_empty() {
            return Ok(());
        }

        let batch_limit = 25usize;
        let mut sql = String::new();
        let mut count = 0usize;

        for row in rows {
            let thing_id = thing("fn_artifact", &row.artifact_sha256);
            let tags_json = serde_json::to_string(&row.tags)
                .unwrap_or_else(|_| "[]".to_string());

            sql.push_str(&format!(
                "UPSERT {thing_id} CONTENT {{ artifact_sha256: {artifact_sha256}, schema_id: {schema_id}, name: {name}, lang: {lang}, source: {source}, tags: {tags}, created_at_utc: {created_at_utc} }} RETURN NONE;\n",
                thing_id = thing_id,
                artifact_sha256 = json_string(&row.artifact_sha256),
                schema_id = json_string(&row.schema_id),
                name = json_string(&row.name),
                lang = json_string(&row.lang),
                source = json_string(&row.source),
                tags = tags_json,
                created_at_utc = json_string(&row.created_at_utc),
            ));

            count += 1;
            if count >= batch_limit {
                self.run_sql(&sql)?;
                sql.clear();
                count = 0;
            }
        }

        if !sql.is_empty() {
            self.run_sql(&sql)?;
        }

        Ok(())
    }

    fn select_doc_files(
        &self,
        prefixes: &[&str],
    ) -> crate::projection_store::ProjectionResult<Vec<(String, String)>> {
        SurrealCliProjectionStore::select_doc_files(self, prefixes).map_err(|e| e.into())
    }

    fn select_unresolved_links(
        &self,
        prefixes: &[&str],
        kinds: &[&str],
        limit: usize,
        projection_run_id: Option<&str>,
    ) -> crate::projection_store::ProjectionResult<Vec<UnresolvedLinkRow>> {
        SurrealCliProjectionStore::select_unresolved_links(self, prefixes, kinds, limit, projection_run_id)
            .map_err(|e| e.into())
    }

    fn search_title_embeddings(
        &self,
        vault_prefix: &str,
        model: &str,
        dim_target: u32,
        query_embedding: &[f32],
        limit: usize,
    ) -> crate::projection_store::ProjectionResult<Vec<(String, f64)>> {
        self.search_doc_title_embeddings(vault_prefix, model, dim_target, query_embedding, limit)
            .map_err(|e| e.into())
    }
}

// VaultDoc, ObsidianLink, ResolutionResult, AssetResolution moved to link_resolver module
use crate::link_resolver::VaultDoc;

#[derive(Debug, Clone, Default)]
struct DocStatsAgg {
    out_links: u32,
    out_file_links: u32,
    missing_out: u32,
    ambiguous_out: u32,
    heading_missing_out: u32,
}

#[derive(Debug, Clone, Default)]
struct DocFrontmatter {
    raw_yaml: String,
    json: serde_json::Value,
    role: Option<String>,
    doc_type: Option<String>,
    canonical: Option<bool>,
    status_date: Option<String>,
    facets: Vec<String>,
}

fn node_upsert_sql(node_id: &str, node: &DagNode) -> String {
    node_upsert_sql_with_run(node_id, node, None)
}

fn node_upsert_sql_with_run(node_id: &str, node: &DagNode, run_id: Option<&str>) -> String {
    let (kind_tag, kind_fields_json) = split_kind(&node.kind);
    let (artifact_sha256, artifact_kind, artifact_schema_id) = match &node.artifact_ref {
        Some(r) => (
            Some(r.sha256.as_str()),
            Some(r.kind.as_str()),
            Some(r.schema_id.as_str()),
        ),
        None => (None, None, None),
    };

    let run_id_field = if let Some(rid) = run_id {
        format!(", projection_run_id: {}", json_string(rid))
    } else {
        String::new()
    };

    format!(
        "UPSERT {thing_id} CONTENT {{ node_id: {node_id}, category: {category}, scope_id: {scope}, kind_tag: {kind_tag}, kind_fields: {kind_fields}, artifact_sha256: {artifact_sha256}, artifact_kind: {artifact_kind}, artifact_schema_id: {artifact_schema_id}{run_id_field} }} RETURN NONE;",
        thing_id = thing("node", node_id),
        node_id = json_string(node_id),
        category = json_string(&format!("{:?}", node.category).to_lowercase()),
        scope = json_string(node.scope.as_str()),
        kind_tag = json_string(&kind_tag),
        kind_fields = kind_fields_json,
        artifact_sha256 = json_opt_string(artifact_sha256),
        artifact_kind = json_opt_string(artifact_kind),
        artifact_schema_id = json_opt_string(artifact_schema_id),
        run_id_field = run_id_field,
    )
}

fn doc_chunk_upsert_sql(
    node_id: &str,
    chunk_sha256: &str,
    doc_path: &str,
    heading_path: &[String],
    start_line: u32,
    artifact_sha256: &str,
    text: &str,
    doc_ref: Option<&str>,
) -> String {
    doc_chunk_upsert_sql_with_run(
        node_id,
        chunk_sha256,
        doc_path,
        heading_path,
        start_line,
        artifact_sha256,
        text,
        doc_ref,
        None,
    )
}

fn doc_chunk_upsert_sql_with_run(
    node_id: &str,
    chunk_sha256: &str,
    doc_path: &str,
    heading_path: &[String],
    start_line: u32,
    artifact_sha256: &str,
    text: &str,
    doc_ref: Option<&str>,
    run_id: Option<&str>,
) -> String {
    let headings_json =
        serde_json::to_string(heading_path).unwrap_or_else(|_| "[]".to_string());
    let node_ref = thing("node", node_id);
    let doc_field = surreal_record_or_null(doc_ref);
    let run_id_field = if let Some(rid) = run_id {
        format!(", projection_run_id: {}", json_string(rid))
    } else {
        String::new()
    };
    format!(
        "UPSERT {thing_id} CONTENT {{ node_id: {node_id}, node: {node_ref}, doc: {doc_ref}, chunk_sha256: {chunk_sha256}, doc_path: {doc_path}, heading_path: {heading_path}, start_line: {start_line}, artifact_sha256: {artifact_sha256}, text: {text}{run_id_field} }} RETURN NONE;",
        thing_id = thing("doc_chunk", node_id),
        node_id = json_string(node_id),
        node_ref = node_ref,
        doc_ref = doc_field,
        chunk_sha256 = json_string(chunk_sha256),
        doc_path = json_string(doc_path),
        heading_path = headings_json,
        start_line = start_line,
        artifact_sha256 = json_string(artifact_sha256),
        text = json_string(text),
        run_id_field = run_id_field,
    )
}

fn doc_file_upsert_sql(doc: &VaultDoc) -> String {
    doc_file_upsert_sql_with_run(doc, None)
}

fn doc_file_upsert_sql_with_run(doc: &VaultDoc, run_id: Option<&str>) -> String {
    let file_node_ref = thing("node", &doc.file_node_id);
    let run_id_field = if let Some(rid) = run_id {
        format!(", projection_run_id = {}", json_string(rid))
    } else {
        String::new()
    };
    format!(
        "UPSERT {thing_id} SET doc_id = {doc_id}, doc_path = {doc_path}, title = {title}, artifact_sha256 = {artifact_sha256}, file_node_id = {file_node_id}, file_node = {file_node}{run_id_field} RETURN NONE;",
        thing_id = thing("doc_file", &doc.doc_id),
        doc_id = json_string(&doc.doc_id),
        doc_path = json_string(&doc.doc_path),
        title = json_string(&doc.title),
        artifact_sha256 = json_string(&doc.artifact_sha256),
        file_node_id = json_string(&doc.file_node_id),
        file_node = file_node_ref,
        run_id_field = run_id_field,
    )
}

fn doc_file_update_frontmatter_sql(doc: &VaultDoc, fm: Option<&DocFrontmatter>) -> String {
    let Some(fm) = fm else {
        return format!(
            "UPDATE {thing_id} SET fm_present = false, fm_role = NULL, fm_type = NULL, fm_canonical = NULL, fm_status_date = NULL, fm_facets = [], frontmatter = NULL, frontmatter_raw = NULL RETURN NONE;",
            thing_id = thing("doc_file", &doc.doc_id),
        );
    };
    let fm_json = serde_json::to_string(&fm.json).unwrap_or_else(|_| "null".to_string());
    let facets_json = serde_json::to_string(&fm.facets).unwrap_or_else(|_| "[]".to_string());
    format!(
        "UPDATE {thing_id} SET fm_present = true, fm_role = {role}, fm_type = {doc_type}, fm_canonical = {canonical}, fm_status_date = {status_date}, fm_facets = {facets}, frontmatter = {frontmatter}, frontmatter_raw = {raw} RETURN NONE;",
        thing_id = thing("doc_file", &doc.doc_id),
        role = json_opt_string(fm.role.as_deref()),
        doc_type = json_opt_string(fm.doc_type.as_deref()),
        canonical = match fm.canonical {
            Some(true) => "true".to_string(),
            Some(false) => "false".to_string(),
            None => "NULL".to_string(),
        },
        status_date = json_opt_string(fm.status_date.as_deref()),
        facets = facets_json,
        frontmatter = fm_json,
        raw = json_string(&fm.raw_yaml),
    )
}

fn doc_heading_upsert_sql(
    heading_id: &str,
    doc_path: &str,
    heading_path: &[String],
    start_line: u32,
    heading_text: &str,
    heading_slug: &str,
) -> String {
    let heading_path_json =
        serde_json::to_string(heading_path).unwrap_or_else(|_| "[]".to_string());
    format!(
        "UPSERT {thing_id} CONTENT {{ heading_id: {heading_id}, doc_path: {doc_path}, heading_path: {heading_path}, start_line: {start_line}, heading_text: {heading_text}, heading_slug: {heading_slug} }} RETURN NONE;",
        thing_id = thing("doc_heading", heading_id),
        heading_id = json_string(heading_id),
        doc_path = json_string(doc_path),
        heading_path = heading_path_json,
        start_line = start_line,
        heading_text = json_string(heading_text),
        heading_slug = json_string(heading_slug),
    )
}

fn doc_stats_upsert_sql(doc: &VaultDoc, stats: &DocStatsAgg, in_links: u32) -> String {
    let doc_ref = thing("doc_file", &doc.doc_id);
    format!(
        "UPSERT {thing_id} CONTENT {{ doc_id: {doc_id}, doc_path: {doc_path}, doc: {doc_ref}, in_links: {in_links}, out_links: {out_links}, out_file_links: {out_file_links}, missing_out: {missing_out}, ambiguous_out: {ambiguous_out}, heading_missing_out: {heading_missing_out} }} RETURN NONE;",
        thing_id = thing("doc_stats", &doc.doc_id),
        doc_id = json_string(&doc.doc_id),
        doc_path = json_string(&doc.doc_path),
        doc_ref = doc_ref,
        in_links = in_links,
        out_links = stats.out_links,
        out_file_links = stats.out_file_links,
        missing_out = stats.missing_out,
        ambiguous_out = stats.ambiguous_out,
        heading_missing_out = stats.heading_missing_out,
    )
}

fn obsidian_link_relate_sql(
    from_doc_path: &str,
    to_doc_path: &str,
    edge_id: &str,
    link: &ObsidianLink,
    resolution_kind: &str,
    run_id: Option<&str>,
) -> String {
    let from_id = sha256_hex_str(from_doc_path);
    let to_id = sha256_hex_str(to_doc_path);
    let record_id = run_scoped_id(edge_id, run_id);
    let run_id_field = if let Some(rid) = run_id {
        format!(", projection_run_id: {}", json_string(rid))
    } else {
        String::new()
    };
    format!(
        "RELATE {from}->{}->{to} CONTENT {{ edge_id: {edge_id}, from_doc_path: {from_doc_path}, to_doc_path: {to_doc_path}, raw: {raw}, target: {target}, alias: {alias}, heading: {heading}, embed: {embed}, line: {line}, resolution_kind: {resolution_kind}{run_id_field} }} RETURN NONE;",
        thing("obsidian_link", &record_id),
        from = thing("doc_file", &from_id),
        to = thing("doc_file", &to_id),
        edge_id = json_string(edge_id),
        from_doc_path = json_string(from_doc_path),
        to_doc_path = json_string(to_doc_path),
        raw = json_string(&link.raw),
        target = json_string(&link.target),
        alias = json_opt_string(link.alias.as_deref()),
        heading = json_opt_string(link.heading.as_deref()),
        embed = if link.embed { "true" } else { "false" },
        line = link.line,
        resolution_kind = json_string(resolution_kind),
        run_id_field = run_id_field,
    )
}

fn doc_link_unresolved_upsert_sql(
    link_id: &str,
    from_doc_path: &str,
    link: &ObsidianLink,
    resolution: &ResolutionResult,
    resolved_doc_path: Option<&str>,
    run_id: Option<&str>,
) -> String {
    let candidates_json =
        serde_json::to_string(&resolution.candidates).unwrap_or_else(|_| "[]".to_string());
    let record_id = run_scoped_id(link_id, run_id);
    let run_id_field = if let Some(rid) = run_id {
        format!(", projection_run_id: {}", json_string(rid))
    } else {
        String::new()
    };
    format!(
        "UPSERT {thing_id} CONTENT {{ link_id: {link_id}, from_doc_path: {from_doc_path}, raw: {raw}, raw_target: {raw_target}, raw_alias: {raw_alias}, raw_heading: {raw_heading}, norm_target: {norm_target}, norm_alias: {norm_alias}, norm_heading: {norm_heading}, resolution_kind: {resolution_kind}, candidates: {candidates}, resolved_doc_path: {resolved_doc_path}, embed: {embed}, line: {line}{run_id_field} }} RETURN NONE;",
        thing_id = thing("doc_link_unresolved", &record_id),
        link_id = json_string(link_id),
        from_doc_path = json_string(from_doc_path),
        raw = json_string(&link.raw),
        raw_target = json_string(&link.target),
        raw_alias = json_opt_string(link.alias.as_deref()),
        raw_heading = json_opt_string(link.heading.as_deref()),
        norm_target = json_string(&resolution.norm_target),
        norm_alias = json_opt_string(resolution.norm_alias.as_deref()),
        norm_heading = json_opt_string(resolution.norm_heading.as_deref()),
        resolution_kind = json_string(&resolution.kind),
        candidates = candidates_json,
        resolved_doc_path = json_opt_string(resolved_doc_path),
        embed = if link.embed { "true" } else { "false" },
        line = link.line,
        run_id_field = run_id_field,
    )
}

fn obsidian_file_link_relate_sql(
    from_doc_path: &str,
    from_doc_id: &str,
    to_file_path: &str,
    to_file_node_id: &str,
    edge_id: &str,
    link: &ObsidianLink,
    resolution_kind: &str,
    run_id: Option<&str>,
) -> String {
    let from = thing("doc_file", from_doc_id);
    let to = thing("node", to_file_node_id);
    let record_id = run_scoped_id(edge_id, run_id);
    let run_id_field = if let Some(rid) = run_id {
        format!(", projection_run_id: {}", json_string(rid))
    } else {
        String::new()
    };
    format!(
        "RELATE {from}->{}->{to} CONTENT {{ edge_id: {edge_id}, from_doc_path: {from_doc_path}, to_file_path: {to_file_path}, to_file_node_id: {to_file_node_id}, raw: {raw}, target: {target}, alias: {alias}, heading: {heading}, embed: {embed}, line: {line}, resolution_kind: {resolution_kind}{run_id_field} }} RETURN NONE;",
        thing("obsidian_file_link", &record_id),
        from = from,
        to = to,
        edge_id = json_string(edge_id),
        from_doc_path = json_string(from_doc_path),
        to_file_path = json_string(to_file_path),
        to_file_node_id = json_string(to_file_node_id),
        raw = json_string(&link.raw),
        target = json_string(&link.target),
        alias = json_opt_string(link.alias.as_deref()),
        heading = json_opt_string(link.heading.as_deref()),
        embed = if link.embed { "true" } else { "false" },
        line = link.line,
        resolution_kind = json_string(resolution_kind),
        run_id_field = run_id_field,
    )
}

fn edge_relate_sql(edge_id: &str, edge: &DagEdge) -> String {
    edge_relate_sql_with_run(edge_id, edge, None)
}

fn edge_relate_sql_with_run(edge_id: &str, edge: &DagEdge, run_id: Option<&str>) -> String {
    let from = edge.from.to_string();
    let to = edge.to.to_string();
    let (edge_tag, edge_fields_json) = split_edge_type(&edge.edge_type);
    let witness_ref = edge.witness_ref.map(|id| id.to_string());

    let run_id_field = if let Some(rid) = run_id {
        format!(", projection_run_id: {}", json_string(rid))
    } else {
        String::new()
    };

    format!(
        "RELATE {from}->{}->{to} CONTENT {{ edge_id: {edge_id_s}, edge_type_tag: {edge_tag}, edge_fields: {edge_fields}, scope_id: {scope}, timeline: {timeline}, seq: {seq}, witness_ref: {witness_ref}{run_id_field} }} RETURN NONE;",
        thing("edge", edge_id),
        from = thing("node", &from),
        to = thing("node", &to),
        edge_id_s = json_string(edge_id),
        edge_tag = json_string(&edge_tag),
        edge_fields = edge_fields_json,
        scope = json_string(edge.scope.as_str()),
        timeline = json_string(&edge.step.timeline),
        seq = edge.step.seq,
        witness_ref = json_opt_string(witness_ref.as_deref()),
        run_id_field = run_id_field,
    )
}

fn edge_identity_sha256(edge: &DagEdge) -> Result<String, String> {
    let value = serde_json::to_value(edge).map_err(|err| format!("edge to value: {}", err))?;
    let cbor = admit_core::encode_canonical_value(&value)
        .map_err(|err| format!("canonical cbor encode edge: {}", err.0))?;
    Ok(hex_lower(&sha2::Sha256::digest(&cbor)))
}

fn split_kind(kind: &NodeKind) -> (String, String) {
    let value = serde_json::to_value(kind).unwrap_or_else(|_| serde_json::json!({}));
    let tag = value
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let fields = match value {
        serde_json::Value::Object(mut map) => {
            map.remove("type");
            serde_json::Value::Object(map)
        }
        other => other,
    };
    (tag, serde_json::to_string(&fields).unwrap_or_else(|_| "{}".to_string()))
}

fn split_edge_type(edge_type: &EdgeType) -> (String, String) {
    let value = serde_json::to_value(edge_type).unwrap_or_else(|_| serde_json::json!({}));
    let tag = value
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown")
        .to_string();
    let fields = match value {
        serde_json::Value::Object(mut map) => {
            map.remove("type");
            serde_json::Value::Object(map)
        }
        other => other,
    };
    (tag, serde_json::to_string(&fields).unwrap_or_else(|_| "{}".to_string()))
}

fn json_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

fn json_opt_string(s: Option<&str>) -> String {
    match s {
        Some(s) => json_string(s),
        None => "null".to_string(),
    }
}

fn surreal_record_or_null(s: Option<&str>) -> String {
    match s {
        Some(s) => s.to_string(),
        None => "null".to_string(),
    }
}

fn thing(table: &str, id: &str) -> String {
    // SurrealDB record IDs after `<table>:` are parsed as identifiers, not string literals.
    // Content hashes are hex and often start with digits, so we map them to a safe identifier
    // by prefixing with a letter.
    //
    // This keeps IDs deterministic and reversible:
    //   record id = "h" + <sha256 hex>
    //   original  = record id without leading "h"
    format!("{}:h{}", table, id)
}

fn run_scoped_id(base_id: &str, run_id: Option<&str>) -> String {
    match run_id {
        Some(rid) => sha256_hex_str(&format!("{}|{}", rid, base_id)),
        None => base_id.to_string(),
    }
}

fn sha256_hex_str(s: &str) -> String {
    hex_lower(&sha2::Sha256::digest(s.as_bytes()))
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn file_stem_title(path: &str) -> String {
    crate::link_resolver::file_stem_title(path)
}

fn build_heading_index(dag: &GovernedDag, vault_prefixes: &[&str]) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (_id, node) in dag.nodes() {
        let NodeKind::TextChunk { doc_path, heading_path, .. } = &node.kind else {
            continue;
        };
        if !vault_prefixes.iter().any(|p| doc_path.starts_with(p)) {
            continue;
        }
        let set = out.entry(doc_path.clone()).or_default();
        for h in heading_path {
            let nh = normalize_heading(h);
            if !nh.is_empty() {
                set.insert(nh);
            }
            let sh = obsidian_heading_slug(h);
            if !sh.is_empty() {
                set.insert(sh);
            }
        }
    }
    out
}

fn build_file_index(dag: &GovernedDag, vault_prefixes: &[&str]) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for (id, node) in dag.nodes() {
        let NodeKind::FileAtPath { path, .. } = &node.kind else {
            continue;
        };
        if !vault_prefixes.iter().any(|p| path.starts_with(p)) {
            continue;
        }
        out.insert(path.clone(), id.to_string());
    }
    out
}

fn vault_root_for_path<'a>(path: &str, vault_prefixes: &[&'a str]) -> Option<&'a str> {
    vault_prefixes
        .iter()
        .copied()
        .filter(|p| path.starts_with(*p))
        .max_by_key(|p| p.len())
}

fn extract_frontmatter(input: &str) -> Option<DocFrontmatter> {
    let mut lines = input.lines();
    let first = lines.next()?.trim_end();
    if first != "---" {
        return None;
    }
    let mut yaml_lines: Vec<&str> = Vec::new();
    for line in lines.by_ref() {
        let trimmed = line.trim_end();
        if trimmed == "---" || trimmed == "..." {
            break;
        }
        yaml_lines.push(line);
    }
    if yaml_lines.is_empty() {
        return None;
    }
    let raw_yaml = yaml_lines.join("\n");
    parse_frontmatter_yaml(&raw_yaml)
}

fn parse_frontmatter_yaml(raw_yaml: &str) -> Option<DocFrontmatter> {
    let mut obj: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let mut current_list_key: Option<String> = None;
    let mut current_list: Vec<String> = Vec::new();

    let flush_list = |obj: &mut BTreeMap<String, serde_json::Value>,
                      key: &mut Option<String>,
                      list: &mut Vec<String>| {
        if let Some(k) = key.take() {
            let arr: Vec<serde_json::Value> = list.drain(..).map(|s| serde_json::Value::String(s)).collect();
            obj.insert(k, serde_json::Value::Array(arr));
        }
    };

    for line in raw_yaml.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        let is_list_item = trimmed.starts_with("- ");
        if is_list_item {
            if current_list_key.is_some() {
                let item = trimmed.trim_start_matches("- ").trim();
                if !item.is_empty() {
                    current_list.push(unquote(item));
                }
                continue;
            }
        }

        // If we were in list mode and hit a non-list line, flush.
        if current_list_key.is_some() {
            flush_list(&mut obj, &mut current_list_key, &mut current_list);
        }

        let Some((k, v)) = trimmed.split_once(':') else {
            continue;
        };
        let key = k.trim().to_string();
        let value = v.trim();
        if value.is_empty() {
            // Start a list (YAML: key:\n  - item).
            current_list_key = Some(key);
            current_list.clear();
            continue;
        }

        // Inline list: key: [a, b]
        if value.starts_with('[') && value.ends_with(']') {
            let inner = value.trim_start_matches('[').trim_end_matches(']');
            let parts: Vec<String> = inner
                .split(',')
                .map(|s| unquote(s.trim()))
                .filter(|s| !s.is_empty())
                .collect();
            let arr: Vec<serde_json::Value> =
                parts.into_iter().map(serde_json::Value::String).collect();
            obj.insert(key, serde_json::Value::Array(arr));
            continue;
        }

        obj.insert(key, parse_scalar(value));
    }

    if current_list_key.is_some() {
        flush_list(&mut obj, &mut current_list_key, &mut current_list);
    }

    if obj.is_empty() {
        return None;
    }

    let json = serde_json::Value::Object(obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect());

    let role = obj.get("role").and_then(|v| v.as_str()).map(|s| s.to_string());
    let doc_type = obj.get("type").and_then(|v| v.as_str()).map(|s| s.to_string());
    let canonical = obj.get("canonical").and_then(|v| {
        if let Some(b) = v.as_bool() {
            Some(b)
        } else if let Some(s) = v.as_str() {
            if s.eq_ignore_ascii_case("true") {
                Some(true)
            } else if s.eq_ignore_ascii_case("false") {
                Some(false)
            } else {
                None
            }
        } else {
            None
        }
    });
    let status_date = obj
        .get("status_date")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let facets = obj
        .get("facets")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    Some(DocFrontmatter {
        raw_yaml: raw_yaml.to_string(),
        json,
        role,
        doc_type,
        canonical,
        status_date,
        facets,
    })
}

fn unquote(s: &str) -> String {
    let t = s.trim();
    if (t.starts_with('"') && t.ends_with('"')) || (t.starts_with('\'') && t.ends_with('\'')) {
        return t[1..t.len().saturating_sub(1)].to_string();
    }
    t.to_string()
}

fn parse_scalar(s: &str) -> serde_json::Value {
    let t = unquote(s.trim());
    if t.eq_ignore_ascii_case("true") {
        return serde_json::Value::Bool(true);
    }
    if t.eq_ignore_ascii_case("false") {
        return serde_json::Value::Bool(false);
    }
    if let Ok(i) = t.parse::<i64>() {
        return serde_json::Value::Number(i.into());
    }
    serde_json::Value::String(t)
}

fn facet_id(facet: &str) -> String {
    sha256_hex_str(facet)
}

fn has_facet_edge_id(doc_path: &str, facet: &str) -> Result<String, String> {
    let value = serde_json::json!({
        "tag": "admit_has_facet_v1",
        "doc_path": doc_path,
        "facet": facet,
    });
    let cbor = admit_core::encode_canonical_value(&value)
        .map_err(|err| format!("canonical cbor encode has_facet: {}", err.0))?;
    Ok(hex_lower(&sha2::Sha256::digest(&cbor)))
}

fn facet_upsert_sql(facet: &str) -> String {
    let id = facet_id(facet);
    format!(
        "UPSERT {thing_id} SET name = {name} RETURN NONE;",
        thing_id = thing("facet", &id),
        name = json_string(facet),
    )
}

fn has_facet_relate_sql(doc: &VaultDoc, facet: &str, edge_id: &str, run_id: Option<&str>) -> String {
    let fid = facet_id(facet);
    let record_id = run_scoped_id(edge_id, run_id);
    let run_id_field = if let Some(rid) = run_id {
        format!(", projection_run_id: {}", json_string(rid))
    } else {
        String::new()
    };
    format!(
        "RELATE {from}->{}->{to} CONTENT {{ edge_id: {edge_id}, doc_path: {doc_path}, facet_name: {facet_name}{run_id_field} }} RETURN NONE;",
        thing("has_facet", &record_id),
        from = thing("doc_file", &doc.doc_id),
        to = thing("facet", &fid),
        edge_id = json_string(edge_id),
        doc_path = json_string(&doc.doc_path),
        facet_name = json_string(facet),
        run_id_field = run_id_field,
    )
}

fn normalize_heading(s: &str) -> String {
    crate::link_resolver::normalize_heading(s)
}

fn obsidian_heading_slug(s: &str) -> String {
    crate::link_resolver::obsidian_heading_slug(s)
}

fn looks_like_asset_target(target: &str) -> bool {
    let t = normalize_target(target);
    if t.is_empty() {
        return false;
    }
    let lower = t.to_lowercase();
    if lower.ends_with(".md") {
        return false;
    }
    // Heuristic: treat anything with an extension as an asset/file link.
    let file = t.rsplit('/').next().unwrap_or(&t);
    file.contains('.')
}

fn resolve_obsidian_asset_target(
    from_doc_path: &str,
    raw_target: &str,
    vault_prefixes: &[&str],
    vault_files: &BTreeMap<String, String>,
) -> Option<AssetResolution> {
    crate::link_resolver::resolve_obsidian_asset_target(from_doc_path, raw_target, vault_prefixes, vault_files)
}

fn normalize_target(s: &str) -> String {
    crate::link_resolver::normalize_target(s)
}

fn normalize_optional(s: Option<&str>) -> Option<String> {
    s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

fn extract_obsidian_links(input: &str) -> Vec<ObsidianLink> {
    crate::link_resolver::extract_obsidian_links(input)
}

fn resolve_obsidian_target(
    from_doc_path: &str,
    raw_target: &str,
    vault_prefixes: &[&str],
    vault_docs: &BTreeMap<String, VaultDoc>,
    title_exact_index: &BTreeMap<String, BTreeSet<String>>,
    title_casefold_index: &BTreeMap<String, BTreeSet<String>>,
) -> ResolutionResult {
    let norm_target = normalize_target(raw_target);
    let norm_heading = None;
    let norm_alias = None;
    if norm_target.is_empty() {
        return ResolutionResult {
            resolved: None,
            kind: "missing".to_string(),
            candidates: Vec::new(),
            norm_target,
            norm_alias,
            norm_heading,
        };
    }

    // Exact path match (as written).
    if vault_docs.contains_key(&norm_target) {
        return ResolutionResult {
            resolved: Some(norm_target.clone()),
            kind: "exact_path".to_string(),
            candidates: vec![norm_target],
            norm_target: normalize_target(raw_target),
            norm_alias,
            norm_heading,
        };
    }

    // Exact path with `.md` appended.
    let with_md = if norm_target.to_lowercase().ends_with(".md") {
        norm_target.clone()
    } else {
        format!("{}.md", norm_target)
    };
    if vault_docs.contains_key(&with_md) {
        return ResolutionResult {
            resolved: Some(with_md.clone()),
            kind: "exact_path".to_string(),
            candidates: vec![with_md],
            norm_target: normalize_target(raw_target),
            norm_alias,
            norm_heading,
        };
    }

    // Path-like targets are assumed relative to the source vault root when possible.
    if norm_target.contains('/') {
        if let Some(root) = vault_root_for_path(from_doc_path, vault_prefixes) {
            if !with_md.starts_with(root) {
                let candidate = format!("{}{}", root, with_md);
                if vault_docs.contains_key(&candidate) {
                    return ResolutionResult {
                        resolved: Some(candidate.clone()),
                        kind: "prefix_join".to_string(),
                        candidates: vec![candidate],
                        norm_target: normalize_target(raw_target),
                        norm_alias,
                        norm_heading,
                    };
                }
            }
        }

        // Fall back to other prefixes for cross-vault references, but make it explicit.
        for prefix in vault_prefixes {
            let candidate = format!("{}{}", prefix, with_md);
            if vault_docs.contains_key(&candidate) {
                return ResolutionResult {
                    resolved: Some(candidate.clone()),
                    kind: "prefix_join_foreign".to_string(),
                    candidates: vec![candidate],
                    norm_target: normalize_target(raw_target),
                    norm_alias,
                    norm_heading,
                };
            }
        }

        return ResolutionResult {
            resolved: None,
            kind: "missing".to_string(),
            candidates: Vec::new(),
            norm_target: normalize_target(raw_target),
            norm_alias,
            norm_heading,
        };
    }

    // Title resolution. Strip `.md` if present.
    let title = norm_target.trim_end_matches(".md").trim_end_matches(".MD").to_string();
    if let Some(cands) = title_exact_index.get(&title) {
        if cands.len() == 1 {
            let p = cands.iter().next().cloned();
            return ResolutionResult {
                resolved: p.clone(),
                kind: "exact_title".to_string(),
                candidates: cands.iter().cloned().collect(),
                norm_target: normalize_target(raw_target),
                norm_alias,
                norm_heading,
            };
        }
        return ResolutionResult {
            resolved: None,
            kind: "ambiguous".to_string(),
            candidates: cands.iter().cloned().collect(),
            norm_target: normalize_target(raw_target),
            norm_alias,
            norm_heading,
        };
    }

    let key = title.to_lowercase();
    if let Some(cands) = title_casefold_index.get(&key) {
        if cands.len() == 1 {
            let p = cands.iter().next().cloned();
            return ResolutionResult {
                resolved: p.clone(),
                kind: "casefold_title".to_string(),
                candidates: cands.iter().cloned().collect(),
                norm_target: normalize_target(raw_target),
                norm_alias,
                norm_heading,
            };
        }
        return ResolutionResult {
            resolved: None,
            kind: "ambiguous".to_string(),
            candidates: cands.iter().cloned().collect(),
            norm_target: normalize_target(raw_target),
            norm_alias,
            norm_heading,
        };
    }

    ResolutionResult {
        resolved: None,
        kind: "missing".to_string(),
        candidates: Vec::new(),
        norm_target: normalize_target(raw_target),
        norm_alias,
        norm_heading,
    }
}

fn choose_ambiguous_target(from_doc_path: &str, candidates: &[String]) -> Option<(String, String)> {
    if candidates.is_empty() {
        return None;
    }
    let from_root = if from_doc_path.starts_with("irrev-vault/") {
        Some("irrev-vault/")
    } else if from_doc_path.starts_with("chatgpt/vault/") {
        Some("chatgpt/vault/")
    } else {
        None
    };
    let Some(from_root) = from_root else {
        return None;
    };

    let in_same_root: Vec<&String> = candidates.iter().filter(|c| c.starts_with(from_root)).collect();
    if in_same_root.len() == 1 {
        return Some((in_same_root[0].clone(), "prefer_same_root".to_string()));
    }
    let in_same_root = if in_same_root.is_empty() {
        // If the source is in one vault root but the candidates only exist in another,
        // allow deterministic resolution inside that other root (e.g. concepts vs meta).
        let all_in_irrev = candidates.iter().all(|c| c.starts_with("irrev-vault/"));
        let all_in_chatgpt = candidates.iter().all(|c| c.starts_with("chatgpt/vault/"));
        if all_in_irrev {
            candidates.iter().collect::<Vec<&String>>()
        } else if all_in_chatgpt {
            candidates.iter().collect::<Vec<&String>>()
        } else {
            return None;
        }
    } else {
        in_same_root
    };

    // Prefer matching neighborhood for intra-vault duplicates (e.g., concepts vs meta).
    let neighborhood = if from_doc_path.contains("/concepts/") {
        Some("/concepts/")
    } else if from_doc_path.contains("/meta/") {
        Some("/meta/")
    } else if from_doc_path.contains("/papers/") {
        Some("/papers/")
    } else if from_doc_path.contains("/diagnostics/") {
        Some("/diagnostics/")
    } else {
        None
    };
    if let Some(n) = neighborhood {
        let matches: Vec<&String> = in_same_root
            .iter()
            .copied()
            .filter(|c| c.contains(n))
            .collect();
        if matches.len() == 1 {
            return Some((matches[0].clone(), format!("prefer_same_root{}", n)));
        }
    }

    // Generic fallback: if there's exactly one concept candidate vs a meta candidate,
    // prefer the concept note as the "canonical" target.
    let concepts: Vec<&String> = in_same_root
        .iter()
        .copied()
        .filter(|c| c.contains("/concepts/"))
        .collect();
    let meta: Vec<&String> = in_same_root
        .iter()
        .copied()
        .filter(|c| c.contains("/meta/"))
        .collect();
    if concepts.len() == 1 && meta.len() >= 1 {
        return Some((concepts[0].clone(), "prefer_concepts".to_string()));
    }

    None
}

fn obsidian_link_edge_id(
    from_doc_path: &str,
    to_doc_path: &str,
    link: &ObsidianLink,
    resolution_kind: &str,
) -> Result<String, String> {
    let value = serde_json::json!({
        "tag": "admit_obsidian_link_v1",
        "from": from_doc_path,
        "to": to_doc_path,
        "target": link.target,
        "alias": link.alias,
        "heading": link.heading,
        "embed": link.embed,
        "line": link.line,
        "resolution_kind": resolution_kind,
    });
    let cbor = admit_core::encode_canonical_value(&value)
        .map_err(|err| format!("canonical cbor encode obsidian link: {}", err.0))?;
    Ok(hex_lower(&sha2::Sha256::digest(&cbor)))
}

fn obsidian_file_link_edge_id(
    from_doc_path: &str,
    to_file_path: &str,
    link: &ObsidianLink,
    resolution_kind: &str,
) -> Result<String, String> {
    let value = serde_json::json!({
        "tag": "admit_obsidian_file_link_v1",
        "from": from_doc_path,
        "to_file_path": to_file_path,
        "target": link.target,
        "alias": link.alias,
        "heading": link.heading,
        "embed": link.embed,
        "line": link.line,
        "resolution_kind": resolution_kind,
    });
    let cbor = admit_core::encode_canonical_value(&value)
        .map_err(|err| format!("canonical cbor encode obsidian file link: {}", err.0))?;
    Ok(hex_lower(&sha2::Sha256::digest(&cbor)))
}

fn obsidian_unresolved_id(from_doc_path: &str, link: &ObsidianLink) -> Result<String, String> {
    let value = serde_json::json!({
        "tag": "admit_obsidian_unresolved_v1",
        "from": from_doc_path,
        "target": link.target,
        "alias": link.alias,
        "heading": link.heading,
        "embed": link.embed,
        "line": link.line,
    });
    let cbor = admit_core::encode_canonical_value(&value)
        .map_err(|err| format!("canonical cbor encode obsidian unresolved: {}", err.0))?;
    Ok(hex_lower(&sha2::Sha256::digest(&cbor)))
}

fn parse_json_stream(input: &str) -> Result<Vec<serde_json::Value>, serde_json::Error> {
    let mut out = Vec::new();
    let deser = serde_json::Deserializer::from_str(input);
    for item in deser.into_iter::<serde_json::Value>() {
        out.push(item?);
    }
    Ok(out)
}

fn extract_result_array(values: &[serde_json::Value]) -> Result<Vec<serde_json::Value>, String> {
    for value in values {
        if let serde_json::Value::Array(arr) = value {
            let Some(first) = arr.first() else {
                continue;
            };
            match first {
                serde_json::Value::Object(obj) => {
                    if let Some(result_val) = obj.get("result") {
                        if let serde_json::Value::Array(result_arr) = result_val {
                            return Ok(result_arr.clone());
                        }
                    }
                }
                serde_json::Value::Array(inner) => {
                    return Ok(inner.clone());
                }
                _ => {
                    return Ok(arr.clone());
                }
            }
        }
    }
    Ok(Vec::new())
}

fn check_surreal_json_stream(values: &[serde_json::Value]) -> Result<(), String> {
    if values.is_empty() {
        return Err("surreal sql returned empty json stream".to_string());
    }
    for v in values {
        // Surreal CLI often returns `null` (or `[null]`) for statements which
        // don't return rows (e.g. DEFINE, UPSERT ... RETURN NONE). Treat null as success.
        if let Some(arr) = v.as_array() {
            if array_looks_like_error(arr) {
                return Err("surreal sql reported error result".to_string());
            }
        }
    }
    Ok(())
}

fn check_surreal_json_stream_allow_already_exists(values: &[serde_json::Value]) -> Result<(), String> {
    if values.is_empty() {
        return Err("surreal sql returned empty json stream".to_string());
    }
    for v in values {
        let Some(arr) = v.as_array() else {
            continue;
        };
        if !array_looks_like_error(arr) {
            continue;
        }
        let all_already_exists = arr.iter().all(|x| {
            x.as_str()
                .is_some_and(|s| s.to_lowercase().contains("already exists"))
        });
        if all_already_exists {
            continue;
        }
        return Err("surreal sql reported error result".to_string());
    }
    Ok(())
}

fn array_looks_like_error(arr: &[serde_json::Value]) -> bool {
    // Heuristic: `surreal sql --json` has been observed to return an array of strings for errors.
    // We treat those as failures for this internal projection surface.
    if arr.is_empty() {
        return false;
    }
    arr.iter().any(|v| {
        v.as_str().is_some_and(|s| {
            s.contains("Parse error")
                || s.contains("IAM error")
                || s.contains("The database encountered")
                || s.contains("error:")
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use admit_dag::{ScopeTag, TimelineStep};

    #[test]
    fn upsert_sql_is_stable_and_safe() {
        let node = DagNode::new(
            NodeKind::RulesetSource {
                content_hash: "abc123".to_string(),
            },
            ScopeTag::new("scope:core.pure"),
            vec![],
            vec![],
        )
        .unwrap();

        let sql = node_upsert_sql(&node.id.to_string(), &node);
        assert!(sql.contains("UPSERT node:h"));
        assert!(sql.contains("RETURN NONE"));
        assert!(sql.contains("kind_tag"));
        assert!(sql.contains("kind_fields"));
    }

    #[test]
    fn edge_identity_is_deterministic() {
        let from = admit_dag::NodeId::from_hex(&"00".repeat(32)).unwrap();
        let to = admit_dag::NodeId::from_hex(&"11".repeat(32)).unwrap();
        let edge = DagEdge::build_depends(
            from,
            to,
            ScopeTag::new("scope:test"),
            TimelineStep::new("t", 1),
        );

        let a = edge_identity_sha256(&edge).unwrap();
        let b = edge_identity_sha256(&edge).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 64);
    }

    #[test]
    fn doc_chunk_upsert_sql_is_stable_and_safe() {
        let node_id = "ab".repeat(32);
        let chunk_sha256 = "cd".repeat(32);
        let artifact_sha256 = "ef".repeat(32);
        let sql = doc_chunk_upsert_sql(
            &node_id,
            &chunk_sha256,
            "docs/readme.md",
            &["Root".to_string(), "Examples".to_string()],
            42,
            &artifact_sha256,
            "hello world",
            None,
        );
        assert!(sql.contains("UPSERT doc_chunk:h"));
        assert!(sql.contains("RETURN NONE"));
        assert!(sql.contains("doc_path"));
        assert!(sql.contains("heading_path"));
        assert!(sql.contains("text"));
        assert!(sql.contains("node:h"));
    }

    #[test]
    fn surreal_json_stream_allows_null_results() {
        let values = vec![serde_json::json!([null]), serde_json::json!([null])];
        check_surreal_json_stream(&values).unwrap();
        check_surreal_json_stream_allow_already_exists(&values).unwrap();
    }

    #[test]
    fn extract_obsidian_links_parses_variants() {
        let text = "\
line 1 [[Foo]]\n\
line 2 [[Bar|Alias]]\n\
line 3 [[Baz#Heading]]\n\
line 4 ![[Embed#H|A]]\n";
        let links = extract_obsidian_links(text);
        assert_eq!(links.len(), 4);
        assert_eq!(links[0].target, "Foo");
        assert_eq!(links[0].line, 1);
        assert_eq!(links[1].target, "Bar");
        assert_eq!(links[1].alias.as_deref(), Some("Alias"));
        assert_eq!(links[2].target, "Baz");
        assert_eq!(links[2].heading.as_deref(), Some("Heading"));
        assert!(links[3].embed);
        assert_eq!(links[3].target, "Embed");
        assert_eq!(links[3].heading.as_deref(), Some("H"));
        assert_eq!(links[3].alias.as_deref(), Some("A"));
    }

    #[test]
    fn resolve_obsidian_target_reports_ambiguous() {
        let mut vault_docs: BTreeMap<String, VaultDoc> = BTreeMap::new();
        vault_docs.insert(
            "irrev-vault/papers/X.md".to_string(),
            VaultDoc {
                doc_path: "irrev-vault/papers/X.md".to_string(),
                doc_id: sha256_hex_str("irrev-vault/papers/X.md"),
                file_node_id: "00".repeat(32),
                title: "X".to_string(),
                artifact_sha256: "11".repeat(32),
                artifact_abs_path: Path::new("C:\\").to_path_buf(),
            },
        );
        vault_docs.insert(
            "chatgpt/vault/papers/X.md".to_string(),
            VaultDoc {
                doc_path: "chatgpt/vault/papers/X.md".to_string(),
                doc_id: sha256_hex_str("chatgpt/vault/papers/X.md"),
                file_node_id: "22".repeat(32),
                title: "X".to_string(),
                artifact_sha256: "33".repeat(32),
                artifact_abs_path: Path::new("C:\\").to_path_buf(),
            },
        );

        let mut exact: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        exact
            .entry("X".to_string())
            .or_default()
            .extend([
                "chatgpt/vault/papers/X.md".to_string(),
                "irrev-vault/papers/X.md".to_string(),
            ]);
        let mut casefold: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        casefold
            .entry("x".to_string())
            .or_default()
            .extend([
                "chatgpt/vault/papers/X.md".to_string(),
                "irrev-vault/papers/X.md".to_string(),
            ]);

        let res = resolve_obsidian_target(
            "irrev-vault/papers/Some.md",
            "X",
            &["irrev-vault/", "chatgpt/vault/"],
            &vault_docs,
            &exact,
            &casefold,
        );
        assert_eq!(res.kind, "ambiguous");
        assert!(res.resolved.is_none());
        assert_eq!(res.candidates.len(), 2);
    }

    #[test]
    fn choose_ambiguous_prefers_concepts_over_meta() {
        let from = "irrev-vault/papers/Some Paper.md";
        let candidates = vec![
            "irrev-vault/meta/Scope Patterns.md".to_string(),
            "irrev-vault/concepts/Scope Patterns.md".to_string(),
        ];
        let chosen = choose_ambiguous_target(from, &candidates).unwrap();
        assert_eq!(chosen.0, "irrev-vault/concepts/Scope Patterns.md");
        assert_eq!(chosen.1, "prefer_concepts");
    }

    #[test]
    fn looks_like_asset_target_detects_non_md_paths() {
        assert!(looks_like_asset_target("meta/graphs/all-notes.svg"));
        assert!(looks_like_asset_target("all-notes.htm"));
        assert!(!looks_like_asset_target("Some Note"));
        assert!(!looks_like_asset_target("Some Note.md"));
    }

    #[test]
    fn resolve_asset_target_prefers_same_root() {
        let mut files: BTreeMap<String, String> = BTreeMap::new();
        files.insert(
            "irrev-vault/meta/graphs/all-notes.svg".to_string(),
            "aa".repeat(32),
        );
        files.insert(
            "chatgpt/vault/meta/graphs/all-notes.svg".to_string(),
            "bb".repeat(32),
        );

        let res = resolve_obsidian_asset_target(
            "chatgpt/vault/meta/Concept Graphs.md",
            "meta/graphs/all-notes.svg",
            &["irrev-vault/", "chatgpt/vault/"],
            &files,
        )
        .unwrap();
        assert_eq!(res.kind, "prefix_join");
        assert_eq!(res.to_file_node_id, "bb".repeat(32));
        assert_eq!(res.to_file_path, "chatgpt/vault/meta/graphs/all-notes.svg");
    }

    #[test]
    fn extract_frontmatter_parses_basic_fields() {
        let text = r#"---
role: meta
type: runtime-plan
canonical: true
facets:
  - governance
  - runtime
status_date: 2026-02-05
---

# Title
"#;
        let fm = extract_frontmatter(text).expect("frontmatter");
        assert_eq!(fm.role.as_deref(), Some("meta"));
        assert_eq!(fm.doc_type.as_deref(), Some("runtime-plan"));
        assert_eq!(fm.canonical, Some(true));
        assert_eq!(fm.status_date.as_deref(), Some("2026-02-05"));
        assert_eq!(fm.facets, vec!["governance".to_string(), "runtime".to_string()]);
    }
}
