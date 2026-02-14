//! Obsidian vault link projection — database-agnostic orchestration.
//!
//! This module defines the [`ObsidianProjectionBackend`] trait for the minimal
//! store surface needed by the Obsidian link projection pipeline.  The actual
//! database implementation lives in `admit_surrealdb`; this module generates
//! SurrealQL strings and delegates execution through the trait.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use admit_dag::{GovernedDag, NodeKind};
use sha2::Digest;

use crate::{
    build_file_index, build_heading_index, choose_ambiguous_target, extract_obsidian_links,
    file_stem_title, normalize_heading, normalize_target, obsidian_heading_slug,
    resolve_obsidian_asset_target, resolve_obsidian_target, sha256_hex_str, ObsidianLink,
    ResolutionResult, VaultDoc,
};

// ---------------------------------------------------------------------------
// Trait: ObsidianProjectionBackend
// ---------------------------------------------------------------------------

/// Batch size configuration exposed to the projection orchestrator.
#[derive(Debug, Clone)]
pub struct BatchConfig {
    pub doc_files: usize,
    pub headings: usize,
    pub links: usize,
    pub stats: usize,
    pub max_sql_bytes: usize,
}

/// Phase result returned from the projection pipeline.
#[derive(Debug, Clone)]
pub struct PhaseResult {
    pub phase: String,
    pub total_batches: usize,
    pub successful_batches: usize,
    pub failed_batches: Vec<FailedBatch>,
    pub duration_ms: u64,
    pub records_processed: u64,
    pub bytes_written: u64,
    pub db_write_time_ms: u64,
    pub files_read: Option<u64>,
    pub parse_time_ms: Option<u64>,
}

/// Information about a failed batch.
#[derive(Debug, Clone)]
pub struct FailedBatch {
    pub phase: String,
    pub run_id: String,
    pub batch_index: usize,
    pub item_ids: Vec<String>,
    pub error: String,
}

/// Minimal store surface for the Obsidian projection pipeline.
///
/// Implementations live in backend crates (e.g. `admit_surrealdb`).
pub trait ObsidianProjectionBackend {
    /// Execute a SurrealQL statement (fire-and-forget).
    fn run_sql(&self, sql: &str) -> Result<(), String>;

    /// Execute a SurrealQL DDL statement, ignoring "already exists" errors.
    fn run_sql_allow_already_exists(&self, sql: &str) -> Result<(), String>;

    /// Execute a SELECT query and return the result rows.
    fn select_rows(&self, sql: &str) -> Result<Vec<serde_json::Value>, String>;

    /// Return batch size configuration.
    fn batch_config(&self) -> BatchConfig;

    /// Ensure the doc_file schema exists.
    fn ensure_doc_file_schema(&self) -> Result<(), String>;
}

// ---------------------------------------------------------------------------
// Row types for query results
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Internal helpers (SQL generation)
// ---------------------------------------------------------------------------

fn json_string(s: &str) -> String {
    serde_json::to_string(s).unwrap_or_else(|_| "\"\"".to_string())
}

fn json_opt_string(s: Option<&str>) -> String {
    match s {
        Some(s) => json_string(s),
        None => "null".to_string(),
    }
}

fn thing(table: &str, id: &str) -> String {
    format!("{}:h{}", table, id)
}

fn run_scoped_id(base_id: &str, run_id: Option<&str>) -> String {
    match run_id {
        Some(rid) => sha256_hex_str(&format!("{}|{}", rid, base_id)),
        None => base_id.to_string(),
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn normalize_optional(s: Option<&str>) -> Option<String> {
    s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

// ---------------------------------------------------------------------------
// Stats aggregation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct DocStatsAgg {
    out_links: u32,
    out_file_links: u32,
    missing_out: u32,
    ambiguous_out: u32,
    heading_missing_out: u32,
}

// ---------------------------------------------------------------------------
// Frontmatter extraction (duplicated from surrealdb; pure logic, no DB)
// ---------------------------------------------------------------------------

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
            let arr: Vec<serde_json::Value> = list
                .drain(..)
                .map(|s| serde_json::Value::String(s))
                .collect();
            obj.insert(k, serde_json::Value::Array(arr));
        }
    };

    for line in raw_yaml.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        // List item continuation
        if let Some(stripped) = trimmed.strip_prefix("- ") {
            if current_list_key.is_some() {
                current_list.push(stripped.trim().to_string());
                continue;
            }
        }
        flush_list(&mut obj, &mut current_list_key, &mut current_list);
        // Key: value
        if let Some(colon_pos) = trimmed.find(':') {
            let key = trimmed[..colon_pos].trim().to_string();
            let val_str = trimmed[colon_pos + 1..].trim();
            if val_str.is_empty() {
                current_list_key = Some(key);
                continue;
            }
            let value = if val_str == "true" {
                serde_json::Value::Bool(true)
            } else if val_str == "false" {
                serde_json::Value::Bool(false)
            } else if let Ok(n) = val_str.parse::<i64>() {
                serde_json::Value::Number(n.into())
            } else {
                let unquoted = val_str
                    .strip_prefix('"')
                    .and_then(|s| s.strip_suffix('"'))
                    .or_else(|| {
                        val_str
                            .strip_prefix('\'')
                            .and_then(|s| s.strip_suffix('\''))
                    })
                    .unwrap_or(val_str);
                serde_json::Value::String(unquoted.to_string())
            };
            obj.insert(key, value);
        }
    }
    flush_list(&mut obj, &mut current_list_key, &mut current_list);

    if obj.is_empty() {
        return None;
    }

    let json = serde_json::Value::Object(serde_json::Map::from_iter(
        obj.iter().map(|(k, v)| (k.clone(), v.clone())),
    ));

    let role = obj
        .get("role")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let doc_type = obj
        .get("type")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let canonical = obj.get("canonical").and_then(|v| v.as_bool());
    let status_date = obj
        .get("status_date")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let facets = obj
        .get("facets")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
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

// ---------------------------------------------------------------------------
// SQL generation helpers
// ---------------------------------------------------------------------------

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
    let json_val = serde_json::to_string(&fm.json).unwrap_or_else(|_| "null".to_string());
    let facets_json = serde_json::to_string(&fm.facets).unwrap_or_else(|_| "[]".to_string());
    format!(
        "UPDATE {thing_id} SET fm_present = true, fm_role = {role}, fm_type = {doc_type}, fm_canonical = {canonical}, fm_status_date = {status_date}, fm_facets = {facets}, frontmatter = {frontmatter}, frontmatter_raw = {raw} RETURN NONE;",
        thing_id = thing("doc_file", &doc.doc_id),
        role = json_opt_string(fm.role.as_deref()),
        doc_type = json_opt_string(fm.doc_type.as_deref()),
        canonical = fm.canonical.map(|b| if b { "true" } else { "false" }).unwrap_or("null"),
        status_date = json_opt_string(fm.status_date.as_deref()),
        facets = facets_json,
        frontmatter = json_val,
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

pub fn looks_like_asset_target(target: &str) -> bool {
    let t = normalize_target(target);
    if t.is_empty() {
        return false;
    }
    let lower = t.to_lowercase();
    if lower.ends_with(".md") {
        return false;
    }
    let file = t.rsplit('/').next().unwrap_or(&t);
    file.contains('.')
}

// ---------------------------------------------------------------------------
// Batch accumulator (trait-based, no direct SurrealCliProjectionStore dep)
// ---------------------------------------------------------------------------

struct BatchAccumulator<'a> {
    backend: &'a dyn ObsidianProjectionBackend,
    phase: String,
    run_id: String,
    batch_limit: usize,
    max_sql_bytes: usize,
    batch_index: usize,
    total_batches: usize,
    successful_batches: usize,
    failed_batches: Vec<FailedBatch>,
    records_processed: u64,
    bytes_written: u64,
    db_write_time_ms: u64,
    sql: String,
    item_ids: Vec<String>,
}

impl<'a> BatchAccumulator<'a> {
    fn new(
        backend: &'a dyn ObsidianProjectionBackend,
        phase: &str,
        run_id: Option<&str>,
        batch_limit: usize,
        max_sql_bytes: usize,
    ) -> Self {
        Self {
            backend,
            phase: phase.to_string(),
            run_id: run_id.unwrap_or("unknown").to_string(),
            batch_limit: batch_limit.max(1),
            max_sql_bytes: max_sql_bytes.max(1),
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
        match self.backend.run_sql(&sql) {
            Ok(()) => {
                self.successful_batches = self.successful_batches.saturating_add(1);
            }
            Err(err) => {
                self.failed_batches.push(FailedBatch {
                    phase: self.phase.clone(),
                    run_id: self.run_id.clone(),
                    batch_index,
                    item_ids,
                    error: err,
                });
            }
        }
        self.db_write_time_ms = self
            .db_write_time_ms
            .saturating_add(start.elapsed().as_millis() as u64);
    }

    fn finish(mut self) -> PhaseResult {
        self.flush();
        PhaseResult {
            phase: self.phase,
            total_batches: self.total_batches,
            successful_batches: self.successful_batches,
            failed_batches: self.failed_batches,
            duration_ms: 0,
            records_processed: self.records_processed,
            bytes_written: self.bytes_written,
            db_write_time_ms: self.db_write_time_ms,
            files_read: None,
            parse_time_ms: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Public API — Obsidian projection operations
// ---------------------------------------------------------------------------

/// Ensure the vault link schema exists in the backend store.
pub fn ensure_vault_link_schema(backend: &dyn ObsidianProjectionBackend) -> Result<(), String> {
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
    backend.run_sql_allow_already_exists(sql)
}

/// Project Obsidian vault links from ingested artifacts.
pub fn project_obsidian_vault_links_from_artifacts(
    backend: &dyn ObsidianProjectionBackend,
    dag: &GovernedDag,
    artifacts_root: &Path,
    obsidian_vault_prefixes: &[&str],
    doc_filter: Option<&BTreeSet<String>>,
    run_id: Option<&str>,
) -> Result<PhaseResult, String> {
    let phase = "obsidian_vault_links";
    let phase_start = std::time::Instant::now();
    backend.ensure_doc_file_schema()?;
    ensure_vault_link_schema(backend)?;

    let batch_cfg = backend.batch_config();

    // Index known vault markdown docs by path + stem for resolution.
    let mut vault_docs: BTreeMap<String, VaultDoc> = BTreeMap::new();
    let mut title_exact_index: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut title_casefold_index: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let heading_index = build_heading_index(dag, obsidian_vault_prefixes);
    let vault_files = build_file_index(dag, obsidian_vault_prefixes);

    for (id, node) in dag.nodes() {
        let NodeKind::FileAtPath { path, .. } = &node.kind else {
            continue;
        };
        if !obsidian_vault_prefixes.iter().any(|p| path.starts_with(p)) {
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
        title_exact_index
            .entry(title.clone())
            .or_default()
            .insert(path.clone());
        title_casefold_index
            .entry(title.to_lowercase())
            .or_default()
            .insert(path.clone());
    }

    // Upsert doc_file records for vault docs we saw.
    let mut doc_file_batches = BatchAccumulator::new(
        backend,
        phase,
        run_id,
        batch_cfg.doc_files,
        batch_cfg.max_sql_bytes,
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

    // Project headings for vault docs.
    let mut heading_batches = BatchAccumulator::new(
        backend,
        phase,
        run_id,
        batch_cfg.headings,
        batch_cfg.max_sql_bytes,
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
        if !obsidian_vault_prefixes
            .iter()
            .any(|p| doc_path.starts_with(p))
        {
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

    // Build relation edges based on Obsidian wiki links.
    let mut stats_by_doc: BTreeMap<String, DocStatsAgg> = BTreeMap::new();
    let mut inbound_links: BTreeMap<String, u32> = BTreeMap::new();

    let mut doc_update_batches = BatchAccumulator::new(
        backend,
        phase,
        run_id,
        batch_cfg.doc_files,
        batch_cfg.max_sql_bytes,
    );
    let mut link_batches = BatchAccumulator::new(
        backend,
        phase,
        run_id,
        batch_cfg.links,
        batch_cfg.max_sql_bytes,
    );

    let mut files_read: u64 = 0;
    for doc in vault_docs.values() {
        if let Some(filter) = doc_filter {
            if !filter.contains(&doc.doc_path) {
                continue;
            }
        }
        if run_id.is_none() {
            // IR-DELETE-JUSTIFIED: per-document replacement semantics for derived link projections.
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
                    obsidian_vault_prefixes,
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
                &vault_docs,
                &title_exact_index,
                &title_casefold_index,
            );
            resolution.norm_alias = normalize_optional(link.alias.as_deref());
            resolution.norm_heading = link
                .heading
                .as_deref()
                .map(normalize_heading)
                .filter(|s| !s.is_empty());

            match resolution.kind.as_str() {
                "missing" | "ambiguous" => {
                    if resolution.kind == "missing" {
                        stats.missing_out = stats.missing_out.saturating_add(1);
                    } else {
                        stats.ambiguous_out = stats.ambiguous_out.saturating_add(1);
                    }

                    if resolution.kind == "ambiguous" {
                        if let Some((chosen, kind)) = choose_ambiguous_target(
                            &doc.doc_path,
                            &resolution.candidates,
                            obsidian_vault_prefixes,
                        ) {
                            resolution.resolved = Some(chosen.clone());
                            resolution.kind = kind;
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
                                stats.heading_missing_out =
                                    stats.heading_missing_out.saturating_add(1);
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
                                link_batches.push_item(
                                    format!("doc_link_unresolved:{}", link_id),
                                    &link_sql,
                                );
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
                    let edge_id =
                        obsidian_link_edge_id(&doc.doc_path, to_doc_path, &link, &resolution.kind)?;
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

    // Materialize doc-level stats.
    let mut stats_batches = BatchAccumulator::new(
        backend,
        phase,
        run_id,
        batch_cfg.stats,
        batch_cfg.max_sql_bytes,
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
    let db_write_ms = doc_file_result.db_write_time_ms
        + heading_result.db_write_time_ms
        + doc_update_result.db_write_time_ms
        + link_result.db_write_time_ms
        + stats_result.db_write_time_ms;

    let total_ms = phase_start.elapsed().as_millis() as u64;
    Ok(PhaseResult {
        phase: phase.to_string(),
        total_batches,
        successful_batches,
        failed_batches,
        duration_ms: total_ms,
        records_processed,
        bytes_written,
        db_write_time_ms: db_write_ms,
        files_read: Some(files_read),
        parse_time_ms: Some(total_ms.saturating_sub(db_write_ms)),
    })
}

/// Select unresolved links from the store.
pub fn select_unresolved_links(
    backend: &dyn ObsidianProjectionBackend,
    prefixes: &[&str],
    kinds: &[&str],
    limit: usize,
    projection_run_id: Option<&str>,
) -> Result<Vec<UnresolvedLinkRow>, String> {
    ensure_vault_link_schema(backend)?;
    if prefixes.is_empty() || kinds.is_empty() {
        return Ok(Vec::new());
    }
    let mut conds = Vec::new();
    for p in prefixes {
        conds.push(format!(
            "string::starts_with(from_doc_path, {})",
            json_string(p)
        ));
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
    let rows = backend.select_rows(&sql)?;
    let mut out = Vec::new();
    for r in rows {
        let Some(obj) = r.as_object() else { continue };
        let link_id = obj
            .get("link_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let from_doc_path = obj
            .get("from_doc_path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let raw_target = obj
            .get("raw_target")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let raw_heading = obj
            .get("raw_heading")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let resolution_kind = obj
            .get("resolution_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let resolved_doc_path = obj
            .get("resolved_doc_path")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
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
        if link_id.is_empty()
            || from_doc_path.is_empty()
            || raw_target.is_empty()
            || resolution_kind.is_empty()
        {
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

/// Project unresolved link suggestions into the store.
pub fn project_unresolved_link_suggestions(
    backend: &dyn ObsidianProjectionBackend,
    run_id: &str,
    rows: &[UnresolvedLinkSuggestionRow],
) -> Result<(), String> {
    ensure_vault_link_schema(backend)?;
    let mut sql = String::new();
    // IR-DELETE-JUSTIFIED: run-scoped replacement semantics for suggestion rows.
    sql.push_str(&format!(
        "DELETE unresolved_link_suggestion WHERE run_id = {} RETURN NONE;",
        json_string(run_id)
    ));

    let batch_cfg = backend.batch_config();
    let batch_limit = batch_cfg.links;
    let max_sql_bytes = batch_cfg.max_sql_bytes.max(1);
    let mut batch_count: usize = 0;

    for row in rows {
        let candidates_json = serde_json::to_string(
            &row.candidates
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
            backend.run_sql(&sql)?;
            sql.clear();
            batch_count = 0;
        }
    }
    if !sql.is_empty() {
        backend.run_sql(&sql)?;
    }
    Ok(())
}

/// Search document title embeddings by cosine similarity.
pub fn search_doc_title_embeddings(
    backend: &dyn ObsidianProjectionBackend,
    obsidian_vault_prefix: &str,
    model: &str,
    dim_target: u32,
    query_embedding: &[f32],
    limit: usize,
) -> Result<Vec<(String, f64)>, String> {
    backend.ensure_doc_file_schema()?;
    let emb_json = serde_json::to_string(query_embedding)
        .map_err(|err| format!("json encode query embedding: {}", err))?;
    let lim = limit.max(1).min(50);
    let sql = format!(
        "SELECT doc_path, vector::similarity::cosine(embedding, {q}) AS sim FROM doc_title_embedding WHERE model={model} AND dim_target={dim} AND string::starts_with(doc_path, {prefix}) ORDER BY sim DESC LIMIT {lim};",
        q = emb_json,
        model = json_string(model),
        dim = dim_target,
        prefix = json_string(obsidian_vault_prefix),
        lim = lim,
    );
    let rows = backend.select_rows(&sql)?;
    let mut out = Vec::new();
    for r in rows {
        let Some(obj) = r.as_object() else { continue };
        let doc_path = obj
            .get("doc_path")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let sim = obj.get("sim").and_then(|v| v.as_f64()).unwrap_or(0.0);
        if doc_path.is_empty() {
            continue;
        }
        out.push((doc_path, sim));
    }
    Ok(out)
}

/// SQL for vacuuming obsidian-specific tables for given projection run IDs.
pub fn vacuum_obsidian_tables_sql(_run_ids_json: &str) -> String {
    // IR-DELETE-JUSTIFIED: explicit vacuum path for projection run cleanup.
    format!(
        "DELETE obsidian_link WHERE projection_run_id IN $runs RETURN NONE;\
DELETE obsidian_file_link WHERE projection_run_id IN $runs RETURN NONE;\
DELETE doc_link_unresolved WHERE projection_run_id IN $runs RETURN NONE;"
    )
}
