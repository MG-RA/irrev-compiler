use std::collections::BTreeSet;
use std::path::Path;

use admit_dag::{GovernedDag, NodeKind};
use admit_embed::OllamaEmbedder;
use admit_scope_obsidian::projection::{
    self, ObsidianProjectionBackend, UnresolvedLinkSuggestionRow,
};
use admit_surrealdb::projection_run::{
    FailedBatch as SurrealFailedBatch, PhaseResult as SurrealPhaseResult,
    PhaseStatus as SurrealPhaseStatus,
};
use admit_surrealdb::{DocTitleEmbeddingRow, SurrealCliProjectionStore};
use sha2::Digest;

pub use admit_scope_obsidian::{
    extract_obsidian_links, file_stem_title, normalize_heading, normalize_target,
    obsidian_heading_slug,
};

pub const OBSIDIAN_VAULT_LINKS_PHASE: &str = admit_scope_obsidian::OBSIDIAN_VAULT_LINKS_PHASE;

pub fn is_obsidian_vault_links_phase(phase: &str) -> bool {
    admit_scope_obsidian::is_obsidian_vault_links_phase(phase)
}

pub fn normalize_obsidian_vault_links_phase(phase: &str) -> String {
    admit_scope_obsidian::normalize_obsidian_vault_links_phase(phase)
}

pub fn markdown_doc_paths(dag: &GovernedDag) -> Vec<String> {
    dag.nodes()
        .iter()
        .filter_map(|(_id, node)| match &node.kind {
            NodeKind::FileAtPath { path, .. } => Some(path.clone()),
            _ => None,
        })
        .filter(|p| p.to_lowercase().ends_with(".md"))
        .collect()
}

pub fn effective_vault_prefixes_for_dag(
    dag: &GovernedDag,
    configured_prefixes: &[String],
) -> (Vec<String>, bool, Vec<String>) {
    let doc_paths = markdown_doc_paths(dag);
    let (effective, did_fallback) = admit_scope_obsidian::effective_vault_prefixes_for_doc_paths(
        &doc_paths,
        configured_prefixes,
    );
    (effective, did_fallback, doc_paths)
}

fn looks_like_file_link(target: &str) -> bool {
    let lower = target.to_lowercase();
    for ext in [
        ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".pdf", ".htm", ".html",
    ] {
        if lower.ends_with(ext) {
            return true;
        }
    }
    false
}

fn vault_prefix_for_doc_path(from_doc_path: &str, vault_prefixes: &[String]) -> String {
    admit_scope_obsidian::select_vault_prefix_for_doc_path(from_doc_path, vault_prefixes)
}

fn sha256_hex(input: &str) -> String {
    hex::encode(sha2::Sha256::digest(input.as_bytes()))
}

// ---------------------------------------------------------------------------
// ObsidianProjectionBackend impl via newtype wrapper (orphan rule)
// ---------------------------------------------------------------------------

/// Newtype wrapper enabling `ObsidianProjectionBackend` for the SurrealDB store.
pub struct SurrealObsidianBackend<'a>(pub &'a SurrealCliProjectionStore);

impl ObsidianProjectionBackend for SurrealObsidianBackend<'_> {
    fn run_sql(&self, sql: &str) -> Result<(), String> {
        self.0.run_sql(sql)
    }

    fn run_sql_allow_already_exists(&self, sql: &str) -> Result<(), String> {
        self.0.run_sql_allow_already_exists(sql)
    }

    fn select_rows(&self, sql: &str) -> Result<Vec<serde_json::Value>, String> {
        self.0.select_rows_from_single_select(sql)
    }

    fn batch_config(&self) -> projection::BatchConfig {
        let bs = &self.0.projection_config.batch_sizes;
        projection::BatchConfig {
            doc_files: bs.doc_files,
            headings: bs.headings,
            links: bs.links,
            stats: bs.stats,
            max_sql_bytes: bs.max_sql_bytes,
        }
    }

    fn ensure_doc_file_schema(&self) -> Result<(), String> {
        self.0.ensure_doc_file_schema()
    }
}

// ---------------------------------------------------------------------------
// PhaseResult conversion: obsidian → surrealdb
// ---------------------------------------------------------------------------

fn convert_phase_result(r: projection::PhaseResult) -> SurrealPhaseResult {
    let status = if r.failed_batches.is_empty() {
        SurrealPhaseStatus::Complete
    } else if r.successful_batches == 0 {
        SurrealPhaseStatus::Failed
    } else {
        SurrealPhaseStatus::Partial
    };
    SurrealPhaseResult {
        phase: r.phase,
        status,
        total_batches: r.total_batches,
        successful_batches: r.successful_batches,
        failed_batches: r
            .failed_batches
            .into_iter()
            .map(|fb| SurrealFailedBatch {
                batch_hash: String::new(),
                batch_index: fb.batch_index,
                item_ids: fb.item_ids,
                error: fb.error,
                attempt_count: 0,
            })
            .collect(),
        duration_ms: r.duration_ms,
        records_processed: r.records_processed,
        batches_executed: r.total_batches as u64,
        bytes_written: r.bytes_written,
        files_read: r.files_read,
        parse_time_ms: r.parse_time_ms,
        db_write_time_ms: Some(r.db_write_time_ms),
        errors: Vec::new(),
        error: None,
    }
}

// ---------------------------------------------------------------------------
// Obsidian vault link projection (delegates to admit_scope_obsidian)
// ---------------------------------------------------------------------------

pub fn project_obsidian_vault_links(
    surreal: &SurrealCliProjectionStore,
    dag: &GovernedDag,
    artifacts_root: &Path,
    obsidian_vault_prefixes: &[&str],
    doc_filter: Option<&BTreeSet<String>>,
    run_id: Option<&str>,
) -> Result<SurrealPhaseResult, String> {
    let backend = SurrealObsidianBackend(surreal);
    let r = projection::project_obsidian_vault_links_from_artifacts(
        &backend,
        dag,
        artifacts_root,
        obsidian_vault_prefixes,
        doc_filter,
        run_id,
    )?;
    Ok(convert_phase_result(r))
}

pub fn project_unresolved_link_suggestions_via_ollama(
    surreal: &SurrealCliProjectionStore,
    embedder: &OllamaEmbedder,
    projection_run_id: Option<&str>,
    run_id: &str,
    model: &str,
    dim_target: u32,
    doc_prefix: &str,
    query_prefix: &str,
    per_link_limit: usize,
    vault_prefixes: &[String],
) -> Result<(), String> {
    // Ensure title embeddings exist for all docs in the vault(s) we care about.
    let mut doc_prefix_refs: Vec<&str> = vault_prefixes.iter().map(|s| s.as_str()).collect();
    if doc_prefix_refs.is_empty() {
        doc_prefix_refs.push("");
    }
    let mut docs = surreal.select_doc_files(&doc_prefix_refs)?;
    if docs.is_empty() && !doc_prefix_refs.iter().any(|p| p.is_empty()) {
        // Fallback: root-relative vault ingest (`Foo.md` instead of `irrev-vault/Foo.md`).
        docs = surreal.select_doc_files(&[""])?;
        doc_prefix_refs = vec![""];
    }
    if !docs.is_empty() {
        let mut inputs: Vec<String> = Vec::with_capacity(docs.len());
        for (_doc_path, title) in docs.iter() {
            let t = if title.is_empty() {
                "untitled".to_string()
            } else {
                title.clone()
            };
            inputs.push(format!("{}{}", doc_prefix, t));
        }

        let mut title_rows: Vec<DocTitleEmbeddingRow> = Vec::with_capacity(docs.len());
        let batch_size = embedder.cfg().batch_size.max(1);
        let mut i = 0usize;
        while i < inputs.len() {
            let end = (i + batch_size).min(inputs.len());
            eprintln!(
                "ollama_suggest: embedding doc titles {}..{} of {}",
                i + 1,
                end,
                inputs.len()
            );
            let batch_started = std::time::Instant::now();
            let embs = embedder.embed_texts(&inputs[i..end])?;
            let batch_ms = batch_started.elapsed().as_millis() as u64;
            eprintln!(
                "ollama_suggest: doc title batch {}..{} done ({} ms)",
                i + 1,
                end,
                batch_ms
            );
            for ((doc_path, title), emb) in docs[i..end].iter().cloned().zip(embs.into_iter()) {
                if emb.is_empty() {
                    continue;
                }
                let mut emb = emb;
                if dim_target > 0 && (dim_target as usize) < emb.len() {
                    emb.truncate(dim_target as usize);
                }
                title_rows.push(DocTitleEmbeddingRow {
                    doc_path,
                    title,
                    model: model.to_string(),
                    dim_target: if dim_target > 0 {
                        dim_target
                    } else {
                        emb.len() as u32
                    },
                    embedding: emb,
                    run_id: run_id.to_string(),
                });
            }
            i = end;
        }
        surreal.project_doc_title_embeddings(&title_rows)?;
    }

    let backend = SurrealObsidianBackend(surreal);
    let unresolved = projection::select_unresolved_links(
        &backend,
        doc_prefix_refs.as_slice(),
        &["missing", "heading_missing", "ambiguous"],
        10_000,
        projection_run_id,
    )?;
    if unresolved.is_empty() {
        eprintln!("ollama_suggest: no unresolved links found");
        return Ok(());
    }

    let mut suggestions: Vec<UnresolvedLinkSuggestionRow> = Vec::new();
    for link in unresolved {
        if looks_like_file_link(&link.raw_target) {
            continue;
        }
        let vault_prefix = vault_prefix_for_doc_path(&link.from_doc_path, vault_prefixes);
        let suggestion_id = sha256_hex(&format!(
            "admit_unresolved_suggestion_v1|{}|{}",
            run_id, link.link_id
        ));

        // Heading missing: we already have a resolved doc path; suggestion is "doc ok, heading missing".
        if link.resolution_kind == "heading_missing" {
            suggestions.push(UnresolvedLinkSuggestionRow {
                suggestion_id,
                run_id: run_id.to_string(),
                link_id: link.link_id,
                from_doc_path: link.from_doc_path,
                line: link.line,
                embed: link.embed,
                raw_target: link.raw_target,
                raw_heading: link.raw_heading,
                resolution_kind: link.resolution_kind,
                vault_prefix,
                model: model.to_string(),
                dim_target,
                recommended_doc_path: link.resolved_doc_path,
                candidates: Vec::new(),
            });
            continue;
        }

        let query_text = format!("{}{}", query_prefix, link.raw_target);
        let mut q = embedder.embed_texts(&[query_text])?;
        let Some(mut q0) = q.pop() else { continue };
        if q0.is_empty() {
            continue;
        }
        if dim_target > 0 && (dim_target as usize) < q0.len() {
            q0.truncate(dim_target as usize);
        }

        let mut candidates: Vec<(String, f64)> = Vec::new();
        if link.resolution_kind == "ambiguous" && !link.candidates.is_empty() {
            // Rank existing candidates with embeddings.
            let rows = projection::search_doc_title_embeddings(
                &backend,
                &vault_prefix,
                model,
                dim_target,
                &q0,
                500,
            )?;
            let mut map: std::collections::BTreeMap<String, f64> =
                std::collections::BTreeMap::new();
            for (p, s) in rows {
                map.insert(p, s);
            }
            for c in link.candidates.iter() {
                candidates.push((c.clone(), *map.get(c).unwrap_or(&0.0)));
            }
            candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        } else {
            candidates = projection::search_doc_title_embeddings(
                &backend,
                &vault_prefix,
                model,
                dim_target,
                &q0,
                per_link_limit,
            )?;
        }

        let recommended_doc_path = candidates.first().map(|x| x.0.clone());
        suggestions.push(UnresolvedLinkSuggestionRow {
            suggestion_id,
            run_id: run_id.to_string(),
            link_id: link.link_id,
            from_doc_path: link.from_doc_path,
            line: link.line,
            embed: link.embed,
            raw_target: link.raw_target,
            raw_heading: link.raw_heading,
            resolution_kind: link.resolution_kind,
            vault_prefix,
            model: model.to_string(),
            dim_target,
            recommended_doc_path,
            candidates,
        });
    }

    projection::project_unresolved_link_suggestions(&backend, run_id, &suggestions)?;
    eprintln!(
        "ollama_suggest: projected suggestions={}",
        suggestions.len()
    );
    Ok(())
}
