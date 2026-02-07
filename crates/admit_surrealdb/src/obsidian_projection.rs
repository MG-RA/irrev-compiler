use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use admit_dag::{GovernedDag, NodeKind};

use super::*;

pub(crate) fn project_obsidian_vault_links_from_artifacts(
    store: &SurrealCliProjectionStore,
    dag: &GovernedDag,
    artifacts_root: &Path,
    obsidian_vault_prefixes: &[&str],
    doc_filter: Option<&BTreeSet<String>>,
    run_id: Option<&str>,
) -> Result<crate::projection_run::PhaseResult, String> {
    let phase = "obsidian_vault_links";
    let phase_start = std::time::Instant::now();
    store.ensure_doc_file_schema()?;
    store.ensure_vault_link_schema()?;

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
    // In incremental mode, `doc_filter` narrows this to changed documents.
    let mut doc_file_batches = BatchAccumulator::new(
        store,
        phase,
        run_id,
        store.projection_config.batch_sizes.doc_files,
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
        store,
        phase,
        run_id,
        store.projection_config.batch_sizes.headings,
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

    // Build relation edges between doc_file records based on Obsidian wiki links.
    let mut stats_by_doc: BTreeMap<String, DocStatsAgg> = BTreeMap::new();
    let mut inbound_links: BTreeMap<String, u32> = BTreeMap::new();

    let mut doc_update_batches = BatchAccumulator::new(
        store,
        phase,
        run_id,
        store.projection_config.batch_sizes.doc_files,
    );
    let mut link_batches = BatchAccumulator::new(
        store,
        phase,
        run_id,
        store.projection_config.batch_sizes.links,
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
                obsidian_vault_prefixes,
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

    // Materialize doc-level stats so the UI can browse without heavy GROUP BY queries.
    let mut stats_batches = BatchAccumulator::new(
        store,
        phase,
        run_id,
        store.projection_config.batch_sizes.stats,
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
