use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use admit_dag::{GovernedDag, NodeKind};
use sha2::Digest;

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

fn build_heading_index(
    dag: &GovernedDag,
    obsidian_vault_prefixes: &[&str],
) -> BTreeMap<String, BTreeSet<String>> {
    let mut out: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for (_id, node) in dag.nodes() {
        let NodeKind::TextChunk {
            doc_path,
            heading_path,
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

fn build_file_index(
    dag: &GovernedDag,
    obsidian_vault_prefixes: &[&str],
) -> BTreeMap<String, String> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();
    for (id, node) in dag.nodes() {
        let NodeKind::FileAtPath { path, .. } = &node.kind else {
            continue;
        };
        if !obsidian_vault_prefixes.iter().any(|p| path.starts_with(p)) {
            continue;
        }
        out.insert(path.clone(), id.to_string());
    }
    out
}

fn vault_root_for_path<'a>(path: &str, obsidian_vault_prefixes: &[&'a str]) -> Option<&'a str> {
    obsidian_vault_prefixes
        .iter()
        .copied()
        .filter(|p| path.starts_with(*p))
        .max_by_key(|p| p.len())
}

pub(crate) fn looks_like_asset_target(target: &str) -> bool {
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

pub(crate) fn resolve_obsidian_asset_target(
    from_doc_path: &str,
    raw_target: &str,
    obsidian_vault_prefixes: &[&str],
    vault_files: &BTreeMap<String, String>,
) -> Option<AssetResolution> {
    crate::link_resolver::resolve_obsidian_asset_target(
        from_doc_path,
        raw_target,
        obsidian_vault_prefixes,
        vault_files,
    )
}

fn normalize_target(s: &str) -> String {
    crate::link_resolver::normalize_target(s)
}

fn normalize_optional(s: Option<&str>) -> Option<String> {
    s.map(|v| v.trim().to_string()).filter(|v| !v.is_empty())
}

pub(crate) fn extract_obsidian_links(input: &str) -> Vec<ObsidianLink> {
    crate::link_resolver::extract_obsidian_links(input)
}

pub(crate) fn resolve_obsidian_target(
    from_doc_path: &str,
    raw_target: &str,
    obsidian_vault_prefixes: &[&str],
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
        if let Some(root) = vault_root_for_path(from_doc_path, obsidian_vault_prefixes) {
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
        for prefix in obsidian_vault_prefixes {
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
    let title = norm_target
        .trim_end_matches(".md")
        .trim_end_matches(".MD")
        .to_string();
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

pub(crate) fn choose_ambiguous_target(
    from_doc_path: &str,
    candidates: &[String],
) -> Option<(String, String)> {
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

    let in_same_root: Vec<&String> = candidates
        .iter()
        .filter(|c| c.starts_with(from_root))
        .collect();
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
    if concepts.len() == 1 && !meta.is_empty() {
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

pub(crate) fn ensure_vault_link_schema(store: &SurrealCliProjectionStore) -> Result<(), String> {
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
    store.run_sql_allow_already_exists(sql)
}

pub(crate) fn select_unresolved_links(
    store: &SurrealCliProjectionStore,
    prefixes: &[&str],
    kinds: &[&str],
    limit: usize,
    projection_run_id: Option<&str>,
) -> Result<Vec<UnresolvedLinkRow>, String> {
    ensure_vault_link_schema(store)?;
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
    let rows = store.select_rows_from_single_select(&sql)?;
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

pub(crate) fn project_unresolved_link_suggestions(
    store: &SurrealCliProjectionStore,
    run_id: &str,
    rows: &[UnresolvedLinkSuggestionRow],
) -> Result<(), String> {
    ensure_vault_link_schema(store)?;
    let mut sql = String::new();
    // IR-DELETE-JUSTIFIED: run-scoped replacement semantics for suggestion rows.
    sql.push_str(&format!(
        "DELETE unresolved_link_suggestion WHERE run_id = {} RETURN NONE;",
        json_string(run_id)
    ));

    let batch_limit = store.projection_config.batch_sizes.links;
    let max_sql_bytes = store.projection_config.batch_sizes.max_sql_bytes.max(1);
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
            store.run_sql(&sql)?;
            sql.clear();
            batch_count = 0;
        }
    }
    if !sql.is_empty() {
        store.run_sql(&sql)?;
    }
    Ok(())
}

pub(crate) fn search_doc_title_embeddings(
    store: &SurrealCliProjectionStore,
    obsidian_vault_prefix: &str,
    model: &str,
    dim_target: u32,
    query_embedding: &[f32],
    limit: usize,
) -> Result<Vec<(String, f64)>, String> {
    store.ensure_doc_file_schema()?;
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
    let rows = store.select_rows_from_single_select(&sql)?;
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

#[cfg(test)]
mod tests {
    use super::*;

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
        exact.entry("X".to_string()).or_default().extend([
            "chatgpt/vault/papers/X.md".to_string(),
            "irrev-vault/papers/X.md".to_string(),
        ]);
        let mut casefold: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        casefold.entry("x".to_string()).or_default().extend([
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
}
