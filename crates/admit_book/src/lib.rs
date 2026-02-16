use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

mod markdown_latex;
mod model;
mod render;

pub use markdown_latex::md_to_latex;
pub use model::*;
pub use render::{
    compile_pdf, default_latex_template, render_invariant_gap_audit, render_latex,
    render_latex_appendices, render_latex_modular, render_layer_invariant_matrix, render_markdown,
    render_spine_index_appendix,
};
pub(crate) use render::{latex_escape, sanitize_label};

fn normalize_lf(input: &str) -> String {
    input.replace("\r\n", "\n").replace('\r', "\n")
}

fn sha256_hex(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input);
    format!("{:x}", hasher.finalize())
}

fn canonical_frontmatter_hash(fm: &BTreeMap<String, serde_json::Value>) -> String {
    let encoded = serde_json::to_string(fm).unwrap_or_else(|_| "{}".to_string());
    sha256_hex(normalize_lf(&encoded).as_bytes())
}

fn compute_dependency_paths(
    deps: &HashMap<String, BTreeSet<String>>,
    seed_ids: &BTreeSet<String>,
    included: &HashSet<String>,
) -> HashMap<String, Vec<String>> {
    let mut best: HashMap<String, (usize, String, Vec<String>)> = HashMap::new();

    for seed in seed_ids {
        let mut queue: VecDeque<String> = VecDeque::new();
        let mut local_paths: HashMap<String, Vec<String>> = HashMap::new();
        local_paths.insert(seed.clone(), vec![seed.clone()]);
        queue.push_back(seed.clone());

        while let Some(cur) = queue.pop_front() {
            let current_path = local_paths
                .get(&cur)
                .cloned()
                .unwrap_or_else(|| vec![cur.clone()]);
            let mut neighbors: Vec<String> = deps
                .get(&cur)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|n| included.contains(n))
                .collect();
            neighbors.sort();

            for next in neighbors {
                let mut candidate = current_path.clone();
                candidate.push(next.clone());
                let should_update_local = match local_paths.get(&next) {
                    None => true,
                    Some(existing) => {
                        candidate.len() < existing.len()
                            || (candidate.len() == existing.len() && candidate < *existing)
                    }
                };
                if should_update_local {
                    local_paths.insert(next.clone(), candidate);
                    queue.push_back(next);
                }
            }
        }

        for (id, path) in local_paths {
            let dist = path.len().saturating_sub(1);
            let should_update = match best.get(&id) {
                None => true,
                Some(existing) => {
                    dist < existing.0
                        || (dist == existing.0 && seed < &existing.1)
                        || (dist == existing.0 && seed == &existing.1 && path < existing.2)
                }
            };
            if should_update {
                best.insert(id, (dist, seed.clone(), path));
            }
        }
    }

    let mut out: HashMap<String, Vec<String>> = HashMap::new();
    for id in included {
        if let Some((_dist, _seed, path)) = best.get(id) {
            out.insert(id.clone(), path.clone());
        } else {
            out.insert(id.clone(), vec![id.clone()]);
        }
    }
    out
}

fn upstream_closure(
    seeds: &BTreeSet<String>,
    deps: &HashMap<String, BTreeSet<String>>,
    included: &HashSet<String>,
) -> BTreeSet<String> {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut stack: Vec<String> = seeds.iter().cloned().collect();
    while let Some(cur) = stack.pop() {
        if !seen.insert(cur.clone()) {
            continue;
        }
        for next in deps.get(&cur).cloned().unwrap_or_default() {
            if included.contains(&next) && !seen.contains(&next) {
                stack.push(next);
            }
        }
    }
    seen
}

fn classify_concept(
    declared: &BTreeSet<String>,
    observed: &BTreeSet<String>,
    inferred: &BTreeSet<String>,
) -> ConceptClassification {
    let aligned = declared.iter().any(|d| observed.contains(d));
    if aligned {
        return ConceptClassification::Aligned;
    }
    if !declared.is_empty() && !observed.is_empty() {
        return ConceptClassification::Mismatch;
    }
    if !declared.is_empty() {
        return ConceptClassification::DeclaredOnly;
    }
    if !observed.is_empty() {
        return ConceptClassification::ObservedOnly;
    }
    if !inferred.is_empty() {
        return ConceptClassification::InferredOnly;
    }
    ConceptClassification::StructuralOnly
}

pub fn analyze_book(
    graph: &BookGraphInput,
    spine_rows: &[SpineEvidenceRow],
    invariant_ids: &[String],
) -> Result<BookAnalytics, String> {
    let invariant_set: BTreeSet<String> = invariant_ids.iter().cloned().collect();
    let mut spine_by_id: HashMap<String, &SpineEvidenceRow> = HashMap::new();
    for row in spine_rows {
        spine_by_id.insert(row.id.clone(), row);
    }

    let mut declared_by_id: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut observed_by_id: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut core_by_inv: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for id in &graph.ordered {
        let concept = graph
            .concepts_by_id
            .get(id)
            .ok_or_else(|| format!("missing concept: {id}"))?;

        let declared: BTreeSet<String> = concept
            .declared_invariants
            .iter()
            .filter(|inv| invariant_set.contains(*inv))
            .cloned()
            .collect();
        declared_by_id.insert(id.clone(), declared);

        let mut observed = BTreeSet::new();
        if let Some(row) = spine_by_id.get(id) {
            for inv in &row.core_in {
                if invariant_set.contains(inv) {
                    observed.insert(inv.clone());
                    core_by_inv
                        .entry(inv.clone())
                        .or_default()
                        .insert(id.clone());
                }
            }
            for inv in &row.footprint_in {
                if invariant_set.contains(inv) {
                    observed.insert(inv.clone());
                }
            }
            for (inv, ct) in &row.refs {
                if ct.invariant + ct.diagnostic == 0 {
                    continue;
                }
                if invariant_set.contains(inv) {
                    observed.insert(inv.clone());
                }
            }
        }
        observed_by_id.insert(id.clone(), observed);
    }

    let mut inferred_by_id: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut dependency_of_core_by_id: HashMap<String, BTreeSet<String>> = HashMap::new();
    for inv in invariant_ids {
        let seeds = core_by_inv.get(inv).cloned().unwrap_or_default();
        if seeds.is_empty() {
            continue;
        }
        let closure = upstream_closure(&seeds, &graph.deps, &graph.included);
        for id in &closure {
            dependency_of_core_by_id
                .entry(id.clone())
                .or_default()
                .insert(inv.clone());
        }
        for id in closure {
            let declared = declared_by_id.get(&id).cloned().unwrap_or_default();
            let observed = observed_by_id.get(&id).cloned().unwrap_or_default();
            if declared.contains(inv) || observed.contains(inv) {
                continue;
            }
            inferred_by_id.entry(id).or_default().insert(inv.clone());
        }
    }

    let dependency_paths = compute_dependency_paths(&graph.deps, &graph.seed_ids, &graph.included);

    let mut records: Vec<ConceptBookRecord> = Vec::new();
    for id in &graph.ordered {
        let concept = graph
            .concepts_by_id
            .get(id)
            .ok_or_else(|| format!("missing concept: {id}"))?;
        let row = spine_by_id.get(id).copied();
        let declared = declared_by_id.get(id).cloned().unwrap_or_default();
        let observed = observed_by_id.get(id).cloned().unwrap_or_default();
        let inferred = inferred_by_id.get(id).cloned().unwrap_or_default();
        let dependency_of_core = dependency_of_core_by_id
            .get(id)
            .cloned()
            .unwrap_or_default();
        let core_in = row
            .map(|r| {
                r.core_in
                    .iter()
                    .filter(|inv| invariant_set.contains(*inv))
                    .cloned()
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        let footprint_in = row
            .map(|r| {
                r.footprint_in
                    .iter()
                    .filter(|inv| invariant_set.contains(*inv))
                    .cloned()
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();

        let mut ref_counts: BTreeMap<String, RefCounts> = BTreeMap::new();
        if let Some(r) = row {
            for inv in invariant_ids {
                if let Some(ct) = r.refs.get(inv) {
                    ref_counts.insert(inv.clone(), ct.clone());
                }
            }
        }

        let classification = classify_concept(&declared, &observed, &inferred);
        let included_reason = graph
            .included_reason
            .get(id)
            .cloned()
            .unwrap_or(IncludedReason::DependencyClosure);

        records.push(ConceptBookRecord {
            id: id.clone(),
            title: concept.title.clone(),
            canonical_path: concept.canonical_path.clone(),
            layer: concept.layer.clone(),
            layer_label: concept.layer_label.clone(),
            canonical: concept.canonical,
            declared_invariants: declared.iter().cloned().collect(),
            observed_invariants: observed.iter().cloned().collect(),
            inferred_invariants: inferred.iter().cloned().collect(),
            dependency_of_core_invariants: dependency_of_core.iter().cloned().collect(),
            core_in: core_in.iter().cloned().collect(),
            footprint_in: footprint_in.iter().cloned().collect(),
            ref_counts,
            primary_spine: row
                .map(|r| r.primary_spine.clone())
                .unwrap_or_else(|| "structural".to_string()),
            classification,
            included_reason,
            dependency_path: dependency_paths
                .get(id)
                .cloned()
                .unwrap_or_else(|| vec![id.clone()]),
            frontmatter_hash: canonical_frontmatter_hash(&concept.frontmatter),
            content_hash: Some(sha256_hex(
                normalize_lf(&concept.source_markdown_body).as_bytes(),
            )),
        });
    }

    records.sort_by(|a, b| a.id.cmp(&b.id));
    let mut records_by_id: HashMap<String, usize> = HashMap::new();
    for (idx, rec) in records.iter().enumerate() {
        records_by_id.insert(rec.id.clone(), idx);
    }

    let mut layer_invariant_summaries: BTreeMap<String, BTreeMap<String, InvariantLayerSummary>> =
        BTreeMap::new();
    let mut layer_core_concepts: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
    for (layer, ids) in &graph.by_layer {
        let mut inv_map: BTreeMap<String, InvariantLayerSummary> = BTreeMap::new();
        let mut core_map: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for inv in invariant_ids {
            let mut summary = InvariantLayerSummary::default();
            let mut core_ids: Vec<String> = Vec::new();
            for id in ids {
                let Some(rec) = records_by_id.get(id).and_then(|idx| records.get(*idx)) else {
                    continue;
                };
                if rec.declared_invariants.iter().any(|v| v == inv) {
                    summary.declared += 1;
                }
                if rec.observed_invariants.iter().any(|v| v == inv) {
                    summary.observed += 1;
                }
                if rec.core_in.iter().any(|v| v == inv) {
                    summary.core += 1;
                    core_ids.push(rec.id.clone());
                }
                if rec.inferred_invariants.iter().any(|v| v == inv) {
                    summary.inferred += 1;
                }
            }
            core_ids.sort();
            inv_map.insert(inv.clone(), summary);
            core_map.insert(inv.clone(), core_ids);
        }
        layer_invariant_summaries.insert(layer.clone(), inv_map);
        layer_core_concepts.insert(layer.clone(), core_map);
    }

    let mut matrix_cells: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
    let mut hybrid_matrix_cells: BTreeMap<String, BTreeMap<String, Vec<String>>> = BTreeMap::new();
    for (layer, ids) in &graph.by_layer {
        let mut row_cells: BTreeMap<String, Vec<String>> = BTreeMap::new();
        let mut row_hybrid_cells: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for inv in invariant_ids {
            let mut entries: Vec<String> = Vec::new();
            let mut hybrid_entries: Vec<String> = Vec::new();
            for id in ids {
                let Some(rec) = records_by_id.get(id).and_then(|idx| records.get(*idx)) else {
                    continue;
                };
                let declared_here = rec.declared_invariants.iter().any(|v| v == inv);
                let observed_here = rec.observed_invariants.iter().any(|v| v == inv);
                let footprint_here = rec.footprint_in.iter().any(|v| v == inv);
                let core_here = rec.core_in.iter().any(|v| v == inv);
                let has_refs_here = rec
                    .ref_counts
                    .get(inv)
                    .map(|ct| ct.invariant + ct.diagnostic > 0)
                    .unwrap_or(false);
                // Footprint-only: observed via footprint but not core/support refs
                let footprint_only_here = footprint_here && !core_here && !has_refs_here;
                if declared_here {
                    let marker = if observed_here {
                        if footprint_only_here {
                            "\u{00b7}"
                        } else {
                            "*"
                        }
                    } else if rec.observed_invariants.is_empty() {
                        "!"
                    } else {
                        "~"
                    };
                    entries.push(format!("{}{}", rec.id, marker));
                    let hybrid_marker = if observed_here {
                        if footprint_only_here {
                            "\u{00b7}"
                        } else {
                            "*"
                        }
                    } else if rec.observed_invariants.is_empty() {
                        if rec.dependency_of_core_invariants.iter().any(|v| v == inv) {
                            "+"
                        } else {
                            "!"
                        }
                    } else {
                        "~"
                    };
                    hybrid_entries.push(format!("{}{}", rec.id, hybrid_marker));
                    continue;
                }
                if matches!(rec.classification, ConceptClassification::InferredOnly)
                    && rec.inferred_invariants.iter().any(|v| v == inv)
                {
                    entries.push(format!("{}^", rec.id));
                    hybrid_entries.push(format!("{}^", rec.id));
                }
            }
            entries.sort();
            hybrid_entries.sort();
            row_cells.insert(inv.clone(), entries);
            row_hybrid_cells.insert(inv.clone(), hybrid_entries);
        }
        matrix_cells.insert(layer.clone(), row_cells);
        hybrid_matrix_cells.insert(layer.clone(), row_hybrid_cells);
    }

    let mut gaps = GapSummary::default();
    for rec in &records {
        match rec.classification {
            ConceptClassification::DeclaredOnly => {
                if rec.dependency_of_core_invariants.is_empty() {
                    gaps.declared_only.push(rec.id.clone());
                } else {
                    gaps.declared_infrastructure.push(rec.id.clone());
                }
            }
            ConceptClassification::Mismatch => gaps.mismatch.push(rec.id.clone()),
            ConceptClassification::InferredOnly => gaps.inferred_only.push(rec.id.clone()),
            ConceptClassification::StructuralOnly => gaps.structural_only.push(rec.id.clone()),
            _ => {}
        }
    }
    gaps.declared_only.sort();
    gaps.declared_infrastructure.sort();
    gaps.mismatch.sort();
    gaps.inferred_only.sort();
    gaps.structural_only.sort();

    Ok(BookAnalytics {
        records,
        records_by_id,
        layer_invariant_summaries,
        layer_core_concepts,
        matrix: LayerInvariantMatrix {
            cells: matrix_cells,
        },
        hybrid_matrix: LayerInvariantMatrix {
            cells: hybrid_matrix_cells,
        },
        gaps,
    })
}

pub fn build_book_ast(
    graph: &BookGraphInput,
    analytics: &BookAnalytics,
    invariant_ids: &[String],
    render_profile: RenderProfile,
) -> Result<BookAst, String> {
    fn primitive_rank(id: &str) -> usize {
        match id {
            "transformation-space" => 0,
            "difference" => 1,
            "persistence" => 2,
            "asymmetry" => 3,
            "erasure-cost" => 4,
            "irreversibility-quanta" => 5,
            "constraint" => 6,
            "degrees-of-freedom" => 7,
            "control-surface" => 8,
            "constraint-surface" => 9,
            "agency-layer" => 10,
            "role-boundary" => 11,
            "exemption" => 12,
            "accumulation" => 13,
            _ => usize::MAX,
        }
    }

    fn order_layer_items(label: &str, items: &[String]) -> Vec<String> {
        let mut indexed: Vec<(usize, &String)> = items.iter().enumerate().collect();
        if label == "Primitives" {
            indexed.sort_by(|(ia, a), (ib, b)| {
                primitive_rank(a).cmp(&primitive_rank(b)).then(ia.cmp(ib))
            });
        }
        indexed.into_iter().map(|(_, id)| id.clone()).collect()
    }

    let mut contents: Vec<BookContentsSection> = Vec::new();
    for label in &graph.layer_order {
        let Some(items) = graph.by_layer.get(label) else {
            continue;
        };
        let ordered_items = order_layer_items(label, items);
        let entries = ordered_items
            .iter()
            .filter_map(|id| {
                graph
                    .concepts_by_id
                    .get(id)
                    .map(|concept| BookContentsEntry {
                        id: id.clone(),
                        anchor: concept.anchor.clone(),
                    })
            })
            .collect();
        contents.push(BookContentsSection {
            label: label.clone(),
            entries,
        });
    }
    if let Some(items) = graph.by_layer.get("Unclassified") {
        let entries = items
            .iter()
            .filter_map(|id| {
                graph
                    .concepts_by_id
                    .get(id)
                    .map(|concept| BookContentsEntry {
                        id: id.clone(),
                        anchor: concept.anchor.clone(),
                    })
            })
            .collect();
        contents.push(BookContentsSection {
            label: "Unclassified".to_string(),
            entries,
        });
    }

    let mut layers: Vec<BookLayerSection> = Vec::new();
    for label in &graph.layer_order {
        let Some(items) = graph.by_layer.get(label) else {
            continue;
        };
        let ordered_items = order_layer_items(label, items);

        let summaries = analytics
            .layer_invariant_summaries
            .get(label)
            .cloned()
            .unwrap_or_default();
        let mut invariant_counts: Vec<InvariantCounts> = Vec::new();
        for inv in invariant_ids {
            let s = summaries.get(inv).cloned().unwrap_or_default();
            invariant_counts.push(InvariantCounts {
                invariant: inv.clone(),
                declared: s.declared,
                observed: s.observed,
                core: s.core,
                inferred: s.inferred,
            });
        }
        let core_map = analytics
            .layer_core_concepts
            .get(label)
            .cloned()
            .unwrap_or_default();
        let mut core_spine_concepts: Vec<InvariantConceptList> = Vec::new();
        for inv in invariant_ids {
            let mut core_items = core_map.get(inv).cloned().unwrap_or_default();
            core_items.sort();
            core_spine_concepts.push(InvariantConceptList {
                invariant: inv.clone(),
                concepts: core_items,
            });
        }

        let mut declared_gap: Vec<String> = Vec::new();
        let mut declared_infra: Vec<String> = Vec::new();
        let mut mismatch: Vec<String> = Vec::new();
        let mut unassigned: Vec<String> = Vec::new();
        for id in &ordered_items {
            let Some(rec) = analytics.get(id) else {
                continue;
            };
            match rec.classification {
                ConceptClassification::DeclaredOnly => {
                    if rec.dependency_of_core_invariants.is_empty() {
                        declared_gap.push(id.clone());
                    } else {
                        declared_infra.push(id.clone());
                    }
                }
                ConceptClassification::Mismatch => mismatch.push(id.clone()),
                ConceptClassification::StructuralOnly => unassigned.push(id.clone()),
                _ => {}
            }
        }
        declared_gap.sort();
        declared_infra.sort();
        mismatch.sort();
        unassigned.sort();

        let mut audit_hooks: Vec<BookAuditHook> = Vec::new();
        if matches!(render_profile, RenderProfile::Hybrid) {
            audit_hooks.push(BookAuditHook {
                label: "declared-gap".to_string(),
                value: if declared_gap.is_empty() {
                    "(none)".to_string()
                } else {
                    declared_gap.join(", ")
                },
            });
            audit_hooks.push(BookAuditHook {
                label: "declared-infrastructure".to_string(),
                value: if declared_infra.is_empty() {
                    "(none)".to_string()
                } else {
                    declared_infra.join(", ")
                },
            });
        } else {
            let mut declared_all = declared_gap;
            declared_all.extend(declared_infra);
            declared_all.sort();
            audit_hooks.push(BookAuditHook {
                label: "declared-only".to_string(),
                value: if declared_all.is_empty() {
                    "(none)".to_string()
                } else {
                    declared_all.join(", ")
                },
            });
        }
        audit_hooks.push(BookAuditHook {
            label: "mismatch".to_string(),
            value: if mismatch.is_empty() {
                "(none)".to_string()
            } else {
                mismatch.join(", ")
            },
        });
        audit_hooks.push(BookAuditHook {
            label: "unassigned (no declared/observed/inferred invariant mapping)".to_string(),
            value: if unassigned.is_empty() {
                "(none)".to_string()
            } else {
                unassigned.join(", ")
            },
        });

        let navigational_matrix = if matches!(render_profile, RenderProfile::Hybrid) {
            let row = analytics
                .hybrid_matrix
                .cells
                .get(label)
                .cloned()
                .unwrap_or_default();
            let per_invariant = invariant_ids
                .iter()
                .map(|inv| InvariantConceptList {
                    invariant: inv.clone(),
                    concepts: row.get(inv).cloned().unwrap_or_default(),
                })
                .collect();
            Some(BookNavigationalMatrix {
                marker_legend: "`*` aligned, `!` declared-gap, `+` declared-infrastructure, `~` drift, `^` inferred-only; `+` marks dependency-of-core infrastructure and is not treated as a gap".to_string(),
                per_invariant,
            })
        } else {
            None
        };

        let mut concept_sections: Vec<BookConceptSection> = Vec::new();
        for id in &ordered_items {
            let concept = graph
                .concepts_by_id
                .get(id)
                .ok_or_else(|| format!("missing concept: {}", id))?;
            concept_sections.push(BookConceptSection {
                id: id.clone(),
                anchor: concept.anchor.clone(),
                title: concept.title.clone(),
                markdown_body: concept.book_markdown_body.clone(),
            });
        }

        layers.push(BookLayerSection {
            label: label.clone(),
            interlude: BookInvariantInterlude {
                reader_contract: "This interlude is a layer-level invariant snapshot: declared intent, observed evidence, and inferred dependency pressure. Read it as a constraint map for interpretation, not as an importance ranking.".to_string(),
                invariant_counts,
                core_spine_concepts,
                navigational_matrix,
                audit_hooks,
            },
            concepts: concept_sections,
        });
    }

    let mut unclassified: Vec<BookConceptSection> = Vec::new();
    if let Some(items) = graph.by_layer.get("Unclassified") {
        for id in items {
            let concept = graph
                .concepts_by_id
                .get(id)
                .ok_or_else(|| format!("missing concept: {}", id))?;
            unclassified.push(BookConceptSection {
                id: id.clone(),
                anchor: concept.anchor.clone(),
                title: concept.title.clone(),
                markdown_body: concept.book_markdown_body.clone(),
            });
        }
    }

    let mut intro_paragraphs = vec![
        "The concept graph is primary. This linear book is a projection for reading; dependency links remain the interpretive ground.".to_string(),
    ];
    if matches!(render_profile, RenderProfile::Hybrid) {
        intro_paragraphs.push("Primitive and infrastructural concepts can appear declared-only because observed invariant evidence is detected primarily at composite and failure layers; this reflects layering, not drift.".to_string());
    }

    Ok(BookAst {
        title: "Irreversibility Vault - Concept Book (Linearized)".to_string(),
        intro_paragraphs,
        has_cycles: graph.has_cycles,
        cycle_nodes: graph
            .cycle_nodes
            .iter()
            .filter_map(|id| {
                graph.concepts_by_id.get(id).map(|concept| BookContentsEntry {
                    id: id.clone(),
                    anchor: concept.anchor.clone(),
                })
            })
            .collect(),
        contents,
        orientation_pages: Vec::new(),
        invariants: Vec::new(),
        supplemental_pages: Vec::new(),
        layers,
        unclassified,
        appendix_files: vec![
            "spine-index.md".to_string(),
            "layer-invariant-matrix.md".to_string(),
        ],
        appendix_note: "These generated appendices are support artifacts for navigation and audit; they are not importance rankings.".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn md_to_latex_inline_nesting() {
        let out = md_to_latex("**a `code` b**");
        assert_eq!(out.trim(), "\\textbf{a \\texttt{code} b}");
    }

    #[test]
    fn md_to_latex_nested_lists_with_continuation() {
        let input = "- one\n  continued\n  - child\n- two";
        let out = md_to_latex(input);
        assert!(out.contains("\\begin{itemize}"));
        assert!(out.contains("\\item one continued"));
        assert!(out.contains("\\item child"));
        assert!(out.contains("\\item two"));
    }

    #[test]
    fn md_to_latex_callout_with_list() {
        let input = "> [!note]\n> - item";
        let out = md_to_latex(input);
        assert!(out.contains("\\begin{irrevcallout}{note}"));
        assert!(out.contains("\\begin{itemize}"));
        assert!(out.contains("\\item item"));
        assert!(out.contains("\\end{irrevcallout}"));
    }

    #[test]
    fn md_to_latex_code_fence_keeps_verbatim() {
        let input = "```adm\n% _ \\\n```";
        let out = md_to_latex(input);
        assert!(out.contains("\\irrevcodelabel{adm}"));
        assert!(out.contains("\\begin{irrevcode}"));
        assert!(out.contains("% _ \\"));
        assert!(out.contains("\\end{irrevcode}"));
    }

    #[test]
    fn md_to_latex_concept_link() {
        let out = md_to_latex("[text](#concept-foo)");
        assert_eq!(out.trim(), "\\hyperref[concept:foo]{text}");
    }

    #[test]
    fn md_to_latex_non_concept_link_falls_back_to_text() {
        let out = md_to_latex("[text](#some-heading)");
        assert_eq!(out.trim(), "text");
    }

    #[test]
    fn md_to_latex_escapes_special_chars() {
        let out = md_to_latex("$100 & 50%");
        assert_eq!(out.trim(), "\\$100 \\& 50\\%");
    }

    #[test]
    fn latex_escape_normalizes_unicode_punctuation() {
        let out = latex_escape("a \u{2014} b \u{201C}q\u{201D} \u{2018}x\u{2019} -> y \u{2192} z");
        assert_eq!(out, "a --- b ``q'' `x' -> y $\\rightarrow$ z");
    }

    #[test]
    fn md_to_latex_empty_input() {
        assert_eq!(md_to_latex(""), "");
    }

    #[test]
    fn md_to_latex_ordered_list() {
        let out = md_to_latex("1. first\n2. second");
        assert!(out.contains("\\begin{enumerate}"));
        assert!(out.contains("\\item first"));
        assert!(out.contains("\\item second"));
        assert!(out.contains("\\end{enumerate}"));
    }

    #[test]
    fn md_to_latex_table_renders_longtable() {
        let out = md_to_latex("| A | B |\n| --- | --- |\n| x | y |");
        assert!(out.contains("\\begin{longtable}"));
        assert!(out.contains("\\textbf{A} & \\textbf{B}"));
        assert!(out.contains("x & y"));
        assert!(out.contains("\\end{longtable}"));
    }

    #[test]
    fn md_to_latex_heading_level_four() {
        let out = md_to_latex("#### Foo");
        assert_eq!(out.trim(), "\\subsection*{Foo}");
    }
}
