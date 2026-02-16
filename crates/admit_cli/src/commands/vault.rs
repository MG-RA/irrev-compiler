//! Vault utilities (content inspection + extraction).
//!
//! Note: these commands operate on a vault *as files* (not via SurrealDB projection),
//! because they are meant to be usable offline and without a DB dependency.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use admit_book::{
    analyze_book as analyze_book_model, build_book_ast as build_book_ast_model, BookAnalytics,
    BookAst, BookGraphInput, BookInvariantSection, BookSupplementalPage, ConceptBookRecord,
    IncludedReason, LayerInvariantMatrixView, RefCounts as BookRefCounts, RenderProfile,
    SourceConcept, SpineEvidenceRow,
};
use admit_scope_vault::frontmatter::extract_frontmatter;
use serde::{Deserialize, Serialize};
use sha2::Digest;

use crate::{
    obsidian_adapter as oa, VaultArgs, VaultBookBuildArgs, VaultBookCommands,
    VaultBookOutputFormat, VaultBookProfile, VaultCommands, VaultDocsCommands,
    VaultDocsCompilerExtractArgs, VaultLinkMode, VaultLinksBacklinksArgs, VaultLinksCommands,
    VaultLinksImplicitArgs, VaultSpinesAuditArgs, VaultSpinesCommands, VaultSpinesGenerateArgs,
    VaultSpinesRenderArgs,
};

pub fn run_vault(args: VaultArgs, _dag_trace_out: Option<&Path>) -> Result<(), String> {
    match args.command {
        VaultCommands::Links(links) => match links.command {
            VaultLinksCommands::Implicit(implicit) => run_links_implicit(implicit),
            VaultLinksCommands::Backlinks(backlinks) => run_links_backlinks(backlinks),
        },
        VaultCommands::Docs(docs) => match docs.command {
            VaultDocsCommands::CompilerExtract(extract) => run_docs_compiler_extract(extract),
        },
        VaultCommands::Spines(spines) => match spines.command {
            VaultSpinesCommands::Generate(generate) => run_spines_generate(generate),
            VaultSpinesCommands::Render(render) => run_spines_render(render),
            VaultSpinesCommands::Audit(audit) => run_spines_audit(audit),
        },
        VaultCommands::Book(book) => match book.command {
            VaultBookCommands::Build(build) => run_book_build(build),
        },
    }
}

#[derive(Debug, Clone)]
struct VaultNote {
    name: String, // file stem
    role: String,
    rel_path: String,
    title: String,
    body: String, // markdown body (frontmatter stripped)
    aliases: Vec<String>,
    invariant_id: Option<String>,
    canonical: bool,
    layer: Option<String>,
    invariants: Vec<String>,
    frontmatter: BTreeMap<String, serde_json::Value>,
}

fn load_vault_notes(vault_root: &Path) -> Result<Vec<VaultNote>, String> {
    let mut files: Vec<PathBuf> = Vec::new();
    collect_md_files(vault_root, &mut files).map_err(|e| e.to_string())?;
    files.sort();

    let mut notes: Vec<VaultNote> = Vec::new();
    for path in files {
        let rel = path
            .strip_prefix(vault_root)
            .map_err(|e| format!("rel path: {e}"))?
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = fs::read(&path).map_err(|e| format!("read {rel}: {e}"))?;
        let content = String::from_utf8_lossy(&bytes).to_string();
        let (fm, body) = split_frontmatter(&content);

        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_default()
            .to_string();
        let title = extract_title(&body, &name);
        let role = extract_role(&fm, &rel).unwrap_or_else(|| "unknown".to_string());

        let aliases = extract_string_list(&fm, "aliases");
        let invariant_id = extract_string(&fm, "invariant_id");
        let canonical = extract_bool(&fm, "canonical").unwrap_or(false);
        let layer = extract_string(&fm, "layer");
        let invariants = extract_string_list(&fm, "invariants");

        notes.push(VaultNote {
            name,
            role,
            rel_path: rel,
            title,
            body,
            aliases,
            invariant_id,
            canonical,
            layer,
            invariants,
            frontmatter: fm,
        });
    }
    Ok(notes)
}

fn collect_md_files(root: &Path, out: &mut Vec<PathBuf>) -> std::io::Result<()> {
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') {
            continue;
        }
        if path.is_dir() {
            collect_md_files(&path, out)?;
            continue;
        }
        if path.extension().and_then(|s| s.to_str()).unwrap_or("") == "md" {
            out.push(path);
        }
    }
    Ok(())
}

fn split_frontmatter(input: &str) -> (BTreeMap<String, serde_json::Value>, String) {
    if let Some((fm, end_line)) = extract_frontmatter(input) {
        let body = input
            .lines()
            .skip(end_line as usize)
            .collect::<Vec<_>>()
            .join("\n");
        (fm, body)
    } else {
        (BTreeMap::new(), input.to_string())
    }
}

fn extract_title(body: &str, fallback: &str) -> String {
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("# ") {
            let t = rest.trim();
            if !t.is_empty() {
                return t.to_string();
            }
        }
    }
    fallback.to_string()
}

fn extract_role(fm: &BTreeMap<String, serde_json::Value>, rel_path: &str) -> Option<String> {
    if let Some(role) = extract_string(fm, "role") {
        return Some(role);
    }
    // Conservative inference: prefer frontmatter when present.
    let first = rel_path.split('/').next()?.to_lowercase();
    let role = match first.as_str() {
        "concepts" => "concept",
        "diagnostics" => "diagnostic",
        "domains" => "domain",
        "projections" => "projection",
        "papers" => "paper",
        "invariants" => "invariant",
        "_templates" => "template",
        "meta" | "engagement" | "plans" | "exports bases" => "support",
        _ => "unknown",
    };
    Some(role.to_string())
}

fn extract_string(fm: &BTreeMap<String, serde_json::Value>, key: &str) -> Option<String> {
    fm.get(key).and_then(|v| v.as_str()).map(|s| s.to_string())
}

fn extract_string_list(fm: &BTreeMap<String, serde_json::Value>, key: &str) -> Vec<String> {
    let Some(v) = fm.get(key) else {
        return Vec::new();
    };
    let Some(arr) = v.as_array() else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|x| x.as_str())
        .map(|s| s.to_string())
        .collect()
}

fn extract_bool(fm: &BTreeMap<String, serde_json::Value>, key: &str) -> Option<bool> {
    fm.get(key).and_then(|v| v.as_bool())
}

fn norm_key(s: &str) -> String {
    s.trim().to_lowercase()
}

fn normalize_obsidian_target_to_key(target: &str) -> String {
    let mut t = oa::normalize_target(target);
    if t.to_lowercase().ends_with(".md") {
        t = t[..t.len().saturating_sub(3)].to_string();
    }
    if let Some(last) = t.rsplit('/').next() {
        norm_key(last)
    } else {
        norm_key(&t)
    }
}

fn note_matches_filter(note: &VaultNote, filter: &Option<String>) -> bool {
    let Some(q) = filter.as_ref() else {
        return true;
    };
    let q = q.trim().to_lowercase();
    if q.is_empty() {
        return true;
    }
    note.name.to_lowercase().contains(&q) || note.title.to_lowercase().contains(&q)
}

fn role_allowed(role: &str, allow: &HashSet<String>) -> bool {
    allow.is_empty() || allow.contains(&role.to_string())
}

fn build_ambiguous_names(notes: &[VaultNote]) -> HashSet<String> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for n in notes {
        *counts.entry(norm_key(&n.name)).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .filter_map(|(k, c)| if c > 1 { Some(k) } else { None })
        .collect()
}

fn normalize_for_mentions(input: &str) -> String {
    // Remove fenced code blocks first (line-based).
    let mut lines_out: Vec<String> = Vec::new();
    let mut in_fence = false;
    for line in input.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        lines_out.push(line.to_string());
    }
    let mut s = lines_out.join("\n");

    // Remove html comments <!-- ... -->
    s = strip_block(&s, "<!--", "-->");
    // Remove wikilinks [[ ... ]]
    s = strip_block(&s, "[[", "]]");
    // Remove inline code `...`
    s = strip_inline_code(&s);
    // Remove markdown link URLs: keep [label] from [label](url)
    s = strip_md_link_urls(&s);

    // Normalize to a space-separated, lowercase token stream.
    let mut out = String::with_capacity(s.len());
    let mut last_space = false;
    for ch in s.chars() {
        let is_word = ch.is_ascii_alphanumeric();
        if is_word {
            out.push(ch.to_ascii_lowercase());
            last_space = false;
            continue;
        }
        if ch == '_' || ch == '-' || ch == '–' || ch == '—' || ch.is_whitespace() {
            if !last_space {
                out.push(' ');
                last_space = true;
            }
            continue;
        }
        // Any other punctuation: treat as separator.
        if !last_space {
            out.push(' ');
            last_space = true;
        }
    }
    out.trim().to_string()
}

fn normalize_term(term: &str) -> String {
    normalize_for_mentions(term)
}

fn count_term_occurrences(text_norm: &str, term_norm: &str) -> u32 {
    if term_norm.is_empty() {
        return 0;
    }
    let mut count: u32 = 0;
    let mut start = 0usize;
    while let Some(idx) = text_norm[start..].find(term_norm) {
        let abs = start + idx;
        let before_ok = abs == 0 || text_norm.as_bytes()[abs - 1] == b' ';
        let end = abs + term_norm.len();
        let after_ok = end >= text_norm.len() || text_norm.as_bytes()[end] == b' ';
        if before_ok && after_ok {
            count += 1;
            start = end;
        } else {
            start = abs + 1;
        }
        if start >= text_norm.len() {
            break;
        }
    }
    count
}

fn strip_block(input: &str, open: &str, close: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < input.len() {
        if input[i..].starts_with(open) {
            if let Some(end) = input[i + open.len()..].find(close) {
                i = i + open.len() + end + close.len();
                continue;
            } else {
                break;
            }
        }
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn strip_inline_code(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_code = false;
    for ch in input.chars() {
        if ch == '`' {
            in_code = !in_code;
            continue;
        }
        if in_code {
            continue;
        }
        out.push(ch);
    }
    out
}

fn strip_md_link_urls(input: &str) -> String {
    // Keep "[label]" from "[label](url)".
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'[' {
            if let Some(end_label) = input[i + 1..].find(']') {
                let end_label = i + 1 + end_label;
                let label = &input[i + 1..end_label];
                let j = end_label + 1;
                if j < bytes.len() && bytes[j] == b'(' {
                    if let Some(end_url) = input[j + 1..].find(')') {
                        let end_url = j + 1 + end_url;
                        out.push_str(label);
                        i = end_url + 1;
                        continue;
                    }
                }
            }
        }
        let ch = input[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

fn build_term_to_target(
    notes: &[VaultNote],
    target_roles: &HashSet<String>,
) -> (
    HashMap<String, String>,
    BTreeMap<String, Vec<String>>,
    HashSet<String>,
) {
    let ambiguous_names = build_ambiguous_names(notes);
    let mut term_to_targets: HashMap<String, BTreeSet<String>> = HashMap::new();

    for note in notes {
        let target = norm_key(&note.name);
        if ambiguous_names.contains(&target) {
            continue;
        }
        if !target_roles.contains(&norm_key(&note.role)) {
            continue;
        }

        term_to_targets
            .entry(norm_key(&note.name))
            .or_default()
            .insert(target.clone());

        if note.role == "concept" {
            for alias in &note.aliases {
                let term = norm_key(alias);
                if term.is_empty() {
                    continue;
                }
                term_to_targets
                    .entry(term)
                    .or_default()
                    .insert(target.clone());
            }
        }

        if note.role == "invariant" {
            if let Some(inv) = note.invariant_id.as_ref() {
                let term = norm_key(inv);
                if !term.is_empty() {
                    term_to_targets
                        .entry(term)
                        .or_default()
                        .insert(target.clone());
                }
            }
        }
    }

    let mut term_to_target: HashMap<String, String> = HashMap::new();
    let mut terms_by_target: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut collisions: HashSet<String> = HashSet::new();

    for (term, targets) in term_to_targets {
        if ambiguous_names.contains(&term) {
            continue;
        }
        if targets.len() != 1 {
            collisions.insert(term);
            continue;
        }
        let target = targets.iter().next().unwrap().clone();
        term_to_target.insert(term.clone(), target.clone());
        terms_by_target.entry(target).or_default().push(term);
    }

    (term_to_target, terms_by_target, collisions)
}

fn resolve_explicit_targets(
    note: &VaultNote,
    term_to_target: &HashMap<String, String>,
) -> HashSet<String> {
    let mut out: HashSet<String> = HashSet::new();
    for link in oa::extract_obsidian_links(&note.body) {
        let key = normalize_obsidian_target_to_key(&link.target);
        if let Some(target) = term_to_target.get(&key) {
            out.insert(target.clone());
        } else {
            out.insert(key);
        }
    }
    out
}

fn run_links_implicit(args: VaultLinksImplicitArgs) -> Result<(), String> {
    let notes = load_vault_notes(&args.path)?;

    let source_roles: HashSet<String> = args
        .source_role
        .iter()
        .map(|s| norm_key(s))
        .filter(|s| !s.is_empty())
        .collect();
    let target_roles: HashSet<String> = args
        .target_role
        .iter()
        .map(|s| norm_key(s))
        .filter(|s| !s.is_empty())
        .collect();

    let (term_to_target, _terms_by_target, collisions) =
        build_term_to_target(&notes, &target_roles);

    // Precompute normalized terms.
    let mut norm_terms: Vec<(String, String, String)> = Vec::new(); // (term, term_norm, target)
    for (term, target) in term_to_target.iter() {
        norm_terms.push((term.clone(), normalize_term(term), target.clone()));
    }

    let mut items: Vec<serde_json::Value> = Vec::new();
    for note in &notes {
        let role = norm_key(&note.role);
        if !role_allowed(&role, &source_roles) {
            continue;
        }
        if !note_matches_filter(note, &args.note) {
            continue;
        }

        let explicit_targets = resolve_explicit_targets(note, &term_to_target);
        let text_norm = normalize_for_mentions(&note.body);

        let mut counts: HashMap<String, u32> = HashMap::new();
        let mut via_counts: HashMap<String, HashMap<String, u32>> = HashMap::new();

        // Treat declared invariant coverage as an explicit (non-text) mention edge so
        // invariant-concept graphs don't depend on prose mentions.
        if note.role == "concept" && target_roles.contains("invariant") {
            for inv in &note.invariants {
                let term = norm_key(inv);
                if term.is_empty() {
                    continue;
                }
                let Some(target) = term_to_target.get(&term) else {
                    continue;
                };
                if target == &norm_key(&note.name) {
                    continue;
                }
                *counts.entry(target.clone()).or_insert(0) += 1;
                via_counts
                    .entry(target.clone())
                    .or_default()
                    .entry(inv.clone())
                    .and_modify(|v| *v += 1)
                    .or_insert(1);
            }
        }

        for (term, term_norm, target) in &norm_terms {
            if !args.include_explicit && explicit_targets.contains(target) {
                continue;
            }
            if target == &norm_key(&note.name) {
                continue;
            }
            let c = count_term_occurrences(&text_norm, term_norm);
            if c == 0 {
                continue;
            }
            *counts.entry(target.clone()).or_insert(0) += c;
            via_counts
                .entry(target.clone())
                .or_default()
                .entry(term.clone())
                .and_modify(|v| *v += c)
                .or_insert(c);
        }

        let mut mentions: Vec<serde_json::Value> = Vec::new();
        for (target, total) in counts {
            if total < args.min_count {
                continue;
            }
            let via = via_counts
                .get(&target)
                .and_then(|m| m.iter().max_by_key(|(_k, v)| *v).map(|(k, _v)| k.clone()))
                .unwrap_or_else(|| target.clone());
            mentions.push(serde_json::json!({
                "target": target,
                "via": via,
                "count": total
            }));
        }

        mentions.sort_by(|a, b| {
            let ca = a.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
            let cb = b.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
            cb.cmp(&ca).then_with(|| {
                let ta = a.get("target").and_then(|v| v.as_str()).unwrap_or("");
                let tb = b.get("target").and_then(|v| v.as_str()).unwrap_or("");
                ta.cmp(tb)
            })
        });
        if args.max_targets_per_note > 0 && mentions.len() > args.max_targets_per_note {
            mentions.truncate(args.max_targets_per_note);
        }

        if mentions.is_empty() {
            continue;
        }
        items.push(serde_json::json!({
            "source": note.name,
            "source_role": note.role,
            "path": note.rel_path,
            "mentions": mentions
        }));
    }

    let payload = serde_json::json!({
        "title": "Implicit link mentions",
        "vault": args.path.to_string_lossy(),
        "min_count": args.min_count,
        "include_explicit": args.include_explicit,
        "source_roles": args.source_role,
        "target_roles": args.target_role,
        "colliding_terms_excluded": collisions.into_iter().collect::<Vec<_>>(),
        "items": items
    });

    write_output(&payload, args.format.json(), args.out.as_ref())?;
    Ok(())
}

fn run_links_backlinks(args: VaultLinksBacklinksArgs) -> Result<(), String> {
    let notes = load_vault_notes(&args.path)?;

    let source_roles: HashSet<String> = args
        .source_role
        .iter()
        .map(|s| norm_key(s))
        .filter(|s| !s.is_empty())
        .collect();

    let target_norm = norm_key(&args.target);
    if target_norm.is_empty() {
        return Err("target must be non-empty".to_string());
    }

    // For explicit alias resolution we need a broad term map.
    let all_roles: HashSet<String> = [
        "concept",
        "diagnostic",
        "domain",
        "projection",
        "paper",
        "meta",
        "support",
        "invariant",
        "template",
        "unknown",
    ]
    .into_iter()
    .map(|s| s.to_string())
    .collect();
    let (term_to_target, terms_by_target, _collisions) = build_term_to_target(&notes, &all_roles);

    let target_terms = terms_by_target
        .get(&target_norm)
        .cloned()
        .unwrap_or_else(|| vec![target_norm.clone()]);
    let target_terms_norm: Vec<(String, String)> = target_terms
        .iter()
        .map(|t| (t.clone(), normalize_term(t)))
        .collect();

    let mut explicit_from: Vec<serde_json::Value> = Vec::new();
    let mut implicit_from: Vec<serde_json::Value> = Vec::new();

    for note in &notes {
        let role = norm_key(&note.role);
        if !role_allowed(&role, &source_roles) {
            continue;
        }
        if norm_key(&note.name) == target_norm {
            continue;
        }

        let explicit_targets = resolve_explicit_targets(note, &term_to_target);
        if matches!(args.mode, VaultLinkMode::Explicit | VaultLinkMode::Both)
            && explicit_targets.contains(&target_norm)
        {
            explicit_from.push(serde_json::json!({
                "source": note.name,
                "source_role": note.role,
                "path": note.rel_path
            }));
        }

        if matches!(args.mode, VaultLinkMode::Implicit | VaultLinkMode::Both) {
            let text_norm = normalize_for_mentions(&note.body);
            let mut total: u32 = 0;
            let mut via: Option<String> = None;
            for (term, term_norm) in &target_terms_norm {
                let c = count_term_occurrences(&text_norm, term_norm);
                if c > 0 {
                    total += c;
                    via.get_or_insert_with(|| term.clone());
                }
            }
            // Include declared invariant coverage as an implicit mention edge.
            if note.role == "concept" {
                for inv in &note.invariants {
                    let key = norm_key(inv);
                    if key.is_empty() {
                        continue;
                    }
                    if term_to_target.get(&key) == Some(&target_norm) {
                        total += 1;
                        via.get_or_insert_with(|| inv.clone());
                        break;
                    }
                }
            }
            if total > 0 {
                implicit_from.push(serde_json::json!({
                    "source": note.name,
                    "source_role": note.role,
                    "path": note.rel_path,
                    "via": via.unwrap_or_else(|| target_norm.clone()),
                    "count": total
                }));
            }
        }
    }

    implicit_from.sort_by(|a, b| {
        let ca = a.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        let cb = b.get("count").and_then(|v| v.as_u64()).unwrap_or(0);
        cb.cmp(&ca).then_with(|| {
            let sa = a.get("source").and_then(|v| v.as_str()).unwrap_or("");
            let sb = b.get("source").and_then(|v| v.as_str()).unwrap_or("");
            sa.cmp(sb)
        })
    });
    explicit_from.sort_by(|a, b| {
        let sa = a.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let sb = b.get("source").and_then(|v| v.as_str()).unwrap_or("");
        sa.cmp(sb)
    });

    let payload = serde_json::json!({
        "title": "Backlinks",
        "vault": args.path.to_string_lossy(),
        "target": args.target,
        "target_normalized": target_norm,
        "mode": format!("{:?}", args.mode).to_lowercase(),
        "explicit_from": explicit_from,
        "implicit_from": implicit_from
    });

    write_output(&payload, args.format.json(), args.out.as_ref())?;
    Ok(())
}

fn write_output(
    payload: &serde_json::Value,
    json: bool,
    out: Option<&PathBuf>,
) -> Result<(), String> {
    let text = if json {
        serde_json::to_string_pretty(payload).map_err(|e| format!("json encode: {e}"))? + "\n"
    } else {
        // Markdown-ish: keep this readable, but JSON mode is the stable contract.
        let title = payload
            .get("title")
            .and_then(|v| v.as_str())
            .unwrap_or("Vault output");
        let vault = payload.get("vault").and_then(|v| v.as_str()).unwrap_or("");
        let mut lines: Vec<String> = Vec::new();
        lines.push(format!("# {title}"));
        if !vault.is_empty() {
            lines.push(String::new());
            lines.push(format!("- Vault: `{vault}`"));
        }
        lines.push(String::new());
        lines.push("```json".to_string());
        lines.push(serde_json::to_string_pretty(payload).map_err(|e| format!("json encode: {e}"))?);
        lines.push("```".to_string());
        lines.push(String::new());
        lines.join("\n")
    };

    if let Some(out_path) = out {
        fs::write(out_path, text).map_err(|e| format!("write {}: {e}", out_path.display()))?;
    } else {
        print!("{text}");
    }
    Ok(())
}

fn sha256_hex_bytes(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn extract_normative_lines(md: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut in_fence = false;
    for line in md.lines() {
        let t = line.trim_start();
        if t.starts_with("```") {
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        if t.contains("MUST NOT")
            || t.contains("MUST")
            || t.contains("SHALL NOT")
            || t.contains("SHALL")
        {
            out.push(line.trim().to_string());
        }
    }
    // Dedup.
    let mut seen: HashSet<String> = HashSet::new();
    out.into_iter().filter(|s| seen.insert(s.clone())).collect()
}

fn extract_summary(md: &str) -> Option<String> {
    let mut lines = md.lines().peekable();
    // Skip title + blanks.
    while let Some(line) = lines.peek() {
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            lines.next();
            continue;
        }
        break;
    }
    let mut para: Vec<String> = Vec::new();
    while let Some(line) = lines.next() {
        if line.trim().is_empty() {
            break;
        }
        para.push(line.trim().to_string());
    }
    if para.is_empty() {
        None
    } else {
        Some(para.join(" "))
    }
}

fn render_extracted_support_note(
    title: &str,
    source_kind: &str,
    source_path: &str,
    source_sha256: &str,
    summary: Option<String>,
    normative: Vec<String>,
) -> String {
    let mut out: Vec<String> = Vec::new();
    out.push("---".to_string());
    out.push("role: support".to_string());
    out.push("type: meta".to_string());
    out.push("generated: true".to_string());
    out.push("source_repo: irrev-compiler".to_string());
    out.push(format!("source_kind: {source_kind}"));
    out.push(format!("source_path: {source_path}"));
    out.push(format!("source_sha256: {source_sha256}"));
    out.push("---".to_string());
    out.push(String::new());
    out.push(format!("# {title}"));
    out.push(String::new());
    out.push(format!("> Source: `{source_path}`"));
    out.push(String::new());
    if let Some(summary) = summary {
        out.push("## Summary".to_string());
        out.push(String::new());
        out.push(summary);
        out.push(String::new());
    }
    if !normative.is_empty() {
        out.push("## Normative statements (extracted)".to_string());
        out.push(String::new());
        for line in normative {
            out.push(format!("- {line}"));
        }
        out.push(String::new());
    }
    out.push("## Notes".to_string());
    out.push(String::new());
    out.push("- This file is generated; edit the compiler source doc instead.".to_string());
    out.push(String::new());
    out.join("\n")
}

fn try_get_bool(fm: &BTreeMap<String, serde_json::Value>, key: &str) -> Option<bool> {
    fm.get(key).and_then(|v| v.as_bool())
}

fn run_docs_compiler_extract(args: VaultDocsCompilerExtractArgs) -> Result<(), String> {
    let vault_root = args.path.clone();
    let compiler_root = resolve_compiler_root(&vault_root, args.compiler_root.as_ref())?;
    let out_dir = args
        .out_dir
        .clone()
        .unwrap_or_else(|| vault_root.join("meta").join("compiler-docs"));

    let kinds: BTreeSet<String> = args.kinds.iter().map(|k| k.to_string()).collect();
    let mut sources: Vec<(String, PathBuf)> = Vec::new();
    collect_compiler_docs(&compiler_root, &kinds, &mut sources)?;

    let mut written = 0usize;
    let mut skipped = 0usize;
    let mut blocked = 0usize;

    for (kind, src_path) in sources {
        let rel_source = src_path
            .strip_prefix(&compiler_root)
            .map_err(|e| format!("source rel: {e}"))?
            .to_string_lossy()
            .replace('\\', "/");
        let bytes = fs::read(&src_path).map_err(|e| format!("read {rel_source}: {e}"))?;
        let src_sha = sha256_hex_bytes(&bytes);
        let src_text = String::from_utf8_lossy(&bytes).to_string();

        let title = extract_title(
            &src_text,
            src_path
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("Doc"),
        );
        let summary = extract_summary(&src_text);
        let normative = extract_normative_lines(&src_text);

        let out_path =
            out_path_for_source(&vault_root, &out_dir, &compiler_root, &kind, &src_path)?;

        if out_path.exists() && !args.force {
            let existing = fs::read_to_string(&out_path)
                .map_err(|e| format!("read {}: {e}", out_path.display()))?;
            let (fm, _body) = split_frontmatter(&existing);
            if try_get_bool(&fm, "generated") != Some(true) {
                blocked += 1;
                continue;
            }
            if extract_string(&fm, "source_repo").as_deref() != Some("irrev-compiler")
                || extract_string(&fm, "source_path").as_deref() != Some(&rel_source)
            {
                blocked += 1;
                continue;
            }
            if extract_string(&fm, "source_sha256").as_deref() == Some(&src_sha) {
                skipped += 1;
                continue;
            }
        }

        if args.dry_run {
            skipped += 1;
            continue;
        }

        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }

        let note =
            render_extracted_support_note(&title, &kind, &rel_source, &src_sha, summary, normative);
        fs::write(&out_path, note).map_err(|e| format!("write {}: {e}", out_path.display()))?;
        written += 1;
    }

    let payload = serde_json::json!({
        "command": "vault docs compiler-extract",
        "vault": vault_root.to_string_lossy(),
        "compiler_root": compiler_root.to_string_lossy(),
        "out_dir": out_dir.to_string_lossy(),
        "dry_run": args.dry_run,
        "force": args.force,
        "written": written,
        "skipped": skipped,
        "blocked": blocked
    });

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).map_err(|e| format!("json encode: {e}"))?
        );
    } else {
        println!(
            "compiler_extract written={} skipped={} blocked={} out_dir={}",
            written,
            skipped,
            blocked,
            out_dir.display()
        );
    }

    if blocked > 0 && !args.force {
        Err(format!(
            "{blocked} file(s) blocked (use --force to overwrite)"
        ))
    } else {
        Ok(())
    }
}

fn resolve_compiler_root(vault_root: &Path, cli_arg: Option<&PathBuf>) -> Result<PathBuf, String> {
    if let Some(p) = cli_arg {
        return Ok(p.clone());
    }
    // Primary: sibling `irrev-compiler` next to the vault root.
    for p in vault_root.ancestors() {
        if let Some(parent) = p.parent() {
            let candidate = parent.join("irrev-compiler");
            if candidate.is_dir() {
                return Ok(candidate);
            }
        }
    }
    // Fallback: current working directory, if it looks like the compiler root.
    if let Ok(cwd) = std::env::current_dir() {
        if cwd.join("Cargo.toml").exists() && cwd.join("crates").is_dir() {
            return Ok(cwd);
        }
    }
    Err("compiler root not found (pass --compiler-root)".to_string())
}

fn collect_compiler_docs(
    compiler_root: &Path,
    kinds: &BTreeSet<String>,
    out: &mut Vec<(String, PathBuf)>,
) -> Result<(), String> {
    let docs_root = compiler_root.join("docs");
    for kind in ["spec", "arch", "ideas", "status"] {
        if !kinds.contains(kind) {
            continue;
        }
        let base = docs_root.join(kind);
        if !base.exists() {
            continue;
        }
        let mut files: Vec<PathBuf> = Vec::new();
        collect_md_files(&base, &mut files).map_err(|e| e.to_string())?;
        files.sort();
        for f in files {
            out.push((kind.to_string(), f));
        }
    }

    if kinds.contains("meta") {
        let base = compiler_root.join("meta");
        if base.exists() {
            let mut files: Vec<PathBuf> = Vec::new();
            collect_md_files(&base, &mut files).map_err(|e| e.to_string())?;
            files.sort();
            for f in files {
                out.push(("meta".to_string(), f));
            }
        }
    }
    Ok(())
}

fn out_path_for_source(
    _vault_root: &Path,
    out_dir: &Path,
    compiler_root: &Path,
    _kind: &str,
    src: &Path,
) -> Result<PathBuf, String> {
    let rel = src
        .strip_prefix(compiler_root)
        .map_err(|e| format!("source rel: {e}"))?
        .to_string_lossy()
        .replace('\\', "/");
    let mut rel_out = rel.clone();
    if rel_out.starts_with("docs/") {
        rel_out = rel_out.trim_start_matches("docs/").to_string();
    } else if rel_out.starts_with("meta/") {
        rel_out = format!("compiler-meta/{}", rel_out.trim_start_matches("meta/"));
    }
    let out_path = out_dir.join(rel_out).with_extension("md");
    Ok(out_path)
}

// ---------------------------------------------------------------------------
// Vault: spines (Concept → Invariant mapping)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SpineId {
    Attribution,
    Governance,
    Decomposition,
    Irreversibility,
    Structural,
}

impl SpineId {
    fn as_str(self) -> &'static str {
        match self {
            SpineId::Attribution => "attribution",
            SpineId::Governance => "governance",
            SpineId::Decomposition => "decomposition",
            SpineId::Irreversibility => "irreversibility",
            SpineId::Structural => "structural",
        }
    }

    fn all_invariants() -> [SpineId; 4] {
        [
            SpineId::Governance,
            SpineId::Irreversibility,
            SpineId::Decomposition,
            SpineId::Attribution,
        ]
    }
}

fn spine_from_str(s: &str) -> Option<SpineId> {
    match s.trim().to_lowercase().as_str() {
        "attribution" => Some(SpineId::Attribution),
        "governance" => Some(SpineId::Governance),
        "decomposition" => Some(SpineId::Decomposition),
        "irreversibility" => Some(SpineId::Irreversibility),
        _ => None,
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct RefCounts {
    invariant: u32,
    diagnostic: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct ConceptEvidence {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    core_in: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    footprint_in: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    refs: BTreeMap<String, RefCounts>, // spine_id -> counts
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum ConceptTier {
    Core,
    Support,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum Confidence {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConceptSpineRow {
    id: String,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    layer: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    role_summary: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    depends_on: Vec<String>,
    primary_spine: String,
    tier: ConceptTier,
    confidence: Confidence,
    evidence: ConceptEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ConceptSpineIndex {
    generated: bool,
    generated_at_utc: String,
    vault_root: String,
    concepts: Vec<ConceptSpineRow>,
}

fn resolve_vault_root_for_spines(path: &Path) -> Result<PathBuf, String> {
    let p = if path.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        path.to_path_buf()
    };
    if p.join("concepts").is_dir() && p.join("invariants").is_dir() {
        return Ok(p);
    }
    let child = p.join("irrev-vault");
    if child.join("concepts").is_dir() && child.join("invariants").is_dir() {
        return Ok(child);
    }
    Err(format!(
        "vault root not found at {} (expected concepts/ and invariants/). Pass PATH as the vault root or a parent containing irrev-vault/.",
        p.display()
    ))
}

fn now_utc_rfc3339() -> String {
    // Keep this dependency-light: chrono is already in the workspace.
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn run_spines_generate(args: VaultSpinesGenerateArgs) -> Result<(), String> {
    let vault_root = resolve_vault_root_for_spines(&args.path)?;
    let out_yaml = args
        .out_yaml
        .clone()
        .unwrap_or_else(|| vault_root.join("meta").join("concept_spines.generated.yml"));
    let out_md = args.out_md.clone().unwrap_or_else(|| {
        vault_root
            .join("meta")
            .join("Concept Spine Index.generated.md")
    });

    let (index, md) = build_concept_spine_index_and_markdown(&vault_root)?;

    if args.dry_run {
        if args.json {
            let payload = serde_json::json!({
                "command": "vault spines generate",
                "vault_root": vault_root.to_string_lossy(),
                "out_yaml": out_yaml.to_string_lossy(),
                "out_md": out_md.to_string_lossy(),
                "dry_run": true,
                "concepts": index.concepts.len(),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).map_err(|e| format!("json encode: {e}"))?
            );
        } else {
            println!(
                "spines_generate dry_run=true concepts={} out_yaml={} out_md={}",
                index.concepts.len(),
                out_yaml.display(),
                out_md.display()
            );
        }
        return Ok(());
    }

    if !args.force {
        if out_yaml.exists() {
            return Err(format!(
                "refusing to overwrite existing file (use --force): {}",
                out_yaml.display()
            ));
        }
        if out_md.exists() {
            return Err(format!(
                "refusing to overwrite existing file (use --force): {}",
                out_md.display()
            ));
        }
    }

    if let Some(parent) = out_yaml.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    if let Some(parent) = out_md.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }

    let yaml = serde_yaml::to_string(&index).map_err(|e| format!("yaml encode: {e}"))?;
    fs::write(&out_yaml, yaml).map_err(|e| format!("write {}: {e}", out_yaml.display()))?;
    fs::write(&out_md, md).map_err(|e| format!("write {}: {e}", out_md.display()))?;

    if args.json {
        let payload = serde_json::json!({
            "command": "vault spines generate",
            "vault_root": vault_root.to_string_lossy(),
            "out_yaml": out_yaml.to_string_lossy(),
            "out_md": out_md.to_string_lossy(),
            "concepts": index.concepts.len(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).map_err(|e| format!("json encode: {e}"))?
        );
    } else {
        println!(
            "spines_generate concepts={} out_yaml={} out_md={}",
            index.concepts.len(),
            out_yaml.display(),
            out_md.display()
        );
    }
    Ok(())
}

fn run_spines_render(args: VaultSpinesRenderArgs) -> Result<(), String> {
    let vault_root = resolve_vault_root_for_spines(&args.path)?;
    let in_yaml = args
        .in_yaml
        .clone()
        .unwrap_or_else(|| vault_root.join("meta").join("concept_spines.generated.yml"));
    let out_md = args.out_md.clone().unwrap_or_else(|| {
        vault_root
            .join("meta")
            .join("Concept Spine Index.generated.md")
    });

    let yaml =
        fs::read_to_string(&in_yaml).map_err(|e| format!("read {}: {e}", in_yaml.display()))?;
    let mut index: ConceptSpineIndex =
        serde_yaml::from_str(&yaml).map_err(|e| format!("yaml decode: {e}"))?;
    index.generated_at_utc = now_utc_rfc3339();
    let md = render_concept_spine_markdown(&index);

    if args.dry_run {
        if args.json {
            let payload = serde_json::json!({
                "command": "vault spines render",
                "vault_root": vault_root.to_string_lossy(),
                "in_yaml": in_yaml.to_string_lossy(),
                "out_md": out_md.to_string_lossy(),
                "dry_run": true,
                "concepts": index.concepts.len(),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).map_err(|e| format!("json encode: {e}"))?
            );
        } else {
            println!(
                "spines_render dry_run=true concepts={} in_yaml={} out_md={}",
                index.concepts.len(),
                in_yaml.display(),
                out_md.display()
            );
        }
        return Ok(());
    }

    if !args.force && out_md.exists() {
        return Err(format!(
            "refusing to overwrite existing file (use --force): {}",
            out_md.display()
        ));
    }

    if let Some(parent) = out_md.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    fs::write(&out_md, md).map_err(|e| format!("write {}: {e}", out_md.display()))?;

    if args.json {
        let payload = serde_json::json!({
            "command": "vault spines render",
            "vault_root": vault_root.to_string_lossy(),
            "in_yaml": in_yaml.to_string_lossy(),
            "out_md": out_md.to_string_lossy(),
            "concepts": index.concepts.len(),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).map_err(|e| format!("json encode: {e}"))?
        );
    } else {
        println!(
            "spines_render concepts={} out_md={}",
            index.concepts.len(),
            out_md.display()
        );
    }
    Ok(())
}

fn run_spines_audit(args: VaultSpinesAuditArgs) -> Result<(), String> {
    let vault_root = resolve_vault_root_for_spines(&args.path)?;
    let report = build_spines_audit_report(&vault_root, args.format.json())?;

    if let Some(out) = args.out.as_ref() {
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        fs::write(out, report).map_err(|e| format!("write {}: {e}", out.display()))?;
        if !args.format.json() {
            println!("spines_audit wrote={}", out.display());
        }
        Ok(())
    } else {
        println!("{}", report);
        Ok(())
    }
}

fn build_concept_spine_index_and_markdown(
    vault_root: &Path,
) -> Result<(ConceptSpineIndex, String), String> {
    let concepts_dir = vault_root.join("concepts");
    let invariants_dir = vault_root.join("invariants");
    let diagnostics_dir = vault_root.join("diagnostics");

    let concepts = load_vault_notes(&concepts_dir)?
        .into_iter()
        .filter(|n| n.role == "concept")
        .collect::<Vec<_>>();

    let invariants = load_vault_notes(&invariants_dir)?
        .into_iter()
        .filter(|n| n.role == "invariant")
        .collect::<Vec<_>>();

    let diagnostics = if diagnostics_dir.exists() {
        load_vault_notes(&diagnostics_dir)?
            .into_iter()
            .filter(|n| n.role == "diagnostic")
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };

    let concept_key_to_id = build_concept_key_map(&concepts);

    // Core concepts: extracted from each invariant's "Minimal decomposition" section.
    let mut core_by_spine: BTreeMap<SpineId, BTreeSet<String>> = BTreeMap::new();
    for inv in &invariants {
        let Some(inv_id) = inv.invariant_id.as_deref() else {
            continue;
        };
        let Some(spine) = spine_from_str(inv_id) else {
            continue;
        };
        let links = extract_minimal_decomposition_concept_ids(&inv.body, &concept_key_to_id);
        core_by_spine
            .entry(spine)
            .or_default()
            .extend(links.into_iter());
    }

    // Footprint concepts: extracted from each invariant's "Structural footprint" section.
    let mut footprint_by_spine: BTreeMap<SpineId, BTreeSet<String>> = BTreeMap::new();
    for inv in &invariants {
        let Some(inv_id) = inv.invariant_id.as_deref() else {
            continue;
        };
        let Some(spine) = spine_from_str(inv_id) else {
            continue;
        };
        let links = extract_structural_footprint_concept_ids(&inv.body, &concept_key_to_id);
        footprint_by_spine
            .entry(spine)
            .or_default()
            .extend(links.into_iter());
    }

    // Reference counts: explicit wikilinks found in invariant and diagnostic notes.
    let mut refs: BTreeMap<String, BTreeMap<SpineId, RefCounts>> = BTreeMap::new();

    for inv in &invariants {
        let Some(inv_id) = inv.invariant_id.as_deref() else {
            continue;
        };
        let Some(spine) = spine_from_str(inv_id) else {
            continue;
        };
        for concept_id in extract_concept_refs(&inv.body, &concept_key_to_id) {
            refs.entry(concept_id)
                .or_default()
                .entry(spine)
                .or_default()
                .invariant += 1;
        }
    }

    for d in &diagnostics {
        let spine = diagnostic_spine_from_rel_path(&d.rel_path);
        for concept_id in extract_concept_refs(&d.body, &concept_key_to_id) {
            refs.entry(concept_id)
                .or_default()
                .entry(spine)
                .or_default()
                .diagnostic += 1;
        }
    }

    let mut rows: Vec<ConceptSpineRow> = Vec::new();
    for c in &concepts {
        let id = c.name.clone();
        let title = c.title.clone();
        // Re-read concept files for accurate frontmatter fields (VaultNote stores only a subset).
        let layer = concept_layer_from_file(&concepts_dir, &id).ok().flatten();
        let role_summary = extract_registry_role_summary(c);
        let depends_on = extract_structural_dependency_ids(&c.body, &concept_key_to_id, &id);

        let core_in = SpineId::all_invariants()
            .iter()
            .filter_map(|sp| {
                if core_by_spine
                    .get(sp)
                    .map(|set| set.contains(&id))
                    .unwrap_or(false)
                {
                    Some(sp.as_str().to_string())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let footprint_in = SpineId::all_invariants()
            .iter()
            .filter_map(|sp| {
                if footprint_by_spine
                    .get(sp)
                    .map(|set| set.contains(&id))
                    .unwrap_or(false)
                {
                    Some(sp.as_str().to_string())
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        let counts = refs.get(&id).cloned().unwrap_or_default();
        let (primary_spine, confidence) = infer_primary_spine(&core_in, &counts)
            .unwrap_or((SpineId::Structural, Confidence::Low));

        let tier = if core_in.len() == 1 {
            ConceptTier::Core
        } else {
            ConceptTier::Support
        };

        let mut refs_out: BTreeMap<String, RefCounts> = BTreeMap::new();
        for (sp, cts) in &counts {
            refs_out.insert(sp.as_str().to_string(), cts.clone());
        }

        rows.push(ConceptSpineRow {
            id,
            title,
            layer,
            role_summary,
            depends_on,
            primary_spine: primary_spine.as_str().to_string(),
            tier,
            confidence,
            evidence: ConceptEvidence {
                core_in,
                footprint_in,
                refs: refs_out,
            },
        });
    }

    rows.sort_by(|a, b| a.id.cmp(&b.id));

    let index = ConceptSpineIndex {
        generated: true,
        generated_at_utc: now_utc_rfc3339(),
        vault_root: vault_root.to_string_lossy().replace('\\', "/"),
        concepts: rows,
    };

    let md = render_concept_spine_markdown(&index);
    Ok((index, md))
}

fn build_concept_key_map(concepts: &[VaultNote]) -> HashMap<String, String> {
    let mut map: HashMap<String, String> = HashMap::new();
    for c in concepts {
        let id = c.name.clone();
        for k in concept_keys(c) {
            map.entry(k).or_insert_with(|| id.clone());
        }
    }
    map
}

fn concept_keys(note: &VaultNote) -> BTreeSet<String> {
    let mut keys = BTreeSet::new();
    let name = note.name.trim().to_lowercase();
    let title = note.title.trim().to_lowercase();
    let slug = oa::obsidian_heading_slug(&note.title);

    for base in [name.as_str(), title.as_str(), slug.as_str()] {
        if base.is_empty() {
            continue;
        }
        keys.insert(base.to_string());
        keys.insert(base.replace('-', " "));
        keys.insert(base.replace(' ', "-"));
    }

    for a in &note.aliases {
        let a = a.trim();
        if a.is_empty() {
            continue;
        }
        let low = a.to_lowercase();
        let slug = oa::obsidian_heading_slug(a);
        for base in [low.as_str(), slug.as_str()] {
            keys.insert(base.to_string());
            keys.insert(base.replace('-', " "));
            keys.insert(base.replace(' ', "-"));
        }
    }
    keys
}

fn extract_concept_refs(body: &str, concept_key_to_id: &HashMap<String, String>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for link in oa::extract_obsidian_links(body) {
        let target = normalize_obsidian_target_to_key(&link.target);
        if let Some(id) = resolve_concept_id(&target, concept_key_to_id) {
            out.push(id);
        }
    }
    out
}

fn resolve_concept_id(
    target_key: &str,
    concept_key_to_id: &HashMap<String, String>,
) -> Option<String> {
    if let Some(id) = concept_key_to_id.get(target_key) {
        return Some(id.clone());
    }
    // Try slugging as a fallback.
    let slug = oa::obsidian_heading_slug(target_key);
    if let Some(id) = concept_key_to_id.get(&slug) {
        return Some(id.clone());
    }
    None
}

fn extract_minimal_decomposition_concept_ids(
    body: &str,
    concept_key_to_id: &HashMap<String, String>,
) -> BTreeSet<String> {
    let slice = minimal_decomposition_slice(body);
    extract_concept_refs(&slice, concept_key_to_id)
        .into_iter()
        .collect()
}

fn minimal_decomposition_slice(body: &str) -> String {
    let mut start: Option<usize> = None;
    let mut end: Option<usize> = None;
    let lines: Vec<&str> = body.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim_start();
        if t.starts_with("## Minimal decomposition") {
            start = Some(i + 1);
            continue;
        }
        if start.is_some() && t.starts_with("## ") {
            end = Some(i);
            break;
        }
    }
    let s = start.unwrap_or(0);
    let e = end.unwrap_or(lines.len());
    lines[s..e].join("\n")
}

fn extract_structural_footprint_concept_ids(
    body: &str,
    concept_key_to_id: &HashMap<String, String>,
) -> BTreeSet<String> {
    let slice = structural_footprint_slice(body);
    extract_concept_refs(&slice, concept_key_to_id)
        .into_iter()
        .collect()
}

fn structural_footprint_slice(body: &str) -> String {
    let mut start: Option<usize> = None;
    let mut end: Option<usize> = None;
    let lines: Vec<&str> = body.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim_start();
        let t_lower = t.to_lowercase();
        if t_lower.starts_with("## structural footprint") {
            start = Some(i + 1);
            continue;
        }
        if start.is_some() && t.starts_with("## ") {
            end = Some(i);
            break;
        }
    }
    match start {
        Some(s) => {
            let e = end.unwrap_or(lines.len());
            lines[s..e].join("\n")
        }
        None => String::new(),
    }
}

fn diagnostic_spine_from_rel_path(rel_path: &str) -> SpineId {
    // When we load notes relative to `<vault>/diagnostics`, rel_path is like:
    //   "attribution/Diagnostic Checklist.md" (spine-specific)
    // or "Domain Template.md" (shared structural diagnostic apparatus).
    let spine = rel_path.split('/').next().unwrap_or_default();
    spine_from_str(spine).unwrap_or(SpineId::Structural)
}

fn infer_primary_spine(
    core_in: &[String],
    counts: &BTreeMap<SpineId, RefCounts>,
) -> Option<(SpineId, Confidence)> {
    if core_in.len() == 1 {
        return spine_from_str(&core_in[0]).map(|s| (s, Confidence::High));
    }

    let mut totals: Vec<(SpineId, u32)> = SpineId::all_invariants()
        .iter()
        .map(|sp| {
            let c = counts.get(sp).cloned().unwrap_or_default();
            (*sp, c.invariant + c.diagnostic)
        })
        .collect();
    totals.sort_by(|a, b| b.1.cmp(&a.1));

    let (best_sp, best) = totals.first().copied()?;
    if best == 0 {
        return Some((SpineId::Structural, Confidence::Low));
    }
    let second = totals.get(1).map(|x| x.1).unwrap_or(0);
    if second == 0 {
        return Some((best_sp, Confidence::Medium));
    }
    Some((SpineId::Structural, Confidence::Low))
}

fn concept_layer_from_file(
    concepts_dir: &Path,
    concept_id: &str,
) -> Result<Option<String>, String> {
    let path = concepts_dir.join(format!("{concept_id}.md"));
    let bytes = fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let content = String::from_utf8_lossy(&bytes).to_string();
    let (fm, _body) = split_frontmatter(&content);
    Ok(extract_string(&fm, "layer"))
}

fn extract_structural_dependency_ids(
    body: &str,
    concept_key_to_id: &HashMap<String, String>,
    concept_id: &str,
) -> Vec<String> {
    let Some(section) = extract_h2_section(body, "Structural dependencies") else {
        return Vec::new();
    };
    if section.is_empty() || has_none_primitive_marker(&section) {
        return Vec::new();
    }
    let mut deps: BTreeSet<String> = BTreeSet::new();
    for link in oa::extract_obsidian_links(&section) {
        let target_key = normalize_obsidian_target_to_key(&link.target);
        if let Some(dep_id) = resolve_concept_id(&target_key, concept_key_to_id) {
            if dep_id != concept_id {
                deps.insert(dep_id);
            }
        }
    }
    deps.into_iter().collect()
}

fn extract_registry_role_summary(note: &VaultNote) -> String {
    for key in ["description", "summary", "blurb"] {
        if let Some(raw) = extract_string(&note.frontmatter, key) {
            let cleaned = clean_registry_cell_text(&raw);
            if !cleaned.is_empty() {
                return truncate_with_ellipsis(cleaned, 140);
            }
        }
    }

    for heading in ["Definition", "Summary"] {
        if let Some(paragraph) = first_paragraph_under_h2(&note.body, heading) {
            let cleaned = clean_registry_cell_text(&paragraph);
            if !cleaned.is_empty() {
                let first_sentence = cleaned
                    .split('.')
                    .next()
                    .map(str::trim)
                    .unwrap_or_default()
                    .to_string();
                if !first_sentence.is_empty() && first_sentence.len() <= 140 {
                    return first_sentence;
                }
                return truncate_with_ellipsis(cleaned, 140);
            }
        }
    }

    if let Some(paragraph) = first_body_paragraph(&note.body) {
        let cleaned = clean_registry_cell_text(&paragraph);
        if !cleaned.is_empty() {
            return truncate_with_ellipsis(cleaned, 140);
        }
    }

    note.name.replace('-', " ")
}

fn first_paragraph_under_h2(body: &str, heading: &str) -> Option<String> {
    let wanted = format!("## {}", heading).to_lowercase();
    let lines: Vec<&str> = body.lines().collect();
    let mut start: Option<usize> = None;
    let mut end: Option<usize> = None;
    for (idx, line) in lines.iter().enumerate() {
        let t = line.trim_start().to_lowercase();
        if t == wanted {
            start = Some(idx + 1);
            continue;
        }
        if start.is_some() && t.starts_with("## ") {
            end = Some(idx);
            break;
        }
    }
    let s = start?;
    let e = end.unwrap_or(lines.len());
    let section = lines[s..e].join("\n");
    for paragraph in section.split("\n\n") {
        let candidate = paragraph.trim();
        if candidate.is_empty() {
            continue;
        }
        if candidate.starts_with('>') {
            continue;
        }
        return Some(candidate.to_string());
    }
    None
}

fn first_body_paragraph(body: &str) -> Option<String> {
    let mut current: Vec<String> = Vec::new();
    let mut paragraphs: Vec<String> = Vec::new();
    for line in body.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('#') {
            continue;
        }
        if trimmed.is_empty() {
            if !current.is_empty() {
                paragraphs.push(current.join(" "));
                current.clear();
            }
            continue;
        }
        current.push(trimmed.to_string());
    }
    if !current.is_empty() {
        paragraphs.push(current.join(" "));
    }
    for paragraph in paragraphs {
        let candidate = paragraph.trim();
        if candidate.is_empty() || candidate.starts_with('>') {
            continue;
        }
        return Some(candidate.to_string());
    }
    None
}

fn clean_registry_cell_text(input: &str) -> String {
    let no_links = strip_obsidian_wikilinks(input);
    let no_md = strip_inline_markdown(&no_links);
    let normalized = normalize_common_mojibake(&no_md);
    let compact = collapse_ws(&normalized);
    compact.replace('|', "\\|").trim().to_string()
}

fn strip_obsidian_wikilinks(input: &str) -> String {
    let mut out = input.to_string();
    for link in oa::extract_obsidian_links(input) {
        let display = link.alias.clone().unwrap_or_else(|| link.target.clone());
        out = out.replace(&link.raw, &display);
    }
    out
}

fn normalize_common_mojibake(input: &str) -> String {
    input
        .replace("â€œ", "\"")
        .replace("â€", "\"")
        .replace("â€˜", "'")
        .replace("â€™", "'")
        .replace("â€”", "-")
        .replace("â€“", "-")
        .replace("â€¦", "...")
}

fn strip_inline_markdown(input: &str) -> String {
    input
        .replace("**", "")
        .replace('*', "")
        .replace('`', "")
        .replace("[!note]", "")
        .replace("[!warning]", "")
        .replace("[!info]", "")
}

fn collapse_ws(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut prev_space = false;
    for ch in input.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                out.push(' ');
            }
            prev_space = true;
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    out.trim().to_string()
}

fn truncate_with_ellipsis(mut input: String, max_chars: usize) -> String {
    if input.chars().count() <= max_chars {
        return input;
    }
    input = input.chars().take(max_chars.saturating_sub(3)).collect();
    input.push_str("...");
    input
}

fn concept_link(concept_id: &str) -> String {
    format!("[{}](#{})", concept_id, concept_anchor_id(concept_id))
}

fn concept_link_with_layer(row: &ConceptSpineRow) -> String {
    let layer = row.layer.as_deref().unwrap_or("unclassified");
    format!("{} (layer: {})", concept_link(&row.id), layer)
}

fn registry_layer_label(layer: Option<&str>) -> String {
    let low = layer.unwrap_or("unknown").trim().to_lowercase();
    for (label, keys) in BOOK_LAYER_ORDER {
        if keys.iter().any(|k| low == *k) {
            return (*label).to_string();
        }
    }
    format!(
        "Unclassified ({})",
        if low.is_empty() { "unknown" } else { &low }
    )
}

fn render_dependency_classes_by_layer(index: &ConceptSpineIndex, out: &mut String) {
    let mut by_layer: BTreeMap<String, Vec<&ConceptSpineRow>> = BTreeMap::new();
    for concept in &index.concepts {
        by_layer
            .entry(registry_layer_label(concept.layer.as_deref()))
            .or_default()
            .push(concept);
    }

    for rows in by_layer.values_mut() {
        rows.sort_by(|a, b| a.id.cmp(&b.id));
    }

    for (label, _keys) in BOOK_LAYER_ORDER {
        let Some(rows) = by_layer.remove(*label) else {
            continue;
        };
        out.push_str(&format!("### Concepts :: {label}\n\n"));
        let concepts = rows.iter().map(|c| concept_link(&c.id)).collect::<Vec<_>>();
        out.push_str(&format!("- concept count: {}\n", concepts.len()));
        for chunk in concepts.chunks(8) {
            out.push_str(&format!("- {}\n", chunk.join(", ")));
        }
        out.push('\n');
    }

    for (label, rows) in by_layer {
        out.push_str(&format!("### Concepts :: {label}\n\n"));
        let concepts = rows.iter().map(|c| concept_link(&c.id)).collect::<Vec<_>>();
        out.push_str(&format!("- concept count: {}\n", concepts.len()));
        for chunk in concepts.chunks(8) {
            out.push_str(&format!("- {}\n", chunk.join(", ")));
        }
        out.push('\n');
    }
}

fn render_invariant_spine_index(index: &ConceptSpineIndex, out: &mut String) {
    let mut by_spine: BTreeMap<String, Vec<&ConceptSpineRow>> = BTreeMap::new();
    for c in &index.concepts {
        by_spine.entry(c.primary_spine.clone()).or_default().push(c);
    }

    let mut footprint_by_spine: BTreeMap<String, Vec<&ConceptSpineRow>> = BTreeMap::new();
    for c in &index.concepts {
        for fp_spine in &c.evidence.footprint_in {
            let is_core_or_support = c.primary_spine == *fp_spine
                && (matches!(c.tier, ConceptTier::Core)
                    || (matches!(c.tier, ConceptTier::Support)
                        && c.evidence
                            .refs
                            .get(fp_spine)
                            .map(|r| r.invariant + r.diagnostic > 0)
                            .unwrap_or(false)));
            if !is_core_or_support {
                footprint_by_spine
                    .entry(fp_spine.clone())
                    .or_default()
                    .push(c);
            }
        }
    }

    for spine in SpineId::all_invariants()
        .iter()
        .map(|s| s.as_str().to_string())
        .collect::<Vec<_>>()
    {
        out.push_str(&format!("### {}\n\n", spine));
        let items = by_spine.get(&spine).cloned().unwrap_or_default();
        let mut core: Vec<&ConceptSpineRow> = items
            .iter()
            .copied()
            .filter(|r| matches!(r.tier, ConceptTier::Core))
            .collect();
        let mut support: Vec<&ConceptSpineRow> = items
            .iter()
            .copied()
            .filter(|r| matches!(r.tier, ConceptTier::Support))
            .collect();
        core.sort_by(|a, b| a.id.cmp(&b.id));
        support.sort_by(|a, b| a.id.cmp(&b.id));

        out.push_str("#### Core\n\n");
        if core.is_empty() {
            out.push_str("- (none)\n");
        } else {
            for c in core {
                out.push_str(&format!("- {}\n", concept_link_with_layer(c)));
            }
        }

        out.push_str("\n#### Footprint\n\n");
        let mut footprint: Vec<&ConceptSpineRow> =
            footprint_by_spine.get(&spine).cloned().unwrap_or_default();
        footprint.sort_by(|a, b| a.id.cmp(&b.id));
        if footprint.is_empty() {
            out.push_str("- (none)\n");
        } else {
            for c in footprint {
                out.push_str(&format!("- {}\n", concept_link_with_layer(c)));
            }
        }

        out.push_str("\n#### Support\n\n");
        if support.is_empty() {
            out.push_str("- (none)\n\n");
        } else {
            for c in support {
                let refs = c.evidence.refs.get(&spine);
                let inv = refs.map(|r| r.invariant).unwrap_or(0);
                let diag = refs.map(|r| r.diagnostic).unwrap_or(0);
                let layer = c.layer.as_deref().unwrap_or("unclassified");
                out.push_str(&format!(
                    "- {} (inv={}, diag={}, layer={})\n",
                    concept_link(&c.id),
                    inv,
                    diag,
                    layer
                ));
            }
            out.push('\n');
        }
    }

    let structural = by_spine.get("structural").cloned().unwrap_or_default();
    out.push_str("### structural\n\n");
    if structural.is_empty() {
        out.push_str("- (none)\n");
    } else {
        for c in structural {
            let mut nonzero: Vec<String> = Vec::new();
            for sp in SpineId::all_invariants() {
                let key = sp.as_str();
                let Some(ct) = c.evidence.refs.get(key) else {
                    continue;
                };
                if ct.invariant + ct.diagnostic > 0 {
                    nonzero.push(format!(
                        "{key}: inv={}, diag={}",
                        ct.invariant, ct.diagnostic
                    ));
                }
            }
            let evidence = if nonzero.is_empty() {
                "unreferenced by invariants/diagnostics".to_string()
            } else {
                nonzero.join("; ")
            };
            out.push_str(&format!("- {} ({})\n", concept_link(&c.id), evidence));
        }
    }
}

fn render_concept_spine_markdown(index: &ConceptSpineIndex) -> String {
    let mut out = String::new();
    out.push_str("---\n");
    out.push_str("role: support\n");
    out.push_str("type: index\n");
    out.push_str("generated: true\n");
    out.push_str(&format!("generated_at_utc: {}\n", index.generated_at_utc));
    out.push_str("---\n\n");
    out.push_str("# Concept -> Spine Index (Generated)\n\n");
    out.push_str(&format!(
        "- Vault: `{}`\n- Concepts: `{}`\n\n",
        index.vault_root,
        index.concepts.len()
    ));
    out.push_str("> [!note]\n");
    out.push_str("> Orientation: Registry of dependency classes and boundaries. Canonical definitions live in `/concepts`; invariant and diagnostic references are evidence overlays.\n\n");
    out.push_str("Directionality: This registry points to `/concepts` (definitions) plus invariants/diagnostics evidence; it does not import templates, examples, or domain notes.\n\n");

    out.push_str("## Core question\n\n");
    out.push_str(
        "- What persistent differences is this system producing, and who is carrying them?\n\n",
    );

    out.push_str("## Dependency classes (by layer)\n\n");
    out.push_str("> [!note]\n");
    out.push_str("> Scope: Higher layers assume lower layers. This grouping does not imply reading order.\n\n");
    render_dependency_classes_by_layer(index, &mut out);

    out.push_str("## Invariant spine index\n\n");
    render_invariant_spine_index(index, &mut out);
    out.push_str("\n\n");

    out.push_str("## Operator (diagnostic sequence)\n\n");
    out.push_str("1. What differences is this system producing?\n");
    out.push_str(&format!(
        "2. Which persist under the declared {}?\n",
        concept_link("transformation-space")
    ));
    out.push_str(&format!(
        "3. What would removal require? ({} check)\n",
        concept_link("erasure-cost")
    ));
    out.push_str(&format!(
        "4. Where is removal work landing? ({} / {} check)\n",
        concept_link("displacement"),
        concept_link("absorption")
    ));
    out.push_str(&format!(
        "5. For whom is this irreversible? ({})\n",
        concept_link("persistence-gradient")
    ));
    out.push_str(&format!(
        "6. Where do accumulated effects eliminate options? ({} -> {})\n\n",
        concept_link("constraint-load"),
        concept_link("collapse-surface")
    ));
    out.push_str(&format!(
        "If steps 2-6 cannot be stated within a declared transformation space, the output is consistent with {}.\n\n",
        concept_link("accounting-failure")
    ));

    out.push_str("## Scope conditions\n\n");
    out.push_str("> [!warning]\n");
    out.push_str(
        "> Validity limit: Apply the lens only within an explicit transformation space and time window.\n\n",
    );
    out.push_str("The lens applies where:\n");
    out.push_str(&format!(
        "- {} accumulates faster than local {} can unwind.\n",
        concept_link("persistent-difference"),
        concept_link("rollback")
    ));
    out.push_str(&format!(
        "- marginal {} dominates marginal action capacity.\n\n",
        concept_link("erasure-cost")
    ));
    out.push_str("The lens does not apply where:\n");
    out.push_str("- effects are local, ephemeral, and symmetric.\n");
    out.push_str(&format!(
        "- {} is cheap, immediate, and coordination-free.\n",
        concept_link("rollback")
    ));
    out.push_str("- activity is exploratory or non-binding (no downstream commitments form).\n\n");

    out.push_str("## Boundaries (distinctions)\n\n");
    out.push_str("| Distinction | Prevents conflating |\n");
    out.push_str("|---|---|\n");
    out.push_str("| Diagnostic vs normative | revealing failure vs judging failure |\n");
    out.push_str("| Constrains vs generates | limiting explanations vs producing explanations |\n");
    out.push_str("| Behavior vs persistence | what happens vs what remains after |\n");
    out.push_str("| Local correction vs global options | fixed here vs restored everywhere |\n");
    out.push_str("| Practical vs metaphysical | operational tests vs ontological claims |\n\n");

    out.push_str("## Declared relations (non-exhaustive)\n\n");
    out.push_str("> [!note]\n");
    out.push_str(
        "> Non-claim: This is a structural dependency list, not a proof or a complete model.\n\n",
    );
    out.push_str(&format!(
        "1. {} is relative to {}.\n",
        concept_link("persistent-difference"),
        concept_link("transformation-space")
    ));
    out.push_str(&format!(
        "2. {} is the operational test for {}.\n",
        concept_link("erasure-cost"),
        concept_link("persistent-difference")
    ));
    out.push_str(&format!(
        "3. {} makes \"undo later\" structurally unreliable under scale.\n",
        concept_link("erasure-asymmetry")
    ));
    out.push_str(&format!(
        "4. {} without {} is consistent with {}.\n",
        concept_link("displacement"),
        concept_link("tracking-mechanism"),
        concept_link("accounting-failure")
    ));
    out.push_str(&format!(
        "5. {} is consistent with {} and rising {}.\n",
        concept_link("accounting-failure"),
        concept_link("constraint-accumulation"),
        concept_link("constraint-load")
    ));
    out.push_str(&format!(
        "6. Accumulated constraints are consistent with {} or {} under perturbation.\n",
        concept_link("brittleness"),
        concept_link("saturation")
    ));
    out.push_str(&format!(
        "7. {} describes conditional boundaries where options disappear.\n\n",
        concept_link("collapse-surface")
    ));

    out.push_str("## Related\n\n");
    out.push_str("- Irreversibility Accounting (Paper)\n");
    out.push_str("- Irreversibility Accounting (Open Questions)\n");
    out
}

fn build_spines_audit_report(vault_root: &Path, json: bool) -> Result<String, String> {
    let (index, _md) = build_concept_spine_index_and_markdown(vault_root)?;

    let mut zero_refs: Vec<&ConceptSpineRow> = Vec::new();
    let mut structural_only: Vec<&ConceptSpineRow> = Vec::new();
    let mut ambiguous: Vec<&ConceptSpineRow> = Vec::new();
    for c in &index.concepts {
        let mut total = 0u32;
        let mut nonzero_spines = 0u32;
        let mut nonzero_invariants = 0u32;
        for sp in SpineId::all_invariants() {
            if let Some(ct) = c.evidence.refs.get(sp.as_str()) {
                let v = ct.invariant + ct.diagnostic;
                if v > 0 {
                    nonzero_spines += 1;
                    nonzero_invariants += 1;
                }
                total += v;
            }
        }
        if total == 0 {
            zero_refs.push(c);
        }
        if nonzero_spines > 1 {
            ambiguous.push(c);
        }
        if nonzero_invariants == 0 {
            if let Some(ct) = c.evidence.refs.get(SpineId::Structural.as_str()) {
                if ct.invariant + ct.diagnostic > 0 {
                    structural_only.push(c);
                }
            }
        }
    }

    // Name collisions: duplicate file stems across the entire vault can cause link ambiguity.
    let notes = load_vault_notes(vault_root)?;
    let mut collisions: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut counts: HashMap<String, usize> = HashMap::new();
    for n in &notes {
        *counts.entry(norm_key(&n.name)).or_insert(0) += 1;
    }
    for n in &notes {
        let k = norm_key(&n.name);
        if counts.get(&k).copied().unwrap_or(0) > 1 {
            collisions.entry(k).or_default().push(n.rel_path.clone());
        }
    }

    if json {
        let payload = serde_json::json!({
            "command": "vault spines audit",
            "vault_root": vault_root.to_string_lossy(),
            "concepts": index.concepts.len(),
            "concepts_zero_refs_in_inv_diag": zero_refs.len(),
            "concepts_structural_only_refs": structural_only.len(),
            "concepts_ambiguous_multi_spine_refs": ambiguous.len(),
            "name_collisions": collisions,
        });
        return serde_json::to_string_pretty(&payload).map_err(|e| format!("json encode: {e}"));
    }

    let mut out = String::new();
    out.push_str("# Spine Audit\n\n");
    out.push_str(&format!("- Vault: `{}`\n", index.vault_root));
    out.push_str(&format!("- Concepts: `{}`\n", index.concepts.len()));
    out.push_str(&format!(
        "- Concepts with zero invariant/diagnostic refs: `{}`\n",
        zero_refs.len()
    ));
    out.push_str(&format!(
        "- Concepts referenced only by structural diagnostics: `{}`\n",
        structural_only.len()
    ));
    out.push_str(&format!(
        "- Concepts referenced by multiple spines (ambiguous): `{}`\n\n",
        ambiguous.len()
    ));

    if !zero_refs.is_empty() {
        out.push_str("## Zero refs (inv/diag)\n\n");
        for c in zero_refs {
            out.push_str(&format!("- [[{}]]\n", c.id));
        }
        out.push('\n');
    }

    if !structural_only.is_empty() {
        out.push_str("## Structural-only refs\n\n");
        for c in structural_only {
            let ct = c
                .evidence
                .refs
                .get(SpineId::Structural.as_str())
                .cloned()
                .unwrap_or_default();
            out.push_str(&format!(
                "- [[{}]] (structural: inv={}, diag={})\n",
                c.id, ct.invariant, ct.diagnostic
            ));
        }
        out.push('\n');
    }

    if !ambiguous.is_empty() {
        out.push_str("## Ambiguous (multi-spine)\n\n");
        for c in ambiguous {
            let mut parts: Vec<String> = Vec::new();
            for sp in SpineId::all_invariants() {
                let key = sp.as_str();
                let Some(ct) = c.evidence.refs.get(key) else {
                    continue;
                };
                let v = ct.invariant + ct.diagnostic;
                if v > 0 {
                    parts.push(format!(
                        "{key}: inv={}, diag={}",
                        ct.invariant, ct.diagnostic
                    ));
                }
            }
            out.push_str(&format!("- [[{}]] ({})\n", c.id, parts.join("; ")));
        }
        out.push('\n');
    }

    if !collisions.is_empty() {
        out.push_str("## Name collisions\n\n");
        out.push_str(
            "Duplicate file stems can make `[[wikilinks]]` resolve ambiguously in Obsidian.\n\n",
        );
        for (k, paths) in collisions {
            out.push_str(&format!("- `{}`\n", k));
            for p in paths {
                out.push_str(&format!("  - `{}`\n", p));
            }
        }
        out.push('\n');
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Vault: concept book (linearized dependency order)
// ---------------------------------------------------------------------------

const BOOK_LAYER_ORDER: &[(&str, &[&str])] = &[
    ("Primitives", &["primitive", "foundational"]),
    ("First-order composites", &["first-order"]),
    ("Mechanisms", &["mechanism"]),
    ("Accounting", &["accounting"]),
    ("Failure states", &["failure-state"]),
    ("Diagnostic apparatus", &["selector", "meta-analytical"]),
];

fn resolve_vault_root_for_book(path: &Path) -> Result<PathBuf, String> {
    let p = if path.as_os_str().is_empty() {
        PathBuf::from(".")
    } else {
        path.to_path_buf()
    };
    if p.join("concepts").is_dir() {
        return Ok(p);
    }
    let child = p.join("irrev-vault");
    if child.join("concepts").is_dir() {
        return Ok(child);
    }
    Err(format!(
        "vault root not found at {} (expected concepts/). Pass PATH as the vault root or a parent containing irrev-vault/.",
        p.display()
    ))
}

fn default_book_export_dir(vault_root: &Path) -> PathBuf {
    vault_root.join("plans").join("book")
}

fn default_book_out_path(vault_root: &Path, format: VaultBookOutputFormat) -> PathBuf {
    let file = match format {
        VaultBookOutputFormat::Markdown => "irrev-book.md",
        VaultBookOutputFormat::Latex => "irrev-book.tex",
        VaultBookOutputFormat::Pdf => "irrev-book.pdf",
    };
    default_book_export_dir(vault_root).join(file)
}

fn is_concept_note(note: &VaultNote) -> bool {
    note.role == "concept" && note.rel_path.starts_with("concepts/")
}

fn extract_h2_section(body: &str, header: &str) -> Option<String> {
    let want = format!("## {}", header);
    let mut start: Option<usize> = None;
    let mut end: Option<usize> = None;
    let lines: Vec<&str> = body.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim_start();
        if t.trim_end() == want {
            start = Some(i + 1);
            continue;
        }
        if start.is_some() && t.starts_with("## ") {
            end = Some(i);
            break;
        }
    }
    let s = start?;
    let e = end.unwrap_or(lines.len());
    Some(lines[s..e].join("\n").trim().to_string())
}

fn has_none_primitive_marker(section: &str) -> bool {
    let low = section.to_lowercase();
    low.contains("none") && (low.contains("primitive") || low.contains("axiomatic"))
}

fn concept_anchor_id(concept_id: &str) -> String {
    format!("concept-{}", oa::obsidian_heading_slug(concept_id))
}

fn demote_markdown_headings(input: &str, levels: usize) -> String {
    let mut out = String::with_capacity(input.len() + 16);
    for line in input.lines() {
        let trimmed = line.trim_start_matches(' ');
        let leading_spaces = line.len() - trimmed.len();
        if trimmed.starts_with('#') {
            let mut hash_count = 0usize;
            for ch in trimmed.chars() {
                if ch == '#' {
                    hash_count += 1;
                } else {
                    break;
                }
            }
            if hash_count > 0 && hash_count <= 6 {
                let rest = trimmed[hash_count..].strip_prefix(' ');
                if let Some(rest) = rest {
                    let new_count = (hash_count + levels).min(6);
                    out.push_str(&" ".repeat(leading_spaces));
                    out.push_str(&"#".repeat(new_count));
                    out.push(' ');
                    out.push_str(rest);
                    out.push('\n');
                    continue;
                }
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn rewrite_wikilinks_to_book_anchors(
    body: &str,
    included_ids: &HashSet<String>,
    concept_key_to_id: &HashMap<String, String>,
) -> String {
    let mut out = body.to_string();
    let links = oa::extract_obsidian_links(body);
    for link in links {
        let target_key = normalize_obsidian_target_to_key(&link.target);
        let display = link
            .alias
            .clone()
            .unwrap_or_else(|| link.target.clone())
            .trim()
            .to_string();
        let replacement = if let Some(id) = resolve_concept_id(&target_key, concept_key_to_id) {
            if included_ids.contains(&id) {
                format!("[{}](#{})", display, concept_anchor_id(&id))
            } else {
                display
            }
        } else {
            display
        };
        out = out.replace(&link.raw, &replacement);
    }
    out
}

fn layer_label(layer: Option<&str>) -> &'static str {
    let low = layer.unwrap_or("unknown").trim().to_lowercase();
    for (label, keys) in BOOK_LAYER_ORDER {
        for k in *keys {
            if low == *k {
                return label;
            }
        }
    }
    "Unclassified"
}

fn layer_index(layer: Option<&str>) -> usize {
    let low = layer.unwrap_or("unknown").trim().to_lowercase();
    for (idx, (_label, keys)) in BOOK_LAYER_ORDER.iter().enumerate() {
        if keys.iter().any(|k| low == *k) {
            return idx;
        }
    }
    BOOK_LAYER_ORDER.len()
}

#[derive(Debug, Clone)]
struct BookBuild {
    ast: BookAst,
    markdown: String,
    concepts_included: usize,
    has_cycles: bool,
    cycle_nodes: Vec<String>,
    analytics: BookAnalytics,
    spine_index_markdown: String,
}

fn output_format_str(format: VaultBookOutputFormat) -> &'static str {
    match format {
        VaultBookOutputFormat::Markdown => "markdown",
        VaultBookOutputFormat::Latex => "latex",
        VaultBookOutputFormat::Pdf => "pdf",
    }
}

fn book_render_profile(profile: VaultBookProfile) -> RenderProfile {
    match profile {
        VaultBookProfile::Hybrid => RenderProfile::Hybrid,
        VaultBookProfile::Diagnostic => RenderProfile::Diagnostic,
    }
}

#[derive(Debug, Clone, Serialize)]
struct ExplainOptions {
    all_concepts: bool,
    no_appendices: bool,
    appendix_dir: String,
    explain_path: Option<String>,
    output_format: String,
    book_profile: String,
}

#[derive(Debug, Clone, Serialize)]
struct ExplainReportV1 {
    schema_id: &'static str,
    explain_version: &'static str,
    book_generator_version: String,
    engine_version: String,
    generated_at_utc: String,
    vault_root: String,
    invariant_id_set: Vec<String>,
    options: ExplainOptions,
    concepts: Vec<ConceptBookRecord>,
}

#[derive(Debug, Clone)]
struct ConceptGraphBuild {
    concepts_by_id: HashMap<String, VaultNote>,
    concept_key_to_id: HashMap<String, String>,
    deps: HashMap<String, BTreeSet<String>>,
    included: HashSet<String>,
    seed_ids: BTreeSet<String>,
    included_reason: HashMap<String, IncludedReason>,
    ordered: Vec<String>,
    has_cycles: bool,
    cycle_nodes: Vec<String>,
    by_layer: BTreeMap<String, Vec<String>>,
}

fn ordered_invariant_ids() -> Vec<&'static str> {
    SpineId::all_invariants()
        .iter()
        .map(|s| s.as_str())
        .collect()
}

fn normalize_invariant_id(input: &str) -> Option<String> {
    spine_from_str(input).map(|s| s.as_str().to_string())
}

#[cfg(test)]
fn build_concept_book(vault_root: &Path, all_concepts: bool) -> Result<BookBuild, String> {
    build_concept_book_with_profile(vault_root, all_concepts, RenderProfile::Hybrid)
}

fn build_concept_book_with_profile(
    vault_root: &Path,
    all_concepts: bool,
    render_profile: RenderProfile,
) -> Result<BookBuild, String> {
    let graph = collect_concepts_and_graph(vault_root, all_concepts)?;
    let (spine_index, spine_markdown) = build_concept_spine_index_and_markdown(vault_root)?;
    let model_graph = to_book_graph_input(&graph)?;
    let spine_rows = to_spine_rows(&spine_index);
    let invariant_ids: Vec<String> = ordered_invariant_ids()
        .into_iter()
        .map(|s| s.to_string())
        .collect();
    let analytics = analyze_book_model(&model_graph, &spine_rows, &invariant_ids)?;
    let mut ast = build_book_ast_model(&model_graph, &analytics, &invariant_ids, render_profile)?;
    ast.orientation_pages = default_orientation_pages();
    ast.invariants =
        collect_invariant_sections(vault_root, &graph.included, &graph.concept_key_to_id)?;
    ast.supplemental_pages = default_non_concept_pages();
    let markdown = admit_book::render_markdown(&ast);

    Ok(BookBuild {
        ast,
        concepts_included: graph.included.len(),
        has_cycles: graph.has_cycles,
        cycle_nodes: graph.cycle_nodes,
        markdown,
        analytics,
        spine_index_markdown: spine_markdown,
    })
}

fn collect_invariant_sections(
    vault_root: &Path,
    included_ids: &HashSet<String>,
    concept_key_to_id: &HashMap<String, String>,
) -> Result<Vec<BookInvariantSection>, String> {
    fn fallback_invariant_id(name: &str) -> String {
        name.to_lowercase()
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '-' {
                    c
                } else if c.is_whitespace() {
                    '-'
                } else {
                    '-'
                }
            })
            .collect()
    }

    let invariants_dir = vault_root.join("invariants");
    if !invariants_dir.is_dir() {
        return Ok(Vec::new());
    }

    let mut sections: Vec<BookInvariantSection> = load_vault_notes(&invariants_dir)?
        .into_iter()
        .map(|note| {
            let id = note
                .invariant_id
                .as_deref()
                .and_then(normalize_invariant_id)
                .unwrap_or_else(|| fallback_invariant_id(&note.name));
            let mut body =
                rewrite_wikilinks_to_book_anchors(&note.body, included_ids, concept_key_to_id);
            body = demote_markdown_headings(&body, 2);
            BookInvariantSection {
                id,
                title: note.title,
                markdown_body: body,
            }
        })
        .collect();

    let order: HashMap<String, usize> = ordered_invariant_ids()
        .into_iter()
        .enumerate()
        .map(|(idx, id)| (id.to_string(), idx))
        .collect();
    sections.sort_by(|a, b| {
        order
            .get(&a.id)
            .copied()
            .unwrap_or(usize::MAX)
            .cmp(&order.get(&b.id).copied().unwrap_or(usize::MAX))
            .then_with(|| a.title.cmp(&b.title))
    });

    Ok(sections)
}

fn default_non_concept_pages() -> Vec<BookSupplementalPage> {
    vec![
        BookSupplementalPage {
            title: "Irreversibility Accounting and Agency Under Constraint".to_string(),
            markdown_body: r#"These are projections, not appendices.

Irreversibility accounting asks what happens under persistent accumulation:
- persistent differences accumulate
- erasure cost is asymmetric
- displacement hides cost
- constraint-load rises
- feasible-set shrinks
- collapse surfaces emerge

Agency is then reframed as constrained navigation:
not freedom from irreversibility, but selection of where the next irreversibility quantum lands."#
                .to_string(),
        },
        BookSupplementalPage {
            title: "Agency Under Constraint Accumulation".to_string(),
            markdown_body: r#"Most frameworks begin with agency and retrofit structure.

This framework does the opposite: agency is derived from constraint geometry under accumulation.

Operational restatement:
- agency is not freedom from irreversibility
- agency is selection of where the next irreversibility quantum lands
- accountability follows from declared control surfaces and degrees of freedom

This preserves responsibility without pretending reversibility where it does not exist."#
                .to_string(),
        },
        BookSupplementalPage {
            title: "Structural Lineage".to_string(),
            markdown_body: r#"This work is not metaphysics and not a totalizing theory.

It sits in continuity with:
- thermodynamics (irreversibility, asymmetry)
- systems theory (constraint and accumulation)
- cybernetics (reflexive diagnosability)
- institutional economics (externalities, path dependence)
- distributed systems and version control (persistence and rollback limits)
- legal precedent (residual constraint across time)

Its distinct move is compression: one substrate-agnostic abstraction for persistence plus asymmetry across domains."#
                .to_string(),
        },
        BookSupplementalPage {
            title: "Graph Structure Over Reading Order".to_string(),
            markdown_body: r#"The ontology is a dependency graph; linear chapter order is only a projection.

Interpretive rule:
- links carry meaning
- sequence carries convenience

Example chain:
Constraint -> Accumulation -> Constraint-load -> Saturation

Removing any node in that chain collapses diagnosability. Structural dependencies are prerequisites for valid interpretation."#
                .to_string(),
        },
        BookSupplementalPage {
            title: "From Ontology to Compiler".to_string(),
            markdown_body: r#"The framework is computable.

Operational mapping:
- concepts -> IR primitives
- constraints -> boolean predicates
- witness -> proof-like evidence object
- ledger -> append-only accountability spine
- scope -> evaluation boundary

The claim is modest: if bookkeeping is taken seriously, irreversibility accounting can be checked rather than merely asserted."#
                .to_string(),
        },
        BookSupplementalPage {
            title: "Why Reversibility Narratives Fail".to_string(),
            markdown_body: r#"Common operational narratives fail under asymmetry:

- "We can clean this up later."
- "We can always roll back."
- "This is only temporary."
- "This exception is harmless."

Failure pattern:
- erasure is deferred
- costs are displaced
- residual constraints accumulate
- option space shrinks before the narrative updates

The lens tracks this as structure, not as morality."#
                .to_string(),
        },
    ]
}

fn default_orientation_pages() -> Vec<BookSupplementalPage> {
    vec![
        BookSupplementalPage {
            title: "Why This Exists".to_string(),
            markdown_body:
                r#"Modern systems repeatedly assume that reversible narratives are sufficient.

This book exists to analyze what happens when that assumption fails.

Its organizing problem is practical:
- persistent differences continue to constrain action
- erasure is asymmetric and often displaced
- bookkeeping of residual constraint is usually absent

The goal is diagnostic clarity, not metaphysical explanation."#
                    .to_string(),
        },
        BookSupplementalPage {
            title: "How to Read This System".to_string(),
            markdown_body: r#"The graph is primary; the chapter order is a projection.

Reading rules:
- dependency edges carry meaning
- linear sequence is a convenience layer
- composite concepts inherit prerequisites
- cherry-picking without prerequisites creates interpretive drift

Example dependency chain:
Constraint -> Accumulation -> Constraint-load -> Saturation

Remove one node and the chain loses interpretability."#
                .to_string(),
        },
        BookSupplementalPage {
            title: "The Invariants - The Hidden Spine".to_string(),
            markdown_body: r#"Invariants are self-binding constraints on the method.

They are not optional extras and not downstream applications.

Function:
- prevent collapse into ideology
- preserve decomposition under scale
- require witness-bearing accountability
- keep diagnosis non-prescriptive

These are constraints on the lens itself."#
                .to_string(),
        },
    ]
}

fn collect_concepts_and_graph(
    vault_root: &Path,
    all_concepts: bool,
) -> Result<ConceptGraphBuild, String> {
    let notes = load_vault_notes(vault_root)?;
    let concepts: Vec<VaultNote> = notes.into_iter().filter(is_concept_note).collect();
    if concepts.is_empty() {
        return Err(format!(
            "no concepts found under {}/concepts",
            vault_root.display()
        ));
    }

    let mut concepts_by_id: HashMap<String, VaultNote> = HashMap::new();
    for c in concepts {
        concepts_by_id.insert(c.name.clone(), c);
    }

    let mut concept_ids: Vec<String> = concepts_by_id.keys().cloned().collect();
    concept_ids.sort();
    let concept_list: Vec<VaultNote> = concept_ids
        .iter()
        .filter_map(|id| concepts_by_id.get(id).cloned())
        .collect();
    let concept_key_to_id = build_concept_key_map(&concept_list);

    let mut deps: HashMap<String, BTreeSet<String>> = HashMap::new();
    for (id, note) in &concepts_by_id {
        let mut set = BTreeSet::new();
        if let Some(section) = extract_h2_section(&note.body, "Structural dependencies") {
            if !section.is_empty() && !has_none_primitive_marker(&section) {
                for link in oa::extract_obsidian_links(&section) {
                    let target_key = normalize_obsidian_target_to_key(&link.target);
                    if let Some(dep_id) = resolve_concept_id(&target_key, &concept_key_to_id) {
                        if dep_id != *id {
                            set.insert(dep_id);
                        }
                    }
                }
            }
        }
        deps.insert(id.clone(), set);
    }

    let mut included: HashSet<String> = HashSet::new();
    let mut seed_ids: BTreeSet<String> = BTreeSet::new();
    let mut included_reason: HashMap<String, IncludedReason> = HashMap::new();
    for (id, note) in &concepts_by_id {
        if all_concepts || note.canonical {
            included.insert(id.clone());
            seed_ids.insert(id.clone());
            included_reason.insert(id.clone(), IncludedReason::CanonicalSeed);
        }
    }
    let mut stack: Vec<String> = included.iter().cloned().collect();
    while let Some(cur) = stack.pop() {
        let Some(d) = deps.get(&cur) else {
            continue;
        };
        for dep in d {
            if concepts_by_id.contains_key(dep) && !included.contains(dep) {
                included.insert(dep.clone());
                included_reason.insert(dep.clone(), IncludedReason::DependencyClosure);
                stack.push(dep.clone());
            }
        }
    }

    let mut in_degree: HashMap<String, usize> = HashMap::new();
    let mut reverse: HashMap<String, BTreeSet<String>> = HashMap::new();
    for id in &included {
        let d = deps.get(id).cloned().unwrap_or_default();
        let count = d.iter().filter(|x| included.contains(*x)).count();
        in_degree.insert(id.clone(), count);
        for dep in d {
            if !included.contains(&dep) {
                continue;
            }
            reverse.entry(dep).or_default().insert(id.clone());
        }
    }

    let mut queue: BTreeSet<String> = BTreeSet::new();
    for (id, deg) in &in_degree {
        if *deg == 0 {
            queue.insert(id.clone());
        }
    }

    let mut ordered: Vec<String> = Vec::with_capacity(included.len());
    while let Some(first) = queue.iter().next().cloned() {
        queue.remove(&first);
        ordered.push(first.clone());
        let dependents = reverse.get(&first).cloned().unwrap_or_default();
        for dep in dependents {
            let Some(deg) = in_degree.get_mut(&dep) else {
                continue;
            };
            *deg = deg.saturating_sub(1);
            if *deg == 0 {
                queue.insert(dep);
            }
        }
    }

    let ordered_set: HashSet<String> = ordered.iter().cloned().collect();
    let mut remaining: Vec<String> = included
        .iter()
        .filter(|id| !ordered_set.contains(*id))
        .cloned()
        .collect();
    remaining.sort_by(|a, b| {
        let la = concepts_by_id.get(a).and_then(|n| n.layer.as_deref());
        let lb = concepts_by_id.get(b).and_then(|n| n.layer.as_deref());
        layer_index(la).cmp(&layer_index(lb)).then_with(|| a.cmp(b))
    });

    let has_cycles = !remaining.is_empty();
    let cycle_nodes = remaining.clone();
    ordered.extend(remaining);

    let mut by_layer: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for id in &ordered {
        let note = concepts_by_id
            .get(id)
            .ok_or_else(|| format!("missing concept: {}", id))?;
        let label = layer_label(note.layer.as_deref());
        by_layer
            .entry(label.to_string())
            .or_default()
            .push(id.clone());
    }

    Ok(ConceptGraphBuild {
        concepts_by_id,
        concept_key_to_id,
        deps,
        included,
        seed_ids,
        included_reason,
        ordered,
        has_cycles,
        cycle_nodes,
        by_layer,
    })
}

fn to_book_graph_input(graph: &ConceptGraphBuild) -> Result<BookGraphInput, String> {
    let mut concepts_by_id: HashMap<String, SourceConcept> = HashMap::new();
    for (id, note) in &graph.concepts_by_id {
        let mut body = rewrite_wikilinks_to_book_anchors(
            &note.body,
            &graph.included,
            &graph.concept_key_to_id,
        );
        body = demote_markdown_headings(&body, 2);
        let mut declared_invariants: BTreeSet<String> = BTreeSet::new();
        for raw in &note.invariants {
            if let Some(inv) = normalize_invariant_id(raw) {
                declared_invariants.insert(inv);
            }
        }
        concepts_by_id.insert(
            id.clone(),
            SourceConcept {
                id: id.clone(),
                anchor: concept_anchor_id(id),
                title: note.title.clone(),
                canonical_path: note.rel_path.clone(),
                layer: note.layer.clone(),
                layer_label: layer_label(note.layer.as_deref()).to_string(),
                canonical: note.canonical,
                declared_invariants: declared_invariants.into_iter().collect(),
                frontmatter: note.frontmatter.clone(),
                source_markdown_body: note.body.clone(),
                book_markdown_body: body,
            },
        );
    }

    let layer_order = BOOK_LAYER_ORDER
        .iter()
        .map(|(label, _keys)| (*label).to_string())
        .collect::<Vec<_>>();

    Ok(BookGraphInput {
        concepts_by_id,
        deps: graph.deps.clone(),
        included: graph.included.clone(),
        seed_ids: graph.seed_ids.clone(),
        included_reason: graph.included_reason.clone(),
        ordered: graph.ordered.clone(),
        has_cycles: graph.has_cycles,
        cycle_nodes: graph.cycle_nodes.clone(),
        by_layer: graph.by_layer.clone(),
        layer_order,
    })
}

fn to_spine_rows(spine_index: &ConceptSpineIndex) -> Vec<SpineEvidenceRow> {
    let mut rows: Vec<SpineEvidenceRow> = Vec::new();
    for row in &spine_index.concepts {
        let mut core_in: BTreeSet<String> = BTreeSet::new();
        for inv in &row.evidence.core_in {
            if let Some(norm) = normalize_invariant_id(inv) {
                core_in.insert(norm);
            }
        }
        let mut refs: BTreeMap<String, BookRefCounts> = BTreeMap::new();
        for (inv, ct) in &row.evidence.refs {
            if let Some(norm) = normalize_invariant_id(inv) {
                refs.insert(
                    norm,
                    BookRefCounts {
                        invariant: ct.invariant,
                        diagnostic: ct.diagnostic,
                    },
                );
            }
        }
        let mut footprint_in: BTreeSet<String> = BTreeSet::new();
        for inv in &row.evidence.footprint_in {
            if let Some(norm) = normalize_invariant_id(inv) {
                footprint_in.insert(norm);
            }
        }
        rows.push(SpineEvidenceRow {
            id: row.id.clone(),
            primary_spine: row.primary_spine.clone(),
            core_in: core_in.into_iter().collect(),
            footprint_in: footprint_in.into_iter().collect(),
            refs,
        });
    }
    rows
}

fn render_appendix_layer_matrix(analytics: &BookAnalytics) -> String {
    let view = LayerInvariantMatrixView {
        invariant_ids: ordered_invariant_ids()
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
        cells: analytics.matrix.cells.clone(),
        diagnostic_note:
            "Diagnostic matrix (declared-first); use this for strict audit and CI surfaces."
                .to_string(),
        marker_legend:
            "Markers: `*` aligned (core/support), `.` aligned (footprint only), `!` declared-only, `~` drift (observed elsewhere), `^` inferred-only (dependency-of-core)."
                .to_string(),
    };
    admit_book::render_layer_invariant_matrix(&view)
}

fn render_explain_json(
    vault_root: &Path,
    analytics: &BookAnalytics,
    options: ExplainOptions,
) -> Result<String, String> {
    let report = ExplainReportV1 {
        schema_id: "admit.book-explain/1",
        explain_version: "1",
        book_generator_version: env!("CARGO_PKG_VERSION").to_string(),
        engine_version: env!("CARGO_PKG_VERSION").to_string(),
        generated_at_utc: now_utc_rfc3339(),
        vault_root: vault_root.to_string_lossy().replace('\\', "/"),
        invariant_id_set: ordered_invariant_ids()
            .into_iter()
            .map(|s| s.to_string())
            .collect(),
        options,
        concepts: analytics.records.clone(),
    };
    serde_json::to_string_pretty(&report).map_err(|e| format!("json encode: {e}"))
}

fn default_book_appendix_dir(out: &Path) -> PathBuf {
    out.parent()
        .map(|p| p.join("appendices"))
        .unwrap_or_else(|| PathBuf::from("appendices"))
}

fn default_book_modules_dir(out: &Path) -> PathBuf {
    let stem = out
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("book");
    out.parent()
        .map(|p| p.join("modules").join(stem))
        .unwrap_or_else(|| PathBuf::from("modules").join(stem))
}

fn default_book_modules_ref(out: &Path) -> String {
    let stem = out
        .file_stem()
        .and_then(|s| s.to_str())
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("book");
    format!("modules/{stem}")
}

fn default_spine_registry_path(vault_root: &Path) -> PathBuf {
    vault_root
        .join("meta")
        .join("Concept Spine Index.generated.md")
}

fn default_latex_template_candidates(vault_root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    out.push(PathBuf::from("meta/design/book-template.tex"));
    out.push(vault_root.join("meta/design/book-template.tex"));
    if let Some(parent) = vault_root.parent() {
        out.push(parent.join("irrev-compiler/meta/design/book-template.tex"));
    }
    out
}

fn sibling_irrevbook_style(template_path: &Path) -> Option<PathBuf> {
    let style_path = template_path.parent()?.join("irrevbook.sty");
    style_path.exists().then_some(style_path)
}

fn load_latex_template(
    vault_root: &Path,
    template_path: Option<&PathBuf>,
) -> Result<(String, Option<PathBuf>, Option<PathBuf>), String> {
    if let Some(path) = template_path {
        let text = fs::read_to_string(path)
            .map_err(|e| format!("read template {}: {e}", path.display()))?;
        return Ok((text, Some(path.clone()), sibling_irrevbook_style(path)));
    }
    for candidate in default_latex_template_candidates(vault_root) {
        if candidate.exists() {
            let text = fs::read_to_string(&candidate)
                .map_err(|e| format!("read template {}: {e}", candidate.display()))?;
            let style = sibling_irrevbook_style(&candidate);
            return Ok((text, Some(candidate), style));
        }
    }
    Ok((admit_book::default_latex_template().to_string(), None, None))
}

fn run_book_build(args: VaultBookBuildArgs) -> Result<(), String> {
    let render_profile = book_render_profile(args.book_profile);
    let output_format = args.format;
    let vault_root = resolve_vault_root_for_book(&args.path)?;
    let out = args
        .out
        .clone()
        .unwrap_or_else(|| default_book_out_path(&vault_root, output_format));
    let appendix_dir = args
        .appendix_dir
        .clone()
        .unwrap_or_else(|| default_book_appendix_dir(&out));
    let modules_dir = default_book_modules_dir(&out);
    let modules_ref = default_book_modules_ref(&out);
    let spine_registry = args
        .spine_registry
        .clone()
        .unwrap_or_else(|| default_spine_registry_path(&vault_root));
    let explain_path: Option<PathBuf> = match &args.explain {
        None => None,
        Some(Some(path)) => Some(path.clone()),
        Some(None) => Some(appendix_dir.join("book-explain.json")),
    };

    let build = build_concept_book_with_profile(&vault_root, args.all_concepts, render_profile)?;
    let mut module_sidecars: Vec<(PathBuf, String)> = Vec::new();
    let write_spine_registry = !args.no_appendices;
    let spine_registry_content = build.spine_index_markdown.clone();
    let spine_index_md = admit_book::render_spine_index_appendix(&spine_registry_content);
    let layer_matrix_md = render_appendix_layer_matrix(&build.analytics);
    let appendices_latex = if args.no_appendices {
        None
    } else {
        Some(admit_book::render_latex_appendices(
            &spine_index_md,
            &layer_matrix_md,
        ))
    };
    let mut sidecars: Vec<(PathBuf, String)> = Vec::new();
    if !args.no_appendices {
        let stale_gap_audit = appendix_dir.join("invariant-gap-audit.md");
        if stale_gap_audit.exists() {
            fs::remove_file(&stale_gap_audit)
                .map_err(|e| format!("remove stale {}: {e}", stale_gap_audit.display()))?;
        }
        sidecars.push((appendix_dir.join("spine-index.md"), spine_index_md.clone()));
        sidecars.push((
            appendix_dir.join("layer-invariant-matrix.md"),
            layer_matrix_md.clone(),
        ));
    }

    let (main_bytes, template_resolved, tex_sidecar, style_sidecar): (
        Vec<u8>,
        Option<PathBuf>,
        Option<(PathBuf, String)>,
        Option<(PathBuf, Vec<u8>)>,
    ) = match output_format {
        VaultBookOutputFormat::Markdown => (build.markdown.clone().into_bytes(), None, None, None),
        VaultBookOutputFormat::Latex => {
            let (template, template_path, style_path) =
                load_latex_template(&vault_root, args.template.as_ref())?;
            let (tex, modules) = admit_book::render_latex_modular(
                &build.ast,
                &template,
                appendices_latex.as_deref(),
                &modules_ref,
            );
            module_sidecars = modules
                .into_iter()
                .map(|(rel_path, content)| (modules_dir.join(rel_path), content))
                .collect();
            let style_file = if let Some(path) = style_path {
                let bytes =
                    fs::read(&path).map_err(|e| format!("read style {}: {e}", path.display()))?;
                let target = out
                    .parent()
                    .map(|p| p.join("irrevbook.sty"))
                    .unwrap_or_else(|| PathBuf::from("irrevbook.sty"));
                Some((target, bytes))
            } else {
                None
            };
            (tex.into_bytes(), template_path, None, style_file)
        }
        VaultBookOutputFormat::Pdf => {
            let (template, template_path, style_path) =
                load_latex_template(&vault_root, args.template.as_ref())?;
            let (tex, modules) = admit_book::render_latex_modular(
                &build.ast,
                &template,
                appendices_latex.as_deref(),
                &modules_ref,
            );
            module_sidecars = modules
                .iter()
                .map(|(rel_path, content)| (modules_dir.join(rel_path), content.clone()))
                .collect();
            let mut extra_file_bytes: Vec<(String, Vec<u8>)> = Vec::new();
            for (rel_path, content) in modules {
                let key = format!("{}/{}", modules_ref, rel_path).replace('\\', "/");
                extra_file_bytes.push((key, content.into_bytes()));
            }
            let mut style_file: Option<(PathBuf, Vec<u8>)> = None;
            if let Some(path) = style_path.as_ref() {
                let bytes =
                    fs::read(path).map_err(|e| format!("read style {}: {e}", path.display()))?;
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("irrevbook.sty")
                    .to_string();
                extra_file_bytes.push((name, bytes.clone()));
                let target = out
                    .parent()
                    .map(|p| p.join("irrevbook.sty"))
                    .unwrap_or_else(|| PathBuf::from("irrevbook.sty"));
                style_file = Some((target, bytes));
            }
            let extra_files: Vec<(&str, &[u8])> = extra_file_bytes
                .iter()
                .map(|(name, bytes)| (name.as_str(), bytes.as_slice()))
                .collect();
            let pdf = admit_book::compile_pdf(&tex, &extra_files)?;
            let tex_file = if args.keep_tex {
                Some((out.with_extension("tex"), tex))
            } else {
                None
            };
            (pdf, template_path, tex_file, style_file)
        }
    };
    let bytes = main_bytes.len();

    let explain_json = if explain_path.is_some() {
        Some(render_explain_json(
            &vault_root,
            &build.analytics,
            ExplainOptions {
                all_concepts: args.all_concepts,
                no_appendices: args.no_appendices,
                appendix_dir: appendix_dir.to_string_lossy().replace('\\', "/"),
                explain_path: explain_path
                    .as_ref()
                    .map(|p| p.to_string_lossy().replace('\\', "/")),
                output_format: output_format_str(output_format).to_string(),
                book_profile: render_profile.as_str().to_string(),
            },
        )?)
    } else {
        None
    };

    if args.dry_run {
        if args.json {
            let payload = serde_json::json!({
                "command": "vault book build",
                "vault_root": vault_root.to_string_lossy(),
                "out": out.to_string_lossy(),
                "appendix_dir": appendix_dir.to_string_lossy(),
                "modules_dir": modules_dir.to_string_lossy(),
                "appendices_enabled": !args.no_appendices,
                "appendices": sidecars.iter().map(|(p, _)| p.to_string_lossy().to_string()).collect::<Vec<_>>(),
                "module_count": module_sidecars.len(),
                "spine_registry": if write_spine_registry { Some(spine_registry.to_string_lossy().to_string()) } else { None },
                "template": template_resolved.as_ref().map(|p| p.to_string_lossy().to_string()),
                "keep_tex": args.keep_tex,
                "tex_sidecar": tex_sidecar.as_ref().map(|(p, _)| p.to_string_lossy().to_string()),
                "style_sidecar": style_sidecar.as_ref().map(|(p, _)| p.to_string_lossy().to_string()),
                "explain": explain_path.as_ref().map(|p| p.to_string_lossy().to_string()),
                "dry_run": true,
                "all_concepts": args.all_concepts,
                "book_profile": render_profile.as_str(),
                "concepts": build.concepts_included,
                "bytes": bytes,
                "has_cycles": build.has_cycles,
                "cycle_nodes": build.cycle_nodes.len(),
                "output_format": output_format_str(output_format),
            });
            println!(
                "{}",
                serde_json::to_string_pretty(&payload).map_err(|e| format!("json encode: {e}"))?
            );
        } else {
            println!(
                "book_build dry_run=true concepts={} bytes={} has_cycles={} out={} appendices={} modules={} explain={}",
                build.concepts_included,
                bytes,
                build.has_cycles,
                out.display(),
                if args.no_appendices { 0 } else { sidecars.len() },
                module_sidecars.len(),
                explain_path
                    .as_ref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|| "(none)".to_string()),
            );
        }
        return Ok(());
    }

    if !args.force {
        if out.exists() {
            return Err(format!(
                "refusing to overwrite existing file (use --force): {}",
                out.display()
            ));
        }
        if !module_sidecars.is_empty() && modules_dir.exists() {
            return Err(format!(
                "refusing to overwrite existing directory (use --force): {}",
                modules_dir.display()
            ));
        }
        for (path, _content) in &sidecars {
            if path.exists() {
                return Err(format!(
                    "refusing to overwrite existing file (use --force): {}",
                    path.display()
                ));
            }
        }
        if let Some(path) = explain_path.as_ref() {
            if path.exists() {
                return Err(format!(
                    "refusing to overwrite existing file (use --force): {}",
                    path.display()
                ));
            }
        }
        if write_spine_registry && spine_registry.exists() {
            return Err(format!(
                "refusing to overwrite existing file (use --force): {}",
                spine_registry.display()
            ));
        }
        if let Some((path, _)) = tex_sidecar.as_ref() {
            if path.exists() {
                return Err(format!(
                    "refusing to overwrite existing file (use --force): {}",
                    path.display()
                ));
            }
        }
        if let Some((path, _)) = style_sidecar.as_ref() {
            if path.exists() {
                return Err(format!(
                    "refusing to overwrite existing file (use --force): {}",
                    path.display()
                ));
            }
        }
    }
    if args.force && !module_sidecars.is_empty() && modules_dir.exists() {
        fs::remove_dir_all(&modules_dir)
            .map_err(|e| format!("remove stale {}: {e}", modules_dir.display()))?;
    }
    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
    }
    fs::write(&out, &main_bytes).map_err(|e| format!("write {}: {e}", out.display()))?;
    if write_spine_registry {
        if let Some(parent) = spine_registry.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        fs::write(&spine_registry, &spine_registry_content)
            .map_err(|e| format!("write {}: {e}", spine_registry.display()))?;
    }
    for (path, content) in &sidecars {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        fs::write(path, content).map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    for (path, content) in &module_sidecars {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        fs::write(path, content).map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    if let Some((path, content)) = tex_sidecar.as_ref() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        fs::write(path, content).map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    if let Some((path, content)) = style_sidecar.as_ref() {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        fs::write(path, content).map_err(|e| format!("write {}: {e}", path.display()))?;
    }
    if let (Some(path), Some(content)) = (explain_path.as_ref(), explain_json.as_ref()) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        fs::write(path, content).map_err(|e| format!("write {}: {e}", path.display()))?;
    }

    if args.json {
        let payload = serde_json::json!({
            "command": "vault book build",
            "vault_root": vault_root.to_string_lossy(),
            "out": out.to_string_lossy(),
            "appendix_dir": appendix_dir.to_string_lossy(),
            "modules_dir": modules_dir.to_string_lossy(),
            "appendices_enabled": !args.no_appendices,
            "appendices": sidecars.iter().map(|(p, _)| p.to_string_lossy().to_string()).collect::<Vec<_>>(),
            "module_count": module_sidecars.len(),
            "spine_registry": if write_spine_registry { Some(spine_registry.to_string_lossy().to_string()) } else { None },
            "template": template_resolved.as_ref().map(|p| p.to_string_lossy().to_string()),
            "keep_tex": args.keep_tex,
            "tex_sidecar": tex_sidecar.as_ref().map(|(p, _)| p.to_string_lossy().to_string()),
            "style_sidecar": style_sidecar.as_ref().map(|(p, _)| p.to_string_lossy().to_string()),
            "explain": explain_path.as_ref().map(|p| p.to_string_lossy().to_string()),
            "all_concepts": args.all_concepts,
            "book_profile": render_profile.as_str(),
            "concepts": build.concepts_included,
            "bytes": bytes,
            "has_cycles": build.has_cycles,
            "cycle_nodes": build.cycle_nodes.len(),
            "output_format": output_format_str(output_format),
        });
        println!(
            "{}",
            serde_json::to_string_pretty(&payload).map_err(|e| format!("json encode: {e}"))?
        );
    } else {
        println!(
            "book_build concepts={} bytes={} has_cycles={} out={} appendices={} modules={} explain={}",
            build.concepts_included,
            bytes,
            build.has_cycles,
            out.display(),
            if args.no_appendices { 0 } else { sidecars.len() },
            module_sidecars.len(),
            explain_path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|| "(none)".to_string()),
        );
    }
    Ok(())
}

#[cfg(test)]
mod book_tests {
    use super::*;
    use tempfile::TempDir;

    fn write(p: &Path, s: &str) {
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, s).unwrap();
    }

    fn write_invariant(vault: &Path, id: &str, body: &str) {
        write(
            &vault.join(format!("invariants/{}.md", id)),
            &format!(
                "---\nrole: invariant\ninvariant_id: {}\n---\n# {}\n\n{}",
                id, id, body
            ),
        );
    }

    fn bootstrap_invariants(vault: &Path) {
        write_invariant(
            vault,
            "governance",
            "## Minimal decomposition\n\n- [[missing-governance-core]]\n",
        );
        write_invariant(
            vault,
            "irreversibility",
            "## Minimal decomposition\n\n- [[missing-irreversibility-core]]\n",
        );
        write_invariant(
            vault,
            "decomposition",
            "## Minimal decomposition\n\n- [[missing-decomposition-core]]\n",
        );
        write_invariant(
            vault,
            "attribution",
            "## Minimal decomposition\n\n- [[missing-attribution-core]]\n",
        );
    }

    fn count_files_with_ext(root: &Path, ext: &str) -> usize {
        if !root.exists() {
            return 0;
        }
        let mut count = 0usize;
        let mut stack = vec![root.to_path_buf()];
        while let Some(cur) = stack.pop() {
            let Ok(entries) = fs::read_dir(&cur) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                } else if path.extension().and_then(|s| s.to_str()) == Some(ext) {
                    count += 1;
                }
            }
        }
        count
    }

    #[test]
    fn book_orders_dependencies_and_rewrites_links() {
        let td = TempDir::new().unwrap();
        let vault = td.path();
        bootstrap_invariants(vault);

        write(
            &vault.join("concepts/primitive-ok.md"),
            r#"---
role: concept
layer: primitive
canonical: true
invariants:
  - governance
---
# Primitive OK

## Structural dependencies

None (primitive)
"#,
        );
        write(
            &vault.join("concepts/object-ok.md"),
            r#"---
role: concept
layer: first-order
canonical: true
invariants:
  - governance
---
# Object OK

## Structural dependencies

- [[primitive-ok]]
"#,
        );
        write(
            &vault.join("concepts/admissibility.md"),
            r#"---
role: concept
layer: selector
canonical: true
invariants:
  - governance
---
# Admissibility

## Structural dependencies

- [[object-ok]]
"#,
        );

        let build = build_concept_book(vault, false).unwrap();
        let md = build.markdown;

        assert!(md.contains("## Primitives"));
        assert!(md.contains("## First-order composites"));
        assert!(md.contains("## Diagnostic apparatus"));

        assert!(md.contains("<a id=\"concept-primitive-ok\"></a>"));
        assert!(md.contains("<a id=\"concept-object-ok\"></a>"));
        assert!(md.contains("<a id=\"concept-admissibility\"></a>"));

        let i_prim = md.find("id=\"concept-primitive-ok\"").unwrap();
        let i_obj = md.find("id=\"concept-object-ok\"").unwrap();
        let i_adm = md.find("id=\"concept-admissibility\"").unwrap();
        assert!(i_prim < i_obj);
        assert!(i_obj < i_adm);

        assert!(md.contains("[primitive-ok](#concept-primitive-ok)"));
        assert!(md.contains("[object-ok](#concept-object-ok)"));
    }

    #[test]
    fn book_reports_cycle_nodes() {
        let td = TempDir::new().unwrap();
        let vault = td.path();
        bootstrap_invariants(vault);

        write(
            &vault.join("concepts/cycle-a.md"),
            r#"---
role: concept
layer: first-order
canonical: true
invariants:
  - governance
---
# Cycle A

## Structural dependencies

- [[cycle-b]]
"#,
        );
        write(
            &vault.join("concepts/cycle-b.md"),
            r#"---
role: concept
layer: first-order
canonical: true
invariants:
  - governance
---
# Cycle B

## Structural dependencies

- [[cycle-a]]
"#,
        );

        let build = build_concept_book(vault, false).unwrap();
        assert!(build.has_cycles);
        assert!(build.markdown.contains("## Cycles"));
        assert!(build.markdown.contains("cycle-a"));
        assert!(build.markdown.contains("cycle-b"));
    }

    #[test]
    fn book_includes_interlude_with_reader_contract_and_fixed_invariant_order() {
        let td = TempDir::new().unwrap();
        let vault = td.path();
        write_invariant(
            vault,
            "governance",
            "## Minimal decomposition\n\n- [[g-core]]\n",
        );
        write_invariant(
            vault,
            "irreversibility",
            "## Minimal decomposition\n\n- [[i-core]]\n",
        );
        write_invariant(
            vault,
            "decomposition",
            "## Minimal decomposition\n\n- [[d-core]]\n",
        );
        write_invariant(
            vault,
            "attribution",
            "## Minimal decomposition\n\n- [[a-core]]\n",
        );

        write(
            &vault.join("concepts/g-core.md"),
            r#"---
role: concept
layer: primitive
canonical: true
invariants:
  - governance
---
# G Core

## Structural dependencies

None (primitive)
"#,
        );
        write(
            &vault.join("concepts/i-core.md"),
            r#"---
role: concept
layer: first-order
canonical: true
invariants:
  - irreversibility
---
# I Core

## Structural dependencies

- [[g-core]]
"#,
        );
        write(
            &vault.join("concepts/d-core.md"),
            r#"---
role: concept
layer: mechanism
canonical: true
invariants:
  - decomposition
---
# D Core

## Structural dependencies

- [[i-core]]
"#,
        );
        write(
            &vault.join("concepts/a-core.md"),
            r#"---
role: concept
layer: selector
canonical: true
invariants:
  - attribution
---
# A Core

## Structural dependencies

- [[d-core]]
"#,
        );

        let build = build_concept_book(vault, false).unwrap();
        let md = build.markdown;
        assert!(md.contains("### Invariant Interlude"));
        assert!(md.contains("This section is generated from concept metadata and spine evidence; it is a map, not a claim of importance."));

        let i_g = md.find("`governance`:").unwrap();
        let i_i = md.find("`irreversibility`:").unwrap();
        let i_d = md.find("`decomposition`:").unwrap();
        let i_a = md.find("`attribution`:").unwrap();
        assert!(i_g < i_i && i_i < i_d && i_d < i_a);
    }

    #[test]
    fn hybrid_profile_marks_declared_infrastructure_in_interlude() {
        let td = TempDir::new().unwrap();
        let vault = td.path();
        write_invariant(
            vault,
            "governance",
            "## Minimal decomposition\n\n- [[g-core]]\n",
        );
        write_invariant(
            vault,
            "irreversibility",
            "## Minimal decomposition\n\n- [[missing-irreversibility-core]]\n",
        );
        write_invariant(
            vault,
            "decomposition",
            "## Minimal decomposition\n\n- [[missing-decomposition-core]]\n",
        );
        write_invariant(
            vault,
            "attribution",
            "## Minimal decomposition\n\n- [[missing-attribution-core]]\n",
        );

        write(
            &vault.join("concepts/g-core.md"),
            r#"---
role: concept
layer: first-order
canonical: true
invariants:
  - governance
---
# G Core

## Structural dependencies

- [[infra-declared]]
"#,
        );
        write(
            &vault.join("concepts/infra-declared.md"),
            r#"---
role: concept
layer: primitive
canonical: true
invariants:
  - governance
---
# Infra Declared

## Structural dependencies

None (primitive)
"#,
        );

        let build = build_concept_book(vault, false).unwrap();
        assert!(build.markdown.contains("Layer navigational matrix:"));
        assert!(build.markdown.contains("infra-declared+"));
        assert!(build
            .markdown
            .contains("- declared-infrastructure: infra-declared"));
        assert!(build.markdown.contains("- declared-gap: (none)"));
        assert!(build
            .analytics
            .gaps
            .declared_infrastructure
            .contains(&"infra-declared".to_string()));
        assert!(!build
            .analytics
            .gaps
            .declared_only
            .contains(&"infra-declared".to_string()));
    }

    #[test]
    fn diagnostic_profile_keeps_declared_only_audit_hook() {
        let td = TempDir::new().unwrap();
        let vault = td.path();
        write_invariant(
            vault,
            "governance",
            "## Minimal decomposition\n\n- [[g-core]]\n",
        );
        write_invariant(
            vault,
            "irreversibility",
            "## Minimal decomposition\n\n- [[missing-irreversibility-core]]\n",
        );
        write_invariant(
            vault,
            "decomposition",
            "## Minimal decomposition\n\n- [[missing-decomposition-core]]\n",
        );
        write_invariant(
            vault,
            "attribution",
            "## Minimal decomposition\n\n- [[missing-attribution-core]]\n",
        );

        write(
            &vault.join("concepts/g-core.md"),
            r#"---
role: concept
layer: first-order
canonical: true
invariants:
  - governance
---
# G Core

## Structural dependencies

- [[infra-declared]]
"#,
        );
        write(
            &vault.join("concepts/infra-declared.md"),
            r#"---
role: concept
layer: primitive
canonical: true
invariants:
  - governance
---
# Infra Declared

## Structural dependencies

None (primitive)
"#,
        );

        let build =
            build_concept_book_with_profile(vault, false, RenderProfile::Diagnostic).unwrap();
        assert!(!build.markdown.contains("Layer navigational matrix:"));
        assert!(build.markdown.contains("- declared-only: infra-declared"));
        assert!(!build.markdown.contains("declared-infrastructure"));
    }

    #[test]
    fn book_matrix_renders_markers_star_bang_tilde_caret() {
        let td = TempDir::new().unwrap();
        let vault = td.path();
        write_invariant(
            vault,
            "governance",
            "## Minimal decomposition\n\n- [[aligned-c]]\n",
        );
        write_invariant(
            vault,
            "irreversibility",
            "## Minimal decomposition\n\n- [[missing-irr-core]]\n",
        );
        write_invariant(
            vault,
            "decomposition",
            "## Minimal decomposition\n\n- [[decomp-core]]\n",
        );
        write_invariant(
            vault,
            "attribution",
            "## Minimal decomposition\n\n- [[drift-c]]\n",
        );

        write(
            &vault.join("concepts/aligned-c.md"),
            r#"---
role: concept
layer: primitive
canonical: true
invariants:
  - governance
---
# Aligned C

## Structural dependencies

None (primitive)
"#,
        );
        write(
            &vault.join("concepts/declared-gap.md"),
            r#"---
role: concept
layer: primitive
canonical: true
invariants:
  - irreversibility
---
# Declared Gap

## Structural dependencies

None (primitive)
"#,
        );
        write(
            &vault.join("concepts/drift-c.md"),
            r#"---
role: concept
layer: first-order
canonical: true
invariants:
  - governance
---
# Drift C

## Structural dependencies

None (primitive)
"#,
        );
        write(
            &vault.join("concepts/decomp-core.md"),
            r#"---
role: concept
layer: first-order
canonical: true
invariants:
  - decomposition
---
# Decomp Core

## Structural dependencies

- [[inferred-base]]
"#,
        );
        write(
            &vault.join("concepts/inferred-base.md"),
            r#"---
role: concept
layer: primitive
canonical: true
---
# Inferred Base

## Structural dependencies

None (primitive)
"#,
        );

        let graph = collect_concepts_and_graph(vault, false).unwrap();
        let (index, _md) = build_concept_spine_index_and_markdown(vault).unwrap();
        let model_graph = to_book_graph_input(&graph).unwrap();
        let spine_rows = to_spine_rows(&index);
        let invariant_ids = ordered_invariant_ids()
            .into_iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let analytics = analyze_book_model(&model_graph, &spine_rows, &invariant_ids).unwrap();
        let matrix = render_appendix_layer_matrix(&analytics);
        assert!(matrix.contains("aligned-c*"));
        assert!(matrix.contains("declared-gap!"));
        assert!(matrix.contains("drift-c~"));
        assert!(matrix.contains("inferred-base^"));
    }

    #[test]
    fn inferred_only_not_reported_as_gap() {
        let td = TempDir::new().unwrap();
        let vault = td.path();
        write_invariant(
            vault,
            "governance",
            "## Minimal decomposition\n\n- [[g-core]]\n",
        );
        write_invariant(
            vault,
            "irreversibility",
            "## Minimal decomposition\n\n- [[i-core]]\n",
        );
        write_invariant(
            vault,
            "decomposition",
            "## Minimal decomposition\n\n- [[d-core]]\n",
        );
        write_invariant(
            vault,
            "attribution",
            "## Minimal decomposition\n\n- [[a-core]]\n",
        );

        write(
            &vault.join("concepts/d-core.md"),
            r#"---
role: concept
layer: first-order
canonical: true
invariants:
  - decomposition
---
# D Core

## Structural dependencies

- [[infra]]
"#,
        );
        write(
            &vault.join("concepts/infra.md"),
            r#"---
role: concept
layer: primitive
canonical: true
---
# Infra

## Structural dependencies

None (primitive)
"#,
        );
        write(
            &vault.join("concepts/g-core.md"),
            r#"---
role: concept
layer: primitive
canonical: true
invariants:
  - governance
---
# G Core

## Structural dependencies

None (primitive)
"#,
        );
        write(
            &vault.join("concepts/i-core.md"),
            r#"---
role: concept
layer: primitive
canonical: true
invariants:
  - irreversibility
---
# I Core

## Structural dependencies

None (primitive)
"#,
        );
        write(
            &vault.join("concepts/a-core.md"),
            r#"---
role: concept
layer: primitive
canonical: true
invariants:
  - attribution
---
# A Core

## Structural dependencies

None (primitive)
"#,
        );

        let graph = collect_concepts_and_graph(vault, false).unwrap();
        let (index, _md) = build_concept_spine_index_and_markdown(vault).unwrap();
        let model_graph = to_book_graph_input(&graph).unwrap();
        let spine_rows = to_spine_rows(&index);
        let invariant_ids = ordered_invariant_ids()
            .into_iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let analytics = analyze_book_model(&model_graph, &spine_rows, &invariant_ids).unwrap();
        assert!(analytics.gaps.inferred_only.contains(&"infra".to_string()));
        assert!(!analytics.gaps.declared_only.contains(&"infra".to_string()));
        assert!(!analytics.gaps.mismatch.contains(&"infra".to_string()));
    }

    #[test]
    fn structural_only_is_tracked_in_analytics() {
        let td = TempDir::new().unwrap();
        let vault = td.path();
        bootstrap_invariants(vault);
        write(
            &vault.join("concepts/unassigned-c.md"),
            r#"---
role: concept
layer: primitive
canonical: true
---
# Unassigned C

## Structural dependencies

None (primitive)
"#,
        );

        let graph = collect_concepts_and_graph(vault, false).unwrap();
        let (index, _md) = build_concept_spine_index_and_markdown(vault).unwrap();
        let model_graph = to_book_graph_input(&graph).unwrap();
        let spine_rows = to_spine_rows(&index);
        let invariant_ids = ordered_invariant_ids()
            .into_iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>();
        let analytics = analyze_book_model(&model_graph, &spine_rows, &invariant_ids).unwrap();
        assert!(analytics
            .gaps
            .structural_only
            .contains(&"unassigned-c".to_string()));
    }

    #[test]
    fn explain_json_contains_schema_and_versions() {
        let td = TempDir::new().unwrap();
        let vault = td.path();
        bootstrap_invariants(vault);
        write(
            &vault.join("concepts/foo.md"),
            r#"---
role: concept
layer: primitive
canonical: true
invariants:
  - governance
---
# Foo

## Structural dependencies

None (primitive)
"#,
        );
        let build = build_concept_book(vault, false).unwrap();
        let json = render_explain_json(
            vault,
            &build.analytics,
            ExplainOptions {
                all_concepts: false,
                no_appendices: false,
                appendix_dir: "x".to_string(),
                explain_path: None,
                output_format: "markdown".to_string(),
                book_profile: "hybrid".to_string(),
            },
        )
        .unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(
            value.get("schema_id").and_then(|v| v.as_str()),
            Some("admit.book-explain/1")
        );
        assert_eq!(
            value.get("explain_version").and_then(|v| v.as_str()),
            Some("1")
        );
        assert!(value.get("book_generator_version").is_some());
        assert!(value.get("engine_version").is_some());
        assert_eq!(
            value
                .get("options")
                .and_then(|v| v.get("book_profile"))
                .and_then(|v| v.as_str()),
            Some("hybrid")
        );
    }

    #[test]
    fn dependency_path_deterministic_under_ties() {
        let td = TempDir::new().unwrap();
        let vault = td.path();
        bootstrap_invariants(vault);
        write(
            &vault.join("concepts/seed-a.md"),
            r#"---
role: concept
layer: primitive
canonical: true
invariants:
  - governance
---
# Seed A

## Structural dependencies

- [[shared]]
"#,
        );
        write(
            &vault.join("concepts/seed-b.md"),
            r#"---
role: concept
layer: primitive
canonical: true
invariants:
  - governance
---
# Seed B

## Structural dependencies

- [[shared]]
"#,
        );
        write(
            &vault.join("concepts/shared.md"),
            r#"---
role: concept
layer: primitive
canonical: false
---
# Shared

## Structural dependencies

None (primitive)
"#,
        );
        let build = build_concept_book(vault, false).unwrap();
        let shared = build
            .analytics
            .records
            .iter()
            .find(|r| r.id == "shared")
            .unwrap();
        assert_eq!(
            shared.dependency_path,
            vec!["seed-a".to_string(), "shared".to_string()]
        );
    }

    #[test]
    fn appendices_written_by_default_and_suppressed_with_no_appendices() {
        let td = TempDir::new().unwrap();
        let vault = td.path();
        bootstrap_invariants(vault);
        write(
            &vault.join("concepts/foo.md"),
            r#"---
role: concept
layer: primitive
canonical: true
invariants:
  - governance
---
# Foo

## Structural dependencies

None (primitive)
"#,
        );

        let out_default = vault.join("exports/book-default.md");
        run_book_build(VaultBookBuildArgs {
            path: vault.to_path_buf(),
            out: Some(out_default.clone()),
            appendix_dir: None,
            spine_registry: None,
            no_appendices: false,
            explain: None,
            format: VaultBookOutputFormat::Markdown,
            template: None,
            keep_tex: false,
            book_profile: VaultBookProfile::Hybrid,
            all_concepts: false,
            dry_run: false,
            force: false,
            json: false,
        })
        .unwrap();
        let default_appendix_dir = default_book_appendix_dir(&out_default);
        let default_modules_dir = default_book_modules_dir(&out_default);
        assert!(default_appendix_dir.join("spine-index.md").exists());
        assert!(default_appendix_dir
            .join("layer-invariant-matrix.md")
            .exists());
        assert!(!default_modules_dir.exists());
        let spine_registry = vault.join("meta/Concept Spine Index.generated.md");
        assert!(spine_registry.exists());
        let spine = fs::read_to_string(default_appendix_dir.join("spine-index.md")).unwrap();
        assert!(spine.contains("# Spine Index Appendix"));
        assert!(spine.contains("Concept -> Spine Index (Generated)"));

        let out_no_appendix = vault.join("exports/book-no-appendix.md");
        let custom_appendix = vault.join("exports/custom-appendices");
        run_book_build(VaultBookBuildArgs {
            path: vault.to_path_buf(),
            out: Some(out_no_appendix),
            appendix_dir: Some(custom_appendix.clone()),
            spine_registry: None,
            no_appendices: true,
            explain: None,
            format: VaultBookOutputFormat::Markdown,
            template: None,
            keep_tex: false,
            book_profile: VaultBookProfile::Hybrid,
            all_concepts: false,
            dry_run: false,
            force: false,
            json: false,
        })
        .unwrap();
        assert!(!custom_appendix.join("spine-index.md").exists());
        assert!(!custom_appendix.join("layer-invariant-matrix.md").exists());
        let no_appendix_modules_dir =
            default_book_modules_dir(&vault.join("exports/book-no-appendix.md"));
        assert!(!no_appendix_modules_dir.exists());
        assert!(spine_registry.exists());
    }

    #[test]
    fn book_writes_latex_from_ast_template() {
        let td = TempDir::new().unwrap();
        let vault = td.path();
        bootstrap_invariants(vault);

        write(
            &vault.join("concepts/foo.md"),
            r#"---
role: concept
layer: primitive
canonical: true
invariants:
  - governance
---
# Foo

## Structural dependencies

None (primitive)
"#,
        );

        let template = vault.join("book-template.tex");
        write(
            &template,
            r#"\documentclass{book}
\usepackage{irrevbook}
\begin{document}
% custom template sentinel
{{BODY}}
{{APPENDICES}}
\end{document}
"#,
        );

        let out_tex = vault.join("exports/book.tex");
        run_book_build(VaultBookBuildArgs {
            path: vault.to_path_buf(),
            out: Some(out_tex.clone()),
            appendix_dir: None,
            spine_registry: None,
            no_appendices: true,
            explain: None,
            format: VaultBookOutputFormat::Latex,
            template: Some(template),
            keep_tex: false,
            book_profile: VaultBookProfile::Hybrid,
            all_concepts: false,
            dry_run: false,
            force: false,
            json: false,
        })
        .unwrap();

        let tex = fs::read_to_string(out_tex).unwrap();
        assert!(tex.contains("% custom template sentinel"));
        assert!(tex.contains("\\input{modules/book/"));
        let modules_dir = default_book_modules_dir(&vault.join("exports/book.tex"));
        assert!(modules_dir.exists());
        assert!(count_files_with_ext(&modules_dir, "tex") > 3);
        let primitive =
            fs::read_to_string(modules_dir.join("02-layers/01-primitives/001-foo.tex")).unwrap();
        assert!(primitive.contains("\\begin{irrevconcept}{foo}{Foo}"));
    }
}

#[cfg(test)]
mod spines_tests {
    use super::*;
    use tempfile::TempDir;

    fn write(p: &Path, s: &str) {
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, s).unwrap();
    }

    #[test]
    fn spine_generate_assigns_core_from_minimal_decomposition() {
        let td = TempDir::new().unwrap();
        let vault = td.path();
        write(
            &vault.join("concepts/control-surface.md"),
            r#"---
role: concept
layer: primitive
---
# Control Surface
"#,
        );
        write(
            &vault.join("concepts/constraint-surface.md"),
            r#"---
role: concept
layer: primitive
---
# Constraint Surface
"#,
        );
        write(
            &vault.join("invariants/Attribution.md"),
            r#"---
role: invariant
invariant_id: attribution
---
# Attribution

## Minimal decomposition

- [[control-surface]]
"#,
        );
        write(
            &vault.join("invariants/Governance.md"),
            r#"---
role: invariant
invariant_id: governance
---
# Governance

## Minimal decomposition

- [[constraint-surface]]
"#,
        );

        let (index, md) = build_concept_spine_index_and_markdown(vault).unwrap();
        let cs = index
            .concepts
            .iter()
            .find(|c| c.id == "control-surface")
            .unwrap();
        assert_eq!(cs.primary_spine, "attribution");
        assert!(matches!(cs.tier, ConceptTier::Core));
        let gov = index
            .concepts
            .iter()
            .find(|c| c.id == "constraint-surface")
            .unwrap();
        assert_eq!(gov.primary_spine, "governance");
        assert!(matches!(gov.tier, ConceptTier::Core));
        assert!(md.contains("## Dependency classes (by layer)"));
        assert!(md.contains("### Concepts :: Primitives"));
        assert!(md.contains("[control-surface](#concept-control-surface)"));
        assert!(md.contains("## Invariant spine index"));
        assert!(md.contains("#### Core"));
        assert!(md.contains("## Operator (diagnostic sequence)"));
        assert!(md.contains("## Boundaries (distinctions)"));
    }

    #[test]
    fn spine_generate_renders_compact_layer_inventory() {
        let td = TempDir::new().unwrap();
        let vault = td.path();
        write(
            &vault.join("concepts/base.md"),
            r#"---
role: concept
layer: primitive
summary: base primitive role
---
# Base
"#,
        );
        write(
            &vault.join("concepts/derived.md"),
            r#"---
role: concept
layer: first-order
description: derived role summary
---
# Derived

## Structural dependencies

- [[base]]
"#,
        );
        write(
            &vault.join("invariants/Governance.md"),
            r#"---
role: invariant
invariant_id: governance
---
# Governance

## Minimal decomposition

- [[derived]]
"#,
        );

        let (_index, md) = build_concept_spine_index_and_markdown(vault).unwrap();
        assert!(md.contains("### Concepts :: Primitives"));
        assert!(md.contains("[base](#concept-base)"));
        assert!(md.contains("### Concepts :: First-order composites"));
        assert!(md.contains("[derived](#concept-derived)"));
        assert!(md.contains("concept count:"));
    }

    #[test]
    fn spine_audit_reports_unreferenced_concepts() {
        let td = TempDir::new().unwrap();
        let vault = td.path();
        write(
            &vault.join("concepts/ratchet.md"),
            r#"---
role: concept
layer: mechanism
---
# Ratchet
"#,
        );
        write(
            &vault.join("invariants/Irreversibility (Invariant).md"),
            r#"---
role: invariant
invariant_id: irreversibility
---
# Irreversibility

## Minimal decomposition

- [[nonexistent]]
"#,
        );
        let report = build_spines_audit_report(vault, false).unwrap();
        assert!(report.contains("## Zero refs (inv/diag)"));
        assert!(report.contains("[[ratchet]]"));
    }
}
