//! Pure link resolution logic for Obsidian vault links.
//!
//! This module extracts business logic from the projection layer, making it:
//! - Testable without database dependencies
//! - Reusable in LSP/CLI tools
//! - Independent of IO concerns
//!
//! The resolver handles:
//! - Obsidian wikilink syntax parsing (`[[target]]`, `[[target|alias]]`, `[[target#heading]]`)
//! - Title-based resolution (exact and case-insensitive)
//! - Path-based resolution (relative and absolute)
//! - Ambiguity resolution heuristics
//! - Asset/file link resolution
//! - Heading validation

use admit_dag::GovernedDag;
use admit_dag::NodeKind;
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub const OBSIDIAN_VAULT_LINKS_PHASE: &str = "obsidian_vault_links";
pub const LEGACY_VAULT_LINKS_PHASE: &str = "vault_links";

/// Returns true when a projection phase refers to the Obsidian vault links phase.
pub fn is_obsidian_vault_links_phase(phase: &str) -> bool {
    matches!(phase, OBSIDIAN_VAULT_LINKS_PHASE | LEGACY_VAULT_LINKS_PHASE)
}

/// Normalize a phase name to the legacy storage key used by existing run records.
pub fn normalize_obsidian_vault_links_phase(phase: &str) -> String {
    if is_obsidian_vault_links_phase(phase) {
        LEGACY_VAULT_LINKS_PHASE.to_string()
    } else {
        phase.to_string()
    }
}

/// Represents a parsed Obsidian wikilink from markdown text.
#[derive(Debug, Clone)]
pub struct ObsidianLink {
    pub raw: String,
    pub target: String,
    pub alias: Option<String>,
    pub heading: Option<String>,
    pub embed: bool,
    pub line: u32,
}

/// Result of resolving a wikilink to a target document.
#[derive(Debug, Clone)]
pub struct ResolutionResult {
    pub resolved: Option<String>,
    pub kind: String,
    pub candidates: Vec<String>,
    pub norm_target: String,
    pub norm_alias: Option<String>,
    pub norm_heading: Option<String>,
}

/// Result of resolving an asset/file link.
#[derive(Debug, Clone)]
pub struct AssetResolution {
    pub to_file_path: String,
    pub to_file_node_id: String,
    pub kind: String,
}

/// Represents a vault document with metadata.
#[derive(Debug, Clone)]
pub struct VaultDoc {
    pub doc_path: String,
    pub doc_id: String,
    pub file_node_id: String,
    pub title: String,
    pub artifact_sha256: String,
    pub artifact_abs_path: std::path::PathBuf,
}

/// Pure link resolver - no database dependencies.
///
/// This resolver builds indexes from a GovernedDag and provides pure
/// resolution logic without any IO or database operations.
pub struct VaultLinkResolver {
    vault_docs: BTreeMap<String, VaultDoc>,
    title_exact_index: BTreeMap<String, BTreeSet<String>>,
    title_casefold_index: BTreeMap<String, BTreeSet<String>>,
    heading_index: BTreeMap<String, BTreeSet<String>>,
    vault_files: BTreeMap<String, String>,
}

impl VaultLinkResolver {
    /// Builds a resolver from a DAG and vault configuration.
    ///
    /// # Arguments
    /// * `dag` - The governed DAG containing file and chunk nodes
    /// * `artifacts_root` - Root directory for artifact paths
    /// * `vault_prefixes` - List of vault root prefixes (e.g., ["irrev-vault/", "chatgpt/vault/"])
    pub fn from_dag(
        dag: &GovernedDag,
        artifacts_root: &Path,
        vault_prefixes: &[&str],
    ) -> Result<Self, String> {
        // Build vault docs index
        let mut vault_docs = BTreeMap::new();
        for (id, node) in dag.nodes() {
            let NodeKind::FileAtPath { path, .. } = &node.kind else {
                continue;
            };
            if !path.to_lowercase().ends_with(".md") {
                continue;
            }
            if !vault_prefixes.iter().any(|p| path.starts_with(p)) {
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
            vault_docs.insert(path.clone(), doc);
        }

        // Build title indexes
        let mut title_exact_index: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut title_casefold_index: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

        for doc in vault_docs.values() {
            title_exact_index
                .entry(doc.title.clone())
                .or_default()
                .insert(doc.doc_path.clone());
            title_casefold_index
                .entry(doc.title.to_lowercase())
                .or_default()
                .insert(doc.doc_path.clone());
        }

        // Build heading index
        let heading_index = build_heading_index(dag, vault_prefixes);

        // Build file index (for asset resolution)
        let vault_files = build_file_index(dag, vault_prefixes);

        Ok(Self {
            vault_docs,
            title_exact_index,
            title_casefold_index,
            heading_index,
            vault_files,
        })
    }

    /// Resolves a wikilink from a source document to a target.
    pub fn resolve_link(&self, from: &str, link: &ObsidianLink) -> ResolutionResult {
        resolve_obsidian_target(
            from,
            &link.target,
            &self.vault_docs,
            &self.title_exact_index,
            &self.title_casefold_index,
        )
    }

    /// Resolves an asset/file link from a source document.
    pub fn resolve_asset(
        &self,
        from_doc_path: &str,
        raw_target: &str,
        vault_prefixes: &[&str],
    ) -> Option<AssetResolution> {
        resolve_obsidian_asset_target(from_doc_path, raw_target, vault_prefixes, &self.vault_files)
    }

    /// Validates a heading reference exists in the target document.
    pub fn validate_heading(&self, doc_path: &str, heading: &str) -> bool {
        if let Some(headings) = self.heading_index.get(doc_path) {
            let norm = normalize_heading(heading);
            let slug = obsidian_heading_slug(heading);
            headings.contains(&norm) || headings.contains(&slug)
        } else {
            false
        }
    }

    /// Returns all vault documents.
    pub fn vault_docs(&self) -> &BTreeMap<String, VaultDoc> {
        &self.vault_docs
    }

    /// Returns the heading index.
    pub fn heading_index(&self) -> &BTreeMap<String, BTreeSet<String>> {
        &self.heading_index
    }
}

// ============================================================================
// Link Resolution Functions
// ============================================================================

/// Resolves an Obsidian wikilink target to a document path.
///
/// Resolution strategy:
/// 1. Exact path match
/// 2. Exact path with .md appended
/// 3. Relative path from vault root
/// 4. Title-based resolution (exact case)
/// 5. Title-based resolution (case-insensitive)
pub fn resolve_obsidian_target(
    _from_doc_path: &str,
    raw_target: &str,
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
            candidates: vec![norm_target.clone()],
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

    // Path-like targets - these are handled by vault prefix logic in the caller
    // We don't handle vault_prefixes here to keep this function pure
    if norm_target.contains('/') {
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

/// Resolves an asset/file link target to a file path.
pub fn resolve_obsidian_asset_target(
    from_doc_path: &str,
    raw_target: &str,
    vault_prefixes: &[&str],
    vault_files: &BTreeMap<String, String>,
) -> Option<AssetResolution> {
    let t = normalize_target(raw_target);
    if t.is_empty() {
        return None;
    }

    let from_root = vault_root_for_path(from_doc_path, vault_prefixes);

    // Asset targets should generally resolve within the same vault root as the source note.
    if vault_files.contains_key(&t) {
        return Some(AssetResolution {
            to_file_node_id: vault_files.get(&t).cloned().unwrap(),
            to_file_path: t,
            kind: "exact_path".to_string(),
        });
    }

    if let Some(root) = from_root {
        if !t.starts_with(root) {
            let joined = format!("{}{}", root, t);
            if vault_files.contains_key(&joined) {
                return Some(AssetResolution {
                    to_file_node_id: vault_files.get(&joined).cloned().unwrap(),
                    to_file_path: joined,
                    kind: "prefix_join".to_string(),
                });
            }
        }
        return None;
    }

    // If we can't determine a vault root, fall back to checking all prefixes.
    for prefix in vault_prefixes {
        let joined = format!("{}{}", prefix, t);
        if vault_files.contains_key(&joined) {
            return Some(AssetResolution {
                to_file_node_id: vault_files.get(&joined).cloned().unwrap(),
                to_file_path: joined,
                kind: "prefix_join".to_string(),
            });
        }
    }

    None
}

/// Chooses the best target from ambiguous candidates.
///
/// Heuristics:
/// 1. Prefer same vault root as source document
/// 2. Prefer same neighborhood (concepts/, meta/, papers/, etc.)
/// 3. Prefer lexicographically first as tiebreaker
pub fn choose_ambiguous_target(
    from_doc_path: &str,
    candidates: &[String],
    vault_prefixes: &[&str],
) -> Option<(String, String)> {
    if candidates.is_empty() {
        return None;
    }

    let from_root = vault_root_for_path(from_doc_path, vault_prefixes);
    let from_root = from_root?;

    let in_same_root: Vec<&String> = candidates
        .iter()
        .filter(|c| c.starts_with(from_root))
        .collect();

    if in_same_root.len() == 1 {
        return Some((in_same_root[0].clone(), "prefer_same_root".to_string()));
    }

    let in_same_root = if in_same_root.is_empty() {
        // If the source is in one vault root but the candidates only exist in another,
        // allow deterministic resolution inside that other root.
        let all_in_same_prefix = vault_prefixes
            .iter()
            .find(|prefix| candidates.iter().all(|c| c.starts_with(*prefix)));

        if all_in_same_prefix.is_some() {
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
            return Some((matches[0].clone(), "prefer_neighborhood".to_string()));
        }

        if !matches.is_empty() {
            let mut sorted = matches.clone();
            sorted.sort();
            return Some((sorted[0].clone(), "first_in_neighborhood".to_string()));
        }
    }

    // Tiebreaker: lexicographically first.
    let mut sorted = in_same_root.clone();
    sorted.sort();
    Some((sorted[0].clone(), "lexicographic_first".to_string()))
}

// ============================================================================
// Helper Functions (Public for backward compatibility)
// ============================================================================

/// Builds an index of headings for each document.
pub fn build_heading_index(
    dag: &GovernedDag,
    vault_prefixes: &[&str],
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

/// Builds an index of file paths to node IDs.
pub fn build_file_index(dag: &GovernedDag, vault_prefixes: &[&str]) -> BTreeMap<String, String> {
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

/// Finds the vault root prefix for a given path.
pub fn vault_root_for_path<'a>(path: &str, vault_prefixes: &[&'a str]) -> Option<&'a str> {
    vault_prefixes
        .iter()
        .copied()
        .filter(|p| path.starts_with(*p))
        .max_by_key(|p| p.len())
}

/// Normalizes a link target by trimming, converting backslashes, and removing leading dots/slashes.
pub fn normalize_target(s: &str) -> String {
    let mut out = s.trim().replace('\\', "/");
    while out.starts_with("./") {
        out = out.trim_start_matches("./").to_string();
    }
    out = out.trim_start_matches('/').to_string();
    out
}

/// Normalizes a heading for comparison (lowercase, collapsed whitespace).
pub fn normalize_heading(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    let mut last_was_space = false;
    for ch in trimmed.chars() {
        if ch.is_whitespace() {
            if !last_was_space {
                out.push(' ');
                last_was_space = true;
            }
            continue;
        }
        last_was_space = false;
        out.push(ch.to_ascii_lowercase());
    }
    out.trim().to_string()
}

/// Converts a heading to an Obsidian-compatible slug.
pub fn obsidian_heading_slug(s: &str) -> String {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let mut out = String::new();
    let mut last_dash = false;
    for ch in trimmed.chars() {
        let ch = ch.to_ascii_lowercase();
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            last_dash = false;
            continue;
        }
        if ch.is_whitespace() || ch == '-' {
            if !last_dash {
                out.push('-');
                last_dash = true;
            }
            continue;
        }
    }
    out.trim_end_matches('-').to_string()
}

/// Extracts the file stem as a title from a path.
pub fn file_stem_title(path: &str) -> String {
    let p = Path::new(path);
    p.file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(path)
        .to_string()
}

/// Computes SHA256 hex string from input string.
pub fn sha256_hex_str(s: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

/// Extracts Obsidian wikilinks from markdown text.
pub fn extract_obsidian_links(input: &str) -> Vec<ObsidianLink> {
    let mut out = Vec::new();
    for (idx, line) in input.lines().enumerate() {
        let line_no = (idx as u32) + 1;
        let bytes = line.as_bytes();
        let mut i = 0usize;
        while i + 1 < bytes.len() {
            if bytes[i] == b'[' && bytes[i + 1] == b'[' {
                let embed = i > 0 && bytes[i - 1] == b'!';
                let start = i;
                i += 2;
                let mut end = None;
                let mut j = i;
                while j + 1 < bytes.len() {
                    if bytes[j] == b']' && bytes[j + 1] == b']' {
                        end = Some(j);
                        break;
                    }
                    j += 1;
                }
                if let Some(end) = end {
                    let inner = &line[i..end];
                    let raw_start = start.saturating_sub(if embed { 1 } else { 0 });
                    let raw = line[raw_start..end + 2].to_string();
                    let parsed = parse_obsidian_inner(inner);
                    if let Some((target, alias, heading)) = parsed {
                        out.push(ObsidianLink {
                            raw,
                            target,
                            alias,
                            heading,
                            embed,
                            line: line_no,
                        });
                    }
                    i = end + 2;
                    continue;
                }
            }
            i += 1;
        }
    }
    out
}

/// Parses the inner content of a wikilink.
pub fn parse_obsidian_inner(inner: &str) -> Option<(String, Option<String>, Option<String>)> {
    let trimmed = inner.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut parts = trimmed.splitn(2, '|');
    let left = parts.next()?.trim();
    let alias = parts
        .next()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let mut left_parts = left.splitn(2, '#');
    let target = left_parts.next()?.trim().to_string();
    let heading = left_parts
        .next()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    if target.is_empty() {
        return None;
    }
    Some((target, alias, heading))
}

/// Select the best (longest) configured vault prefix that matches `doc_path`.
///
/// Returns `""` when no configured prefix matches.
pub fn select_vault_prefix_for_doc_path(doc_path: &str, vault_prefixes: &[String]) -> String {
    let mut best: Option<&str> = None;
    for p in vault_prefixes {
        if p.is_empty() {
            continue;
        }
        if doc_path.starts_with(p) {
            match best {
                Some(b) if b.len() >= p.len() => {}
                _ => best = Some(p.as_str()),
            }
        }
    }
    best.unwrap_or("").to_string()
}

/// If configured prefixes match none of the provided doc paths, fall back to `[""]`.
///
/// Returns `(effective_prefixes, did_fallback)`.
pub fn effective_vault_prefixes_for_doc_paths(
    doc_paths: &[String],
    vault_prefixes: &[String],
) -> (Vec<String>, bool) {
    if vault_prefixes.is_empty() {
        return (vec!["".to_string()], false);
    }
    if doc_paths.is_empty() {
        return (vault_prefixes.to_vec(), false);
    }
    if vault_prefixes.iter().any(|p| p.is_empty()) {
        return (vault_prefixes.to_vec(), false);
    }

    let mut any_match = false;
    'outer: for doc_path in doc_paths {
        for p in vault_prefixes {
            if doc_path.starts_with(p) {
                any_match = true;
                break 'outer;
            }
        }
    }

    if any_match {
        (vault_prefixes.to_vec(), false)
    } else {
        (vec!["".to_string()], true)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_target() {
        assert_eq!(normalize_target("  foo/bar  "), "foo/bar");
        assert_eq!(normalize_target("./foo/bar"), "foo/bar");
        assert_eq!(normalize_target("foo\\bar"), "foo/bar");
        assert_eq!(normalize_target("/foo/bar"), "foo/bar");
    }

    #[test]
    fn test_normalize_heading() {
        assert_eq!(normalize_heading("  Hello  World  "), "hello world");
        assert_eq!(normalize_heading("CamelCase"), "camelcase");
        assert_eq!(normalize_heading(""), "");
    }

    #[test]
    fn test_obsidian_heading_slug() {
        assert_eq!(obsidian_heading_slug("Hello World"), "hello-world");
        assert_eq!(obsidian_heading_slug("Foo - Bar"), "foo-bar");
        assert_eq!(obsidian_heading_slug("A B  C"), "a-b-c");
    }

    #[test]
    fn test_file_stem_title() {
        assert_eq!(file_stem_title("foo/bar.md"), "bar");
        assert_eq!(file_stem_title("test.md"), "test");
        assert_eq!(file_stem_title("no-extension"), "no-extension");
    }

    #[test]
    fn test_parse_obsidian_inner() {
        assert_eq!(
            parse_obsidian_inner("target"),
            Some(("target".to_string(), None, None))
        );
        assert_eq!(
            parse_obsidian_inner("target|alias"),
            Some(("target".to_string(), Some("alias".to_string()), None))
        );
        assert_eq!(
            parse_obsidian_inner("target#heading"),
            Some(("target".to_string(), None, Some("heading".to_string())))
        );
        assert_eq!(
            parse_obsidian_inner("target#heading|alias"),
            Some((
                "target".to_string(),
                Some("alias".to_string()),
                Some("heading".to_string())
            ))
        );
        assert_eq!(parse_obsidian_inner(""), None);
    }

    #[test]
    fn test_extract_obsidian_links() {
        let text =
            "Some text [[target1]] and [[target2|alias]] here.\n![[embed]] and [[with#heading]]";
        let links = extract_obsidian_links(text);

        assert_eq!(links.len(), 4);
        assert_eq!(links[0].target, "target1");
        assert_eq!(links[0].embed, false);
        assert_eq!(links[1].target, "target2");
        assert_eq!(links[1].alias, Some("alias".to_string()));
        assert_eq!(links[2].target, "embed");
        assert_eq!(links[2].embed, true);
        assert_eq!(links[3].target, "with");
        assert_eq!(links[3].heading, Some("heading".to_string()));
    }

    #[test]
    fn test_vault_root_for_path() {
        let prefixes = vec!["irrev-vault/", "chatgpt/vault/"];
        assert_eq!(
            vault_root_for_path("irrev-vault/foo/bar.md", &prefixes),
            Some("irrev-vault/")
        );
        assert_eq!(
            vault_root_for_path("chatgpt/vault/foo.md", &prefixes),
            Some("chatgpt/vault/")
        );
        assert_eq!(vault_root_for_path("other/path.md", &prefixes), None);
    }

    #[test]
    fn phase_alias_helpers_accept_both_names() {
        assert!(is_obsidian_vault_links_phase(OBSIDIAN_VAULT_LINKS_PHASE));
        assert!(is_obsidian_vault_links_phase(LEGACY_VAULT_LINKS_PHASE));
        assert!(!is_obsidian_vault_links_phase("doc_chunks"));
        assert_eq!(
            normalize_obsidian_vault_links_phase(OBSIDIAN_VAULT_LINKS_PHASE),
            LEGACY_VAULT_LINKS_PHASE
        );
        assert_eq!(
            normalize_obsidian_vault_links_phase(LEGACY_VAULT_LINKS_PHASE),
            LEGACY_VAULT_LINKS_PHASE
        );
    }

    #[test]
    fn selects_longest_matching_prefix_or_root() {
        let prefixes = vec!["a/".to_string(), "a/b/".to_string()];
        assert_eq!(
            select_vault_prefix_for_doc_path("a/b/c.md", &prefixes),
            "a/b/"
        );
        assert_eq!(select_vault_prefix_for_doc_path("x.md", &prefixes), "");
    }

    #[test]
    fn falls_back_to_root_when_prefixes_match_nothing() {
        let prefixes = vec!["irrev-vault/".to_string(), "chatgpt/vault/".to_string()];
        let doc_paths = vec!["Foo.md".to_string(), "Bar/Baz.md".to_string()];
        let (effective, did_fallback) =
            effective_vault_prefixes_for_doc_paths(&doc_paths, &prefixes);
        assert!(did_fallback);
        assert_eq!(effective, vec!["".to_string()]);
    }

    #[test]
    fn does_not_fallback_when_any_prefix_matches() {
        let prefixes = vec!["irrev-vault/".to_string(), "chatgpt/vault/".to_string()];
        let doc_paths = vec!["irrev-vault/Foo.md".to_string()];
        let (effective, did_fallback) =
            effective_vault_prefixes_for_doc_paths(&doc_paths, &prefixes);
        assert!(!did_fallback);
        assert_eq!(effective, prefixes);
    }
}
