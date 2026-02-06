/// Helpers for dealing with "vault prefix" filtering across different ingest roots.
///
/// When ingesting a vault directory directly (e.g. `...\irrev-vault`), doc paths are typically
/// root-relative like `Foo.md`, not prefixed like `irrev-vault/Foo.md`. Many operations want
/// a configurable "vault prefix" filter, but that filter must degrade safely when the configured
/// prefixes match nothing.

/// Select the best (longest) vault prefix that matches `doc_path`.
///
/// Returns `""` when no configured prefix matches (i.e. treat as root-relative).
pub fn select_vault_prefix_for_doc_path(doc_path: &str, vault_prefixes: &[String]) -> String {
    let mut best: Option<&str> = None;
    for p in vault_prefixes {
        if p.is_empty() {
            // Empty prefix matches everything but we only want it if nothing else matches.
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

/// If the configured `vault_prefixes` match **zero** of the provided `doc_paths`, fall back to `[""]`.
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

#[cfg(test)]
mod tests {
    use super::*;

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

