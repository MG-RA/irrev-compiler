/// Helpers for dealing with "vault prefix" filtering across different ingest roots.
///
/// When ingesting a vault directory directly (e.g. `...\irrev-vault`), doc paths are typically
/// root-relative like `Foo.md`, not prefixed like `irrev-vault/Foo.md`. Many operations want
/// a configurable "vault prefix" filter, but that filter must degrade safely when the configured
/// prefixes match nothing.

pub fn select_vault_prefix_for_doc_path(doc_path: &str, vault_prefixes: &[String]) -> String {
    admit_scope_obsidian::select_vault_prefix_for_doc_path(doc_path, vault_prefixes)
}

pub fn effective_vault_prefixes_for_doc_paths(
    doc_paths: &[String],
    vault_prefixes: &[String],
) -> (Vec<String>, bool) {
    admit_scope_obsidian::effective_vault_prefixes_for_doc_paths(doc_paths, vault_prefixes)
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
