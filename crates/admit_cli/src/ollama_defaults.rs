/// Small helpers for embedding defaults (used by the CLI surface).

/// Default `(doc_prefix, query_prefix)` for a given embedding model.
///
/// We keep the nomic-style `search_document:` / `search_query:` defaults for
/// `nomic-embed-text*` models, and use empty prefixes for other models (e.g. Qwen).
pub fn default_prefixes_for_model(model: &str) -> (String, String) {
    if model.starts_with("nomic-embed-text") {
        (
            "search_document: ".to_string(),
            "search_query: ".to_string(),
        )
    } else {
        ("".to_string(), "".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_empty_for_qwen() {
        let (d, q) = default_prefixes_for_model("qwen3-embedding:0.6b");
        assert_eq!(d, "");
        assert_eq!(q, "");
    }

    #[test]
    fn defaults_are_search_for_nomic() {
        let (d, q) = default_prefixes_for_model("nomic-embed-text-v2");
        assert_eq!(d, "search_document: ");
        assert_eq!(q, "search_query: ");
    }
}
