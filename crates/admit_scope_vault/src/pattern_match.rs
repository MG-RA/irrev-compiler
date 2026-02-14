use crate::type_registry::ArtifactTypeDef;

/// Match a vault-relative file path against a glob pattern.
///
/// Supports `*` (single segment wildcard) and `**` (recursive wildcard).
/// Uses the `glob_match` crate for correct glob semantics.
pub fn matches_pattern(path: &str, pattern: &str) -> bool {
    // Normalize separators to forward slashes
    let path = path.replace('\\', "/");
    glob_match::glob_match(pattern, &path)
}

/// Resolve which artifact type a file matches, using most-specific-pattern-wins.
///
/// Specificity is determined by the number of literal (non-wildcard) path segments
/// in the matching pattern. More segments = more specific.
///
/// Returns `None` if no type matches the file path.
pub fn resolve_type<'a>(path: &str, types: &'a [ArtifactTypeDef]) -> Option<&'a ArtifactTypeDef> {
    let mut best: Option<(&ArtifactTypeDef, usize)> = None;

    for typedef in types {
        for pattern in &typedef.locations.allowed_patterns {
            if matches_pattern(path, pattern) {
                let specificity = pattern_specificity(pattern);
                if best.is_none() || specificity > best.unwrap().1 {
                    best = Some((typedef, specificity));
                }
            }
        }
    }

    best.map(|(t, _)| t)
}

/// Check if a file matches any forbidden pattern for its resolved type.
pub fn matches_forbidden(path: &str, typedef: &ArtifactTypeDef) -> bool {
    typedef
        .locations
        .forbidden_patterns
        .iter()
        .any(|pattern| matches_pattern(path, pattern))
}

/// Check if a file has an allowed extension for its resolved type.
/// Returns `true` if no extension constraints exist or the extension matches.
pub fn has_allowed_extension(path: &str, typedef: &ArtifactTypeDef) -> bool {
    if typedef.locations.allowed_extensions.is_empty() {
        return true;
    }
    typedef
        .locations
        .allowed_extensions
        .iter()
        .any(|ext| path.ends_with(ext))
}

/// Compute specificity of a glob pattern.
/// More literal path segments = higher specificity.
/// `**` contributes 0, `*` contributes 0, literal segments contribute 1 each.
fn pattern_specificity(pattern: &str) -> usize {
    pattern
        .split('/')
        .filter(|seg| *seg != "*" && *seg != "**" && !seg.contains('*'))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::type_registry::{
        ArtifactTypeDef, GovernanceConstraints, LocationConstraints, MetadataConstraints,
        ValidationConstraints,
    };

    fn make_type(type_id: &str, patterns: Vec<&str>) -> ArtifactTypeDef {
        ArtifactTypeDef {
            type_id: type_id.to_string(),
            description: String::new(),
            locations: LocationConstraints {
                allowed_patterns: patterns.into_iter().map(String::from).collect(),
                allowed_extensions: vec![".md".to_string()],
                forbidden_patterns: vec![],
            },
            metadata: MetadataConstraints::default(),
            governance: GovernanceConstraints::default(),
            validation: ValidationConstraints::default(),
        }
    }

    #[test]
    fn basic_glob_matching() {
        assert!(matches_pattern("concepts/foo.md", "concepts/*.md"));
        assert!(!matches_pattern("concepts/sub/foo.md", "concepts/*.md"));
        assert!(matches_pattern(
            "diagnostics/attr/check.md",
            "diagnostics/**/*.md"
        ));
        assert!(matches_pattern(
            "diagnostics/a/b/c.md",
            "diagnostics/**/*.md"
        ));
    }

    #[test]
    fn root_level_glob() {
        assert!(matches_pattern("index.md", "*.md"));
        assert!(matches_pattern("foo.md", "*.md"));
        assert!(!matches_pattern("sub/foo.md", "*.md"));
    }

    #[test]
    fn resolve_most_specific() {
        let types = vec![
            make_type("vault:concept", vec!["concepts/*.md"]),
            make_type("vault:support", vec!["*.md", "meta/*.md"]),
        ];
        let resolved = resolve_type("concepts/foo.md", &types).unwrap();
        assert_eq!(resolved.type_id, "vault:concept");
    }

    #[test]
    fn resolve_support_fallback() {
        let types = vec![
            make_type("vault:concept", vec!["concepts/*.md"]),
            make_type("vault:support", vec!["*.md"]),
        ];
        let resolved = resolve_type("index.md", &types).unwrap();
        assert_eq!(resolved.type_id, "vault:support");
    }

    #[test]
    fn resolve_no_match() {
        let types = vec![make_type("vault:concept", vec!["concepts/*.md"])];
        assert!(resolve_type("other/foo.md", &types).is_none());
    }

    #[test]
    fn pattern_specificity_ordering() {
        assert!(pattern_specificity("concepts/*.md") > pattern_specificity("*.md"));
        assert!(pattern_specificity("diagnostics/**/*.md") > pattern_specificity("*.md"));
        assert_eq!(pattern_specificity("*.md"), 0);
    }

    #[test]
    fn backslash_normalization() {
        assert!(matches_pattern("concepts\\foo.md", "concepts/*.md"));
    }
}
