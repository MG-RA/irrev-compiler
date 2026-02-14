use serde_json::Value;
use std::collections::BTreeMap;

/// Extract YAML frontmatter from markdown content.
///
/// Returns `Some((fields, end_line))` where `end_line` is the 1-based line number
/// of the closing `---` delimiter. Returns `None` if no valid frontmatter block found.
pub fn extract_frontmatter(input: &str) -> Option<(BTreeMap<String, Value>, u32)> {
    let mut lines = input.lines();

    // First line must be "---" (with optional BOM)
    let first = lines.next()?.trim_start_matches('\u{feff}').trim_end();
    if first != "---" {
        return None;
    }

    let mut yaml_lines: Vec<&str> = Vec::new();
    let mut end_line: u32 = 1; // 1-based, starting after the opening ---

    for line in lines {
        end_line += 1;
        let trimmed = line.trim_end();
        if trimmed == "---" || trimmed == "..." {
            break;
        }
        yaml_lines.push(line);
    }

    if yaml_lines.is_empty() {
        return None;
    }

    let raw_yaml = yaml_lines.join("\n");
    parse_yaml_to_json_map(&raw_yaml).map(|map| (map, end_line))
}

/// Parse a YAML string into a JSON-compatible BTreeMap.
///
/// Uses serde_yaml to parse, then converts to serde_json::Value
/// for uniform downstream handling.
fn parse_yaml_to_json_map(yaml: &str) -> Option<BTreeMap<String, Value>> {
    let yaml_value: serde_yaml::Value = serde_yaml::from_str(yaml).ok()?;
    let json_value: Value = serde_json::to_value(yaml_value).ok()?;

    match json_value {
        Value::Object(map) => Some(map.into_iter().collect()),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_frontmatter() {
        let input = "---\nrole: concept\nlayer: primitive\ncanonical: true\n---\n# Title\nBody";
        let (fm, end_line) = extract_frontmatter(input).unwrap();
        assert_eq!(fm["role"], Value::String("concept".into()));
        assert_eq!(fm["layer"], Value::String("primitive".into()));
        assert_eq!(fm["canonical"], Value::Bool(true));
        assert_eq!(end_line, 5);
    }

    #[test]
    fn frontmatter_with_lists() {
        let input = "---\naliases:\n  - one\n  - two\nfacets:\n  - implicit-constraint\n---\n";
        let (fm, _) = extract_frontmatter(input).unwrap();
        let aliases = fm["aliases"].as_array().unwrap();
        assert_eq!(aliases.len(), 2);
        assert_eq!(aliases[0], Value::String("one".into()));
    }

    #[test]
    fn frontmatter_with_bom() {
        let input = "\u{feff}---\nrole: concept\n---\n";
        let (fm, _) = extract_frontmatter(input).unwrap();
        assert_eq!(fm["role"], Value::String("concept".into()));
    }

    #[test]
    fn no_frontmatter() {
        assert!(extract_frontmatter("# Title\nBody").is_none());
    }

    #[test]
    fn empty_frontmatter() {
        assert!(extract_frontmatter("---\n---\n").is_none());
    }

    #[test]
    fn depends_on_with_wikilinks() {
        let input = "---\ndepends_on:\n  - \"[[Concept A]]\"\n  - \"[[Concept B]]\"\n---\n";
        let (fm, _) = extract_frontmatter(input).unwrap();
        let deps = fm["depends_on"].as_array().unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[0], Value::String("[[Concept A]]".into()));
    }
}
