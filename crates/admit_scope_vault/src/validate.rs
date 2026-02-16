use admit_core::LintFinding;
use admit_core::Severity;
use admit_core::Span;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

use crate::frontmatter::extract_frontmatter;
use crate::pattern_match::{has_allowed_extension, matches_forbidden, resolve_type};
use crate::type_registry::{ArtifactTypeDef, ArtifactTypeRegistry, FieldConstraint};

#[derive(Debug, Clone, Copy, Default)]
pub struct ValidateOptions {
    pub include_higher_order: bool,
}

/// Validate all vault files against the artifact type registry.
///
/// Each entry in `files` is `(vault_relative_path, file_content)`.
/// Returns a list of lint findings sorted by path.
pub fn validate_vault(
    registry: &ArtifactTypeRegistry,
    files: &[(String, String)],
) -> Vec<LintFinding> {
    validate_vault_with_options(registry, files, ValidateOptions::default())
}

pub fn validate_vault_with_options(
    registry: &ArtifactTypeRegistry,
    files: &[(String, String)],
    options: ValidateOptions,
) -> Vec<LintFinding> {
    let mut findings = Vec::new();

    for (path, content) in files {
        validate_file(registry, path, content, &mut findings);
    }

    if options.include_higher_order {
        run_higher_order_checks(registry, files, &mut findings);
    }

    findings.sort_by(|a, b| a.path.cmp(&b.path));
    findings
}

fn run_higher_order_checks(
    registry: &ArtifactTypeRegistry,
    files: &[(String, String)],
    findings: &mut Vec<LintFinding>,
) {
    let allowed_type_values = collect_enum_values(registry, "type");
    let allowed_facet_values = collect_allowed_list_values(registry, "facets");

    let tracked_roles: BTreeSet<&str> =
        BTreeSet::from(["concept", "diagnostic", "domain", "projection", "paper"]);
    let mut coverage_total = 0usize;
    let mut coverage_without_refs = 0usize;
    let mut coverage_counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    for invariant in INVARIANT_NAMES {
        coverage_counts.insert(invariant.name, 0);
    }

    for (path, content) in files {
        let typedef = resolve_type(path, &registry.types);
        let fm = extract_frontmatter(content).map(|(fm, _)| fm);

        if let Some(fm) = fm.as_ref() {
            // Taxonomy drift detection: surface newly introduced values even if
            // the specific type does not currently constrain the field.
            if let Some(value) = fm.get("type").and_then(|v| v.as_str()) {
                if !allowed_type_values.is_empty() && !allowed_type_values.contains(value) {
                    findings.push(finding(
                        "vault-higher-order/taxonomy-drift-type",
                        Severity::Error,
                        path,
                        None,
                        format!(
                            "frontmatter field `type` value `{value}` is not registered in artifact type enums"
                        ),
                    ));
                }
            }

            if let Some(facets) = fm.get("facets").and_then(|v| v.as_array()) {
                for facet in facets.iter().filter_map(|v| v.as_str()) {
                    if !allowed_facet_values.is_empty() && !allowed_facet_values.contains(facet) {
                        findings.push(finding(
                            "vault-higher-order/taxonomy-drift-facet",
                            Severity::Error,
                            path,
                            None,
                            format!(
                                "frontmatter field `facets` contains `{facet}` which is not registered"
                            ),
                        ));
                    }
                }
            }

            // Role purity checks (high-confidence only).
            if typedef.map(|t| t.type_id.as_str()) == Some("vault:support") {
                let role_specialized_fields = ["layer", "invariant_id", "template_for"];
                let mut leaked = Vec::new();
                for key in role_specialized_fields {
                    if fm.contains_key(key) {
                        leaked.push(key);
                    }
                }
                if !leaked.is_empty() {
                    findings.push(finding(
                        "vault-higher-order/role-purity",
                        Severity::Warning,
                        path,
                        None,
                        format!(
                            "support artifact carries role-specific fields: {}",
                            leaked.join(", ")
                        ),
                    ));
                }
            }

            let role = fm.get("role").and_then(|v| v.as_str());
            if let Some(role) = role {
                if role == "concept" {
                    if let Some(Value::Array(arr)) = fm.get("invariants") {
                        if arr.is_empty() {
                            findings.push(finding(
                                "vault-higher-order/concept-empty-invariants",
                                Severity::Error,
                                path,
                                None,
                                "concept frontmatter field `invariants` must be non-empty"
                                    .to_string(),
                            ));
                        }
                    }
                }

                if tracked_roles.contains(role) {
                    coverage_total += 1;
                    let refs = detect_invariant_references(fm, content);
                    if refs.is_empty() {
                        coverage_without_refs += 1;
                    } else {
                        for invariant in refs {
                            if let Some(count) = coverage_counts.get_mut(invariant) {
                                *count += 1;
                            }
                        }
                    }
                }
            }
        }

        // Template compliance: catch unresolved scaffolding in live artifacts.
        if path.starts_with("domains/") || path.starts_with("projections/") {
            if contains_template_placeholder(content) {
                findings.push(finding(
                    "vault-higher-order/template-placeholder",
                    Severity::Warning,
                    path,
                    None,
                    "unresolved template placeholder detected".to_string(),
                ));
            }
        }

        if path.starts_with("projections/")
            && !path.ends_with("Projections Index.md")
            && !has_projection_shape(content)
        {
            findings.push(finding(
                "vault-higher-order/template-shape",
                Severity::Warning,
                path,
                None,
                "projection note missing expected template sections".to_string(),
            ));
        }
    }

    if coverage_total > 0 {
        findings.push(finding(
            "vault-higher-order/invariant-coverage",
            Severity::Info,
            "vault://coverage",
            None,
            format!(
                "tracked_artifacts={coverage_total} without_invariant_refs={coverage_without_refs}"
            ),
        ));

        for invariant in INVARIANT_NAMES {
            let count = coverage_counts.get(invariant.name).copied().unwrap_or(0);
            findings.push(finding(
                "vault-higher-order/invariant-coverage",
                Severity::Info,
                "vault://coverage",
                None,
                format!("invariant={} referenced_by={count}", invariant.name),
            ));
        }
    }
}

struct InvariantDescriptor {
    name: &'static str,
    tokens: &'static [&'static str],
}

const INVARIANT_NAMES: &[InvariantDescriptor] = &[
    InvariantDescriptor {
        name: "irreversibility",
        tokens: &["[[irreversibility", "irreversibility (invariant)"],
    },
    InvariantDescriptor {
        name: "attribution",
        tokens: &["[[attribution]]", "attribution (invariant)"],
    },
    InvariantDescriptor {
        name: "governance",
        tokens: &["[[governance]]", "governance (invariant)"],
    },
    InvariantDescriptor {
        name: "decomposition",
        tokens: &["[[decomposition]]", "decomposition (invariant)"],
    },
];

fn detect_invariant_references(
    fm: &BTreeMap<String, Value>,
    content: &str,
) -> BTreeSet<&'static str> {
    let mut refs = BTreeSet::new();

    // Explicit invariant coverage declaration (preferred).
    if let Some(val) = fm.get("invariants") {
        let mut declared: Vec<&str> = Vec::new();
        match val {
            Value::String(s) => declared.push(s.as_str()),
            Value::Array(arr) => {
                for item in arr {
                    if let Value::String(s) = item {
                        declared.push(s.as_str());
                    }
                }
            }
            _ => {}
        }
        for raw in declared {
            let key = raw.trim().to_ascii_lowercase();
            for invariant in INVARIANT_NAMES {
                if key == invariant.name {
                    refs.insert(invariant.name);
                }
            }
        }
    }

    let haystack = format!(
        "{}\n{}",
        content.to_ascii_lowercase(),
        flatten_value_strings(fm)
    );

    for invariant in INVARIANT_NAMES {
        if invariant
            .tokens
            .iter()
            .any(|token| haystack.contains(token))
        {
            refs.insert(invariant.name);
        }
    }

    refs
}

fn flatten_value_strings(map: &BTreeMap<String, Value>) -> String {
    fn walk(value: &Value, out: &mut String) {
        match value {
            Value::String(s) => {
                out.push_str(&s.to_ascii_lowercase());
                out.push('\n');
            }
            Value::Array(arr) => {
                for item in arr {
                    walk(item, out);
                }
            }
            Value::Object(obj) => {
                for value in obj.values() {
                    walk(value, out);
                }
            }
            _ => {}
        }
    }

    let mut out = String::new();
    for value in map.values() {
        walk(value, &mut out);
    }
    out
}

fn contains_template_placeholder(content: &str) -> bool {
    content.contains("{{")
        || content.contains("}}")
        || content.contains("[Domain Name]")
        || content.contains("YYYY-MM-DD")
}

fn has_projection_shape(content: &str) -> bool {
    let lower = content.to_ascii_lowercase();
    lower.contains("## original framing")
        && lower.contains("## implicit constraint insight")
        && lower.contains("## what survives translation")
}

fn collect_enum_values(registry: &ArtifactTypeRegistry, field_name: &str) -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    for t in &registry.types {
        if let Some(FieldConstraint::Enum {
            values: enum_values,
        }) = t.metadata.constraints.get(field_name)
        {
            for value in enum_values {
                values.insert(value.clone());
            }
        }
    }
    values
}

fn collect_allowed_list_values(
    registry: &ArtifactTypeRegistry,
    field_name: &str,
) -> BTreeSet<String> {
    let mut values = BTreeSet::new();
    for t in &registry.types {
        if let Some(FieldConstraint::List {
            allowed: Some(allowed),
            ..
        }) = t.metadata.constraints.get(field_name)
        {
            for value in allowed {
                values.insert(value.clone());
            }
        }
    }
    values
}

fn validate_file(
    registry: &ArtifactTypeRegistry,
    path: &str,
    content: &str,
    findings: &mut Vec<LintFinding>,
) {
    let Some(typedef) = resolve_type(path, &registry.types) else {
        findings.push(finding(
            "vault-schema/untyped-file",
            Severity::Warning,
            path,
            None,
            format!("file matches no artifact type definition"),
        ));
        return;
    };

    // Extension check
    if !has_allowed_extension(path, typedef) {
        findings.push(finding(
            "vault-schema/extension-mismatch",
            Severity::Error,
            path,
            None,
            format!(
                "extension not allowed for type `{}`; expected one of: {}",
                typedef.type_id,
                typedef.locations.allowed_extensions.join(", ")
            ),
        ));
    }

    // Forbidden pattern check
    if matches_forbidden(path, typedef) {
        findings.push(finding(
            "vault-schema/forbidden-location",
            Severity::Error,
            path,
            None,
            format!(
                "file matches forbidden pattern for type `{}`",
                typedef.type_id
            ),
        ));
    }

    // Frontmatter checks
    let needs_frontmatter = typedef.requires_frontmatter(&registry.defaults);
    if !needs_frontmatter {
        return;
    }

    let Some((fm, _end_line)) = extract_frontmatter(content) else {
        findings.push(finding(
            "vault-schema/missing-frontmatter",
            Severity::Error,
            path,
            None,
            format!("frontmatter required for type `{}`", typedef.type_id),
        ));
        return;
    };

    validate_metadata(path, &fm, typedef, findings);
    validate_required_sections(path, content, typedef, findings);
}

fn validate_metadata(
    path: &str,
    fm: &BTreeMap<String, Value>,
    typedef: &ArtifactTypeDef,
    findings: &mut Vec<LintFinding>,
) {
    // Required fields
    for field in &typedef.metadata.required {
        if !fm.contains_key(field) {
            findings.push(finding(
                "vault-schema/missing-required-field",
                Severity::Error,
                path,
                None,
                format!(
                    "required field `{field}` missing in frontmatter (type `{}`)",
                    typedef.type_id
                ),
            ));
        }
    }

    // Field constraints
    for (field, constraint) in &typedef.metadata.constraints {
        if let Some(value) = fm.get(field) {
            validate_field_constraint(path, field, value, constraint, &typedef.type_id, findings);
        }
    }
}

fn validate_field_constraint(
    path: &str,
    field: &str,
    value: &Value,
    constraint: &FieldConstraint,
    type_id: &str,
    findings: &mut Vec<LintFinding>,
) {
    match constraint {
        FieldConstraint::Literal { value: expected } => {
            let actual = match value {
                Value::String(s) => s.as_str(),
                _ => {
                    findings.push(finding(
                        "vault-schema/type-mismatch",
                        Severity::Error,
                        path,
                        None,
                        format!(
                            "field `{field}` should be a string literal, got {}",
                            value_type_name(value)
                        ),
                    ));
                    return;
                }
            };
            if actual != expected {
                findings.push(finding(
                    "vault-schema/literal-mismatch",
                    Severity::Error,
                    path,
                    None,
                    format!(
                        "field `{field}` must be `{expected}`, got `{actual}` (type `{type_id}`)"
                    ),
                ));
            }
        }

        FieldConstraint::Enum { values } => {
            let actual = match value {
                Value::String(s) => s.as_str(),
                _ => {
                    findings.push(finding(
                        "vault-schema/type-mismatch",
                        Severity::Error,
                        path,
                        None,
                        format!(
                            "field `{field}` should be a string, got {}",
                            value_type_name(value)
                        ),
                    ));
                    return;
                }
            };
            if !values.iter().any(|v| v == actual) {
                findings.push(finding(
                    "vault-schema/enum-mismatch",
                    Severity::Error,
                    path,
                    None,
                    format!(
                        "field `{field}` value `{actual}` not in allowed values: [{}]",
                        values.join(", ")
                    ),
                ));
            }
        }

        FieldConstraint::Boolean { .. } => {
            if !value.is_boolean() {
                findings.push(finding(
                    "vault-schema/type-mismatch",
                    Severity::Error,
                    path,
                    None,
                    format!(
                        "field `{field}` should be a boolean, got {}",
                        value_type_name(value)
                    ),
                ));
            }
        }

        FieldConstraint::List { allowed, .. } => {
            let items = match value {
                Value::Array(arr) => arr,
                _ => {
                    findings.push(finding(
                        "vault-schema/type-mismatch",
                        Severity::Error,
                        path,
                        None,
                        format!(
                            "field `{field}` should be a list, got {}",
                            value_type_name(value)
                        ),
                    ));
                    return;
                }
            };

            if let Some(allowed_values) = allowed {
                for item in items {
                    if let Value::String(s) = item {
                        if !allowed_values.iter().any(|a| a == s) {
                            findings.push(finding(
                                "vault-schema/list-item-invalid",
                                Severity::Error,
                                path,
                                None,
                                format!(
                                    "field `{field}` contains `{s}` which is not in allowed values: [{}]",
                                    allowed_values.join(", ")
                                ),
                            ));
                        }
                    }
                }
            }
        }

        FieldConstraint::String {} => {
            if !value.is_string() {
                findings.push(finding(
                    "vault-schema/type-mismatch",
                    Severity::Error,
                    path,
                    None,
                    format!(
                        "field `{field}` should be a string, got {}",
                        value_type_name(value)
                    ),
                ));
            }
        }

        FieldConstraint::Integer {} => {
            if !value.is_i64() && !value.is_u64() {
                findings.push(finding(
                    "vault-schema/type-mismatch",
                    Severity::Error,
                    path,
                    None,
                    format!(
                        "field `{field}` should be an integer, got {}",
                        value_type_name(value)
                    ),
                ));
            }
        }
    }
}

fn validate_required_sections(
    path: &str,
    content: &str,
    typedef: &ArtifactTypeDef,
    findings: &mut Vec<LintFinding>,
) {
    for section in &typedef.governance.required_sections {
        let heading = format!("## {section}");
        if !content.lines().any(|line| line.trim() == heading) {
            findings.push(finding(
                "vault-schema/missing-section",
                Severity::Warning,
                path,
                None,
                format!("required section `{section}` not found"),
            ));
        }
    }
}

fn finding(
    rule_id: &str,
    severity: Severity,
    path: &str,
    line: Option<u32>,
    message: String,
) -> LintFinding {
    LintFinding {
        rule_id: rule_id.to_string(),
        severity,
        invariant: None,
        path: path.to_string(),
        span: Span {
            file: path.to_string(),
            start: None,
            end: None,
            line,
            col: None,
        },
        message,
        evidence: None,
    }
}

fn value_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_registry() -> ArtifactTypeRegistry {
        ArtifactTypeRegistry::from_toml(
            r#"
registry_version = 1
description = "test"

[defaults]
requires_frontmatter = true

[[types]]
type_id = "vault:concept"
description = "A concept"

[types.locations]
allowed_patterns = ["concepts/*.md"]
allowed_extensions = [".md"]
forbidden_patterns = ["concepts/_*"]

[types.metadata]
required = ["role", "layer", "canonical"]

[types.metadata.constraints]
role = { type = "literal", value = "concept" }
layer = { type = "enum", values = ["primitive", "first-order", "mechanism"] }
canonical = { type = "boolean" }
aliases = { type = "list", item_type = "string" }
facets = { type = "list", item_type = "string", allowed = ["implicit-constraint", "anti-belief"] }

[types.governance]
required_sections = ["Structural dependencies"]

[[types]]
type_id = "vault:config"
description = "Config"

[types.locations]
allowed_patterns = ["meta/*.yml"]
allowed_extensions = [".yml", ".yaml"]

[types.governance]
requires_frontmatter = false

[[types]]
type_id = "vault:support"
description = "Support doc"

[types.locations]
allowed_patterns = ["support/*.md"]
allowed_extensions = [".md"]

[types.metadata]
required = ["role"]
optional = ["type"]

[types.metadata.constraints]
role = { type = "literal", value = "support" }
type = { type = "enum", values = ["meta", "index"] }
"#,
        )
        .unwrap()
    }

    #[test]
    fn valid_concept() {
        let reg = test_registry();
        let files = vec![(
            "concepts/foo.md".to_string(),
            "---\nrole: concept\nlayer: primitive\ncanonical: true\n---\n## Structural dependencies\nNone".to_string(),
        )];
        let findings = validate_vault(&reg, &files);
        assert!(
            findings.is_empty(),
            "expected no findings, got: {findings:?}"
        );
    }

    #[test]
    fn missing_frontmatter() {
        let reg = test_registry();
        let files = vec![(
            "concepts/foo.md".to_string(),
            "# No frontmatter\nBody".to_string(),
        )];
        let findings = validate_vault(&reg, &files);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule_id, "vault-schema/missing-frontmatter");
    }

    #[test]
    fn missing_required_field() {
        let reg = test_registry();
        let files = vec![(
            "concepts/foo.md".to_string(),
            "---\nrole: concept\n---\n".to_string(),
        )];
        let findings = validate_vault(&reg, &files);
        let missing: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "vault-schema/missing-required-field")
            .collect();
        assert_eq!(missing.len(), 2); // layer and canonical
    }

    #[test]
    fn literal_mismatch() {
        let reg = test_registry();
        let files = vec![(
            "concepts/foo.md".to_string(),
            "---\nrole: paper\nlayer: primitive\ncanonical: true\n---\n".to_string(),
        )];
        let findings = validate_vault(&reg, &files);
        let literal: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "vault-schema/literal-mismatch")
            .collect();
        assert_eq!(literal.len(), 1);
        assert!(literal[0].message.contains("paper"));
    }

    #[test]
    fn enum_mismatch() {
        let reg = test_registry();
        let files = vec![(
            "concepts/foo.md".to_string(),
            "---\nrole: concept\nlayer: invalid-layer\ncanonical: true\n---\n".to_string(),
        )];
        let findings = validate_vault(&reg, &files);
        let enums: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "vault-schema/enum-mismatch")
            .collect();
        assert_eq!(enums.len(), 1);
        assert!(enums[0].message.contains("invalid-layer"));
    }

    #[test]
    fn type_mismatch_boolean() {
        let reg = test_registry();
        let files = vec![(
            "concepts/foo.md".to_string(),
            "---\nrole: concept\nlayer: primitive\ncanonical: \"yes\"\n---\n".to_string(),
        )];
        let findings = validate_vault(&reg, &files);
        let types: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "vault-schema/type-mismatch")
            .collect();
        assert_eq!(types.len(), 1);
        assert!(types[0].message.contains("boolean"));
    }

    #[test]
    fn list_item_invalid() {
        let reg = test_registry();
        let files = vec![(
            "concepts/foo.md".to_string(),
            "---\nrole: concept\nlayer: primitive\ncanonical: true\nfacets:\n  - unknown-facet\n---\n".to_string(),
        )];
        let findings = validate_vault(&reg, &files);
        let invalid: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "vault-schema/list-item-invalid")
            .collect();
        assert_eq!(invalid.len(), 1);
        assert!(invalid[0].message.contains("unknown-facet"));
    }

    #[test]
    fn forbidden_pattern() {
        let reg = test_registry();
        let files = vec![(
            "concepts/_private.md".to_string(),
            "---\nrole: concept\nlayer: primitive\ncanonical: true\n---\n".to_string(),
        )];
        let findings = validate_vault(&reg, &files);
        let forbidden: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "vault-schema/forbidden-location")
            .collect();
        assert_eq!(forbidden.len(), 1);
    }

    #[test]
    fn missing_section() {
        let reg = test_registry();
        let files = vec![(
            "concepts/foo.md".to_string(),
            "---\nrole: concept\nlayer: primitive\ncanonical: true\n---\n# Foo\nBody".to_string(),
        )];
        let findings = validate_vault(&reg, &files);
        let sections: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id == "vault-schema/missing-section")
            .collect();
        assert_eq!(sections.len(), 1);
        assert!(sections[0].message.contains("Structural dependencies"));
    }

    #[test]
    fn untyped_file() {
        let reg = test_registry();
        let files = vec![(
            "unknown/foo.md".to_string(),
            "---\nrole: something\n---\n".to_string(),
        )];
        let findings = validate_vault(&reg, &files);
        assert_eq!(findings[0].rule_id, "vault-schema/untyped-file");
    }

    #[test]
    fn config_file_no_frontmatter_ok() {
        let reg = test_registry();
        let files = vec![(
            "meta/hubs.yml".to_string(),
            "# YAML config\nhub_classes:\n  - name: Primitive".to_string(),
        )];
        let findings = validate_vault(&reg, &files);
        assert!(
            findings.is_empty(),
            "config files should not require frontmatter: {findings:?}"
        );
    }

    #[test]
    fn validate_real_vault() {
        let registry_content = include_str!("../testdata/artifact-types.toml");
        let reg = ArtifactTypeRegistry::from_toml(registry_content).unwrap();

        // Validate a known-good fixture concept file.
        let concept = include_str!("../testdata/concepts/irreversibility.md");
        let files = vec![(
            "concepts/irreversibility.md".to_string(),
            concept.to_string(),
        )];
        let findings = validate_vault(&reg, &files);

        // Filter out warnings (like missing-section) — focus on errors only
        let errors: Vec<_> = findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .collect();
        assert!(
            errors.is_empty(),
            "core concept file should have no errors: {errors:#?}"
        );
    }

    #[test]
    fn higher_order_flags_unknown_type_value() {
        let reg = test_registry();
        let files = vec![(
            "concepts/foo.md".to_string(),
            "---\nrole: concept\nlayer: primitive\ncanonical: true\ntype: not-registered\n---\n## Structural dependencies\nNone".to_string(),
        )];
        let findings = validate_vault_with_options(
            &reg,
            &files,
            ValidateOptions {
                include_higher_order: true,
            },
        );
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "vault-higher-order/taxonomy-drift-type"));
    }

    #[test]
    fn higher_order_flags_projection_placeholder() {
        let reg = test_registry();
        let files = vec![(
            "projections/foo.md".to_string(),
            "---\nrole: projection\n---\n# {{Projection Name}}\n".to_string(),
        )];
        let findings = validate_vault_with_options(
            &reg,
            &files,
            ValidateOptions {
                include_higher_order: true,
            },
        );
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "vault-higher-order/template-placeholder"));
    }

    #[test]
    fn higher_order_emits_invariant_coverage_summary() {
        let reg = test_registry();
        let files = vec![(
            "concepts/foo.md".to_string(),
            "---\nrole: concept\nlayer: primitive\ncanonical: true\n---\n[[Governance]]"
                .to_string(),
        )];
        let findings = validate_vault_with_options(
            &reg,
            &files,
            ValidateOptions {
                include_higher_order: true,
            },
        );
        assert!(findings
            .iter()
            .any(|f| f.rule_id == "vault-higher-order/invariant-coverage"
                && f.severity == Severity::Info));
    }
}
