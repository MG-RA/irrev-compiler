use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Top-level artifact type registry loaded from `artifact-types.toml`.
///
/// Design principle: vault owns policy, tool enforces it.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ArtifactTypeRegistry {
    pub registry_version: u32,
    pub description: String,
    #[serde(default)]
    pub defaults: RegistryDefaults,
    #[serde(rename = "types")]
    pub types: Vec<ArtifactTypeDef>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct RegistryDefaults {
    #[serde(default)]
    pub linkable: bool,
    #[serde(default = "default_true")]
    pub requires_frontmatter: bool,
    #[serde(default)]
    pub governance_scope: Option<String>,
}

fn default_true() -> bool {
    true
}

/// A single artifact type definition (e.g. `vault:concept`, `vault:diagnostic`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ArtifactTypeDef {
    pub type_id: String,
    pub description: String,
    #[serde(default)]
    pub locations: LocationConstraints,
    #[serde(default)]
    pub metadata: MetadataConstraints,
    #[serde(default)]
    pub governance: GovernanceConstraints,
    #[serde(default)]
    pub validation: ValidationConstraints,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct LocationConstraints {
    #[serde(default)]
    pub allowed_patterns: Vec<String>,
    #[serde(default)]
    pub allowed_extensions: Vec<String>,
    #[serde(default)]
    pub forbidden_patterns: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct MetadataConstraints {
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub optional: Vec<String>,
    #[serde(default)]
    pub constraints: BTreeMap<String, FieldConstraint>,
}

/// A constraint on a single frontmatter field, tagged by `type`.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FieldConstraint {
    Literal {
        value: String,
    },
    Enum {
        values: Vec<String>,
    },
    Boolean {
        #[serde(default)]
        default: Option<bool>,
    },
    List {
        #[serde(default)]
        item_type: Option<String>,
        #[serde(default)]
        allowed: Option<Vec<String>>,
    },
    String {},
    Integer {},
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct GovernanceConstraints {
    #[serde(default)]
    pub linkable: bool,
    #[serde(default)]
    pub requires_envelope: bool,
    #[serde(default)]
    pub requires_frontmatter: Option<bool>,
    #[serde(default)]
    pub invariants: Vec<String>,
    #[serde(default)]
    pub required_sections: Vec<String>,
    #[serde(default)]
    pub ephemeral: bool,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ValidationConstraints {
    #[serde(default)]
    pub enforce_unique_canonical: bool,
    #[serde(default)]
    pub enforce_layer_dependencies: bool,
    #[serde(default)]
    pub enforce_schema: bool,
    #[serde(default)]
    pub git_ignore_recommended: bool,
}

impl ArtifactTypeRegistry {
    /// Parse an artifact type registry from TOML content.
    pub fn from_toml(content: &str) -> Result<Self, String> {
        toml::from_str(content).map_err(|e| format!("parse artifact-types.toml: {e}"))
    }
}

impl ArtifactTypeDef {
    /// Whether this type requires frontmatter (checks governance override, then registry default).
    pub fn requires_frontmatter(&self, defaults: &RegistryDefaults) -> bool {
        self.governance
            .requires_frontmatter
            .unwrap_or(defaults.requires_frontmatter)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_registry() {
        let toml = r#"
registry_version = 1
description = "test"

[[types]]
type_id = "vault:concept"
description = "A concept"

[types.locations]
allowed_patterns = ["concepts/*.md"]
allowed_extensions = [".md"]

[types.metadata]
required = ["role", "layer"]

[types.metadata.constraints]
role = { type = "literal", value = "concept" }
layer = { type = "enum", values = ["primitive", "first-order"] }
canonical = { type = "boolean" }
aliases = { type = "list", item_type = "string" }
"#;
        let reg = ArtifactTypeRegistry::from_toml(toml).unwrap();
        assert_eq!(reg.registry_version, 1);
        assert_eq!(reg.types.len(), 1);
        let t = &reg.types[0];
        assert_eq!(t.type_id, "vault:concept");
        assert_eq!(t.locations.allowed_patterns, vec!["concepts/*.md"]);
        assert_eq!(t.metadata.required, vec!["role", "layer"]);
        assert_eq!(t.metadata.constraints.len(), 4);
        match &t.metadata.constraints["role"] {
            FieldConstraint::Literal { value } => assert_eq!(value, "concept"),
            other => panic!("expected Literal, got {other:?}"),
        }
        match &t.metadata.constraints["layer"] {
            FieldConstraint::Enum { values } => {
                assert_eq!(values, &["primitive", "first-order"]);
            }
            other => panic!("expected Enum, got {other:?}"),
        }
    }

    #[test]
    fn parse_real_artifact_types_toml() {
        let content = include_str!("../../../../irrev-vault/meta/artifact-types.toml");
        let reg = ArtifactTypeRegistry::from_toml(content).unwrap();
        assert_eq!(reg.registry_version, 1);
        assert!(
            reg.types.len() >= 10,
            "expected at least 10 types, got {}",
            reg.types.len()
        );

        // Spot-check a few types
        let concept = reg
            .types
            .iter()
            .find(|t| t.type_id == "vault:concept")
            .unwrap();
        assert!(concept.metadata.required.contains(&"role".to_string()));
        assert!(concept.metadata.required.contains(&"layer".to_string()));
        assert!(concept.metadata.required.contains(&"canonical".to_string()));

        let diag = reg
            .types
            .iter()
            .find(|t| t.type_id == "vault:diagnostic")
            .unwrap();
        assert_eq!(diag.locations.allowed_patterns, vec!["diagnostics/**/*.md"]);

        let ruleset = reg
            .types
            .iter()
            .find(|t| t.type_id == "vault:ruleset")
            .unwrap();
        assert_eq!(ruleset.locations.allowed_extensions, vec![".toml"]);
        assert!(!ruleset.requires_frontmatter(&reg.defaults));
    }
}
