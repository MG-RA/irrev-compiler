use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownScope {
    pub id: &'static str,
    pub default_enabled: bool,
}

pub const KNOWN_SCOPES: [KnownScope; 5] = [
    KnownScope {
        id: "rust.ir_lint",
        default_enabled: true,
    },
    KnownScope {
        id: "markdown.chunk",
        default_enabled: true,
    },
    KnownScope {
        id: "ingest.dir",
        default_enabled: true,
    },
    KnownScope {
        id: "obsidian.links",
        default_enabled: false,
    },
    KnownScope {
        id: "vault.ir_lint",
        default_enabled: false,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScopeOperation {
    RustIrLint,
    ObsidianLinksProjection,
    IngestDir,
}

#[derive(Debug, Clone)]
pub struct ScopeEnablement {
    pub enabled: Vec<String>,
    pub source: Option<PathBuf>,
}

impl ScopeEnablement {
    pub fn allows(&self, operation: ScopeOperation) -> bool {
        operation_is_enabled(&self.enabled, operation)
    }

    pub fn enabled_scope_ids(&self) -> &[String] {
        &self.enabled
    }
}

#[derive(Debug, Deserialize)]
struct AdmitTomlConfig {
    scopes: Option<AdmitTomlScopesSection>,
}

#[derive(Debug, Deserialize)]
struct AdmitTomlScopesSection {
    enabled: Option<Vec<String>>,
}

pub fn scope_operation_human_hint(operation: ScopeOperation) -> &'static str {
    match operation {
        ScopeOperation::RustIrLint => "rust.ir_lint",
        ScopeOperation::ObsidianLinksProjection => "obsidian.links or vault.ir_lint",
        ScopeOperation::IngestDir => "ingest.dir",
    }
}

pub fn resolve_scope_enablement(root_hint: &Path) -> Result<ScopeEnablement, String> {
    let admit_toml = admit_toml_path_for_root_hint(root_hint);
    if !admit_toml.exists() {
        return Ok(ScopeEnablement {
            enabled: default_enabled_scopes(),
            source: None,
        });
    }

    let raw = std::fs::read_to_string(&admit_toml)
        .map_err(|err| format!("read {}: {}", admit_toml.display(), err))?;
    let parsed: AdmitTomlConfig =
        toml::from_str(&raw).map_err(|err| format!("parse {}: {}", admit_toml.display(), err))?;

    let enabled = parsed
        .scopes
        .and_then(|scopes| scopes.enabled)
        .map(normalize_scope_entries)
        .filter(|enabled| !enabled.is_empty())
        .unwrap_or_else(default_enabled_scopes);

    Ok(ScopeEnablement {
        enabled,
        source: Some(admit_toml),
    })
}

pub fn operation_is_enabled(enabled_scopes: &[String], operation: ScopeOperation) -> bool {
    match operation {
        ScopeOperation::RustIrLint => scope_is_enabled(enabled_scopes, "rust.ir_lint"),
        ScopeOperation::ObsidianLinksProjection => {
            scope_is_enabled(enabled_scopes, "obsidian.links")
                || scope_is_enabled(enabled_scopes, "vault.ir_lint")
        }
        ScopeOperation::IngestDir => scope_is_enabled(enabled_scopes, "ingest.dir"),
    }
}

pub fn scope_is_enabled(enabled_scopes: &[String], scope: &str) -> bool {
    let Some(target) = normalize_scope_entry(scope) else {
        return false;
    };
    enabled_scopes.iter().any(|enabled| enabled == &target)
}

fn admit_toml_path_for_root_hint(root_hint: &Path) -> PathBuf {
    let base = if root_hint.is_file() {
        root_hint.parent().unwrap_or_else(|| Path::new("."))
    } else {
        root_hint
    };
    base.join("admit.toml")
}

fn default_enabled_scopes() -> Vec<String> {
    KNOWN_SCOPES
        .iter()
        .filter(|scope| scope.default_enabled)
        .map(|scope| scope.id.to_string())
        .collect()
}

fn normalize_scope_entry(scope: &str) -> Option<String> {
    let mut normalized = scope.trim().to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    if let Some(stripped) = normalized.strip_prefix("scope:") {
        normalized = stripped.to_string();
    }
    if normalized.is_empty() {
        return None;
    }
    Some(normalized)
}

fn normalize_scope_entries(scopes: Vec<String>) -> Vec<String> {
    let mut out = Vec::new();
    for scope in scopes {
        let Some(normalized) = normalize_scope_entry(&scope) else {
            continue;
        };
        if !out.iter().any(|existing| existing == &normalized) {
            out.push(normalized);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("admit-scope-enablement-{}-{}", label, nanos))
    }

    #[test]
    fn resolve_scope_enablement_uses_defaults_when_missing() {
        let dir = temp_dir("defaults");
        std::fs::create_dir_all(&dir).expect("create temp dir");

        let resolved = resolve_scope_enablement(&dir).expect("resolve scope enablement");
        assert_eq!(resolved.source, None);
        assert!(resolved.allows(ScopeOperation::RustIrLint));
        assert!(!resolved.allows(ScopeOperation::ObsidianLinksProjection));
    }

    #[test]
    fn resolve_scope_enablement_reads_enabled_scopes_from_admit_toml() {
        let dir = temp_dir("custom");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        std::fs::write(
            dir.join("admit.toml"),
            r#"[scopes]
enabled = ["scope:rust.ir_lint", "OBSIDIAN.LINKS", "vault.ir_lint", "obsidian.links"]
"#,
        )
        .expect("write admit.toml");

        let resolved = resolve_scope_enablement(&dir).expect("resolve scope enablement");
        assert_eq!(resolved.source, Some(dir.join("admit.toml")));
        assert_eq!(
            resolved.enabled_scope_ids(),
            &[
                "rust.ir_lint".to_string(),
                "obsidian.links".to_string(),
                "vault.ir_lint".to_string()
            ]
        );
        assert!(resolved.allows(ScopeOperation::ObsidianLinksProjection));
    }

    #[test]
    fn resolve_scope_enablement_empty_scopes_falls_back_to_defaults() {
        let dir = temp_dir("empty");
        std::fs::create_dir_all(&dir).expect("create temp dir");
        std::fs::write(
            dir.join("admit.toml"),
            r#"[scopes]
enabled = []
"#,
        )
        .expect("write admit.toml");

        let resolved = resolve_scope_enablement(&dir).expect("resolve scope enablement");
        assert!(resolved.allows(ScopeOperation::RustIrLint));
        assert!(!resolved.allows(ScopeOperation::ObsidianLinksProjection));
    }
}
