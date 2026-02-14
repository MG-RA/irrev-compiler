use std::path::{Path, PathBuf};

use admit_scope_vault::type_registry::ArtifactTypeRegistry;
use admit_scope_vault::validate::{validate_vault_with_options, ValidateOptions};

use super::types::DeclareCostError;

const ARTIFACT_TYPES_FILENAME: &str = "meta/artifact-types.toml";

#[derive(Debug, Clone)]
pub struct VaultSchemaLintInput {
    pub vault_root: PathBuf,
    pub json: bool,
    pub higher_order: bool,
}

#[derive(Debug, Clone)]
pub struct VaultSchemaLintOutput {
    pub files_scanned: u64,
    pub errors: u64,
    pub warnings: u64,
    pub passed: bool,
    pub findings: Vec<VaultSchemaFinding>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct VaultSchemaFinding {
    pub rule_id: String,
    pub severity: String,
    pub path: String,
    pub message: String,
}

pub fn run_vault_schema_lint(
    input: VaultSchemaLintInput,
) -> Result<VaultSchemaLintOutput, DeclareCostError> {
    let registry_path = input.vault_root.join(ARTIFACT_TYPES_FILENAME);
    if !registry_path.exists() {
        return Err(DeclareCostError::Io(format!(
            "artifact type registry not found: {}",
            registry_path.display()
        )));
    }

    let registry_content = std::fs::read_to_string(&registry_path)
        .map_err(|e| DeclareCostError::Io(format!("read {}: {e}", registry_path.display())))?;
    let registry =
        ArtifactTypeRegistry::from_toml(&registry_content).map_err(|e| DeclareCostError::Io(e))?;

    let files = collect_vault_files(&input.vault_root)?;
    let files_scanned = files.len() as u64;

    let lint_findings = validate_vault_with_options(
        &registry,
        &files,
        ValidateOptions {
            include_higher_order: input.higher_order,
        },
    );

    let findings: Vec<VaultSchemaFinding> = lint_findings
        .iter()
        .map(|f| VaultSchemaFinding {
            rule_id: f.rule_id.clone(),
            severity: format!("{:?}", f.severity).to_lowercase(),
            path: f.path.clone(),
            message: f.message.clone(),
        })
        .collect();

    let errors = lint_findings
        .iter()
        .filter(|f| f.severity == admit_core::Severity::Error)
        .count() as u64;
    let warnings = lint_findings
        .iter()
        .filter(|f| f.severity == admit_core::Severity::Warning)
        .count() as u64;

    Ok(VaultSchemaLintOutput {
        files_scanned,
        errors,
        warnings,
        passed: errors == 0,
        findings,
    })
}

fn collect_vault_files(vault_root: &Path) -> Result<Vec<(String, String)>, DeclareCostError> {
    // Canonicalize to resolve relative paths before passing to walk_files.
    // On Windows, canonicalize produces \\?\ UNC paths which can cause issues
    // with git ls-files path matching, so we strip the UNC prefix.
    let resolved_root = vault_root
        .canonicalize()
        .unwrap_or_else(|_| vault_root.to_path_buf());
    let resolved_root = strip_unc_prefix(&resolved_root);

    // Use walk_files which tries git ls-files first, then falls back to filesystem walk.
    // On Windows/MSYS, git ls-files path matching can fail due to path format differences,
    // so set ADMIT_INGEST_DISABLE_GIT to force filesystem walk if git walk returns 0 paths.
    let walk = admit_scope_ingest::walk_files(&resolved_root)
        .map_err(|e| DeclareCostError::Io(format!("walk vault files: {e}")))?;
    let walk = if walk.paths.is_empty() {
        // Retry with git disabled — path format mismatch on Windows
        std::env::set_var("ADMIT_INGEST_DISABLE_GIT", "1");
        let retry = admit_scope_ingest::walk_files(&resolved_root)
            .map_err(|e| DeclareCostError::Io(format!("walk vault files (fs fallback): {e}")))?;
        std::env::remove_var("ADMIT_INGEST_DISABLE_GIT");
        retry
    } else {
        walk
    };

    let mut files = Vec::new();
    for abs_path in &walk.paths {
        // Only include files with extensions we care about (.md, .toml, .yml, .yaml)
        let ext = abs_path.extension().and_then(|e| e.to_str()).unwrap_or("");
        if !matches!(ext, "md" | "toml" | "yml" | "yaml") {
            continue;
        }

        // Compute vault-relative path
        let rel = abs_path
            .strip_prefix(&resolved_root)
            .or_else(|_| abs_path.strip_prefix(vault_root))
            .unwrap_or(abs_path);
        let rel_str = rel.to_string_lossy().replace('\\', "/");

        // Skip hidden directories and special paths
        if rel_str.starts_with('.') || rel_str.contains("/.") {
            continue;
        }

        match std::fs::read_to_string(abs_path) {
            Ok(content) => {
                files.push((rel_str, content));
            }
            Err(_) => continue, // Skip unreadable files
        }
    }

    Ok(files)
}

/// Strip Windows UNC `\\?\` prefix that `canonicalize()` adds.
fn strip_unc_prefix(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        path.to_path_buf()
    }
}
