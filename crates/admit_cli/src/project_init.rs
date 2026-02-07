use std::fs;
use std::path::{Path, PathBuf};

use super::types::DeclareCostError;

const ADMIT_TOML_TEMPLATE: &str = r#"[project]
root = "."
artifacts_dir = "out/artifacts"
ledger_path = "out/ledger.jsonl"

[ingest]
include = ["**/*.md", "**/*.rs", "**/*.py", "**/*.ipynb"]
exclude = ["**/target/**", "**/.git/**", "**/node_modules/**"]

[projection]
enabled = ["dag_trace", "doc_files", "doc_chunks", "obsidian_vault_links"]
failure_mode = "warn"
max_sql_bytes = 1000000

[projection.batch_sizes]
doc_chunks = 200
doc_files = 500
nodes = 1000
edges = 1000
links = 300

[surrealdb]
mode = "auto"
endpoint = "ws://127.0.0.1:8000"
namespace = "test"
database = "test"
"#;

const OUT_GITIGNORE_TEMPLATE: &str = "*\n!.gitignore\n";
const STARTER_RULES_MD: &str =
    "# Starter Rulesets\n\nThis folder is for local ruleset templates.\n";
const MINI_FIXTURE_README: &str =
    "# mini_vault\n\nMinimal fixture folder for deterministic ingest/lint tests.\n";

#[derive(Debug, Clone)]
pub struct InitProjectInput {
    pub root: PathBuf,
}

#[derive(Debug, Clone)]
pub struct InitProjectOutput {
    pub root: PathBuf,
    pub created: Vec<String>,
    pub existing: Vec<String>,
}

pub fn init_project(input: InitProjectInput) -> Result<InitProjectOutput, DeclareCostError> {
    let root = input.root;
    if !root.exists() {
        fs::create_dir_all(&root).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    }

    let mut created = Vec::new();
    let mut existing = Vec::new();

    ensure_dir(&root.join("out"), "out", &mut created, &mut existing)?;
    ensure_file(
        &root.join("admit.toml"),
        "admit.toml",
        ADMIT_TOML_TEMPLATE,
        &mut created,
        &mut existing,
    )?;
    ensure_file(
        &root.join("out").join(".gitignore"),
        "out/.gitignore",
        OUT_GITIGNORE_TEMPLATE,
        &mut created,
        &mut existing,
    )?;

    ensure_dir(&root.join("meta"), "meta", &mut created, &mut existing)?;
    ensure_dir(
        &root.join("meta").join("rules"),
        "meta/rules",
        &mut created,
        &mut existing,
    )?;
    ensure_file(
        &root.join("meta").join("rules").join("README.md"),
        "meta/rules/README.md",
        STARTER_RULES_MD,
        &mut created,
        &mut existing,
    )?;
    ensure_dir(
        &root.join("meta").join("fixtures"),
        "meta/fixtures",
        &mut created,
        &mut existing,
    )?;
    ensure_dir(
        &root.join("meta").join("fixtures").join("mini_vault"),
        "meta/fixtures/mini_vault",
        &mut created,
        &mut existing,
    )?;
    ensure_file(
        &root
            .join("meta")
            .join("fixtures")
            .join("mini_vault")
            .join("README.md"),
        "meta/fixtures/mini_vault/README.md",
        MINI_FIXTURE_README,
        &mut created,
        &mut existing,
    )?;

    Ok(InitProjectOutput {
        root,
        created,
        existing,
    })
}

fn ensure_dir(
    path: &Path,
    label: &str,
    created: &mut Vec<String>,
    existing: &mut Vec<String>,
) -> Result<(), DeclareCostError> {
    if path.exists() {
        existing.push(label.to_string());
        return Ok(());
    }
    fs::create_dir_all(path).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    created.push(label.to_string());
    Ok(())
}

fn ensure_file(
    path: &Path,
    label: &str,
    contents: &str,
    created: &mut Vec<String>,
    existing: &mut Vec<String>,
) -> Result<(), DeclareCostError> {
    if path.exists() {
        existing.push(label.to_string());
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    }
    fs::write(path, contents).map_err(|err| DeclareCostError::Io(err.to_string()))?;
    created.push(label.to_string());
    Ok(())
}
