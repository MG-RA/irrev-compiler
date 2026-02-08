//! Pure ingestion logic: file walking, chunking, and format detection.
//!
//! This scope provides substrate-agnostic ingestion functionality that can be
//! used across CLI, LSP, and embedded contexts. Database-specific operations
//! are abstracted through the `backend` module.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

pub mod backend;

// Re-export scope identifiers
pub use backend::{INGEST_DIR_SCOPE_ID, INGEST_DIR_PHASE, is_ingest_dir_scope};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

pub const SNAPSHOT_SCHEMA_ID: &str = "dir-snapshot/0";
pub const PARSE_SCHEMA_ID: &str = "dir-parse/1";
pub const FILE_SCHEMA_ID: &str = "file-blob/0";
pub const CHUNK_SCHEMA_ID: &str = "text-chunk/1";
pub const CHUNK_REPR_SCHEMA_ID: &str = "chunk-repr/1";
pub const DEFAULT_CHUNK_MAX_CHARS: usize = 2400;
pub const DEFAULT_CHUNK_OVERLAP_CHARS: usize = 160;

// ---------------------------------------------------------------------------
// Public data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestedFile {
    pub rel_path: String,
    pub sha256: String,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestedChunk {
    pub rel_path: String,
    pub format: String,
    pub language: Option<String>,
    pub chunk_kind: String,
    pub heading_path: Vec<String>,
    pub start_line: u32,
    pub end_line: u32,
    pub start_byte: u32,
    pub end_byte: u32,
    pub chunk_sha256: String,
    pub chunk_text: String,
    pub repr_cbor: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestWarning {
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rel_path: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone)]
pub struct IngestDirOutput {
    pub root: PathBuf,
    pub snapshot_value: serde_json::Value,
    pub parse_value: serde_json::Value,
    pub files: Vec<IngestedFile>,
    pub chunks: Vec<IngestedChunk>,
    pub total_bytes: u64,
    pub walk_mode: String,
    pub skipped_by_skip_dir: u64,
    pub warnings: Vec<IngestWarning>,
}

#[derive(Debug, Clone)]
pub struct ChunkSpec {
    pub format: String,
    pub language: Option<String>,
    pub chunk_kind: String,
    pub heading_path: Vec<String>,
    pub start_line: u32,
    pub end_line: u32,
    pub start_byte: u32,
    pub end_byte: u32,
    pub text: String,
    pub extra_meta: Option<serde_json::Value>,
    pub ast_summary: Option<serde_json::Value>,
}

// ---------------------------------------------------------------------------
// File walking
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy)]
pub enum WalkMode {
    GitLsFiles,
    FsWalk,
}

impl WalkMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            WalkMode::GitLsFiles => "git_ls_files",
            WalkMode::FsWalk => "fs_walk",
        }
    }
}

#[derive(Debug, Clone)]
pub struct WalkFilesOutput {
    pub mode: WalkMode,
    pub paths: Vec<PathBuf>,
    pub skipped_by_skip_dir: u64,
    pub warnings: Vec<IngestWarning>,
}

pub fn walk_files(root: &Path) -> Result<WalkFilesOutput, String> {
    let disable_git = std::env::var_os("ADMIT_INGEST_DISABLE_GIT")
        .and_then(|v| v.to_str().map(|s| s.to_string()))
        .is_some_and(|s| s == "1" || s.eq_ignore_ascii_case("true"));

    if !disable_git {
        if let Ok(out) = walk_files_via_git(root) {
            return Ok(out);
        }
    }

    walk_files_via_fs(root)
}

fn walk_files_via_fs(root: &Path) -> Result<WalkFilesOutput, String> {
    let patterns = load_root_gitignore_patterns(root)?;
    let mut out: Vec<PathBuf> = Vec::new();
    let mut warnings: Vec<IngestWarning> = Vec::new();
    let mut skipped_by_skip_dir: u64 = 0;

    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(err) => {
                let rel_path = dir
                    .strip_prefix(root)
                    .ok()
                    .map(|p| p.to_string_lossy().replace('\\', "/"));
                warnings.push(IngestWarning {
                    kind: "read_dir_error".to_string(),
                    rel_path,
                    message: err.to_string(),
                });
                continue;
            }
        };

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(err) => {
                    warnings.push(IngestWarning {
                        kind: "read_dir_entry_error".to_string(),
                        rel_path: None,
                        message: err.to_string(),
                    });
                    continue;
                }
            };
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(t) => t,
                Err(err) => {
                    let rel_path = path
                        .strip_prefix(root)
                        .ok()
                        .map(|p| p.to_string_lossy().replace('\\', "/"));
                    warnings.push(IngestWarning {
                        kind: "file_type_error".to_string(),
                        rel_path,
                        message: err.to_string(),
                    });
                    continue;
                }
            };

            if file_type.is_dir() {
                if should_skip_dir(&path) {
                    skipped_by_skip_dir = skipped_by_skip_dir.saturating_add(1);
                    continue;
                }
                if is_ignored_by_root_gitignore(root, &path, &patterns, true)? {
                    continue;
                }
                stack.push(path);
                continue;
            }

            if file_type.is_file() {
                if is_ignored_by_root_gitignore(root, &path, &patterns, false)? {
                    continue;
                }
                out.push(path);
            }
        }
    }

    out.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
    warnings.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then(a.rel_path.cmp(&b.rel_path))
            .then(a.message.cmp(&b.message))
    });

    Ok(WalkFilesOutput {
        mode: WalkMode::FsWalk,
        paths: out,
        skipped_by_skip_dir,
        warnings,
    })
}

fn walk_files_via_git(root: &Path) -> Result<WalkFilesOutput, String> {
    let (toplevel, toplevel_for_git) = git_toplevel(root)?;
    let root_rel = root
        .strip_prefix(&toplevel)
        .unwrap_or_else(|_| Path::new(""));
    let pathspec = if root_rel.as_os_str().is_empty() {
        ".".to_string()
    } else {
        root_rel.to_string_lossy().replace('\\', "/")
    };

    let output = Command::new("git")
        .arg("-C")
        .arg(&toplevel_for_git)
        .args(["ls-files", "-co", "--exclude-standard", "-z", "--"])
        .arg(&pathspec)
        .output()
        .map_err(|err| format!("git ls-files: {}", err))?;
    if !output.status.success() {
        return Err(format!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let mut warnings: Vec<IngestWarning> = Vec::new();
    let mut out: Vec<PathBuf> = Vec::new();
    let mut skipped_by_skip_dir: u64 = 0;
    for entry in output.stdout.split(|b| *b == 0) {
        if entry.is_empty() {
            continue;
        }
        let rel = match String::from_utf8(entry.to_vec()) {
            Ok(s) => s,
            Err(_) => {
                warnings.push(IngestWarning {
                    kind: "git_non_utf8_path".to_string(),
                    rel_path: None,
                    message: "git returned non-utf8 path; skipping".to_string(),
                });
                continue;
            }
        };
        let abs = toplevel.join(Path::new(&rel));
        if !abs.starts_with(root) {
            continue;
        }
        let rel_to_root = abs.strip_prefix(root).map_err(|err| {
            format!("strip_prefix {}: {}", abs.display(), err)
        })?;
        if should_skip_rel_path(rel_to_root) {
            skipped_by_skip_dir = skipped_by_skip_dir.saturating_add(1);
            continue;
        }
        match std::fs::metadata(&abs) {
            Ok(meta) => {
                if meta.is_file() {
                    out.push(abs);
                }
            }
            Err(err) => {
                warnings.push(IngestWarning {
                    kind: "metadata_error".to_string(),
                    rel_path: Some(rel_to_root.to_string_lossy().replace('\\', "/")),
                    message: err.to_string(),
                });
            }
        }
    }
    out.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
    Ok(WalkFilesOutput {
        mode: WalkMode::GitLsFiles,
        paths: out,
        skipped_by_skip_dir,
        warnings,
    })
}

fn git_toplevel(root: &Path) -> Result<(PathBuf, PathBuf), String> {
    let root_for_git = path_for_git(root);
    let output = Command::new("git")
        .arg("-C")
        .arg(&root_for_git)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|err| format!("git rev-parse: {}", err))?;
    if !output.status.success() {
        return Err(format!(
            "git rev-parse failed: {}",
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let s = String::from_utf8_lossy(&output.stdout);
    let p = s.trim();
    if p.is_empty() {
        return Err("git rev-parse returned empty toplevel".to_string());
    }
    let toplevel_for_git = PathBuf::from(p);
    let toplevel = toplevel_for_git
        .canonicalize()
        .map_err(|err| format!("canonicalize git toplevel: {}", err))?;
    Ok((toplevel, toplevel_for_git))
}

#[cfg(windows)]
fn path_for_git(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        return PathBuf::from(stripped);
    }
    path.to_path_buf()
}

#[cfg(not(windows))]
fn path_for_git(path: &Path) -> PathBuf {
    path.to_path_buf()
}

// ---------------------------------------------------------------------------
// Gitignore parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct GitignorePattern {
    raw: String,
    negated: bool,
}

fn load_root_gitignore_patterns(root: &Path) -> Result<Vec<GitignorePattern>, String> {
    let path = root.join(".gitignore");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&path).map_err(|err| {
        format!("read .gitignore {}: {}", path.display(), err)
    })?;

    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (negated, raw) = if let Some(rest) = line.strip_prefix('!') {
            (true, rest.trim())
        } else {
            (false, line)
        };
        if raw.is_empty() {
            continue;
        }
        out.push(GitignorePattern {
            raw: raw.to_string(),
            negated,
        });
    }
    Ok(out)
}

fn is_ignored_by_root_gitignore(
    root: &Path,
    abs: &Path,
    patterns: &[GitignorePattern],
    is_dir: bool,
) -> Result<bool, String> {
    if patterns.is_empty() {
        return Ok(false);
    }
    let rel = abs
        .strip_prefix(root)
        .map_err(|err| format!("strip_prefix {}: {}", abs.display(), err))?;
    let rel_str = rel.to_string_lossy().replace('\\', "/");
    let file_name = abs.file_name().and_then(|s| s.to_str()).unwrap_or("");

    let mut ignored = false;
    for p in patterns {
        if gitignore_matches(&p.raw, &rel_str, file_name, is_dir) {
            ignored = !p.negated;
        }
    }
    Ok(ignored)
}

fn gitignore_matches(pattern: &str, rel_path: &str, file_name: &str, is_dir: bool) -> bool {
    let mut pat = pattern.trim().replace('\\', "/");
    if pat.is_empty() {
        return false;
    }

    // Directory-only patterns (trailing slash).
    let dir_only = pat.ends_with('/');
    if dir_only {
        pat = pat.trim_end_matches('/').to_string();
        if pat.is_empty() {
            return false;
        }
        if !is_dir {
            return false;
        }
        // If the pattern is a bare directory name (no path separators / globs),
        // match any component with that name.
        if !pat.contains('/') && !pat.contains('*') && !pat.contains('?') {
            return rel_path.split('/').any(|c| c == pat);
        }
        return glob_match(&pat, rel_path);
    }

    // If the pattern contains no path separators, match against the basename.
    if !pat.contains('/') {
        return glob_match(&pat, file_name);
    }

    // Anchored patterns start at the root.
    if let Some(stripped) = pat.strip_prefix('/') {
        return glob_match(stripped, rel_path);
    }

    glob_match(&pat, rel_path)
}

fn glob_match(pattern: &str, text: &str) -> bool {
    // Minimal glob matcher supporting `*` and `?`.
    let (p, t) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star_pi: Option<usize> = None;
    let mut star_ti: usize = 0;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == t[ti] || p[pi] == b'?') {
            pi += 1;
            ti += 1;
            continue;
        }
        if pi < p.len() && p[pi] == b'*' {
            star_pi = Some(pi);
            pi += 1;
            star_ti = ti;
            continue;
        }
        if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
            continue;
        }
        return false;
    }

    while pi < p.len() && p[pi] == b'*' {
        pi += 1;
    }
    pi == p.len()
}

// ---------------------------------------------------------------------------
// Path utilities
// ---------------------------------------------------------------------------

pub fn should_skip_dir(path: &Path) -> bool {
    let name = path.file_name().and_then(|s| s.to_str()).unwrap_or("");
    if name.starts_with("surrealdb") {
        return true;
    }
    matches!(
        name,
        ".git"
            | "target"
            | "out"
            | "node_modules"
            | ".venv"
            | ".mypy_cache"
            | "logs"
            | "surrealdb"
            | ".surrealdb"
    )
}

pub fn should_skip_rel_path(rel: &Path) -> bool {
    rel.components().any(|c| match c {
        std::path::Component::Normal(s) => should_skip_dir(Path::new(s)),
        _ => false,
    })
}

pub fn to_rel_path(root: &Path, path: &Path) -> Result<String, String> {
    let rel = path
        .strip_prefix(root)
        .map_err(|err| format!("strip_prefix {}: {}", path.display(), err))?;
    let mut parts = Vec::new();
    for comp in rel.components() {
        let s = comp.as_os_str().to_str().ok_or_else(|| {
            format!(
                "non-utf8 path component under root: {}",
                path.display()
            )
        })?;
        parts.push(s);
    }
    Ok(parts.join("/"))
}

// ---------------------------------------------------------------------------
// Format inference
// ---------------------------------------------------------------------------

pub fn infer_format_from_path(rel_path: &str) -> String {
    Path::new(rel_path)
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or("bin")
        .to_lowercase()
}

pub fn default_language_for_format(format: &str) -> Option<String> {
    match format {
        "md" => Some("markdown".to_string()),
        "rs" => Some("rust".to_string()),
        "py" => Some("python".to_string()),
        "txt" => Some("text".to_string()),
        "ipynb" => Some("notebook".to_string()),
        _ => None,
    }
}

pub fn default_chunk_kind_for_format(format: &str) -> String {
    match format {
        "md" => "markdown_section".to_string(),
        "rs" => "rust_item".to_string(),
        "py" => "python_block".to_string(),
        "txt" => "text_paragraph".to_string(),
        "ipynb" => "ipynb_cell".to_string(),
        _ => "text_chunk".to_string(),
    }
}

pub fn chunk_artifact_ext<'a>(format: &'a str, language: Option<&str>) -> &'a str {
    if format == "ipynb" {
        if let Some(lang) = language {
            return match lang {
                "python" => "py",
                "markdown" => "md",
                _ => "txt",
            };
        }
        return "txt";
    }
    match format {
        "md" | "rs" | "py" | "txt" => format,
        _ => "txt",
    }
}

pub fn is_chunked_text_format(ext: &str) -> bool {
    matches!(ext, "md" | "rs" | "py" | "txt" | "ipynb")
}

// ---------------------------------------------------------------------------
// Line-based text utilities
// ---------------------------------------------------------------------------

pub fn split_inclusive_lines(input: &str) -> Vec<&str> {
    if input.is_empty() {
        return Vec::new();
    }
    input.split_inclusive('\n').collect()
}

pub fn line_offsets(lines: &[&str]) -> Vec<u32> {
    let mut out = Vec::with_capacity(lines.len() + 1);
    let mut acc: u32 = 0;
    out.push(acc);
    for line in lines {
        acc = acc.saturating_add(line.len() as u32);
        out.push(acc);
    }
    out
}

pub fn lines_concat(lines: &[&str], start: usize, end: usize) -> String {
    let mut out = String::new();
    for line in &lines[start..end] {
        out.push_str(line);
    }
    out
}

// ---------------------------------------------------------------------------
// Chunking: markdown
// ---------------------------------------------------------------------------

pub fn parse_heading(line: &str) -> Option<(u8, String)> {
    let trimmed = line.trim_start();
    let hashes = trimmed.chars().take_while(|c| *c == '#').count();
    if hashes == 0 || hashes > 6 {
        return None;
    }
    let rest = trimmed[hashes..].trim();
    if rest.is_empty() {
        return None;
    }
    let title = rest.trim_end_matches('#').trim().to_string();
    Some((hashes as u8, title))
}

pub fn chunk_markdown_specs(input: &str) -> Vec<ChunkSpec> {
    let lines = split_inclusive_lines(input);
    if lines.is_empty() {
        return Vec::new();
    }
    let offsets = line_offsets(&lines);

    let mut out = Vec::new();
    let mut heading_stack: Vec<(u8, String)> = Vec::new();
    let mut current_heading_path: Vec<String> = Vec::new();
    let mut current_start = 0usize;

    for (idx, line) in lines.iter().enumerate() {
        let line_no_nl = line.trim_end_matches('\n').trim_end_matches('\r');
        if let Some((level, title)) = parse_heading(line_no_nl) {
            if let Some(chunk) = make_line_chunk(
                "md",
                Some("markdown"),
                "markdown_section",
                current_heading_path.clone(),
                &lines,
                &offsets,
                current_start,
                idx,
                None,
                None,
            ) {
                out.push(chunk);
            }

            while let Some((l, _)) = heading_stack.last() {
                if *l >= level {
                    heading_stack.pop();
                } else {
                    break;
                }
            }
            heading_stack.push((level, title));
            current_heading_path = heading_stack.iter().map(|(_, t)| t.clone()).collect();
            current_start = idx;
        }
    }

    if let Some(chunk) = make_line_chunk(
        "md",
        Some("markdown"),
        "markdown_section",
        current_heading_path,
        &lines,
        &offsets,
        current_start,
        lines.len(),
        None,
        None,
    ) {
        out.push(chunk);
    }
    out
}

// ---------------------------------------------------------------------------
// Chunking: Rust
// ---------------------------------------------------------------------------

pub fn rust_ast_summary(input: &str) -> Option<serde_json::Value> {
    // Note: This depends on syn which is in admit_cli Cargo.toml
    // For the scope to be fully independent, we'd need to add syn here
    // or make this optional. For now, we'll keep it and add syn to dependencies.
    let parsed = syn::parse_file(input).ok()?;
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for item in parsed.items {
        let key = match item {
            syn::Item::Const(_) => "const",
            syn::Item::Enum(_) => "enum",
            syn::Item::ExternCrate(_) => "extern_crate",
            syn::Item::Fn(_) => "fn",
            syn::Item::ForeignMod(_) => "foreign_mod",
            syn::Item::Impl(_) => "impl",
            syn::Item::Macro(_) => "macro",
            syn::Item::Mod(_) => "mod",
            syn::Item::Static(_) => "static",
            syn::Item::Struct(_) => "struct",
            syn::Item::Trait(_) => "trait",
            syn::Item::TraitAlias(_) => "trait_alias",
            syn::Item::Type(_) => "type",
            syn::Item::Union(_) => "union",
            syn::Item::Use(_) => "use",
            _ => "other",
        };
        *counts.entry(key.to_string()).or_default() += 1;
    }
    Some(serde_json::json!({
        "summary_type": "rust_ast_item_counts",
        "counts": counts,
    }))
}

pub fn looks_like_rust_item_start(line: &str) -> bool {
    let t = line.trim_start();
    [
        "fn ",
        "pub fn ",
        "struct ",
        "pub struct ",
        "enum ",
        "pub enum ",
        "trait ",
        "pub trait ",
        "impl ",
        "pub impl ",
        "mod ",
        "pub mod ",
        "type ",
        "pub type ",
        "const ",
        "pub const ",
        "static ",
        "pub static ",
    ]
    .iter()
    .any(|p| t.starts_with(p))
}

pub fn chunk_rust_specs(input: &str) -> Vec<ChunkSpec> {
    let lines = split_inclusive_lines(input);
    if lines.is_empty() {
        return Vec::new();
    }
    let offsets = line_offsets(&lines);
    let ast_summary = rust_ast_summary(input);

    let mut boundaries = vec![0usize];
    let mut depth: i64 = 0;
    for (idx, line) in lines.iter().enumerate() {
        if idx > 0 && depth == 0 && looks_like_rust_item_start(line) {
            boundaries.push(idx);
        }
        for ch in line.chars() {
            if ch == '{' {
                depth += 1;
            } else if ch == '}' {
                depth -= 1;
            }
        }
    }
    boundaries.sort_unstable();
    boundaries.dedup();
    if boundaries.is_empty() {
        boundaries.push(0);
    }

    let mut out = Vec::new();
    if boundaries.len() <= 1 {
        return chunk_line_windows(
            "rs",
            Some("rust"),
            "rust_fallback_window",
            input,
            120,
            24,
            ast_summary,
        );
    }
    boundaries.push(lines.len());
    for i in 0..(boundaries.len() - 1) {
        if let Some(chunk) = make_line_chunk(
            "rs",
            Some("rust"),
            "rust_item",
            Vec::new(),
            &lines,
            &offsets,
            boundaries[i],
            boundaries[i + 1],
            None,
            ast_summary.clone(),
        ) {
            out.push(chunk);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Chunking: Python
// ---------------------------------------------------------------------------

pub fn looks_like_python_block_start(line: &str) -> bool {
    let t = line.trim_start();
    if t.starts_with('#') {
        return false;
    }
    t.starts_with("def ") || t.starts_with("async def ") || t.starts_with("class ")
}

pub fn chunk_python_specs(
    input: &str,
    format: &str,
    chunk_kind: &str,
    extra_meta: Option<serde_json::Value>,
) -> Vec<ChunkSpec> {
    let lines = split_inclusive_lines(input);
    if lines.is_empty() {
        return Vec::new();
    }
    let offsets = line_offsets(&lines);
    let mut boundaries = vec![0usize];
    for (idx, line) in lines.iter().enumerate() {
        if idx == 0 {
            continue;
        }
        if line.starts_with(' ') || line.starts_with('\t') {
            continue;
        }
        if looks_like_python_block_start(line) {
            boundaries.push(idx);
        }
    }
    boundaries.sort_unstable();
    boundaries.dedup();
    if boundaries.len() <= 1 {
        return chunk_line_windows(
            format,
            Some("python"),
            "python_fallback_window",
            input,
            100,
            20,
            None,
        );
    }

    boundaries.push(lines.len());
    let mut out = Vec::new();
    for i in 0..(boundaries.len() - 1) {
        if let Some(chunk) = make_line_chunk(
            format,
            Some("python"),
            chunk_kind,
            Vec::new(),
            &lines,
            &offsets,
            boundaries[i],
            boundaries[i + 1],
            extra_meta.clone(),
            None,
        ) {
            out.push(chunk);
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Chunking: text and ipynb
// ---------------------------------------------------------------------------

pub fn chunk_txt_specs(
    input: &str,
    format: &str,
    language: Option<&str>,
    chunk_kind: &str,
    extra_meta: Option<serde_json::Value>,
) -> Vec<ChunkSpec> {
    let lines = split_inclusive_lines(input);
    if lines.is_empty() {
        return Vec::new();
    }
    let offsets = line_offsets(&lines);
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut idx = 0usize;
    while idx < lines.len() {
        let trimmed = lines[idx].trim();
        if trimmed.is_empty() {
            if let Some(chunk) = make_line_chunk(
                format,
                language,
                chunk_kind,
                Vec::new(),
                &lines,
                &offsets,
                start,
                idx,
                extra_meta.clone(),
                None,
            ) {
                out.push(chunk);
            }
            start = idx + 1;
        }
        idx += 1;
    }
    if let Some(chunk) = make_line_chunk(
        format,
        language,
        chunk_kind,
        Vec::new(),
        &lines,
        &offsets,
        start,
        lines.len(),
        extra_meta,
        None,
    ) {
        out.push(chunk);
    }
    out
}

pub fn chunk_ipynb_specs(input: &str) -> Result<Vec<ChunkSpec>, String> {
    let value: serde_json::Value =
        serde_json::from_str(input).map_err(|e| format!("parse ipynb json: {}", e))?;
    let cells = value
        .get("cells")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "ipynb missing cells array".to_string())?;

    let mut out = Vec::new();
    for (idx, cell) in cells.iter().enumerate() {
        let cell_type = cell
            .get("cell_type")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let source = match cell.get("source") {
            Some(serde_json::Value::String(s)) => s.clone(),
            Some(serde_json::Value::Array(arr)) => {
                let mut s = String::new();
                for v in arr {
                    if let Some(line) = v.as_str() {
                        s.push_str(line);
                    }
                }
                s
            }
            _ => String::new(),
        };
        if source.trim().is_empty() {
            continue;
        }
        let base_meta = Some(serde_json::json!({
            "cell_index": idx,
            "cell_type": cell_type,
        }));
        let mut cell_chunks = match cell_type {
            "markdown" => {
                let mut chunks = chunk_markdown_specs(&source);
                for c in chunks.iter_mut() {
                    c.format = "ipynb".to_string();
                    c.language = Some("markdown".to_string());
                    c.chunk_kind = "ipynb_markdown_cell".to_string();
                    c.heading_path.insert(0, format!("Cell {}", idx + 1));
                    c.extra_meta = base_meta.clone();
                }
                chunks
            }
            "code" => chunk_python_specs(&source, "ipynb", "ipynb_code_cell", base_meta.clone()),
            _ => chunk_txt_specs(
                &source,
                "ipynb",
                Some("text"),
                "ipynb_text_cell",
                base_meta.clone(),
            ),
        };
        out.append(&mut cell_chunks);
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Generic chunking utilities
// ---------------------------------------------------------------------------

pub fn make_line_chunk(
    format: &str,
    language: Option<&str>,
    chunk_kind: &str,
    heading_path: Vec<String>,
    lines: &[&str],
    offsets: &[u32],
    start: usize,
    end: usize,
    extra_meta: Option<serde_json::Value>,
    ast_summary: Option<serde_json::Value>,
) -> Option<ChunkSpec> {
    if start >= end || end > lines.len() {
        return None;
    }
    let text = lines_concat(lines, start, end);
    if text.trim().is_empty() {
        return None;
    }
    Some(ChunkSpec {
        format: format.to_string(),
        language: language.map(|s| s.to_string()),
        chunk_kind: chunk_kind.to_string(),
        heading_path,
        start_line: (start as u32) + 1,
        end_line: end as u32,
        start_byte: offsets[start],
        end_byte: offsets[end],
        text,
        extra_meta,
        ast_summary,
    })
}

pub fn chunk_line_windows(
    format: &str,
    language: Option<&str>,
    chunk_kind: &str,
    input: &str,
    window_lines: usize,
    overlap_lines: usize,
    ast_summary: Option<serde_json::Value>,
) -> Vec<ChunkSpec> {
    let lines = split_inclusive_lines(input);
    if lines.is_empty() {
        return Vec::new();
    }
    let offsets = line_offsets(&lines);
    let window = window_lines.max(1);
    let step = window.saturating_sub(overlap_lines).max(1);
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < lines.len() {
        let end = (i + window).min(lines.len());
        if let Some(chunk) = make_line_chunk(
            format,
            language,
            chunk_kind,
            Vec::new(),
            &lines,
            &offsets,
            i,
            end,
            None,
            ast_summary.clone(),
        ) {
            out.push(chunk);
        }
        if end == lines.len() {
            break;
        }
        i = i.saturating_add(step);
    }
    out
}

pub fn chunk_file_by_format(rel_path: &str, ext: &str, input: &str) -> Result<Vec<ChunkSpec>, String> {
    let mut chunks = match ext {
        "md" => chunk_markdown_specs(input),
        "rs" => chunk_rust_specs(input),
        "py" => chunk_python_specs(input, "py", "python_block", None),
        "txt" => chunk_txt_specs(input, "txt", Some("text"), "text_paragraph", None),
        "ipynb" => chunk_ipynb_specs(input)?,
        _ => Vec::new(),
    };

    if chunks.is_empty() && !input.trim().is_empty() {
        // Conservative fallback for formats we thought we could parse.
        chunks = chunk_line_windows(
            ext,
            default_language_for_format(ext).as_deref(),
            "fallback_window",
            input,
            120,
            24,
            None,
        );
    }

    let mut out = Vec::new();
    for chunk in chunks {
        out.extend(split_chunk_by_size(
            chunk,
            DEFAULT_CHUNK_MAX_CHARS,
            DEFAULT_CHUNK_OVERLAP_CHARS,
        ));
    }
    if out.is_empty() && !input.trim().is_empty() {
        return Err(format!("no chunks emitted for {}", rel_path));
    }
    Ok(out)
}

fn byte_at_char(s: &str, char_idx: usize) -> usize {
    if char_idx == 0 {
        return 0;
    }
    let mut count = 0usize;
    for (i, (byte_idx, _)) in s.char_indices().enumerate() {
        if i == char_idx {
            return byte_idx;
        }
        count = i + 1;
    }
    if char_idx >= count {
        s.len()
    } else {
        0
    }
}

pub fn split_chunk_by_size(chunk: ChunkSpec, max_chars: usize, overlap_chars: usize) -> Vec<ChunkSpec> {
    let max_chars = max_chars.max(1);
    let overlap_chars = overlap_chars.min(max_chars.saturating_sub(1));
    let step = max_chars.saturating_sub(overlap_chars).max(1);
    let total_chars = chunk.text.chars().count();
    if total_chars <= max_chars {
        return vec![chunk];
    }
    let mut out = Vec::new();
    let mut start_char = 0usize;
    while start_char < total_chars {
        let end_char = (start_char + max_chars).min(total_chars);
        let start_byte_rel = byte_at_char(&chunk.text, start_char);
        let end_byte_rel = byte_at_char(&chunk.text, end_char);
        let sub = chunk.text[start_byte_rel..end_byte_rel].to_string();
        let prior = &chunk.text[..start_byte_rel];
        let start_line = chunk.start_line + (prior.matches('\n').count() as u32);
        let end_line = start_line + (sub.matches('\n').count() as u32);
        out.push(ChunkSpec {
            format: chunk.format.clone(),
            language: chunk.language.clone(),
            chunk_kind: chunk.chunk_kind.clone(),
            heading_path: chunk.heading_path.clone(),
            start_line,
            end_line,
            start_byte: chunk.start_byte.saturating_add(start_byte_rel as u32),
            end_byte: chunk.start_byte.saturating_add(end_byte_rel as u32),
            text: sub,
            extra_meta: chunk.extra_meta.clone(),
            ast_summary: chunk.ast_summary.clone(),
        });
        if end_char == total_chars {
            break;
        }
        start_char = start_char.saturating_add(step);
    }
    out
}

// ---------------------------------------------------------------------------
// Chunk representation helpers
// ---------------------------------------------------------------------------

pub fn normalize_text_for_hash(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub fn tokenize_simple(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut cur = String::new();
    for ch in text.chars() {
        if ch.is_alphanumeric() || ch == '_' {
            cur.push(ch);
            continue;
        }
        if !cur.is_empty() {
            out.push(cur.clone());
            cur.clear();
        }
        if !ch.is_whitespace() {
            out.push(ch.to_string());
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    out
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

pub fn chunk_repr_value(rel_path: &str, chunk_sha256: &str, chunk: &ChunkSpec) -> serde_json::Value {
    let normalized = normalize_text_for_hash(&chunk.text);
    let normalized_text_sha256 = sha256_hex(normalized.as_bytes());
    let tokens = tokenize_simple(&chunk.text).join("\n");
    let token_sha256 = sha256_hex(tokens.as_bytes());
    let ast_sha256 = chunk
        .ast_summary
        .as_ref()
        .and_then(|v| serde_json::to_vec(v).ok().map(|b| sha256_hex(&b)));
    serde_json::json!({
        "schema_id": CHUNK_REPR_SCHEMA_ID,
        "schema_version": 1,
        "doc_path": rel_path,
        "chunk_sha256": chunk_sha256,
        "format": chunk.format,
        "language": chunk.language,
        "chunk_kind": chunk.chunk_kind,
        "byte_len": chunk.text.as_bytes().len(),
        "line_count": chunk.text.lines().count(),
        "normalized_text_sha256": normalized_text_sha256,
        "token_sha256": token_sha256,
        "ast_sha256": ast_sha256,
        "ast_summary": chunk.ast_summary,
        "start_line": chunk.start_line,
        "end_line": chunk.end_line,
        "start_byte": chunk.start_byte,
        "end_byte": chunk.end_byte,
        "heading_path": chunk.heading_path,
        "meta": chunk.extra_meta,
    })
}
