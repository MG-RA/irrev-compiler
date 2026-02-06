use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::artifact::default_artifacts_dir;
use crate::artifact::store_artifact;
use crate::internal::sha256_hex;
use crate::types::{ArtifactRef, DeclareCostError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestedFile {
    pub rel_path: String,
    pub artifact: ArtifactRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestedChunk {
    pub rel_path: String,
    pub heading_path: Vec<String>,
    pub start_line: u32,
    pub chunk_sha256: String,
    pub artifact: ArtifactRef,
}

#[derive(Debug, Clone)]
pub struct IngestDirOutput {
    pub root: PathBuf,
    pub snapshot: ArtifactRef,
    pub snapshot_sha256: String,
    pub parse: ArtifactRef,
    pub parse_sha256: String,
    pub files: Vec<IngestedFile>,
    pub chunks: Vec<IngestedChunk>,
    pub total_bytes: u64,
}

const SNAPSHOT_SCHEMA_ID: &str = "dir-snapshot/0";
const SNAPSHOT_KIND: &str = "dir_snapshot";
const PARSE_SCHEMA_ID: &str = "dir-parse/0";
const PARSE_KIND: &str = "dir_parse";
const FILE_SCHEMA_ID: &str = "file-blob/0";
const FILE_KIND: &str = "file_blob";
const CHUNK_SCHEMA_ID: &str = "text-chunk/0";
const CHUNK_KIND: &str = "text_chunk";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SnapshotEntry {
    path: String,
    sha256: String,
    size_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ParseEntry {
    path: String,
    chunk_sha256: String,
    start_line: u32,
    heading_path: Vec<String>,
}

pub fn ingest_dir(root: &Path, artifacts_root: Option<&Path>) -> Result<IngestDirOutput, DeclareCostError> {
    let root = root
        .canonicalize()
        .map_err(|err| DeclareCostError::Io(format!("canonicalize root: {}", err)))?;
    let artifacts_root_buf = artifacts_root
        .map(|p| p.to_path_buf())
        .unwrap_or_else(default_artifacts_dir);
    let artifacts_root = artifacts_root_buf.as_path();

    let mut files = Vec::new();
    let mut chunks = Vec::new();
    let mut snapshot_entries = Vec::new();
    let mut parse_entries = Vec::new();
    let mut total_bytes: u64 = 0;

    let paths = walk_files(&root)?;
    for path in paths {
        let rel_path = to_rel_path(&root, &path)?;
        let bytes =
            std::fs::read(&path).map_err(|err| DeclareCostError::Io(format!("read {}: {}", rel_path, err)))?;
        total_bytes = total_bytes.saturating_add(bytes.len() as u64);

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("bin")
            .to_lowercase();
        let artifact = store_artifact(
            artifacts_root,
            FILE_KIND,
            FILE_SCHEMA_ID,
            &bytes,
            &ext,
            None,
            None,
        )?;

        snapshot_entries.push(SnapshotEntry {
            path: rel_path.clone(),
            sha256: artifact.sha256.clone(),
            size_bytes: artifact.size_bytes,
        });
        files.push(IngestedFile {
            rel_path: rel_path.clone(),
            artifact: artifact.clone(),
        });

        if ext == "md" {
            if let Ok(text) = std::str::from_utf8(&bytes) {
                let md_chunks = chunk_markdown(text);
                for c in md_chunks {
                    let chunk_bytes = c.text.as_bytes();
                    let chunk_sha256 = sha256_hex(chunk_bytes);
                    let chunk_artifact = store_artifact(
                        artifacts_root,
                        CHUNK_KIND,
                        CHUNK_SCHEMA_ID,
                        chunk_bytes,
                        "md",
                        None,
                        None,
                    )?;
                    parse_entries.push(ParseEntry {
                        path: rel_path.clone(),
                        chunk_sha256: chunk_sha256.clone(),
                        start_line: c.start_line,
                        heading_path: c.heading_path.clone(),
                    });
                    chunks.push(IngestedChunk {
                        rel_path: rel_path.clone(),
                        heading_path: c.heading_path,
                        start_line: c.start_line,
                        chunk_sha256,
                        artifact: chunk_artifact,
                    });
                }
            }
        }
    }

    snapshot_entries.sort_by(|a, b| a.path.cmp(&b.path).then(a.sha256.cmp(&b.sha256)));
    parse_entries.sort_by(|a, b| a.path.cmp(&b.path).then(a.start_line.cmp(&b.start_line)));

    let snapshot_value = serde_json::json!({
        "schema_id": SNAPSHOT_SCHEMA_ID,
        "schema_version": 0,
        "root": ".",
        "entries": snapshot_entries,
    });
    let snapshot_cbor = admit_core::encode_canonical_value(&snapshot_value)
        .map_err(|err| DeclareCostError::CanonicalEncode(err.0))?;
    let snapshot_json =
        serde_json::to_vec_pretty(&snapshot_value).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    let snapshot = store_artifact(
        artifacts_root,
        SNAPSHOT_KIND,
        SNAPSHOT_SCHEMA_ID,
        &snapshot_cbor,
        "cbor",
        Some(snapshot_json),
        None,
    )?;

    let parse_value = serde_json::json!({
        "schema_id": PARSE_SCHEMA_ID,
        "schema_version": 0,
        "snapshot_sha256": snapshot.sha256,
        "entries": parse_entries,
    });
    let parse_cbor = admit_core::encode_canonical_value(&parse_value)
        .map_err(|err| DeclareCostError::CanonicalEncode(err.0))?;
    let parse_json =
        serde_json::to_vec_pretty(&parse_value).map_err(|err| DeclareCostError::Json(err.to_string()))?;
    let parse = store_artifact(
        artifacts_root,
        PARSE_KIND,
        PARSE_SCHEMA_ID,
        &parse_cbor,
        "cbor",
        Some(parse_json),
        None,
    )?;

    Ok(IngestDirOutput {
        root,
        snapshot_sha256: snapshot.sha256.clone(),
        snapshot,
        parse_sha256: parse.sha256.clone(),
        parse,
        files,
        chunks,
        total_bytes,
    })
}

fn walk_files(root: &Path) -> Result<Vec<PathBuf>, DeclareCostError> {
    let disable_git = std::env::var_os("ADMIT_INGEST_DISABLE_GIT")
        .and_then(|v| v.to_str().map(|s| s.to_string()))
        .is_some_and(|s| s == "1" || s.eq_ignore_ascii_case("true"));

    if !disable_git {
        if let Ok(paths) = walk_files_via_git(root) {
            return Ok(paths);
        }
    }

    let gitignore = load_root_gitignore_patterns(root)?;
    let mut out = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let entries = std::fs::read_dir(&dir).map_err(|err| {
            DeclareCostError::Io(format!("read_dir {}: {}", dir.display(), err))
        })?;
        for entry in entries {
            let entry = entry
                .map_err(|err| DeclareCostError::Io(format!("read_dir entry: {}", err)))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .map_err(|err| DeclareCostError::Io(format!("file_type {}: {}", path.display(), err)))?;
            if file_type.is_dir() {
                if should_skip_dir(&path) {
                    continue;
                }
                if is_ignored_by_root_gitignore(root, &path, &gitignore, true)? {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if file_type.is_file() {
                if is_ignored_by_root_gitignore(root, &path, &gitignore, false)? {
                    continue;
                }
                out.push(path);
            }
        }
    }
    out.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
    Ok(out)
}

#[derive(Debug, Clone)]
struct GitignorePattern {
    raw: String,
}

fn load_root_gitignore_patterns(root: &Path) -> Result<Vec<GitignorePattern>, DeclareCostError> {
    let path = root.join(".gitignore");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let text = std::fs::read_to_string(&path).map_err(|err| {
        DeclareCostError::Io(format!("read .gitignore {}: {}", path.display(), err))
    })?;

    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('!') {
            // v0 fallback ignores negation patterns; this path is only used when git isn't available.
            continue;
        }
        out.push(GitignorePattern {
            raw: line.to_string(),
        });
    }
    Ok(out)
}

fn is_ignored_by_root_gitignore(
    root: &Path,
    abs: &Path,
    patterns: &[GitignorePattern],
    is_dir: bool,
) -> Result<bool, DeclareCostError> {
    if patterns.is_empty() {
        return Ok(false);
    }
    let rel = abs.strip_prefix(root).map_err(|err| {
        DeclareCostError::Io(format!("strip_prefix {}: {}", abs.display(), err))
    })?;
    let rel_str = rel.to_string_lossy().replace('\\', "/");
    let file_name = abs.file_name().and_then(|s| s.to_str()).unwrap_or("");

    for p in patterns {
        if gitignore_matches(&p.raw, &rel_str, file_name, is_dir) {
            return Ok(true);
        }
    }
    Ok(false)
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

fn walk_files_via_git(root: &Path) -> Result<Vec<PathBuf>, DeclareCostError> {
    let (toplevel, toplevel_for_git) = git_toplevel(root)?;
    let root_rel = root.strip_prefix(&toplevel).unwrap_or_else(|_| Path::new(""));
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
        .map_err(|err| DeclareCostError::Io(format!("git ls-files: {}", err)))?;
    if !output.status.success() {
        return Err(DeclareCostError::Io(format!(
            "git ls-files failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }

    let mut out = Vec::new();
    for entry in output.stdout.split(|b| *b == 0) {
        if entry.is_empty() {
            continue;
        }
        let rel = String::from_utf8(entry.to_vec())
            .map_err(|_| DeclareCostError::Io("git returned non-utf8 path".to_string()))?;
        let abs = toplevel.join(Path::new(&rel));
        if !abs.starts_with(root) {
            continue;
        }
        let rel_to_root = abs.strip_prefix(root).map_err(|err| {
            DeclareCostError::Io(format!("strip_prefix {}: {}", abs.display(), err))
        })?;
        if should_skip_rel_path(rel_to_root) {
            continue;
        }
        let meta = std::fs::metadata(&abs).map_err(|err| {
            DeclareCostError::Io(format!("metadata {}: {}", abs.display(), err))
        })?;
        if meta.is_file() {
            out.push(abs);
        }
    }
    out.sort_by(|a, b| a.to_string_lossy().cmp(&b.to_string_lossy()));
    Ok(out)
}

fn git_toplevel(root: &Path) -> Result<(PathBuf, PathBuf), DeclareCostError> {
    let root_for_git = path_for_git(root);
    let output = Command::new("git")
        .arg("-C")
        .arg(&root_for_git)
        .args(["rev-parse", "--show-toplevel"])
        .output()
        .map_err(|err| DeclareCostError::Io(format!("git rev-parse: {}", err)))?;
    if !output.status.success() {
        return Err(DeclareCostError::Io(format!(
            "git rev-parse failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    let s = String::from_utf8_lossy(&output.stdout);
    let p = s.trim();
    if p.is_empty() {
        return Err(DeclareCostError::Io("git rev-parse returned empty toplevel".to_string()));
    }
    let toplevel_for_git = PathBuf::from(p);
    let toplevel = toplevel_for_git.canonicalize().map_err(|err| {
        DeclareCostError::Io(format!("canonicalize git toplevel: {}", err))
    })?;
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

fn should_skip_dir(path: &Path) -> bool {
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

fn should_skip_rel_path(rel: &Path) -> bool {
    rel.components().any(|c| match c {
        std::path::Component::Normal(s) => should_skip_dir(Path::new(s)),
        _ => false,
    })
}

fn to_rel_path(root: &Path, path: &Path) -> Result<String, DeclareCostError> {
    let rel = path.strip_prefix(root).map_err(|err| {
        DeclareCostError::Io(format!("strip_prefix {}: {}", path.display(), err))
    })?;
    let mut parts = Vec::new();
    for comp in rel.components() {
        let s = comp.as_os_str().to_str().ok_or_else(|| {
            DeclareCostError::Io(format!(
                "non-utf8 path component under root: {}",
                path.display()
            ))
        })?;
        parts.push(s);
    }
    Ok(parts.join("/"))
}

#[derive(Debug, Clone)]
struct MdChunk {
    heading_path: Vec<String>,
    start_line: u32,
    text: String,
}

fn chunk_markdown(input: &str) -> Vec<MdChunk> {
    let mut chunks = Vec::new();
    let mut heading_stack: Vec<(u8, String)> = Vec::new();
    let mut current_start: u32 = 1;
    let mut current_text = String::new();
    let mut current_heading_path: Vec<String> = Vec::new();

    let lines: Vec<&str> = input.lines().collect();
    for (idx, line) in lines.iter().enumerate() {
        let line_no = (idx as u32) + 1;
        if let Some((level, title)) = parse_heading(line) {
            if !current_text.is_empty() {
                chunks.push(MdChunk {
                    heading_path: current_heading_path.clone(),
                    start_line: current_start,
                    text: current_text.clone(),
                });
                current_text.clear();
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
            current_start = line_no;
        }
        current_text.push_str(line);
        current_text.push('\n');
    }
    if !current_text.is_empty() {
        chunks.push(MdChunk {
            heading_path: current_heading_path,
            start_line: current_start,
            text: current_text,
        });
    }
    chunks
}

fn parse_heading(line: &str) -> Option<(u8, String)> {
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
