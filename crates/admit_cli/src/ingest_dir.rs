use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};

use admit_surrealdb::link_resolver::{
    extract_obsidian_links, file_stem_title, normalize_heading, normalize_target,
    obsidian_heading_slug,
};

use crate::artifact::default_artifacts_dir;
use crate::artifact::store_artifact;
use crate::ingest_cache::{CachedChunk, CachedFile, IngestCache};
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
    pub snapshot: ArtifactRef,
    pub snapshot_sha256: String,
    pub parse: ArtifactRef,
    pub parse_sha256: String,
    pub files: Vec<IngestedFile>,
    pub chunks: Vec<IngestedChunk>,
    pub total_bytes: u64,
    pub walk_mode: String,
    pub skipped_by_skip_dir: u64,
    pub warnings: Vec<IngestWarning>,
    pub incremental: Option<IngestIncremental>,
}

#[derive(Debug, Clone)]
pub struct IngestIncremental {
    pub enabled: bool,
    pub cache_path: Option<PathBuf>,
    pub cache_reset: bool,
    pub cache_reset_reason: Option<String>,
    pub files_cached: u64,
    pub files_parsed: u64,
    pub chunks_cached: u64,
    pub chunks_parsed: u64,
    pub docs_to_resolve_links: Vec<String>,
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
    ingest_dir_with_cache(root, artifacts_root, None)
}

pub fn ingest_dir_with_cache(
    root: &Path,
    artifacts_root: Option<&Path>,
    incremental_cache: Option<&Path>,
) -> Result<IngestDirOutput, DeclareCostError> {
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

    let mut warnings: Vec<IngestWarning> = Vec::new();
    let mut incremental = incremental_cache.map(|p| IngestIncremental {
        enabled: false,
        cache_path: Some(p.to_path_buf()),
        cache_reset: false,
        cache_reset_reason: None,
        files_cached: 0,
        files_parsed: 0,
        chunks_cached: 0,
        chunks_parsed: 0,
        docs_to_resolve_links: Vec::new(),
    });
    let mut cache = if let Some(cache_path) = incremental_cache {
        match IngestCache::load_or_create(cache_path, &root, artifacts_root) {
            Ok(cache) => {
                if let Some(info) = incremental.as_mut() {
                    info.enabled = true;
                    info.cache_reset = cache.reset;
                    info.cache_reset_reason = cache.reset_reason.clone();
                }
                Some(cache)
            }
            Err(err) => {
                warnings.push(IngestWarning {
                    kind: "incremental_cache_error".to_string(),
                    rel_path: Some(cache_path.to_string_lossy().to_string()),
                    message: err,
                });
                None
            }
        }
    } else {
        None
    };

    let mut current_paths: BTreeSet<String> = BTreeSet::new();
    let mut current_docs: BTreeSet<String> = BTreeSet::new();
    let mut changed_docs: BTreeSet<String> = BTreeSet::new();
    let mut target_title_keys: BTreeSet<String> = BTreeSet::new();
    let mut target_title_keys_casefold: BTreeSet<String> = BTreeSet::new();
    let mut target_path_keys: BTreeSet<String> = BTreeSet::new();
    let walk = walk_files(&root)?;
    let walk_mode = walk.mode.as_str().to_string();
    let skipped_by_skip_dir = walk.skipped_by_skip_dir;
    warnings.extend(walk.warnings);

    for path in walk.paths {
        let rel_path = match to_rel_path(&root, &path) {
            Ok(p) => p,
            Err(err) => {
                warnings.push(IngestWarning {
                    kind: "non_utf8_path".to_string(),
                    rel_path: None,
                    message: err.to_string(),
                });
                continue;
            }
        };
        current_paths.insert(rel_path.clone());

        let metadata = match std::fs::metadata(&path) {
            Ok(m) => m,
            Err(err) => {
                warnings.push(IngestWarning {
                    kind: "metadata_error".to_string(),
                    rel_path: Some(rel_path.clone()),
                    message: err.to_string(),
                });
                continue;
            }
        };
        let size_bytes = metadata.len();
        let mtime_unix_ms = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let ext = path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("bin")
            .to_lowercase();
        let is_markdown = ext == "md";
        if is_markdown {
            current_docs.insert(rel_path.clone());
        }

        if let Some(cache) = cache.as_mut() {
            if let Some(cached) = cache.get(&rel_path) {
                if cached.size_bytes == size_bytes && cached.mtime_unix_ms == mtime_unix_ms {
                    total_bytes = total_bytes.saturating_add(cached.size_bytes);
                    snapshot_entries.push(SnapshotEntry {
                        path: rel_path.clone(),
                        sha256: cached.artifact.sha256.clone(),
                        size_bytes: cached.size_bytes,
                    });
                    files.push(IngestedFile {
                        rel_path: rel_path.clone(),
                        artifact: cached.artifact.clone(),
                    });
                    if cached.is_markdown {
                        for chunk in &cached.chunks {
                            parse_entries.push(ParseEntry {
                                path: rel_path.clone(),
                                chunk_sha256: chunk.chunk_sha256.clone(),
                                start_line: chunk.start_line,
                                heading_path: chunk.heading_path.clone(),
                            });
                            chunks.push(IngestedChunk {
                                rel_path: rel_path.clone(),
                                heading_path: chunk.heading_path.clone(),
                                start_line: chunk.start_line,
                                chunk_sha256: chunk.chunk_sha256.clone(),
                                artifact: chunk.artifact.clone(),
                            });
                        }
                    }
                    if let Some(info) = incremental.as_mut() {
                        info.files_cached = info.files_cached.saturating_add(1);
                        info.chunks_cached = info.chunks_cached.saturating_add(cached.chunks.len() as u64);
                    }
                    continue;
                }
            }
        }

        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) => {
                warnings.push(IngestWarning {
                    kind: "read_error".to_string(),
                    rel_path: Some(rel_path.clone()),
                    message: err.to_string(),
                });
                continue;
            }
        };
        total_bytes = total_bytes.saturating_add(bytes.len() as u64);
        let content_sha256 = sha256_hex(&bytes);

        if let Some(cache) = cache.as_mut() {
            if let Some(cached) = cache.get_mut(&rel_path) {
                if cached.content_sha256 == content_sha256 {
                    cached.size_bytes = size_bytes;
                    cached.mtime_unix_ms = mtime_unix_ms;
                    snapshot_entries.push(SnapshotEntry {
                        path: rel_path.clone(),
                        sha256: cached.artifact.sha256.clone(),
                        size_bytes: cached.size_bytes,
                    });
                    files.push(IngestedFile {
                        rel_path: rel_path.clone(),
                        artifact: cached.artifact.clone(),
                    });
                    if cached.is_markdown {
                        for chunk in &cached.chunks {
                            parse_entries.push(ParseEntry {
                                path: rel_path.clone(),
                                chunk_sha256: chunk.chunk_sha256.clone(),
                                start_line: chunk.start_line,
                                heading_path: chunk.heading_path.clone(),
                            });
                            chunks.push(IngestedChunk {
                                rel_path: rel_path.clone(),
                                heading_path: chunk.heading_path.clone(),
                                start_line: chunk.start_line,
                                chunk_sha256: chunk.chunk_sha256.clone(),
                                artifact: chunk.artifact.clone(),
                            });
                        }
                    }
                    if let Some(info) = incremental.as_mut() {
                        info.files_cached = info.files_cached.saturating_add(1);
                        info.chunks_cached = info.chunks_cached.saturating_add(cached.chunks.len() as u64);
                    }
                    continue;
                }
            }
        }

        let prev_cached = cache.as_ref().and_then(|c| c.get(&rel_path)).cloned();
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

        let mut file_chunks: Vec<IngestedChunk> = Vec::new();
        let mut link_title_keys: Vec<String> = Vec::new();
        let mut link_title_keys_casefold: Vec<String> = Vec::new();
        let mut link_path_keys: Vec<String> = Vec::new();
        let mut heading_hash: Option<String> = None;
        let mut title: Option<String> = None;

        if is_markdown {
            title = Some(file_stem_title(&rel_path));
            match std::str::from_utf8(&bytes) {
                Ok(text) => {
                    let (lt, ltc, lp) = extract_link_keys(text);
                    link_title_keys = lt;
                    link_title_keys_casefold = ltc;
                    link_path_keys = lp;

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
                        let ingested = IngestedChunk {
                            rel_path: rel_path.clone(),
                            heading_path: c.heading_path,
                            start_line: c.start_line,
                            chunk_sha256,
                            artifact: chunk_artifact,
                        };
                        file_chunks.push(ingested.clone());
                        chunks.push(ingested);
                    }
                    heading_hash = heading_hash_from_chunks(&file_chunks);
                }
                Err(_) => {
                    warnings.push(IngestWarning {
                        kind: "md_non_utf8".to_string(),
                        rel_path: Some(rel_path.clone()),
                        message: "markdown file is not valid utf-8; skipping chunking".to_string(),
                    });
                }
            }
        }

        if is_markdown {
            changed_docs.insert(rel_path.clone());
            let title_changed = prev_cached
                .as_ref()
                .and_then(|c| c.title.as_ref())
                .map(|t| title.as_ref().map(|n| n != t).unwrap_or(true))
                .unwrap_or(true);
            let heading_changed = prev_cached
                .as_ref()
                .map(|c| c.heading_hash != heading_hash)
                .unwrap_or(true);
            if title_changed || heading_changed {
                if let Some(t) = title.as_ref() {
                    add_target_keys(
                        &rel_path,
                        t,
                        &mut target_title_keys,
                        &mut target_title_keys_casefold,
                        &mut target_path_keys,
                    );
                }
                if title_changed {
                    if let Some(prev_title) = prev_cached.as_ref().and_then(|c| c.title.as_ref()) {
                        add_target_keys(
                            &rel_path,
                            prev_title,
                            &mut target_title_keys,
                            &mut target_title_keys_casefold,
                            &mut target_path_keys,
                        );
                    }
                }
            }
        }

        if let Some(cache) = cache.as_mut() {
            let cached_chunks: Vec<CachedChunk> = file_chunks
                .iter()
                .map(|c| CachedChunk {
                    heading_path: c.heading_path.clone(),
                    start_line: c.start_line,
                    chunk_sha256: c.chunk_sha256.clone(),
                    artifact: c.artifact.clone(),
                })
                .collect();
            cache.update(CachedFile {
                rel_path: rel_path.clone(),
                size_bytes,
                mtime_unix_ms,
                content_sha256,
                artifact: artifact.clone(),
                is_markdown,
                chunks: cached_chunks,
                link_title_keys,
                link_title_keys_casefold,
                link_path_keys,
                title,
                heading_hash,
            });
        }

        if let Some(info) = incremental.as_mut() {
            info.files_parsed = info.files_parsed.saturating_add(1);
            info.chunks_parsed = info.chunks_parsed.saturating_add(file_chunks.len() as u64);
        }
    }

    if let Some(cache) = cache.as_mut() {
        let mut removed: Vec<String> = Vec::new();
        for (path, cached) in cache.files() {
            if !current_paths.contains(path) {
                removed.push(path.clone());
                if cached.is_markdown {
                    let title = cached
                        .title
                        .clone()
                        .unwrap_or_else(|| file_stem_title(path));
                    add_target_keys(
                        path,
                        &title,
                        &mut target_title_keys,
                        &mut target_title_keys_casefold,
                        &mut target_path_keys,
                    );
                }
            }
        }
        for path in removed {
            cache.remove(&path);
        }

        if let Some(info) = incremental.as_mut() {
            let mut docs_to_resolve: BTreeSet<String> = BTreeSet::new();
            docs_to_resolve.extend(changed_docs.iter().cloned());
            for (path, cached) in cache.files() {
                if !current_docs.contains(path) {
                    continue;
                }
                if intersects(&cached.link_path_keys, &target_path_keys)
                    || intersects(&cached.link_title_keys, &target_title_keys)
                    || intersects(&cached.link_title_keys_casefold, &target_title_keys_casefold)
                {
                    docs_to_resolve.insert(path.clone());
                }
            }
            info.docs_to_resolve_links = docs_to_resolve.into_iter().collect();
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

    warnings.sort_by(|a, b| {
        a.kind
            .cmp(&b.kind)
            .then(a.rel_path.cmp(&b.rel_path))
            .then(a.message.cmp(&b.message))
    });

    if let Some(cache) = cache.as_ref() {
        cache
            .save()
            .map_err(|err| DeclareCostError::Io(format!("save cache: {}", err)))?;
    }

    Ok(IngestDirOutput {
        root,
        snapshot_sha256: snapshot.sha256.clone(),
        snapshot,
        parse_sha256: parse.sha256.clone(),
        parse,
        files,
        chunks,
        total_bytes,
        walk_mode,
        skipped_by_skip_dir,
        warnings,
        incremental,
    })
}

#[derive(Debug, Clone, Copy)]
enum WalkMode {
    GitLsFiles,
    FsWalk,
}

impl WalkMode {
    fn as_str(&self) -> &'static str {
        match self {
            WalkMode::GitLsFiles => "git_ls_files",
            WalkMode::FsWalk => "fs_walk",
        }
    }
}

#[derive(Debug, Clone)]
struct WalkFilesOutput {
    mode: WalkMode,
    paths: Vec<PathBuf>,
    skipped_by_skip_dir: u64,
    warnings: Vec<IngestWarning>,
}

fn walk_files(root: &Path) -> Result<WalkFilesOutput, DeclareCostError> {
    let disable_git = std::env::var_os("ADMIT_INGEST_DISABLE_GIT")
        .and_then(|v| v.to_str().map(|s| s.to_string()))
        .is_some_and(|s| s == "1" || s.eq_ignore_ascii_case("true"));

    if !disable_git {
        if let Ok(out) = walk_files_via_git(root) {
            return Ok(out);
        }
    }

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

#[derive(Debug, Clone)]
struct GitignorePattern {
    raw: String,
    negated: bool,
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
) -> Result<bool, DeclareCostError> {
    if patterns.is_empty() {
        return Ok(false);
    }
    let rel = abs.strip_prefix(root).map_err(|err| {
        DeclareCostError::Io(format!("strip_prefix {}: {}", abs.display(), err))
    })?;
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

fn walk_files_via_git(root: &Path) -> Result<WalkFilesOutput, DeclareCostError> {
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
            DeclareCostError::Io(format!("strip_prefix {}: {}", abs.display(), err))
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

fn strip_md_extension(value: &str) -> String {
    let lower = value.to_lowercase();
    if lower.ends_with(".md") && value.len() >= 3 {
        value[..value.len() - 3].to_string()
    } else {
        value.to_string()
    }
}

fn extract_link_keys(input: &str) -> (Vec<String>, Vec<String>, Vec<String>) {
    let mut title_keys: BTreeSet<String> = BTreeSet::new();
    let mut title_casefold: BTreeSet<String> = BTreeSet::new();
    let mut path_keys: BTreeSet<String> = BTreeSet::new();

    for link in extract_obsidian_links(input) {
        let target = normalize_target(&link.target);
        if target.is_empty() {
            continue;
        }
        let target_no_ext = strip_md_extension(&target);
        if target.contains('/') {
            path_keys.insert(target.clone());
            if target_no_ext != target {
                path_keys.insert(target_no_ext);
            }
        } else {
            title_keys.insert(target.clone());
            title_casefold.insert(target.to_lowercase());
            if target_no_ext != target {
                title_keys.insert(target_no_ext.clone());
                title_casefold.insert(target_no_ext.to_lowercase());
            }
        }
    }

    (
        title_keys.into_iter().collect(),
        title_casefold.into_iter().collect(),
        path_keys.into_iter().collect(),
    )
}

fn add_target_keys(
    rel_path: &str,
    title: &str,
    title_keys: &mut BTreeSet<String>,
    title_keys_casefold: &mut BTreeSet<String>,
    path_keys: &mut BTreeSet<String>,
) {
    if !title.is_empty() {
        title_keys.insert(title.to_string());
        title_keys_casefold.insert(title.to_lowercase());
    }
    let norm_path = normalize_target(rel_path);
    if !norm_path.is_empty() {
        path_keys.insert(norm_path.clone());
        let norm_no_ext = strip_md_extension(&norm_path);
        if norm_no_ext != norm_path {
            path_keys.insert(norm_no_ext);
        }
    }
}

fn intersects(values: &[String], set: &BTreeSet<String>) -> bool {
    values.iter().any(|v| set.contains(v))
}

fn heading_hash_from_chunks(chunks: &[IngestedChunk]) -> Option<String> {
    let mut set: BTreeSet<String> = BTreeSet::new();
    for chunk in chunks {
        for heading in &chunk.heading_path {
            let nh = normalize_heading(heading);
            if !nh.is_empty() {
                set.insert(nh);
            }
            let sh = obsidian_heading_slug(heading);
            if !sh.is_empty() {
                set.insert(sh);
            }
        }
    }
    if set.is_empty() {
        return None;
    }
    let joined = set.into_iter().collect::<Vec<_>>().join("\n");
    Some(sha256_hex(joined.as_bytes()))
}
