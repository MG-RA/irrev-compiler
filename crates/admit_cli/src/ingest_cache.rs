use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::types::ArtifactRef;

const CACHE_VERSION: u32 = 2;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedChunk {
    pub heading_path: Vec<String>,
    pub start_line: u32,
    #[serde(default)]
    pub end_line: Option<u32>,
    #[serde(default)]
    pub start_byte: Option<u32>,
    #[serde(default)]
    pub end_byte: Option<u32>,
    #[serde(default)]
    pub format: Option<String>,
    #[serde(default)]
    pub language: Option<String>,
    #[serde(default)]
    pub chunk_kind: Option<String>,
    pub chunk_sha256: String,
    pub artifact: ArtifactRef,
    #[serde(default)]
    pub repr_artifact: Option<ArtifactRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedFile {
    pub rel_path: String,
    pub size_bytes: u64,
    pub mtime_unix_ms: u64,
    pub content_sha256: String,
    pub artifact: ArtifactRef,
    pub is_markdown: bool,
    pub chunks: Vec<CachedChunk>,
    pub link_title_keys: Vec<String>,
    pub link_title_keys_casefold: Vec<String>,
    pub link_path_keys: Vec<String>,
    pub title: Option<String>,
    pub heading_hash: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IngestCacheManifest {
    pub version: u32,
    pub root_abs: String,
    pub artifacts_root: String,
    pub files: BTreeMap<String, CachedFile>,
}

#[derive(Debug)]
pub struct IngestCache {
    manifest: IngestCacheManifest,
    cache_path: PathBuf,
    pub reset: bool,
    pub reset_reason: Option<String>,
}

impl IngestCache {
    pub fn load_or_create(
        cache_path: &Path,
        root_abs: &Path,
        artifacts_root: &Path,
    ) -> Result<Self, String> {
        let root_abs_str = root_abs.to_string_lossy().to_string();
        let artifacts_root_str = artifacts_root.to_string_lossy().to_string();

        let mut reset = false;
        let mut reset_reason: Option<String> = None;
        let manifest = if cache_path.exists() {
            let bytes = std::fs::read(cache_path)
                .map_err(|e| format!("read cache {}: {}", cache_path.display(), e))?;
            match serde_json::from_slice::<IngestCacheManifest>(&bytes) {
                Ok(mut manifest) => {
                    if manifest.version != CACHE_VERSION {
                        reset = true;
                        reset_reason = Some(format!(
                            "cache version mismatch ({} != {})",
                            manifest.version, CACHE_VERSION
                        ));
                        manifest = Self::empty_manifest(&root_abs_str, &artifacts_root_str);
                    } else if manifest.root_abs != root_abs_str {
                        reset = true;
                        reset_reason = Some("cache root mismatch".to_string());
                        manifest = Self::empty_manifest(&root_abs_str, &artifacts_root_str);
                    } else if manifest.artifacts_root != artifacts_root_str {
                        reset = true;
                        reset_reason = Some("cache artifacts_root mismatch".to_string());
                        manifest = Self::empty_manifest(&root_abs_str, &artifacts_root_str);
                    }
                    manifest
                }
                Err(err) => {
                    reset = true;
                    reset_reason = Some(format!("cache parse failed: {}", err));
                    Self::empty_manifest(&root_abs_str, &artifacts_root_str)
                }
            }
        } else {
            Self::empty_manifest(&root_abs_str, &artifacts_root_str)
        };

        Ok(Self {
            manifest,
            cache_path: cache_path.to_path_buf(),
            reset,
            reset_reason,
        })
    }

    pub fn save(&self) -> Result<(), String> {
        let json = serde_json::to_vec_pretty(&self.manifest)
            .map_err(|e| format!("serialize cache: {}", e))?;
        if let Some(parent) = self.cache_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| format!("create cache parent {}: {}", parent.display(), e))?;
            }
        }
        std::fs::write(&self.cache_path, json)
            .map_err(|e| format!("write cache {}: {}", self.cache_path.display(), e))?;
        Ok(())
    }

    pub fn get(&self, rel_path: &str) -> Option<&CachedFile> {
        self.manifest.files.get(rel_path)
    }

    pub fn get_mut(&mut self, rel_path: &str) -> Option<&mut CachedFile> {
        self.manifest.files.get_mut(rel_path)
    }

    pub fn update(&mut self, entry: CachedFile) {
        self.manifest.files.insert(entry.rel_path.clone(), entry);
    }

    pub fn remove(&mut self, rel_path: &str) -> Option<CachedFile> {
        self.manifest.files.remove(rel_path)
    }

    pub fn files(&self) -> impl Iterator<Item = (&String, &CachedFile)> {
        self.manifest.files.iter()
    }

    fn empty_manifest(root_abs: &str, artifacts_root: &str) -> IngestCacheManifest {
        IngestCacheManifest {
            version: CACHE_VERSION,
            root_abs: root_abs.to_string(),
            artifacts_root: artifacts_root.to_string(),
            files: BTreeMap::new(),
        }
    }
}
