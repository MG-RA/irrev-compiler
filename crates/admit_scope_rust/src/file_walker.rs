//! Filesystem traversal for Rust source files.
//!
//! Pure functions with no CLI or database dependencies.

use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// A Rust source file with content and content-addressable hash.
#[derive(Debug, Clone)]
pub struct RustSourceFile {
    /// Path relative to the scan root, forward-slash normalized.
    pub rel_path: String,
    /// File content as UTF-8 text.
    pub content: String,
    /// SHA-256 hex digest of the raw file bytes.
    pub sha256: String,
}

/// Load all Rust source files under `root`, sorted by relative path.
pub fn load_rust_sources(root: &Path) -> Result<Vec<RustSourceFile>, String> {
    let root_canon = root
        .canonicalize()
        .map_err(|e| format!("canonicalize {}: {}", root.display(), e))?;

    let mut paths = Vec::new();
    collect_rs_paths(&root_canon, &mut paths)?;
    paths.sort();

    let mut files = Vec::with_capacity(paths.len());
    for path in paths {
        let bytes = fs::read(&path).map_err(|e| format!("read {}: {}", path.display(), e))?;
        let content = String::from_utf8_lossy(&bytes).into_owned();
        let rel = path
            .strip_prefix(&root_canon)
            .ok()
            .map(normalize_path)
            .unwrap_or_else(|| normalize_path(&path));
        files.push(RustSourceFile {
            rel_path: rel,
            content,
            sha256: sha256_hex(&bytes),
        });
    }
    Ok(files)
}

/// Recursively collect `.rs` file paths, skipping common non-source directories.
pub fn collect_rs_paths(path: &Path, out: &mut Vec<PathBuf>) -> Result<(), String> {
    if path.is_file() {
        if path.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(path.to_path_buf());
        }
        return Ok(());
    }

    if !path.is_dir() {
        return Ok(());
    }

    let mut entries = Vec::new();
    for entry in fs::read_dir(path).map_err(|e| format!("read_dir {}: {}", path.display(), e))? {
        let entry = entry.map_err(|e| format!("dir entry: {}", e))?;
        entries.push(entry.path());
    }
    entries.sort();

    for entry_path in entries {
        if entry_path.is_dir() {
            let skip = entry_path
                .file_name()
                .and_then(|s| s.to_str())
                .is_some_and(should_skip_dir);
            if skip {
                continue;
            }
            collect_rs_paths(&entry_path, out)?;
        } else if entry_path.extension().and_then(|s| s.to_str()) == Some("rs") {
            out.push(entry_path);
        }
    }
    Ok(())
}

/// Directories to skip during traversal.
fn should_skip_dir(name: &str) -> bool {
    matches!(
        name,
        ".git" | "target" | "node_modules" | ".venv" | "venv" | "out"
    )
}

/// Normalize path separators to forward slashes.
pub fn normalize_path(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("admit-scope-rust-walker-{}-{}", label, nanos))
    }

    #[test]
    fn collects_only_rs_files() {
        let dir = temp_dir("rs-only");
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::write(dir.join("src/main.rs"), "fn main() {}").unwrap();
        fs::write(dir.join("src/readme.md"), "# hello").unwrap();
        fs::write(dir.join("src/lib.txt"), "not rust").unwrap();

        let files = load_rust_sources(&dir).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].rel_path, "src/main.rs");
    }

    #[test]
    fn skips_target_and_git_dirs() {
        let dir = temp_dir("skip-dirs");
        fs::create_dir_all(dir.join("src")).unwrap();
        fs::create_dir_all(dir.join("target/debug")).unwrap();
        fs::create_dir_all(dir.join(".git/objects")).unwrap();
        fs::write(dir.join("src/lib.rs"), "pub fn f() {}").unwrap();
        fs::write(dir.join("target/debug/build.rs"), "fn build() {}").unwrap();
        fs::write(dir.join(".git/objects/hook.rs"), "fn hook() {}").unwrap();

        let files = load_rust_sources(&dir).unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].rel_path, "src/lib.rs");
    }

    #[test]
    fn normalizes_paths_to_forward_slashes() {
        let p = Path::new("foo\\bar\\baz.rs");
        assert_eq!(normalize_path(p), "foo/bar/baz.rs");
    }

    #[test]
    fn sha256_is_stable() {
        let hash1 = sha256_hex(b"hello world");
        let hash2 = sha256_hex(b"hello world");
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 64); // hex-encoded SHA-256 = 64 chars
    }
}
