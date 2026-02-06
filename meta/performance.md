# Performance Optimization Plan: Irreversibility Projection Pipeline

## Executive Summary

Your system has excellent design foundations (content-addressed DAG, deterministic IDs, provenance tracking) but is currently **single-threaded and subprocess-bound**. With your hardware (32GB RAM, 24 threads, GPU), we can achieve **10-20x performance improvement** by introducing parallelism at multiple levels.

**Current Bottlenecks** (200s doc_chunks, 174s dag_trace, 75s vault_links):
1. **Sequential phase execution** - phases run one at a time
2. **Subprocess overhead** - each batch spawns new `surreal sql` CLI process
3. **Single-threaded parsing** - 1000+ files parsed sequentially
4. **No incremental processing** - all files re-parsed every run
5. **Excessive string allocations** - 31+ clone() calls per file

**Target Architecture**:
- **Phase-level parallelism**: Independent phases run concurrently
- **Batch-level pipelining**: Parse while writing, read while parsing
- **CPU pool for parsing**: Rayon-based parallel file processing
- **Native DB SDK**: Replace subprocess with connection pool
- **Incremental mode**: Skip unchanged files

---

## Step 0: Benchmarking Harness (Est. 1-2 hours)

**CRITICAL: Do this first** - you cannot optimize what you don't measure

### 0.1 Enhanced Timing and Instrumentation

**Problem**: Current timing only shows phase duration, not internal bottlenecks

**Files to modify**:
- [crates/admit_surrealdb/src/projection_run.rs](crates/admit_surrealdb/src/projection_run.rs) (add detailed metrics)
- [crates/admit_cli/src/main.rs:2177-2368](crates/admit_cli/src/main.rs#L2177-L2368) (add instrumentation)

**Add to PhaseResult**:
```rust
pub struct PhaseResult {
    pub phase: String,
    pub status: PhaseStatus,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub duration_ms: Option<u64>,

    // NEW: Detailed metrics
    pub records_processed: u64,
    pub batches_executed: u64,
    pub bytes_written: u64,
    pub files_read: Option<u64>,
    pub parse_time_ms: Option<u64>,
    pub db_write_time_ms: Option<u64>,
    pub errors: Vec<String>,
}
```

**Add --bench mode**:
```rust
#[arg(long, help = "Run projection twice and report performance delta")]
bench: bool,
```

**Expected Output**:

```text
Phase: doc_chunks
  Files read: 1247 in 2.3s (IO)
  Parse time: 15.4s (CPU)
  DB write: 3.1s (8 batches, avg 387ms/batch)
  Total: 20.8s
  Bottleneck: CPU parsing (74% of time)
```

This tells you **where** to optimize.

---

## Phase 1: Adaptive Batching (Est. 1-2 hours)

### 1.1 Size-Aware Batch Limits (not just count)

**Problem**: Large SQL strings can hit parsing limits or cause latency spikes

**Files to modify**:
- [crates/admit_surrealdb/src/projection_config.rs:180-240](crates/admit_surrealdb/src/projection_config.rs#L180-L240)

**Changes**:
```rust
pub struct BatchSizes {
    pub nodes: usize,        // Max records per batch
    pub edges: usize,
    pub doc_chunks: usize,
    pub doc_files: usize,
    pub headings: usize,
    pub links: usize,
    pub stats: usize,
    pub embeddings: usize,

    // NEW: Size-based limits
    pub max_sql_bytes: usize,  // Default: 1MB (1_000_000)
}

impl BatchSizes {
    pub fn should_flush(&self, count: usize, sql_bytes: usize, phase: &str) -> bool {
        let count_limit = match phase {
            "nodes" => self.nodes,
            "edges" => self.edges,
            "doc_chunks" => self.doc_chunks,
            // ...
            _ => 200,
        };

        count >= count_limit || sql_bytes >= self.max_sql_bytes
    }
}
```

**Update batch building**:
```rust
// In project_doc_chunks, etc:
let mut batch_count = 0;
let mut sql = String::new();

for item in items {
    sql.push_str(&generate_sql(item));
    batch_count += 1;

    // Flush on count OR size limit
    if config.batch_sizes.should_flush(batch_count, sql.len(), "doc_chunks") {
        self.run_sql(&sql)?;
        sql.clear();
        batch_count = 0;
    }
}
```

**Tune initial sizes** (via benchmarking, not guessing):
```rust
pub fn default_batch_sizes() -> BatchSizes {
    BatchSizes {
        nodes: 500,           // Conservative increase
        edges: 500,
        doc_chunks: 100,      // Not 200 - test first
        doc_files: 300,
        headings: 300,
        links: 200,
        stats: 300,
        embeddings: 16,       // Keep small (expensive)
        max_sql_bytes: 1_000_000,  // 1MB cap
    }
}
```

**Expected Impact**: 30-50% reduction in batches **without** hitting size cliffs

---

---

### 1.2 Profile Before Optimizing Allocations

**Problem**: The plan originally suggested fixing "31+ clones" but we need data first

**Action**: Run profiling to identify real hot spots

**Tools**:

- **Linux**: `perf record -g ./admit project ... && perf report`
- **Windows**: Use `cargo flamegraph` or Windows Performance Analyzer
- **Cross-platform**: `cargo build --release && samply record ./target/release/admit project ...`

**Only optimize allocations if profiling shows they're in top 5 hot spots**

If clones ARE the bottleneck, then:

**Files to modify**:

- [crates/admit_cli/src/ingest_dir.rs:73-728](crates/admit_cli/src/ingest_dir.rs#L73-L728)

**Key optimizations**:

#### A. Use `Arc<String>` for shared paths
```rust
// Current (line 111, 135, 140, 141):
parse_entries.push(ParseEntry {
    path: rel_path.clone(),  // ← Clone per chunk
    // ...
});

// Optimized:
let rel_path_arc = Arc::new(rel_path);
parse_entries.push(ParseEntry {
    path: Arc::clone(&rel_path_arc),  // ← Cheap pointer copy
    // ...
});
```

#### B. Reuse heading_path with Cow or Arc
```rust
// Current (line 161-164):
heading_path: c.heading_path.clone(),  // Vec<String> cloned

// Optimized:
use std::sync::Arc;
pub struct MdChunk<'a> {
    heading_path: Arc<Vec<String>>,  // Shared across chunks
}
```

#### C. Pre-allocate vectors with capacity
```rust
// Before parsing loop:
let mut parse_entries = Vec::with_capacity(estimated_chunks);
```

**Expected Impact**: 30-40% reduction in allocation overhead for large vaults

---

### 1.3 Compile Regexes Once (15 min)

**Problem**: Link extraction rebuilds patterns on every call

**Files to modify**:
- [crates/admit_surrealdb/src/link_resolver.rs:595-639](crates/admit_surrealdb/src/link_resolver.rs#L595-L639)

**Solution**: Use `once_cell` or `lazy_static` for regex patterns

```rust
use once_cell::sync::Lazy;
use regex::Regex;

static HEADING_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"^#+\s+(.+)$").unwrap()
});

// Use in parse_heading():
HEADING_PATTERN.captures(line)
```

**Expected Impact**: Negligible for small vaults, 5-10% for large vaults with many links

---

## Step 1: Incremental Processing (HIGHEST ROI for repeat runs)

### 1.1 Content-Hash-Based Change Detection (3-4 hours)

**Problem**: All files re-parsed every run, even if unchanged
**Impact**: This is the **biggest win** for typical workflows (90%+ files unchanged between runs)

**Key Insight**: With content-addressed hashes, unchanged hash → skip all derived work

#### Mental Model: Two Levels of Identity

**Level 1: file_content_hash** (hash of raw bytes)

If unchanged → skip:

- Markdown parsing
- Chunking
- Link extraction
- Embedding generation

**Level 2: derived_hashes** (hash of outputs + config versions)

- `chunking_hash`: Skip chunking if `(file_hash, chunker_version)` unchanged
- `link_extract_hash`: Skip extraction if `(file_hash, link_grammar_version)` unchanged
- `embedding_hash`: Skip embeddings if `(chunk_hash, model_id)` unchanged

This allows skipping stages even when CODE changes, if the relevant stage didn't change.

**Files to modify**:
- [crates/admit_cli/src/ingest_dir.rs:73-184](crates/admit_cli/src/ingest_dir.rs#L73-L184)
- New file: `crates/admit_cli/src/ingest_cache.rs`

**Implementation**:

#### A. Create multi-level file metadata cache

```rust
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use std::time::SystemTime;

#[derive(Serialize, Deserialize, Clone)]
pub struct FileMetadata {
    // File identity
    pub path: String,
    pub size: u64,
    pub mtime: SystemTime,
    pub content_hash: String,  // SHA256 of raw file bytes (authoritative)

    // Derived product hashes (for stage skipping)
    pub chunking_hash: String,       // Hash of chunks produced
    pub link_extract_hash: String,   // Hash of extracted links
    pub embedding_hash: Option<String>, // Hash of embeddings (if generated)

    // Configuration versions (for invalidation on code changes)
    pub chunker_version: String,
    pub link_extractor_version: String,
    pub embedder_model_id: Option<String>,

    // Derived output IDs (for cleanup/updates)
    pub chunk_ids: Vec<String>,
    pub link_ids: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct IngestCacheManifest {
    // File-level cache
    pub files: HashMap<String, FileMetadata>,

    // Global index hashes (for dependency tracking)
    pub doc_title_index_hash: String,
    pub heading_index_hash: String,

    // Configuration versions
    pub chunker_version: String,
    pub link_extractor_version: String,

    // Metadata
    pub cache_version: u32,  // For cache format migrations
    pub last_run_id: Option<String>,
}

pub struct IngestCache {
    manifest: IngestCacheManifest,
    cache_path: PathBuf,
}

impl IngestCache {
    pub fn load_or_create(cache_path: &Path) -> Result<Self, String> {
        let manifest = if cache_path.exists() {
            let bytes = std::fs::read(cache_path)
                .map_err(|e| format!("read cache: {}", e))?;
            serde_json::from_slice(&bytes)
                .map_err(|e| format!("parse cache: {}", e))?
        } else {
            IngestCacheManifest {
                files: HashMap::new(),
                doc_title_index_hash: String::new(),
                heading_index_hash: String::new(),
                chunker_version: current_chunker_version(),
                link_extractor_version: current_link_extractor_version(),
                cache_version: 1,
                last_run_id: None,
            }
        };

        Ok(Self {
            manifest,
            cache_path: cache_path.to_path_buf(),
        })
    }

    pub fn save(&self) -> Result<(), String> {
        let json = serde_json::to_string_pretty(&self.manifest)
            .map_err(|e| format!("serialize cache: {}", e))?;
        std::fs::write(&self.cache_path, json)
            .map_err(|e| format!("write cache: {}", e))?;
        Ok(())
    }

    /// Check if file content unchanged (for skipping parse)
    pub fn is_file_content_unchanged(&self, path: &str, content_hash: &str) -> bool {
        if let Some(meta) = self.manifest.files.get(path) {
            meta.content_hash == content_hash
        } else {
            false
        }
    }

    /// Check if chunking can be skipped (file + config unchanged)
    pub fn can_skip_chunking(&self, path: &str, content_hash: &str) -> bool {
        if let Some(meta) = self.manifest.files.get(path) {
            meta.content_hash == content_hash
                && meta.chunker_version == current_chunker_version()
        } else {
            false
        }
    }

    /// Check if link extraction can be skipped
    pub fn can_skip_link_extraction(&self, path: &str, content_hash: &str) -> bool {
        if let Some(meta) = self.manifest.files.get(path) {
            meta.content_hash == content_hash
                && meta.link_extractor_version == current_link_extractor_version()
        } else {
            false
        }
    }

    /// Check if link resolution needs re-running (index changed)
    pub fn needs_link_reresolution(&self, new_title_hash: &str, new_heading_hash: &str) -> bool {
        self.manifest.doc_title_index_hash != new_title_hash
            || self.manifest.heading_index_hash != new_heading_hash
    }

    pub fn update_file(&mut self, meta: FileMetadata) {
        self.manifest.files.insert(meta.path.clone(), meta);
    }

    pub fn update_global_indexes(&mut self, title_hash: String, heading_hash: String) {
        self.manifest.doc_title_index_hash = title_hash;
        self.manifest.heading_index_hash = heading_hash;
    }

    pub fn remove_file(&mut self, path: &str) -> Option<FileMetadata> {
        self.manifest.files.remove(path)
    }

    /// Find files that were deleted (in cache but not in current file set)
    pub fn find_deleted_files(&self, current_files: &HashSet<String>) -> Vec<String> {
        self.manifest.files.keys()
            .filter(|path| !current_files.contains(*path))
            .cloned()
            .collect()
    }
}

// Version tracking helpers
fn current_chunker_version() -> String {
    // Use git commit hash or semantic version
    format!("v1.0.0+{}", env!("GIT_HASH", "unknown"))
}

fn current_link_extractor_version() -> String {
    format!("v1.0.0+{}", env!("GIT_HASH", "unknown"))
}
```

#### B. Integrate into ingest_dir with smart skipping

**Mental model**: Classify each file as Unchanged / Modified / Added / Deleted

#### B

```rust
pub fn ingest_dir(
    root: &Path,
    cache: Option<&mut IngestCache>,
) -> Result<IngestDirOutput, String> {
    let mut parse_entries = Vec::new();
    let mut files_to_parse = Vec::new();

    // Pass 1: Quick scan with size+mtime precheck
    for entry in WalkDir::new(root) {
        let entry = entry.map_err(|e| format!("walk: {}", e))?;
        let path = entry.path();

        if !entry.file_type().is_file() {
            continue;
        }

        let metadata = std::fs::metadata(path)
            .map_err(|e| format!("stat {}: {}", path.display(), e))?;
        let size = metadata.len();
        let mtime = metadata.modified()
            .map_err(|e| format!("mtime {}: {}", path.display(), e))?;

        let rel_path = path.strip_prefix(root)
            .map_err(|e| format!("strip prefix: {}", e))?
            .to_string_lossy()
            .into_owned();

        // Fast precheck: size+mtime
        let needs_hash_check = if let Some(cache) = cache.as_ref() {
            if let Some(cached) = cache.metadata.get(&rel_path) {
                cached.size != size || cached.mtime != mtime
            } else {
                true  // New file
            }
        } else {
            true  // No cache
        };

        if needs_hash_check {
            files_to_parse.push((path.to_path_buf(), rel_path, size, mtime));
        } else {
            eprintln!("skip unchanged (fast): {}", rel_path);
        }
    }

    // Pass 2: Hash check for potentially changed files
    let mut final_parse_list = Vec::new();

    for (path, rel_path, size, mtime) in files_to_parse {
        let bytes = std::fs::read(&path)
            .map_err(|e| format!("read {}: {}", path.display(), e))?;
        let content_hash = sha256_hex(&bytes);

        let is_unchanged = if let Some(cache) = cache.as_ref() {
            cache.is_file_unchanged(&rel_path, size, mtime, &content_hash)
        } else {
            false
        };

        if is_unchanged {
            eprintln!("skip unchanged (hash verified): {}", rel_path);
            continue;
        }

        final_parse_list.push((path, rel_path, bytes, content_hash, size, mtime));
    }

    // Pass 3: Parse changed files
    for (path, rel_path, bytes, content_hash, size, mtime) in final_parse_list {
        // ... existing parsing logic ...
        let text = String::from_utf8_lossy(&bytes);
        let chunks = chunk_markdown(&text);

        let chunk_ids: Vec<String> = chunks.iter()
            .map(|c| c.chunk_sha256.clone())
            .collect();

        // Store in parse_entries
        for chunk in chunks {
            parse_entries.push(ParseEntry {
                path: rel_path.clone(),
                chunk_sha256: chunk.chunk_sha256.clone(),
                heading_path: chunk.heading_path.clone(),
                start_line: chunk.start_line,
            });
        }

        // Update cache
        if let Some(cache) = cache.as_mut() {
            cache.update_file(FileMetadata {
                path: rel_path,
                size,
                mtime,
                content_hash,
                chunk_ids,
            });
        }
    }

    // Save cache
    if let Some(cache) = cache {
        cache.save()?;
    }

    Ok(IngestDirOutput {
        parse_entries,
        // ... rest of output
    })
}
```

#### C. Add CLI flag

```rust
#[arg(long, help = "Path to incremental cache file (enables incremental mode)")]
incremental_cache: Option<PathBuf>,
```

**Expected Impact**:
- First run: ~2% overhead (hashing)
- Repeat run with 10% changes: **90% speedup** (200s → ~20s)
- Repeat run with no changes: **Near-instant** (<5s for metadata scan)

**Critical correctness note**: Dependency invalidation for links
- When a file changes, its outbound links may change
- When a file's title/headings change, inbound links from OTHER files may need re-resolution
- Solution: Track "link invalidation" separately in Step 1.2

---

### 1.2 Incremental Link Resolution with Dependency Tracking (2-3 hours)

**Problem**: When unchanged doc A links to changed doc B (whose heading was renamed), A's links need re-resolution

**Files to modify**:
- [crates/admit_surrealdb/src/link_resolver.rs](crates/admit_surrealdb/src/link_resolver.rs)

**Implementation**:

```rust
pub struct LinkInvalidationTracker {
    // Docs whose content changed (outbound links need re-extraction)
    pub changed_docs: HashSet<String>,

    // Docs whose titles/headings changed (inbound links need re-resolution)
    pub target_changed: HashSet<String>,
}

pub fn resolve_vault_obsidian_links_incremental(
    vault_docs: &BTreeMap<String, VaultDoc>,
    invalidation: &LinkInvalidationTracker,
    heading_index: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<ResolvedLink> {
    let mut resolved = Vec::new();

    for (doc_path, doc) in vault_docs {
        // Re-extract links if doc content changed
        let links = if invalidation.changed_docs.contains(doc_path) {
            extract_obsidian_links(&doc.text)
        } else {
            // Load cached links from previous run
            continue;  // Or load from cache
        };

        // Resolve each link
        for link in links {
            // Always re-resolve if target doc changed (even if source unchanged)
            let needs_resolution = invalidation.changed_docs.contains(doc_path)
                || invalidation.target_changed.contains(&link.target);

            if needs_resolution {
                resolved.push(resolve_link(link, vault_docs, heading_index)?);
            }
        }
    }

    resolved
}
```

**Expected Impact**: 80-90% speedup on vault_links for incremental runs

---

## Step 2: Parallel File Processing with Deterministic Ordering (Est. 5-10x speedup)

### 2.1 Add Rayon for Parallel Parsing (2-3 hours)

**Problem**: 1000 files parsed sequentially in `ingest_dir()`

**Critical constraint**: Output must be **deterministic** (same input → same output order)

**Files to modify**:
- [crates/admit_cli/src/ingest_dir.rs:94-184](crates/admit_cli/src/ingest_dir.rs#L94-L184)
- `Cargo.toml` (add dependency)

**Implementation**:

#### A. Add Rayon dependency

```toml
[dependencies]
rayon = "1.10"
```

#### B. Parallelize with deterministic ordering

```rust
use rayon::prelude::*;

pub fn ingest_dir_parallel(
    root: &Path,
    cache: Option<&mut IngestCache>,
) -> Result<IngestDirOutput, String> {
    // Step 1: Gather all files to parse (sequential, fast)
    let files_to_parse: Vec<_> = WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .filter_map(|entry| {
            let path = entry.path();
            // ... incremental cache check from Step 1.1 ...
            Some(path.to_path_buf())
        })
        .collect();

    // Step 2: Parse in parallel (nondeterministic order during compute)
    let mut parsed_results: Vec<(String, Vec<ParseEntry>)> = files_to_parse
        .par_iter()
        .filter_map(|path| {
            // Per-file parsing (all CPU-bound work here)
            let bytes = std::fs::read(path).ok()?;
            let rel_path = path.strip_prefix(root).ok()?.to_string_lossy().into_owned();
            let text = std::str::from_utf8(&bytes).ok()?;
            let chunks = chunk_markdown(text);

            let entries: Vec<ParseEntry> = chunks.into_iter().map(|c| {
                ParseEntry {
                    path: rel_path.clone(),
                    chunk_sha256: c.chunk_sha256,
                    heading_path: c.heading_path,
                    start_line: c.start_line,
                }
            }).collect();

            Some((rel_path, entries))
        })
        .collect();

    // Step 3: CRITICAL - Sort to ensure deterministic output
    parsed_results.sort_by(|a, b| a.0.cmp(&b.0));  // Sort by rel_path

    // Step 4: Flatten into final output (now deterministic)
    let mut parse_entries = Vec::new();
    for (_path, entries) in parsed_results {
        parse_entries.extend(entries);
    }

    Ok(IngestDirOutput {
        parse_entries,
        // ...
    })
}
```

**Memory safety**: This approach does NOT load all files into memory
- Each thread reads one file, parses, returns structured data (small)
- Bytes are dropped after parsing
- Only structured `ParseEntry` records are accumulated

**Thread tuning**:

```rust
// Optionally configure Rayon pool size
use rayon::ThreadPoolBuilder;

if let Some(threads) = cli.threads {
    ThreadPoolBuilder::new()
        .num_threads(threads)
        .build_global()
        .map_err(|e| format!("thread pool: {}", e))?;
}
```

**Expected Impact**: Near-linear speedup with core count
- 1000 files: 50s → ~5s on 24 threads (**10x**)
- Works best for many small-medium files
- For few large files, gains are smaller

---

### 2.2 Parallel Link Extraction (1-2 hours)

**Problem**: Link extraction iterates all docs sequentially

**Files to modify**:

- [crates/admit_surrealdb/src/link_resolver.rs:196-325](crates/admit_surrealdb/src/link_resolver.rs#L196-L325)

**Implementation**:

```rust
use rayon::prelude::*;

// Parallelize link extraction per document
let all_links: Vec<(String, ObsidianLink)> = vault_docs
    .par_iter()
    .flat_map(|(doc_path, doc)| {
        let text = read_doc_text(doc_path);
        extract_obsidian_links(&text)
            .into_iter()
            .map(move |link| (doc_path.clone(), link))
    })
    .collect();

// Then sort for determinism
all_links.sort_by(|a, b| {
    a.0.cmp(&b.0)  // Sort by source doc path
        .then_with(|| a.1.line.cmp(&b.1.line))  // Then by line number
});
```

**Expected Impact**: 50-70% speedup on vault_links phase (75s → ~25s)

---

## Step 3: Native SurrealDB SDK with Bounded Concurrency (Est. 4-6x speedup)

### 3.1 Replace Subprocess with Native Client (6-8 hours)

**Problem**: Each batch spawns `surreal sql` subprocess
- Process creation overhead (~10-50ms per batch)
- No connection reuse
- JSON serialization roundtrip
- No true transactions

**CRITICAL ARCHITECTURE DECISION**: Single writer vs connection pool

The SurrealDB Rust client may serialize queries internally. Test both approaches:

**Files to modify**:

- [crates/admit_surrealdb/src/lib.rs:196-275](crates/admit_surrealdb/src/lib.rs#L196-L275) (`run_sql_output`)
- `Cargo.toml` (add dependency)

**Implementation**:

#### A. Add SurrealDB SDK dependency

```toml
[dependencies]
surrealdb = { version = "2.2", features = ["protocol-ws"] }
tokio = { version = "1.42", features = ["rt-multi-thread", "macros", "sync", "fs"] }
```

#### B. Create native client with configurable concurrency

```rust
use surrealdb::engine::remote::ws::Ws;
use surrealdb::opt::auth::Root;
use surrealdb::Surreal;
use std::sync::Arc;

pub struct SurrealNativeProjectionStore {
    // Option 1: Shared client (if SDK internally multiplexes)
    db: Arc<Surreal<Ws>>,

    // Option 2: Connection pool (if SDK serializes)
    db_pool: Vec<Surreal<Ws>>,
    pool_size: usize,
    pool_semaphore: Arc<Semaphore>,

    config: ProjectionConfig,
}

impl SurrealNativeProjectionStore {
    pub async fn new(config: ProjectionConfig) -> Result<Self, String> {
        // Create single connection for now
        let db = Surreal::new::<Ws>(&config.endpoint)
            .await
            .map_err(|e| format!("connect: {}", e))?;

        db.signin(Root {
            username: &config.username,
            password: &config.password,
        })
        .await
        .map_err(|e| format!("signin: {}", e))?;

        db.use_ns(&config.namespace)
            .use_db(&config.database)
            .await
            .map_err(|e| format!("use db: {}", e))?;

        Ok(Self {
            db: Arc::new(db),
            config,
        })
    }

    // Start with single-threaded writer
    pub async fn run_sql(&self, sql: &str) -> Result<(), String> {
        self.db.query(sql)
            .await
            .map_err(|e| format!("query: {}", e))?;
        Ok(())
    }
}
```

#### C. Convert phases to async

```rust
// Current:
pub fn project_dag_trace(&self, ...) -> Result<(), String> { ... }

// Async version:
pub async fn project_dag_trace(&self, ...) -> Result<(), String> {
    // Batch building stays the same
    let mut sql = String::new();
    for node in nodes {
        sql.push_str(&node_upsert_sql(node));
        if sql.len() > batch_threshold {
            self.run_sql(&sql).await?;  // ← Now async
            sql.clear();
        }
    }
    Ok(())
}
```

#### D. Add run-scoped transactions with status tracking

```rust
pub async fn project_ingest_with_atomicity(
    &self,
    trace_sha256: &str,
    phases: &[String],
) -> Result<(), String> {
    let run_id = generate_run_id();

    // 1. Mark run as "running"
    self.run_sql(&format!(
        "INSERT INTO projection_run {{
            run_id: {},
            trace_sha256: {},
            status: 'running',
            started_at: time::now()
        }}",
        json_string(&run_id),
        json_string(trace_sha256)
    )).await?;

    // 2. Execute phases (with run_id stamping)
    let result = self.execute_phases(phases, Some(&run_id)).await;

    // 3. Mark completion status
    match result {
        Ok(_) => {
            self.run_sql(&format!(
                "UPDATE projection_run:{} SET status = 'complete', finished_at = time::now()",
                run_id
            )).await?;
        }
        Err(e) => {
            self.run_sql(&format!(
                "UPDATE projection_run:{} SET status = 'failed', error = {}, finished_at = time::now()",
                run_id,
                json_string(&e.to_string())
            )).await?;
            return Err(e);
        }
    }

    Ok(())
}
```

**Expected Impact**:

- Eliminates subprocess overhead (200 processes → 0)
- Batch execution: ~50ms → ~5-10ms per batch
- Total: 50-70% speedup on all projection phases

---

### 3.2 Bounded Concurrent Batch Submission (2-3 hours)

**CRITICAL**: Only add concurrency after benchmarking shows it helps

**Problem**: Even with native SDK, batches are submitted serially

**Files to modify**:

- [crates/admit_surrealdb/src/lib.rs:976-1044](crates/admit_surrealdb/src/lib.rs#L976-L1044) (projection functions)

**Implementation**: Start conservative (2-4 concurrent batches max)

```rust
use tokio::sync::Semaphore;
use futures::future::try_join_all;

pub async fn project_doc_chunks_bounded_concurrent(
    &self,
    dag: &GovernedDag,
    artifacts_root: &Path,
) -> Result<(), String> {
    // Prepare all batches upfront (still deterministic)
    let batches: Vec<String> = self.prepare_chunk_batches(dag, artifacts_root)?;

    // CRITICAL: Limit to 2-4 concurrent writers (not 20!)
    // Too many = lock contention + latency spikes
    let semaphore = Arc::new(Semaphore::new(2));

    let db = Arc::clone(&self.db);

    let tasks: Vec<_> = batches
        .into_iter()
        .map(|sql| {
            let db = Arc::clone(&db);
            let sem = Arc::clone(&semaphore);

            tokio::spawn(async move {
                let _permit = sem.acquire().await.unwrap();
                db.query(&sql).await
                    .map_err(|e| format!("batch: {}", e))
            })
        })
        .collect();

    // Wait for all batches
    for task in tasks {
        task.await
            .map_err(|e| format!("task join: {}", e))??;
    }

    Ok(())
}
```

**Benchmarking strategy**:

```bash
# Test with different concurrency levels
admit project --concurrent-batches=1  # Baseline
admit project --concurrent-batches=2  # Test
admit project --concurrent-batches=4  # Test
admit project --concurrent-batches=8  # Likely too high
```

**Expected Impact**: 1.5-2.5x speedup (only if DB can handle concurrency)

**Warning**: If SurrealDB serializes internally, this adds overhead with no benefit

---

## Step 4 (OPTIONAL): Tokio Pipeline - Only After Profiling (Advanced)

**⚠️ WARNING**: Only implement this if Step 0-3 profiling shows file I/O is a bottleneck (unlikely)

### When to skip this step

Skip if profiling shows:

- Parsing is CPU-dominant (most likely)
- OS cache is already handling file reads efficiently
- Rayon parallel parsing (Step 2) already saturates your cores

### 4.1 Conservative Pipeline Architecture (4-6 hours)

**Goal**: Overlap I/O, CPU, and DB operations WITHOUT memory blow-up

```
┌─────────────────┐      ┌──────────────┐      ┌─────────────┐
│  Stage 1:       │      │   Stage 2:   │      │  Stage 3:   │
│  Bounded File   │ ───→ │  Rayon Parse │ ───→ │  Single DB  │
│  Reader (Tokio) │      │  (not spawn_ │      │  Writer     │
│  MAX 20 at once │      │   blocking)  │      │  (batched)  │
└─────────────────┘      └──────────────┘      └─────────────┘
```

**Files to modify**:

- [crates/admit_cli/src/ingest_dir.rs](crates/admit_cli/src/ingest_dir.rs) (convert to async)
- [crates/admit_cli/src/main.rs:2177-2368](crates/admit_cli/src/main.rs#L2177-L2368) (async orchestration)

**Implementation**:

#### A. Stage 1: Bounded async file reader (NOT per-file tasks)

```rust
use tokio::fs;
use tokio::sync::mpsc;
use tokio::sync::Semaphore;
use futures::stream::{self, StreamExt};

async fn read_files_stage_bounded(
    files: Vec<PathBuf>,  // Already discovered
    tx: mpsc::Sender<(PathBuf, Vec<u8>)>,
) -> Result<(), String> {
    // CRITICAL: Bound concurrency to avoid file handle exhaustion
    let semaphore = Arc::new(Semaphore::new(20));  // Max 20 concurrent reads

    stream::iter(files)
        .map(|path| {
            let sem = Arc::clone(&semaphore);
            let tx = tx.clone();
            async move {
                let _permit = sem.acquire().await.unwrap();
                let bytes = fs::read(&path).await
                    .map_err(|e| format!("read {}: {}", path.display(), e))?;
                tx.send((path, bytes)).await
                    .map_err(|_| "channel closed".to_string())?;
                Ok::<_, String>(())
            }
        })
        .buffer_unordered(20)  // Process 20 at a time
        .collect::<Vec<_>>()
        .await;

    Ok(())
}
```

#### B. Stage 2: Use Rayon (NOT spawn_blocking per file)

```rust
use tokio::sync::mpsc;
use rayon::prelude::*;

async fn parse_chunks_stage_rayon(
    mut rx: mpsc::Receiver<(PathBuf, Vec<u8>)>,
    tx: mpsc::Sender<Vec<ParseEntry>>,
) -> Result<(), String> {
    // Accumulate files into chunks for batch processing
    let mut files_buffer = Vec::new();
    let buffer_size = 50;  // Process 50 files at a time with Rayon

    while let Some((path, bytes)) = rx.recv().await {
        files_buffer.push((path, bytes));

        if files_buffer.len() >= buffer_size {
            let batch = std::mem::take(&mut files_buffer);

            // Use Rayon for parallel parsing (more efficient than spawn_blocking)
            let parsed: Vec<Vec<ParseEntry>> = batch
                .into_par_iter()
                .filter_map(|(path, bytes)| {
                    let text = std::str::from_utf8(&bytes).ok()?;
                    let chunks = chunk_markdown(text);
                    let entries = chunks.into_iter().map(|c| ParseEntry {
                        // ... build entry
                    }).collect();
                    Some(entries)
                })
                .collect();

            // Send all parsed results
            for entries in parsed {
                tx.send(entries).await.ok();
            }
        }
    }

    // Process remaining files
    if !files_buffer.is_empty() {
        // ... same Rayon processing
    }

    Ok(())
}
```

#### C. Stage 3: Single writer with optimal batching

```rust
async fn write_batches_stage_single_writer(
    mut rx: mpsc::Receiver<Vec<ParseEntry>>,
    db: Arc<Surreal<Ws>>,
    config: &BatchConfig,
) -> Result<(), String> {
    let mut batch = Vec::new();
    let mut sql_bytes = 0;

    while let Some(entries) = rx.recv().await {
        batch.extend(entries);

        // Use adaptive batching from Phase 1
        let should_flush = batch.len() >= config.max_count
            || sql_bytes >= config.max_bytes;

        if should_flush {
            let sql = build_batch_sql(&batch)?;
            db.query(&sql).await.map_err(|e| format!("write: {}", e))?;
            batch.clear();
            sql_bytes = 0;
        }
    }

    // Final partial batch
    if !batch.is_empty() {
        let sql = build_batch_sql(&batch)?;
        db.query(&sql).await.map_err(|e| format!("write: {}", e))?;
    }

    Ok(())
}
```

#### D. Pipeline orchestrator with proper error handling

```rust
pub async fn ingest_dir_pipeline(
    root: &Path,
    db: Arc<Surreal<Ws>>,
) -> Result<(), String> {
    // Step 1: Discover all files (sync, fast)
    let files: Vec<PathBuf> = WalkDir::new(root)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .map(|e| e.path().to_path_buf())
        .collect();

    // Step 2: Create bounded channels
    let (file_tx, file_rx) = mpsc::channel(100);  // Bounded backpressure
    let (parse_tx, parse_rx) = mpsc::channel(100);

    // Step 3: Spawn all three stages
    let reader = tokio::spawn(read_files_stage_bounded(files, file_tx));
    let parser = tokio::spawn(parse_chunks_stage_rayon(file_rx, parse_tx));
    let writer = tokio::spawn(write_batches_stage_single_writer(parse_rx, db, config));

    // Step 4: Wait for all stages with proper error propagation
    let reader_result = reader.await
        .map_err(|e| format!("reader panicked: {}", e))?;
    let parser_result = parser.await
        .map_err(|e| format!("parser panicked: {}", e))?;
    let writer_result = writer.await
        .map_err(|e| format!("writer panicked: {}", e))?;

    reader_result?;
    parser_result?;
    writer_result?;

    Ok(())
}
```

**Key safety properties**:

- **Bounded concurrency**: Max 20 concurrent file reads (not 1000)
- **Bounded channels**: Automatic backpressure prevents memory explosion
- **Rayon for CPU**: More efficient than spawn_blocking loops
- **Single writer**: Avoids DB lock contention

**Expected Impact**: 1.5-2x additional speedup (only if I/O is bottleneck)

**Realistic expectation**: After Steps 1-3, I/O is rarely the bottleneck, so this may add <20% benefit

---

### 4.2 Phase Dependency Graph (NOT "parallel phases")

**Problem**: Most phases have dependencies, so "parallel phases" is mostly an illusion

**Actual dependencies**:

```text
dag_trace (independent - can start first)
    ↓
doc_files (depends on DAG artifacts)
    ↓
doc_chunks (depends on DAG artifacts)
    ↓
vault_links (depends on doc_files + doc_chunks + heading index)
    ↓
embeddings (depends on doc_chunks)
```

**Reality**: Only doc_files and doc_chunks can truly run in parallel

**Files to modify**:

- [crates/admit_cli/src/main.rs:2177-2368](crates/admit_cli/src/main.rs#L2177-L2368)

**Implementation**: Minimal parallel opportunity

```rust
// Phase 1: DAG trace (must complete first)
store_ops.project_dag_trace(...).await?;

// Phase 2: Doc files + chunks can run parallel
let (files_result, chunks_result) = tokio::try_join!(
    store_ops.project_doc_files(...),
    store_ops.project_doc_chunks(...),
)?;

// Phase 3: Vault links (depends on Phase 2)
store_ops.project_vault_links(...).await?;

// Phase 4: Embeddings (depends on chunks)
if phases.contains("embeddings") {
    store_ops.project_embeddings(...).await?;
}
```

**Expected Impact**: 20-30% speedup (only 2 phases overlap)

**Recommendation**: Keep phases sequential for simplicity, focus on making EACH phase fast

---

## Step 5 (OPTIONAL): GPU-Accelerated Embeddings (Only if running locally)

### 5.1 File Change Detection (3-4 hours)

**Problem**: All files re-parsed every run, even if unchanged

**Files to modify**:
- [crates/admit_cli/src/ingest_dir.rs:73-184](crates/admit_cli/src/ingest_dir.rs#L73-L184)
- New file: `crates/admit_cli/src/ingest_cache.rs`

**Implementation**:

#### A. Create file metadata cache
```rust
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct FileMetadata {
    pub path: String,
    pub size: u64,
    pub mtime: SystemTime,
    pub content_hash: String,  // SHA256 of file content
    pub chunk_ids: Vec<String>, // IDs of chunks produced
}

pub struct IngestCache {
    metadata: HashMap<String, FileMetadata>,
    cache_path: PathBuf,
}

impl IngestCache {
    pub fn load(cache_path: &Path) -> Result<Self, String> {
        // Load from JSON or CBOR
    }

    pub fn save(&self) -> Result<(), String> {
        // Persist to disk
    }

    pub fn is_file_unchanged(&self, path: &str, size: u64, mtime: SystemTime) -> bool {
        if let Some(meta) = self.metadata.get(path) {
            meta.size == size && meta.mtime == mtime
        } else {
            false
        }
    }

    pub fn update_file(&mut self, path: String, meta: FileMetadata) {
        self.metadata.insert(path, meta);
    }
}
```

#### B. Integrate into ingest_dir
```rust
pub fn ingest_dir(
    root: &Path,
    cache: &mut IngestCache,
) -> Result<IngestDirOutput, String> {
    let mut parse_entries = Vec::new();

    for entry in WalkDir::new(root) {
        let path = entry.path();
        let metadata = std::fs::metadata(path)?;
        let size = metadata.len();
        let mtime = metadata.modified()?;

        // Check cache
        if cache.is_file_unchanged(rel_path, size, mtime) {
            eprintln!("skip unchanged: {}", rel_path);
            continue;  // ← Skip parsing
        }

        // Parse as usual
        let bytes = std::fs::read(path)?;
        let content_hash = sha256_hex(&bytes);
        let chunks = chunk_markdown(&text);

        // Update cache
        cache.update_file(rel_path.to_string(), FileMetadata {
            path: rel_path.to_string(),
            size,
            mtime,
            content_hash,
            chunk_ids: chunks.iter().map(|c| c.chunk_sha256.clone()).collect(),
        });

        // ... store chunks
    }

    cache.save()?;
    Ok(output)
}
```

**Cache invalidation strategy**:
- On vault structure change (files added/removed): full re-parse
- On file content change: re-parse only that file
- On links change: re-resolve links for affected docs only

**Expected Impact**:
- First run: No change
- Subsequent runs with ~10% file changes: 90% speedup (200s → ~20s)
- Subsequent runs with no changes: Near-instant (<5s for metadata scan)

---

### 5.2 Incremental Link Resolution (2-3 hours)

**Files to modify**:
- [crates/admit_surrealdb/src/link_resolver.rs](crates/admit_surrealdb/src/link_resolver.rs)

**Strategy**: Track which docs have changed, only re-resolve links for those docs

```rust
pub fn resolve_vault_obsidian_links_incremental(
    vault_docs: &BTreeMap<String, VaultDoc>,
    changed_docs: &HashSet<String>,  // ← New parameter
    heading_index: &BTreeMap<String, BTreeSet<String>>,
) -> Vec<ResolvedLink> {
    let mut resolved = Vec::new();

    for (doc_path, doc) in vault_docs {
        // Skip unchanged docs
        if !changed_docs.contains(doc_path) {
            continue;
        }

        // Resolve links only for changed docs
        let links = extract_obsidian_links(&doc.text);
        for link in links {
            resolved.push(resolve_link(link, vault_docs, heading_index)?);
        }
    }

    resolved
}
```

**Expected Impact**: 80-90% speedup on vault_links phase for incremental runs

---

**⚠️ Skip this entirely if using Ollama API** - GPU is already utilized via Ollama

### 5.1 GPU-Accelerated Embeddings (4-6 hours, advanced)

**Only implement if**:

- You're generating embeddings locally (not via Ollama API)
- Embeddings are dominating wall time (check Step 0 profiling)
- You have CUDA/ROCm set up and working

**Files to modify**:

- [crates/admit_surrealdb/src/lib.rs:1183-1275](crates/admit_surrealdb/src/lib.rs#L1183-L1275) (embedding generation)

**Options** (in order of practicality):

1. **Keep using Ollama** (recommended) - it already uses GPU efficiently
2. **Candle** (Rust-native): GPU tensor library, good for deployment
3. **tch-rs** (PyTorch bindings): More mature but heavier dependency

**Implementation sketch** (Candle):

```rust
use candle_core::{Device, Tensor};
use candle_transformers::models::bert;

pub struct GpuEmbedder {
    model: bert::BertModel,
    device: Device,
}

impl GpuEmbedder {
    pub fn new(model_path: &Path) -> Result<Self, String> {
        let device = Device::cuda_if_available(0)
            .map_err(|e| format!("cuda device: {}", e))?;
        let model = bert::BertModel::load(model_path, &device)
            .map_err(|e| format!("load model: {}", e))?;
        Ok(Self { model, device })
    }

    pub fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, String> {
        // Tokenize
        let tokens = self.tokenize_batch(texts)?;

        // Run on GPU
        let embeddings = self.model.forward(&tokens)
            .map_err(|e| format!("forward: {}", e))?;

        // Convert to CPU
        let cpu_embeddings = embeddings.to_device(&Device::Cpu)
            .map_err(|e| format!("to_cpu: {}", e))?;

        cpu_embeddings.to_vec2()
            .map_err(|e| format!("to_vec: {}", e))
    }
}
```

**Expected Impact**: 2-5x speedup for embedding generation (only if embeddings are the bottleneck)

**Reality**: Usually embeddings via Ollama are already fast enough, and the network call overhead dominates

---

## Implementation Roadmap (Corrected Priority Order)

### Phase A: Measure First (1-2 hours, REQUIRED)

**DO THIS BEFORE ANY OPTIMIZATION**

- [ ] Step 0: Add detailed benchmarking instrumentation
  - Add per-phase metrics (files, batches, bytes, timing breakdown)
  - Add `--bench` mode for A/B testing
  - Expected: **No speedup, but enables all future work**

---

### Phase B: Incremental Mode (3-6 hours, HIGHEST ROI)

**Biggest win for repeat runs (typical workflow)**

- [ ] Step 1.1: Content-hash-based change detection (3-4 hours) → **10-50x on repeat runs**
- [ ] Step 1.2: Incremental link resolution with dependency tracking (2-3 hours) → **5-10x on vault_links**

**Total Phase B: 2-5% overhead on first run, 10-50x on repeat runs**

---

### Phase C: Parallel Processing (3-5 hours, HIGH ROI for first runs)

**Makes first runs actually fast**

- [ ] Step 2.1: Rayon parallel parsing with deterministic ordering (3 hours) → **5-10x on parsing**
- [ ] Step 2.2: Parallel link extraction (2 hours) → **2-3x on link extraction**

**Total Phase C: ~8-15x speedup on CPU-bound first runs**

---

### Phase D: Native SDK (8-10 hours, MEDIUM ROI but enables future work)

**Removes subprocess overhead, unlocks async patterns**

- [ ] Step 3.1: Replace subprocess with native client (6-8 hours) → **2-3x on DB writes**
- [ ] Step 3.2: Add run-scoped transactions with status tracking (1-2 hours) → **Better observability**
- [ ] Step 3.3: Bounded concurrent batch submission (2 hours, TEST FIRST) → **1.5-2x IF DB supports it**

**Total Phase D: ~3-5x speedup on projection phases**

---

### Phase E: Advanced Optimizations (OPTIONAL, only if profiling justifies)

**Only implement these if Step 0 profiling shows they'd help**

- [ ] Phase 1: Adaptive batch sizing (1-2 hours) → **10-20% improvement**
- [ ] Phase 1.2: Profile-guided allocation reduction (2-3 hours) → **5-15% IF hot**
- [ ] Step 4.1: Tokio pipeline (6 hours) → **1.5-2x IF I/O is bottleneck** (unlikely)
- [ ] Step 4.2: Phase dependency graph (2 hours) → **1.2-1.3x** (limited parallelism)
- [ ] Step 5: GPU embeddings (4-6 hours) → **2-5x IF using local embeddings** (not Ollama)

**Total Phase E: Highly variable, 1.2-3x depending on workload**

---

## Realistic Performance Expectations

### Current Baseline (single-threaded, no cache)

- `doc_chunks`: 200s
- `dag_trace`: 174s
- `vault_links`: 75s
- **Total: ~450s** (7.5 minutes)

### After Phase A+B+C (Measure + Incremental + Parallel)

#### First run (no cache)

- `doc_chunks`: 20-30s (parallel parsing, no subprocess yet)
- `dag_trace`: 40-60s (still subprocess, but bigger batches)
- `vault_links`: 15-25s (parallel extraction)
- **Total: ~75-115s** (4-6x speedup)

#### Repeat run (90% files unchanged)

- `doc_chunks`: 2-5s (skip unchanged)
- `dag_trace`: 4-8s (only changed nodes)
- `vault_links`: 1-3s (incremental resolution)
- **Total: ~7-16s** (30-60x speedup)

### After Phase A+B+C+D (Add Native SDK)

#### First run

- `doc_chunks`: 10-15s (parallel + native SDK)
- `dag_trace`: 15-25s (native SDK batching)
- `vault_links`: 8-12s (parallel + native SDK)
- **Total: ~33-52s** (9-14x speedup)

#### Repeat run

- `doc_chunks`: 1-3s
- `dag_trace`: 2-4s
- `vault_links`: 1-2s
- **Total: ~4-9s** (50-100x speedup)

### With All Optimizations (Phase A+B+C+D+E)

#### First run performance

25-40s (12-18x speedup)

#### Repeat run performance

3-7s (65-150x speedup)

**Key insight**: Incremental mode is THE killer feature. Everything else is just making first runs tolerable.

---

## Risk Mitigation & Testing

### Correctness-First Testing Strategy

**CRITICAL**: Every optimization must preserve deterministic output

1. **Baseline capture** (before any changes):

   ```bash
   # Run projection and capture full output
   admit project --vault=/path/to/test/vault > baseline_output.txt

   # Export DB state
   surreal export --ns test --db test baseline.surreal
   ```

2. **After each optimization**:

   ```bash
   # Run projection with optimization
   admit project --vault=/path/to/test/vault > optimized_output.txt

   # Byte-for-byte comparison
   diff baseline_output.txt optimized_output.txt

   # Should be EMPTY (except timing lines)
   ```

3. **DB integrity checks**:

   ```sql
   -- Verify counts match
   SELECT count() FROM node;
   SELECT count() FROM doc_chunk;
   SELECT count() FROM obsidian_link;

   -- Verify run provenance
   SELECT * FROM projection_run ORDER BY started_at DESC LIMIT 5;

   -- Check for orphaned records (should be 0)
   SELECT * FROM node WHERE projection_run_id IS NULL;
   ```

4. **Performance regression tests**:

   ```bash
   # Run with --bench mode (from Step 0)
   admit project --vault=/path/to/vault --bench

   # Should output timing comparison
   ```

### Rollback Strategy

**Feature flags for safe rollback**:

```rust
pub struct PerformanceConfig {
    pub use_parallel_parsing: bool,      // Default: true
    pub use_incremental_mode: bool,      // Default: false (opt-in)
    pub use_native_sdk: bool,            // Default: false (fallback to subprocess)
    pub max_parallel_threads: Option<usize>,  // None = auto-detect
    pub concurrent_batches: usize,       // Default: 1 (serial)
}
```

**CLI override flags**:

```bash
# Force serial mode (disable all parallelism)
admit project --serial-mode

# Disable incremental mode (force full parse)
admit project --no-incremental

# Use subprocess instead of native SDK
admit project --use-subprocess

# Limit thread count
admit project --threads=4
```

### Monitoring & Observability

**Enhanced instrumentation** (from Step 0):

```rust
pub struct PhaseMetrics {
    pub phase: String,
    pub duration_ms: u64,

    // New detailed metrics
    pub files_scanned: u64,
    pub files_skipped: u64,      // Incremental mode
    pub files_parsed: u64,
    pub parse_time_ms: u64,      // CPU time
    pub db_write_time_ms: u64,   // DB time
    pub batches_executed: u64,
    pub records_written: u64,
    pub bytes_written: u64,
    pub errors: Vec<String>,
}
```

**Export to projection_event table**:

```sql
-- Example query: find slow phases
SELECT phase, avg(duration_ms) as avg_time_ms
FROM projection_event
WHERE event_type = 'phase.completed'
GROUP BY phase
ORDER BY avg_time_ms DESC;

-- Incremental mode effectiveness
SELECT
    files_scanned,
    files_skipped,
    (files_skipped * 100.0 / files_scanned) as skip_percent
FROM projection_event
WHERE phase = 'doc_chunks'
ORDER BY timestamp DESC
LIMIT 10;
```

---

## Configuration Additions

### New CLI flags

```rust
#[derive(Parser)]
pub struct IngestDirArgs {
    // Existing
    #[arg(long)]
    projection_batch_size: Option<Vec<String>>,

    // NEW: Performance options
    #[arg(long, help = "Path to incremental cache file (enables incremental mode)")]
    incremental_cache: Option<PathBuf>,

    #[arg(long, default_value = "0", help = "Thread count (0 = auto-detect)")]
    threads: usize,

    #[arg(long, help = "Force serial execution (disable parallelism)")]
    serial_mode: bool,

    #[arg(long, help = "Disable incremental mode (force full parse)")]
    no_incremental: bool,

    #[arg(long, help = "Use subprocess mode instead of native SDK")]
    use_subprocess: bool,

    #[arg(long, default_value = "1", help = "Concurrent DB batch writers (1=serial)")]
    concurrent_batches: usize,

    #[arg(long, help = "Enable detailed benchmarking output")]
    bench: bool,
}
```

### Environment variables

```bash
# Override default thread count
ADMIT_THREADS=16

# Enable incremental by default
ADMIT_INCREMENTAL_CACHE=~/.cache/admit/ingest.cache

# Force subprocess mode (for testing/compatibility)
ADMIT_USE_SUBPROCESS=1
```

---

## Files to Modify (Prioritized)

| Phase | Priority | File | Changes | Est. Time |
|-------|----------|------|---------|-----------|
| **0** | 🔴 CRITICAL | [projection_run.rs](crates/admit_surrealdb/src/projection_run.rs) | Add detailed metrics | 1h |
| **0** | 🔴 CRITICAL | [main.rs:2177-2368](crates/admit_cli/src/main.rs#L2177-L2368) | Add --bench mode | 1h |
| **1** | 🔴 HIGH | New: `ingest_cache.rs` | Incremental cache | 3h |
| **1** | 🔴 HIGH | [ingest_dir.rs:73-728](crates/admit_cli/src/ingest_dir.rs#L73-L728) | Integrate cache | 2h |
| **2** | 🔴 HIGH | [ingest_dir.rs:73-728](crates/admit_cli/src/ingest_dir.rs#L73-L728) | Add Rayon parallel parsing | 3h |
| **2** | 🟡 MED | [link_resolver.rs:595-639](crates/admit_surrealdb/src/link_resolver.rs#L595-L639) | Parallel link extraction | 2h |
| **3** | 🔴 HIGH | [lib.rs:196-275](crates/admit_surrealdb/src/lib.rs#L196-L275) | Native SDK client | 6h |
| **3** | 🟡 MED | [lib.rs:976-1900](crates/admit_surrealdb/src/lib.rs#L976-L1900) | Convert phases to async | 4h |
| **3** | 🟡 MED | [main.rs:2177-2368](crates/admit_cli/src/main.rs#L2177-L2368) | Async orchestration | 2h |
| **E** | 🟢 LOW | [projection_config.rs:180-240](crates/admit_surrealdb/src/projection_config.rs#L180-L240) | Adaptive batching | 2h |
| **E** | 🟢 LOW | [ingest_dir.rs](crates/admit_cli/src/ingest_dir.rs) | Tokio pipeline (optional) | 6h |

**Total critical path**: Phase 0 (2h) + Phase 1 (5h) + Phase 2 (5h) + Phase 3 (12h) = **24 hours of focused work**

---

## Next Steps & Recommendation

### Recommended Implementation Order

#### Week 1: Measure & Incremental

1. Implement Step 0 (benchmarking harness) - **REQUIRED**
2. Implement Step 1 (incremental mode) - **HIGHEST ROI**
3. Validate: Run on your actual vault, measure speedup on repeat runs

Expected result: 10-50x speedup on typical workflows

---

#### Week 2: Parallel Processing

1. Implement Step 2.1 (Rayon parallel parsing)
2. Implement Step 2.2 (Parallel link extraction)
3. Validate: Compare output byte-for-byte with baseline

Expected result: 5-10x speedup on first runs

---

#### Week 3: Native SDK (if Week 1-2 results justify it)

1. Implement Step 3.1 (Native SurrealDB client)
2. Convert projection phases to async
3. Validate: Stress test with large vault

Expected result: Additional 2-3x speedup

---

### Decision Point After Each Week

#### After Week 1

Is incremental mode working correctly? Are repeat runs 10x+ faster?

- ✅ YES → Proceed to Week 2
- ❌ NO → Debug incremental logic, verify cache invalidation

#### After Week 2

Are first runs 5x+ faster? Is output deterministic?

- ✅ YES → Proceed to Week 3
- ❌ NO → Profile to find remaining bottlenecks, may need different approach

#### After Week 3

Is Native SDK stable? Worth the maintenance burden?

- ✅ YES → Keep it, consider Phase E optimizations
- ❌ NO → Revert to subprocess, live with 5-10x gains from Weeks 1-2

---

### What I Recommend You Do RIGHT NOW

**Option 1: Start with measurement** (safest)

```bash
# Implement Step 0 first
# Then run on your actual vault
admit project --vault=/your/vault --bench

# This tells you exactly where to optimize
```

**Option 2: Quick incremental win** (highest ROI)

```bash
# Implement Steps 0+1 (incremental mode)
# Test on your workflow (edit a few files, re-run)
# This is the 10-50x win for typical dev workflows
```

**My recommendation**: Start with **Option 2**. Incremental mode is the killer feature that makes everything else feel fast.
