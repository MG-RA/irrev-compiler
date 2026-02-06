# Projection Configuration Guide

## Overview

The projection configuration layer (Phase 1 of the SurrealDB integration improvement plan) centralizes all tunable projection parameters and makes them explicit and configurable via CLI flags.

## Key Components

### 1. ProjectionConfig

The main configuration struct that holds all projection settings:

```rust
pub struct ProjectionConfig {
    pub enabled_phases: ProjectionPhases,
    pub batch_sizes: BatchSizes,
    pub retry_policy: RetryPolicy,
    pub failure_handling: FailureHandling,
    pub vault_prefixes: Vec<String>,
}
```

### 2. ProjectionPhases

Defines which projection phases are enabled:

- `dag_trace`: Project DAG trace nodes and edges
- `doc_files`: Project document file metadata
- `doc_chunks`: Project document text chunks
- `headings`: Project document headings
- `vault_links`: Project Obsidian vault links
- `stats`: Project statistics
- `embeddings`: Project document embeddings (opt-in, expensive)
- `title_embeddings`: Project title embeddings for search
- `unresolved_link_suggestions`: Project link resolution suggestions

### 3. BatchSizes

Configurable batch sizes for different projection phases:

```rust
pub struct BatchSizes {
    pub nodes: usize,           // default: 200
    pub edges: usize,           // default: 200
    pub doc_chunks: usize,      // default: 50
    pub doc_files: usize,       // default: 200
    pub headings: usize,        // default: 200
    pub links: usize,           // default: 100
    pub stats: usize,           // default: 200
    pub embeddings: usize,      // default: 16
}
```

### 4. RetryPolicy

Configures retry behavior for failed projection operations:

```rust
pub struct RetryPolicy {
    pub max_attempts: usize,        // default: 3
    pub initial_delay_ms: u64,      // default: 100
    pub max_delay_ms: u64,          // default: 5000
    pub backoff_multiplier: f64,    // default: 2.0
}
```

### 5. FailureHandling

How to handle projection failures:

- `FailFast`: Abort on any error (strict mode)
- `WarnAndContinue`: Log warning, continue with other phases (default)
- `SilentIgnore`: No error, no warning (silent)

## CLI Usage

### Enable Specific Phases

```bash
# Enable only specific projection phases
admit-cli --projection-enabled=dag_trace,doc_files,vault_links ingest dir ./vault

# Disable all phases (equivalent to --surrealdb-mode=off)
admit-cli --projection-enabled= ingest dir ./vault
```

### Override Batch Sizes

```bash
# Override batch size for nodes
admit-cli --projection-batch-size=nodes:100 ingest dir ./vault

# Override multiple batch sizes
admit-cli \
  --projection-batch-size=nodes:100 \
  --projection-batch-size=doc_chunks:25 \
  ingest dir ./vault
```

### Configure Failure Handling

```bash
# Fail fast on any projection error
admit-cli --projection-failure-mode=fail-fast ingest dir ./vault

# Warn and continue (default)
admit-cli --projection-failure-mode=warn-and-continue ingest dir ./vault

# Silent ignore
admit-cli --projection-failure-mode=silent-ignore ingest dir ./vault
```

### Configure Vault Prefixes

```bash
# Add custom vault prefix
admit-cli --vault-prefix=my-vault/ ingest dir ./vault

# Multiple vault prefixes
admit-cli \
  --vault-prefix=irrev-vault/ \
  --vault-prefix=chatgpt/vault/ \
  --vault-prefix=my-vault/ \
  ingest dir ./vault
```

### Combined Example

```bash
admit-cli \
  --surrealdb-mode=auto \
  --surrealdb-namespace=admit \
  --surrealdb-database=compiler_dev \
  --projection-enabled=dag_trace,doc_files,doc_chunks,vault_links \
  --projection-batch-size=nodes:100 \
  --projection-batch-size=doc_chunks:25 \
  --projection-failure-mode=warn-and-continue \
  --vault-prefix=irrev-vault/ \
  ingest dir ./vault
```

## Configuration as Witness Artifact

The `ProjectionConfig` can be serialized as canonical CBOR witness bytes using the compiler's canonical encoder (Rust-minted, deterministic):

```rust
let config = ProjectionConfig::default();
let cbor_bytes = config.to_canonical_cbor_witness();

// Compute stable hash for lineage tracking
let config_hash = config.compute_hash();
```

This enables:

1. **Auditability**: Track which configuration produced which DB state
2. **Reproducibility**: Recreate exact projection conditions
3. **Lineage**: Link projection runs to their configuration
4. **Self-description**: Configuration itself becomes an inspectable artifact

## Configuration Priority Order

When Phase 8 (TOML config file support) is implemented, the priority order will be:

1. CLI flags (highest priority)
2. Environment variables
3. Config file (`admit.toml`)
4. Compiled defaults (lowest priority)

Currently, only CLI flags and defaults are supported.

## Implementation Details

### Location

- **Module**: `irrev-compiler/crates/admit_surrealdb/src/projection_config.rs`
- **Tests**: Included in the module
- **Demo**: `irrev-compiler/crates/admit_surrealdb/examples/projection_config_demo.rs`

### Dependencies

Added to `admit_surrealdb/Cargo.toml`:

```toml
serde = { version = "1.0", features = ["derive"] }
clap = { version = "4.5", features = ["derive"] }
```

### CLI Integration

Added to `admit_cli/src/main.rs`:

- CLI flag definitions in `Cli` struct
- Helper function `build_projection_config(cli: &Cli) -> ProjectionConfig`
- Import of `ProjectionConfig` from `admit_surrealdb::projection_config`

## Running the Demo

```bash
cd irrev-compiler
cargo run --package admit_surrealdb --example projection_config_demo
```

Expected output shows:
1. Default configuration
2. Configuration from CLI-like inputs
3. Retry policy behavior
4. Configuration as CBOR witness
5. Configuration hash stability

## Testing

Run the unit tests:

```bash
cargo test --package admit_surrealdb projection_config
```

Tests verify:
- Configuration hash stability
- Configuration hash changes with modifications
- Batch size override application
- Retry policy delay calculation
- Phase name parsing
- Enabled phase name extraction
- CBOR serialization/deserialization

## Next Steps

After Phase 1, the plan proceeds with:

- **Phase 0**: ProjectionRun primitive (foundational run tracking)
- **Phase 2A**: ProjectionStore trait (abstraction layer)
- **Phase 2B**: Extract link resolver business logic
- **Phase 3**: Projection coordinator (orchestration)
- **Phase 4**: Queryable observability via SurrealDB
- **Phase 5**: Run-scoped replacement (replaces hard deletes)
- **Phase 6**: Deterministic batch retry
- **Phase 7**: Make SurrealDB truly optional with circuit breaker
- **Phase 8**: Configuration file support (TOML)

## Benefits Achieved

- Externalized configuration: all tunable parameters now explicit
- CLI control: fine-grained control over projection behavior
- Configuration as witness: self-describing system via canonical CBOR witness bytes
- Hash stability: deterministic configuration hashing for lineage tracking
- Testable: unit tests for configuration logic
- Documented: usage guide and examples
- Type-safe: leverages Rust's type system and clap value enums

## See Also

- [Plan: Improve Compiler Integration with SurrealDB](./buzzing-giggling-snail.md)
- [Compiler Runtime Loop](./Compiler%20Runtime%20Loop.md)
- [SurrealDB DAG Ledger Projection](./design/compiler/surrealdb-dag-ledger-projection.md)
