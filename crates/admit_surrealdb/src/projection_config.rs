use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Centralized configuration for all projection parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectionConfig {
    pub enabled_phases: ProjectionPhases,
    pub batch_sizes: BatchSizes,
    pub retry_policy: RetryPolicy,
    pub failure_handling: FailureHandling,
    pub vault_prefixes: Vec<String>,
}

impl Default for ProjectionConfig {
    fn default() -> Self {
        Self {
            enabled_phases: ProjectionPhases::default(),
            batch_sizes: BatchSizes::default(),
            retry_policy: RetryPolicy::default(),
            failure_handling: FailureHandling::WarnAndContinue,
            vault_prefixes: vec![
                "irrev-vault/".to_string(),
                "chatgpt/vault/".to_string(),
            ],
        }
    }
}

impl ProjectionConfig {
    /// Compute a stable hash of this configuration for lineage tracking
    pub fn compute_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.to_canonical_cbor_witness().as_slice());
        format!("{:x}", hasher.finalize())
    }

    /// Create a configuration from CLI flags and environment
    pub fn from_cli_and_env(
        enabled_phases: Option<Vec<String>>,
        batch_size_overrides: Option<BTreeMap<String, usize>>,
        max_sql_bytes: Option<usize>,
        failure_mode: Option<FailureHandling>,
        vault_prefixes: Option<Vec<String>>,
    ) -> Self {
        let mut config = Self::default();

        // Apply enabled phases if specified
        if let Some(phases) = enabled_phases {
            config.enabled_phases = ProjectionPhases::from_phase_names(&phases);
        }

        // Apply batch size overrides
        if let Some(overrides) = batch_size_overrides {
            config.batch_sizes.apply_overrides(&overrides);
        }

        // Apply SQL byte cap
        if let Some(max_bytes) = max_sql_bytes {
            config.batch_sizes.max_sql_bytes = max_bytes.max(1);
        }

        // Apply failure handling mode
        if let Some(mode) = failure_mode {
            config.failure_handling = mode;
        }

        // Apply vault prefixes
        if let Some(prefixes) = vault_prefixes {
            config.vault_prefixes = prefixes;
        }

        config
    }

    /// Serialize configuration as canonical CBOR witness bytes (Rust-minted).
    ///
    /// Note: This uses the compiler's canonical CBOR encoder (`admit_core::encode_canonical_value`),
    /// not `serde_cbor`. This keeps bytes deterministic and aligned with identity rules.
    pub fn to_canonical_cbor_witness(&self) -> Vec<u8> {
        let value = serde_json::to_value(self).expect("ProjectionConfig should always serialize");
        admit_core::encode_canonical_value(&value)
            .expect("ProjectionConfig must be encodable as canonical CBOR")
    }
}

/// Defines which projection phases are enabled
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectionPhases {
    pub dag_trace: bool,
    pub doc_files: bool,
    pub doc_chunks: bool,
    pub headings: bool,
    pub vault_links: bool,
    pub stats: bool,
    pub embeddings: bool,
    pub title_embeddings: bool,
    pub unresolved_link_suggestions: bool,
}

impl Default for ProjectionPhases {
    fn default() -> Self {
        Self {
            dag_trace: true,
            doc_files: true,
            doc_chunks: true,
            headings: true,
            vault_links: true,
            stats: true,
            embeddings: false, // Expensive, opt-in
            title_embeddings: false,
            unresolved_link_suggestions: false,
        }
    }
}

impl ProjectionPhases {
    /// Parse phase names into a ProjectionPhases struct
    pub fn from_phase_names(names: &[String]) -> Self {
        let mut phases = Self::all_disabled();
        for name in names {
            match name.as_str() {
                "dag_trace" => phases.dag_trace = true,
                "doc_files" => phases.doc_files = true,
                "doc_chunks" => phases.doc_chunks = true,
                "headings" => phases.headings = true,
                "vault_links" => phases.vault_links = true,
                "stats" => phases.stats = true,
                "embeddings" => phases.embeddings = true,
                "title_embeddings" => phases.title_embeddings = true,
                "unresolved_link_suggestions" => phases.unresolved_link_suggestions = true,
                _ => eprintln!("Warning: unknown projection phase '{}', ignoring", name),
            }
        }
        phases
    }

    fn all_disabled() -> Self {
        Self {
            dag_trace: false,
            doc_files: false,
            doc_chunks: false,
            headings: false,
            vault_links: false,
            stats: false,
            embeddings: false,
            title_embeddings: false,
            unresolved_link_suggestions: false,
        }
    }

    /// Get list of all enabled phase names
    pub fn enabled_phase_names(&self) -> Vec<String> {
        let mut names = Vec::new();
        if self.dag_trace {
            names.push("dag_trace".to_string());
        }
        if self.doc_files {
            names.push("doc_files".to_string());
        }
        if self.doc_chunks {
            names.push("doc_chunks".to_string());
        }
        if self.headings {
            names.push("headings".to_string());
        }
        if self.vault_links {
            names.push("vault_links".to_string());
        }
        if self.stats {
            names.push("stats".to_string());
        }
        if self.embeddings {
            names.push("embeddings".to_string());
        }
        if self.title_embeddings {
            names.push("title_embeddings".to_string());
        }
        if self.unresolved_link_suggestions {
            names.push("unresolved_link_suggestions".to_string());
        }
        names
    }
}

/// Batch sizes for different projection phases
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchSizes {
    pub nodes: usize,
    pub edges: usize,
    pub doc_chunks: usize,
    pub doc_files: usize,
    pub headings: usize,
    pub links: usize,
    pub stats: usize,
    pub embeddings: usize,

    /// Max bytes of SurrealQL per `surreal sql` invocation.
    ///
    /// This is primarily to reduce CLI subprocess spawn overhead while avoiding
    /// pathological "giant statement" behavior.
    pub max_sql_bytes: usize,
}

impl Default for BatchSizes {
    fn default() -> Self {
        Self {
            nodes: 200,
            edges: 200,
            doc_chunks: 50,
            doc_files: 200,
            headings: 200,
            links: 100,
            stats: 200,
            embeddings: 16,
            max_sql_bytes: 1_000_000,
        }
    }
}

impl BatchSizes {
    /// Apply batch size overrides from a map
    pub fn apply_overrides(&mut self, overrides: &BTreeMap<String, usize>) {
        for (phase, size) in overrides {
            match phase.as_str() {
                "nodes" => self.nodes = *size,
                "edges" => self.edges = *size,
                "doc_chunks" => self.doc_chunks = *size,
                "doc_files" => self.doc_files = *size,
                "headings" => self.headings = *size,
                "links" => self.links = *size,
                "stats" => self.stats = *size,
                "embeddings" => self.embeddings = *size,
                "max_sql_bytes" => self.max_sql_bytes = (*size).max(1),
                _ => eprintln!("Warning: unknown batch size phase '{}', ignoring", phase),
            }
        }
    }

    /// Determine whether a SurrealQL batch should be flushed based on record count and SQL bytes.
    ///
    /// `phase` is a batch-size key such as `doc_chunks`, `doc_files`, `nodes`, etc.
    pub fn should_flush(&self, phase: &str, count: usize, sql_bytes: usize) -> bool {
        let count_limit = self.get(phase).unwrap_or(200).max(1);
        count >= count_limit || sql_bytes >= self.max_sql_bytes.max(1)
    }

    /// Get batch size for a given phase name
    pub fn get(&self, phase: &str) -> Option<usize> {
        match phase {
            "nodes" => Some(self.nodes),
            "edges" => Some(self.edges),
            "doc_chunks" => Some(self.doc_chunks),
            "doc_files" => Some(self.doc_files),
            "headings" => Some(self.headings),
            "links" => Some(self.links),
            "stats" => Some(self.stats),
            "embeddings" => Some(self.embeddings),
            _ => None,
        }
    }
}

/// Retry policy for projection operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_attempts: usize,
    pub initial_delay_ms: u64,
    pub max_delay_ms: u64,
    /// Backoff multiplier stored as a rational number to keep canonical encoding integer-only.
    ///
    /// Example: 2/1 = 2.0
    pub backoff_multiplier_numer: u64,
    pub backoff_multiplier_denom: u64,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_attempts: 3,
            initial_delay_ms: 100,
            max_delay_ms: 5000,
            backoff_multiplier_numer: 2,
            backoff_multiplier_denom: 1,
        }
    }
}

impl RetryPolicy {
    /// Calculate delay for a given attempt number (0-indexed)
    pub fn delay_for_attempt(&self, attempt: usize) -> u64 {
        if attempt == 0 {
            return 0;
        }
        let denom = self.backoff_multiplier_denom.max(1) as f64;
        let mult = (self.backoff_multiplier_numer as f64) / denom;
        let delay = self.initial_delay_ms as f64
            * mult.powi((attempt - 1) as i32);
        delay.min(self.max_delay_ms as f64) as u64
    }
}

/// How to handle projection failures
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
pub enum FailureHandling {
    /// Abort on any error (strict mode)
    FailFast,
    /// Log warning, continue with other phases
    WarnAndContinue,
    /// No error, no warning (silent)
    SilentIgnore,
}

impl std::fmt::Display for FailureHandling {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FailureHandling::FailFast => write!(f, "fail-fast"),
            FailureHandling::WarnAndContinue => write!(f, "warn-and-continue"),
            FailureHandling::SilentIgnore => write!(f, "silent-ignore"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_hash_stability() {
        let config1 = ProjectionConfig::default();
        let config2 = ProjectionConfig::default();
        assert_eq!(config1.compute_hash(), config2.compute_hash());
    }

    #[test]
    fn test_config_hash_changes_with_modifications() {
        let config1 = ProjectionConfig::default();
        let mut config2 = ProjectionConfig::default();
        config2.batch_sizes.nodes = 100;
        assert_ne!(config1.compute_hash(), config2.compute_hash());
    }

    #[test]
    fn test_batch_size_overrides() {
        let mut batch_sizes = BatchSizes::default();
        let mut overrides = BTreeMap::new();
        overrides.insert("nodes".to_string(), 100);
        overrides.insert("doc_chunks".to_string(), 25);
        overrides.insert("max_sql_bytes".to_string(), 1234);

        batch_sizes.apply_overrides(&overrides);

        assert_eq!(batch_sizes.nodes, 100);
        assert_eq!(batch_sizes.doc_chunks, 25);
        assert_eq!(batch_sizes.edges, 200); // Unchanged
        assert_eq!(batch_sizes.max_sql_bytes, 1234);
    }

    #[test]
    fn test_batch_should_flush_by_count_or_bytes() {
        let mut batch_sizes = BatchSizes::default();
        batch_sizes.doc_chunks = 3;
        batch_sizes.max_sql_bytes = 10;

        assert!(!batch_sizes.should_flush("doc_chunks", 2, 9));
        assert!(batch_sizes.should_flush("doc_chunks", 3, 0));
        assert!(batch_sizes.should_flush("doc_chunks", 0, 10));
    }

    #[test]
    fn test_retry_policy_delay_calculation() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.delay_for_attempt(0), 0);
        assert_eq!(policy.delay_for_attempt(1), 100);
        assert_eq!(policy.delay_for_attempt(2), 200);
        assert_eq!(policy.delay_for_attempt(3), 400);

        // Should cap at max_delay_ms
        assert_eq!(policy.delay_for_attempt(10), 5000);
    }

    #[test]
    fn test_phase_names_parsing() {
        let names = vec!["dag_trace".to_string(), "doc_chunks".to_string()];
        let phases = ProjectionPhases::from_phase_names(&names);

        assert!(phases.dag_trace);
        assert!(phases.doc_chunks);
        assert!(!phases.vault_links);
    }

    #[test]
    fn test_enabled_phase_names() {
        let mut phases = ProjectionPhases::all_disabled();
        phases.dag_trace = true;
        phases.vault_links = true;

        let names = phases.enabled_phase_names();
        assert_eq!(names, vec!["dag_trace", "vault_links"]);
    }

    #[test]
    fn test_config_cbor_serialization() {
        let config = ProjectionConfig::default();
        let bytes1 = config.to_canonical_cbor_witness();
        let bytes2 = config.to_canonical_cbor_witness();
        assert!(!bytes1.is_empty());
        assert_eq!(bytes1, bytes2);

        // Hash should be sha256(canonical_cbor(config))
        let mut hasher = Sha256::new();
        hasher.update(bytes1.as_slice());
        assert_eq!(config.compute_hash(), format!("{:x}", hasher.finalize()));
    }
}
