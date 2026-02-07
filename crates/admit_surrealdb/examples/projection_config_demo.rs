use admit_surrealdb::projection_config::{FailureHandling, ProjectionConfig, RetryPolicy};
use std::collections::BTreeMap;

fn main() {
    println!("=== Projection Configuration Demo ===\n");

    // 1. Default configuration
    println!("1. Default Configuration:");
    let default_config = ProjectionConfig::default();
    println!("   Config hash: {}", default_config.compute_hash());
    println!("   Enabled phases: {:?}", default_config.enabled_phases.enabled_phase_names());
    println!("   Batch sizes - nodes: {}, chunks: {}",
        default_config.batch_sizes.nodes,
        default_config.batch_sizes.doc_chunks);
    println!("   Failure handling: {}", default_config.failure_handling);
    println!();

    // 2. Configuration from CLI-like inputs
    println!("2. Configuration from CLI flags:");
    let enabled_phases = vec![
        "dag_trace".to_string(),
        "doc_files".to_string(),
        "vault_links".to_string(),
    ];

    let mut batch_overrides = BTreeMap::new();
    batch_overrides.insert("nodes".to_string(), 100);
    batch_overrides.insert("doc_chunks".to_string(), 25);

    let custom_config = ProjectionConfig::from_cli_and_env(
        Some(enabled_phases),
        Some(batch_overrides),
        None,
        Some(FailureHandling::FailFast),
        Some(vec!["my-vault/".to_string()]),
    );

    println!("   Config hash: {}", custom_config.compute_hash());
    println!("   Enabled phases: {:?}", custom_config.enabled_phases.enabled_phase_names());
    println!("   Batch sizes - nodes: {}, chunks: {}",
        custom_config.batch_sizes.nodes,
        custom_config.batch_sizes.doc_chunks);
    println!("   Failure handling: {}", custom_config.failure_handling);
    println!("   Vault prefixes: {:?}", custom_config.vault_prefixes);
    println!();

    // 3. Retry policy
    println!("3. Retry Policy:");
    let retry = RetryPolicy::default();
    println!("   Max attempts: {}", retry.max_attempts);
    println!("   Delays: attempt 0: {}ms, attempt 1: {}ms, attempt 2: {}ms, attempt 3: {}ms",
        retry.delay_for_attempt(0),
        retry.delay_for_attempt(1),
        retry.delay_for_attempt(2),
        retry.delay_for_attempt(3),
    );
    println!();

    // 4. Config as witness artifact
    println!("4. Configuration as Witness Artifact:");
    let cbor_bytes = default_config.to_canonical_cbor_witness();
    println!("   Canonical CBOR size: {} bytes", cbor_bytes.len());
    println!(
        "   First 20 bytes (hex): {}",
        cbor_bytes
            .iter()
            .take(20)
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .join(" ")
    );
    println!();

    // 5. Configuration hash stability
    println!("5. Configuration Hash Stability:");
    let config1 = ProjectionConfig::default();
    let config2 = ProjectionConfig::default();
    let mut config3 = ProjectionConfig::default();
    config3.batch_sizes.nodes = 150;

    println!("   config1 hash: {}", config1.compute_hash());
    println!("   config2 hash: {}", config2.compute_hash());
    println!("   config3 hash (modified): {}", config3.compute_hash());
    println!("   config1 == config2: {}", config1.compute_hash() == config2.compute_hash());
    println!("   config1 == config3: {}", config1.compute_hash() == config3.compute_hash());
}
