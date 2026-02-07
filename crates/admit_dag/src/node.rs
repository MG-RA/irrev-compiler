use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

use admit_core::ArtifactRef;

use crate::edge::ScopeTag;

/// Content-addressed node identity. Stored as raw bytes, displayed as hex.
/// Avoids normalization bugs and case drift vs String representation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NodeId([u8; 32]);

impl NodeId {
    /// Create a NodeId from the canonical hash of a NodeIdPayload.
    pub fn from_payload(payload: &NodeIdPayload) -> Result<Self, String> {
        // Serialize payload as canonical CBOR map
        let cbor_bytes = payload.to_canonical_cbor()?;

        // Hash the CBOR bytes
        let mut hasher = Sha256::new();
        hasher.update(&cbor_bytes);
        let hash: [u8; 32] = hasher.finalize().into();

        Ok(NodeId(hash))
    }

    /// Access the raw bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Create from hex string
    pub fn from_hex(s: &str) -> Result<Self, String> {
        if s.len() != 64 {
            return Err(format!("hex string must be 64 chars, got {}", s.len()));
        }

        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|e| format!("invalid hex at position {}: {}", i * 2, e))?;
        }

        Ok(NodeId(bytes))
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in &self.0 {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl std::str::FromStr for NodeId {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl Serialize for NodeId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for NodeId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

/// Identity payload — what gets hashed to produce NodeId.
/// Serialized as a canonical CBOR **map** with explicit keys, so encoding changes
/// are obviously versioned, not accidental drift.
///
/// NodeId = sha256(canonical_cbor({
///   "tag": "admit_dag_node_v1",
///   "kind": <NodeKind as canonical CBOR>,
///   "inputs": [<NodeId bytes>...],       // sorted by raw bytes (lexicographic on [u8;32])
///   "params": <params_cbor bytes>        // canonical CBOR of kind-specific params
/// }))
#[derive(Debug, Clone, Serialize)]
pub struct NodeIdPayload {
    pub tag: &'static str, // "admit_dag_node_v1" — domain separator + version
    pub kind: NodeKind,
    pub inputs: Vec<NodeId>, // sorted by raw [u8;32] bytes (lexicographic), NOT by hex string
    pub params_cbor: Vec<u8>, // canonical CBOR of kind-specific params (storage form)
}

impl NodeIdPayload {
    /// Convert to canonical CBOR bytes for hashing
    fn to_canonical_cbor(&self) -> Result<Vec<u8>, String> {
        // Create a deterministic map representation
        let mut map = BTreeMap::new();
        map.insert("tag", serde_json::json!(self.tag));
        map.insert(
            "kind",
            serde_json::to_value(&self.kind)
                .map_err(|e| format!("failed to serialize kind: {}", e))?,
        );

        // Serialize inputs as hex strings (already sorted by raw bytes)
        let inputs_hex: Vec<String> = self.inputs.iter().map(|id| id.to_string()).collect();
        map.insert("inputs", serde_json::json!(inputs_hex));

        // params_cbor is already in CBOR form - we hex-encode it for the JSON intermediate
        let params_hex = hex::encode(&self.params_cbor);
        map.insert("params", serde_json::json!(params_hex));

        // Use admit_core's canonical encoding
        admit_core::encode_canonical_value(
            &serde_json::to_value(map).map_err(|e| format!("failed to create map: {}", e))?,
        )
        .map_err(|e| format!("canonical encoding failed: {}", e))
    }
}

/// Node category for high-level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeCategory {
    Source,
    Derived,
    Governance,
}

/// Core kinds as a closed enum. Extension point via `kind_ext` on DagNode.
///
/// CRITICAL: Identity fields must be content-derived, not environment-derived.
/// Paths, names, and environment-specific identifiers go in DagNode.metadata,
/// not in NodeKind fields. This is the #1 place content-addressed systems
/// silently stop being content-addressed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeKind {
    // Source — identity via content hash, not path/location
    RulesetSource {
        content_hash: String,
    },
    RegistrySource {
        content_hash: String,
    },
    DirectorySnapshot {
        snapshot_sha256: String,
    },
    FileAtPath {
        path: String,
        content_sha256: String,
    },

    // Derived — identity via input content, not module names
    ParsedIr {
        content_hash: String,
    },
    DependencyGraph {
        content_hash: String,
    },
    RegistryTable {
        schema_id: String,
    },
    SnapshotExport {
        snapshot_hash: String,
    },
    LintReport {
        content_hash: String,
    },
    FactsBundle {
        bundle_hash: String,
    },
    CalcPlan {
        plan_hash: String,
    },
    CalcResult {
        witness_hash: String,
    },
    DirectoryParse {
        parse_sha256: String,
    },
    TextChunk {
        chunk_sha256: String,
        doc_path: String,
        heading_path: Vec<String>,
        start_line: u32,
    },

    // Governance — event_id is fine only if already content-addressed
    PlanArtifact {
        plan_hash: String,
        template_id: String,
    },
    Approval {
        plan_hash: String,
        approver_hash: String,
    },
    ExecutionLog {
        log_hash: String,
    },
    Witness {
        witness_sha256: String,
        schema_id: String,
    },
    CostDeclaration {
        content_hash: String,
    },
    AdmissibilityCheck {
        content_hash: String,
    },
    AdmissibilityExecution {
        content_hash: String,
    },

    // Explicit authority root — see "Authority source nodes"
    AuthorityRoot {
        authority_id: String,
        authority_hash: String,
    },
}

impl NodeKind {
    /// Get the category for this kind
    pub fn category(&self) -> NodeCategory {
        match self {
            NodeKind::RulesetSource { .. }
            | NodeKind::RegistrySource { .. }
            | NodeKind::DirectorySnapshot { .. }
            | NodeKind::FileAtPath { .. } => NodeCategory::Source,
            NodeKind::ParsedIr { .. }
            | NodeKind::DependencyGraph { .. }
            | NodeKind::RegistryTable { .. }
            | NodeKind::SnapshotExport { .. }
            | NodeKind::LintReport { .. }
            | NodeKind::FactsBundle { .. }
            | NodeKind::CalcPlan { .. }
            | NodeKind::CalcResult { .. }
            | NodeKind::DirectoryParse { .. }
            | NodeKind::TextChunk { .. } => NodeCategory::Derived,
            NodeKind::PlanArtifact { .. }
            | NodeKind::Approval { .. }
            | NodeKind::ExecutionLog { .. }
            | NodeKind::Witness { .. }
            | NodeKind::CostDeclaration { .. }
            | NodeKind::AdmissibilityCheck { .. }
            | NodeKind::AdmissibilityExecution { .. }
            | NodeKind::AuthorityRoot { .. } => NodeCategory::Governance,
        }
    }
}

/// A node in the governed DAG
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagNode {
    pub id: NodeId,
    pub category: NodeCategory,
    pub kind: NodeKind,
    pub scope: ScopeTag, // metadata, not part of identity
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_ref: Option<ArtifactRef>, // reuses existing type from admit_core

    /// Extension point for experimental kinds. Hashed into identity if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind_ext: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind_meta: Option<Value>,

    /// Non-identity metadata: paths, module names, human labels, timestamps.
    /// Environment-derived identifiers (paths, names) belong HERE, not in NodeKind.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
}

impl DagNode {
    /// Create a new node with automatic category inference
    pub fn new(
        kind: NodeKind,
        scope: ScopeTag,
        mut inputs: Vec<NodeId>,
        params_cbor: Vec<u8>,
    ) -> Result<Self, String> {
        let category = kind.category();

        // Enforce identity determinism: inputs must be sorted by raw bytes
        // (NodeId derives Ord over its raw [u8; 32] bytes).
        inputs.sort();

        let payload = NodeIdPayload {
            tag: "admit_dag_node_v1",
            kind: kind.clone(),
            inputs,
            params_cbor,
        };

        let id = NodeId::from_payload(&payload)?;

        Ok(DagNode {
            id,
            category,
            kind,
            scope,
            artifact_ref: None,
            kind_ext: None,
            kind_meta: None,
            metadata: None,
        })
    }
}

// Temporary hex encoding utility (replace with hex crate in production)
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_id_hex_roundtrip() {
        let original = NodeId([0x42; 32]);
        let hex_str = original.to_string();
        assert_eq!(hex_str.len(), 64);

        let parsed = NodeId::from_hex(&hex_str).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn node_id_determinism() {
        // Same inputs should produce same NodeId
        let kind = NodeKind::RulesetSource {
            content_hash: "abc123".to_string(),
        };

        let payload1 = NodeIdPayload {
            tag: "admit_dag_node_v1",
            kind: kind.clone(),
            inputs: vec![],
            params_cbor: vec![],
        };

        let payload2 = NodeIdPayload {
            tag: "admit_dag_node_v1",
            kind,
            inputs: vec![],
            params_cbor: vec![],
        };

        let id1 = NodeId::from_payload(&payload1).unwrap();
        let id2 = NodeId::from_payload(&payload2).unwrap();

        assert_eq!(id1, id2);
    }
}
