use serde::{Deserialize, Serialize};

/// Reference to a content-addressed artifact with schema and size metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactRef {
    pub kind: String,
    pub schema_id: String,
    pub sha256: String,
    pub size_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

/// Reference to a compiler build by build identifier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerRef {
    pub build_id: String,
}

/// Reference to a program by module and scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgramRef {
    pub module: String,
    pub scope: String,
}
