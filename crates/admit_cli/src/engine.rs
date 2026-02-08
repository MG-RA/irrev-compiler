use serde_json::json;

use std::path::Path;

use crate::artifact::store_artifact;
use crate::internal::sha256_hex;
use crate::types::{ArtifactRef, DeclareCostError, MetaRegistryV0};

const ENGINE_QUERY_SCHEMA_ID: &str = "engine-query/1";
const ENGINE_QUERY_KIND: &str = "query_artifact";

const ENGINE_FUNCTION_SCHEMA_ID: &str = "engine-function/1";
const ENGINE_FUNCTION_KIND: &str = "fn_artifact";

fn sort_tags(mut tags: Vec<String>) -> Vec<String> {
    tags.sort();
    tags.dedup();
    tags
}

pub fn register_query_artifact(
    artifacts_root: &Path,
    name: &str,
    lang: &str,
    source: &str,
    tags: Vec<String>,
    registry: Option<&MetaRegistryV0>,
) -> Result<ArtifactRef, DeclareCostError> {
    let tags = sort_tags(tags);
    let value = json!({
        "schema_id": ENGINE_QUERY_SCHEMA_ID,
        "schema_version": 0,
        "name": name,
        "lang": lang,
        "source": source,
        "tags": tags,
    });

    let cbor = admit_core::encode_canonical_value(&value)
        .map_err(|err| DeclareCostError::CanonicalEncode(err.0))?;
    let sha256 = sha256_hex(&cbor);
    let projection = json!({
        "schema_id": ENGINE_QUERY_SCHEMA_ID,
        "sha256": sha256,
        "kind": ENGINE_QUERY_KIND,
        "query": value,
    });

    store_artifact(
        artifacts_root,
        ENGINE_QUERY_KIND,
        ENGINE_QUERY_SCHEMA_ID,
        &cbor,
        "cbor",
        Some(
            serde_json::to_vec_pretty(&projection)
                .map_err(|err| DeclareCostError::Json(err.to_string()))?,
        ),
        registry,
    )
}

pub fn register_function_artifact(
    artifacts_root: &Path,
    name: &str,
    lang: &str,
    source: &str,
    tags: Vec<String>,
    registry: Option<&MetaRegistryV0>,
) -> Result<ArtifactRef, DeclareCostError> {
    let tags = sort_tags(tags);
    let value = json!({
        "schema_id": ENGINE_FUNCTION_SCHEMA_ID,
        "schema_version": 0,
        "name": name,
        "lang": lang,
        "source": source,
        "tags": tags,
    });

    let cbor = admit_core::encode_canonical_value(&value)
        .map_err(|err| DeclareCostError::CanonicalEncode(err.0))?;
    let sha256 = sha256_hex(&cbor);
    let projection = json!({
        "schema_id": ENGINE_FUNCTION_SCHEMA_ID,
        "sha256": sha256,
        "kind": ENGINE_FUNCTION_KIND,
        "function": value,
    });

    store_artifact(
        artifacts_root,
        ENGINE_FUNCTION_KIND,
        ENGINE_FUNCTION_SCHEMA_ID,
        &cbor,
        "cbor",
        Some(
            serde_json::to_vec_pretty(&projection)
                .map_err(|err| DeclareCostError::Json(err.to_string()))?,
        ),
        registry,
    )
}
