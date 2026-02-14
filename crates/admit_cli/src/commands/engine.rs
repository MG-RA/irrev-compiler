//! Engine command implementations (query and function artifact registration)

use admit_cli::{
    append_engine_event, build_engine_event, default_artifacts_dir, default_ledger_path,
    load_meta_registry, read_file_bytes, register_function_artifact, register_query_artifact,
    MetaRegistryV0,
};
use admit_surrealdb::{FunctionArtifactRow, ProjectionStoreOps, QueryArtifactRow};

use crate::{commands::current_utc_rfc3339, EngineFunctionAddArgs, EngineQueryAddArgs, ProjectionCoordinator};

pub fn run_engine_query_add(
    args: EngineQueryAddArgs,
    projection: &mut ProjectionCoordinator,
) -> Result<(), String> {
    let artifacts_dir = args
        .artifacts_dir
        .clone()
        .unwrap_or_else(default_artifacts_dir);
    let ledger_path = args.ledger.clone().unwrap_or_else(default_ledger_path);

    let source_bytes =
        read_file_bytes(&args.file).map_err(|e| format!("read query file: {}", e))?;
    let source =
        String::from_utf8(source_bytes).map_err(|e| format!("query file must be UTF-8: {}", e))?;

    let mut tags = args.tags.clone();
    tags.sort();
    tags.dedup();

    let (registry, _registry_hash): (Option<MetaRegistryV0>, Option<String>) =
        match load_meta_registry(args.meta_registry.as_deref()).map_err(|e| e.to_string())? {
            Some((r, h)) => (Some(r), Some(h)),
            None => (None, None),
        };

    let artifact = register_query_artifact(
        &artifacts_dir,
        &args.name,
        &args.lang,
        &source,
        tags.clone(),
        registry.as_ref(),
    )
    .map_err(|e| e.to_string())?;

    let timestamp = current_utc_rfc3339();
    let event = build_engine_event(
        "engine.query.registered",
        timestamp.clone(),
        "query",
        artifact.clone(),
        Some(args.name.clone()),
        Some(args.lang.clone()),
        Some(tags.clone()),
    )
    .map_err(|e| e.to_string())?;

    if !args.no_ledger {
        append_engine_event(&ledger_path, &event).map_err(|e| e.to_string())?;
    }

    projection.with_store("surrealdb project query artifact", |surreal| {
        let store_ops: &dyn ProjectionStoreOps = surreal;
        store_ops
            .ensure_schemas()
            .map_err(|err| format!("surrealdb ensure schemas failed: {}", err))?;
        store_ops
            .project_query_artifacts(&[QueryArtifactRow {
                artifact_sha256: artifact.sha256.clone(),
                schema_id: artifact.schema_id.clone(),
                name: args.name.clone(),
                lang: args.lang.clone(),
                source,
                tags: tags.clone(),
                created_at_utc: timestamp.clone(),
            }])
            .map_err(|err| format!("surrealdb project query artifact failed: {}", err))?;
        Ok(())
    })?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "event": event,
                "artifact": artifact,
                "ledger": ledger_path,
                "artifacts_dir": artifacts_dir,
            }))
            .map_err(|e| format!("json encode: {}", e))?
        );
    } else {
        println!("event_id={}", event.event_id);
        println!("artifact_kind={}", artifact.kind);
        println!("artifact_sha256={}", artifact.sha256);
        println!("schema_id={}", artifact.schema_id);
        println!("ledger={}", ledger_path.display());
        println!("artifacts_dir={}", artifacts_dir.display());
        if args.no_ledger {
            println!("no_ledger=true");
        }
    }

    Ok(())
}

pub fn run_engine_function_add(
    args: EngineFunctionAddArgs,
    projection: &mut ProjectionCoordinator,
) -> Result<(), String> {
    let artifacts_dir = args
        .artifacts_dir
        .clone()
        .unwrap_or_else(default_artifacts_dir);
    let ledger_path = args.ledger.clone().unwrap_or_else(default_ledger_path);

    let source_bytes =
        read_file_bytes(&args.file).map_err(|e| format!("read function file: {}", e))?;
    let source = String::from_utf8(source_bytes)
        .map_err(|e| format!("function file must be UTF-8: {}", e))?;

    let mut tags = args.tags.clone();
    tags.sort();
    tags.dedup();

    let (registry, _registry_hash): (Option<MetaRegistryV0>, Option<String>) =
        match load_meta_registry(args.meta_registry.as_deref()).map_err(|e| e.to_string())? {
            Some((r, h)) => (Some(r), Some(h)),
            None => (None, None),
        };

    let artifact = register_function_artifact(
        &artifacts_dir,
        &args.name,
        &args.lang,
        &source,
        tags.clone(),
        registry.as_ref(),
    )
    .map_err(|e| e.to_string())?;

    let timestamp = current_utc_rfc3339();
    let event = build_engine_event(
        "engine.function.registered",
        timestamp.clone(),
        "function",
        artifact.clone(),
        Some(args.name.clone()),
        Some(args.lang.clone()),
        Some(tags.clone()),
    )
    .map_err(|e| e.to_string())?;

    if !args.no_ledger {
        append_engine_event(&ledger_path, &event).map_err(|e| e.to_string())?;
    }

    projection.with_store("surrealdb project function artifact", |surreal| {
        let store_ops: &dyn ProjectionStoreOps = surreal;
        store_ops
            .ensure_schemas()
            .map_err(|err| format!("surrealdb ensure schemas failed: {}", err))?;
        store_ops
            .project_function_artifacts(&[FunctionArtifactRow {
                artifact_sha256: artifact.sha256.clone(),
                schema_id: artifact.schema_id.clone(),
                name: args.name.clone(),
                lang: args.lang.clone(),
                source,
                tags: tags.clone(),
                created_at_utc: timestamp.clone(),
            }])
            .map_err(|err| format!("surrealdb project function artifact failed: {}", err))?;
        Ok(())
    })?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({
                "event": event,
                "artifact": artifact,
                "ledger": ledger_path,
                "artifacts_dir": artifacts_dir,
            }))
            .map_err(|e| format!("json encode: {}", e))?
        );
    } else {
        println!("event_id={}", event.event_id);
        println!("artifact_kind={}", artifact.kind);
        println!("artifact_sha256={}", artifact.sha256);
        println!("schema_id={}", artifact.schema_id);
        println!("ledger={}", ledger_path.display());
        println!("artifacts_dir={}", artifacts_dir.display());
        if args.no_ledger {
            println!("no_ledger=true");
        }
    }

    Ok(())
}
