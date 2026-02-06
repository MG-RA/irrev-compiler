-- SurrealDB schema for projection run tracking
-- Phase 0: ProjectionRun primitive
--
-- This schema enables auditable accounting of all projection runs.
-- Every projection run gets tracked with full lineage, and all projected
-- records are stamped with the run_id that created them.

-- ============================================================================
-- TABLE: projection_run
-- ============================================================================
-- Tracks each projection execution with full lineage and status

DEFINE TABLE projection_run SCHEMALESS;

-- Index by trace identity (find all runs for a given trace)
DEFINE INDEX projection_run_trace
    ON TABLE projection_run
    COLUMNS trace_sha256;

-- Index by status (find all failed/partial/complete runs)
DEFINE INDEX projection_run_status
    ON TABLE projection_run
    COLUMNS status;

-- Index by started timestamp (chronological queries)
DEFINE INDEX projection_run_started
    ON TABLE projection_run
    COLUMNS started_at;

-- Index by config hash (find runs with same configuration)
DEFINE INDEX projection_run_config
    ON TABLE projection_run
    COLUMNS config_hash;

-- ============================================================================
-- EXAMPLE QUERIES
-- ============================================================================

-- Get latest projection run for a trace
-- SELECT * FROM projection_run
-- WHERE trace_sha256 = $trace_sha
-- ORDER BY started_at DESC
-- LIMIT 1;

-- Get all runs in the last 24 hours
-- SELECT * FROM projection_run
-- WHERE started_at > time::now() - 1d
-- ORDER BY started_at DESC;

-- Get all failed or partial runs
-- SELECT * FROM projection_run
-- WHERE status IN ["failed", "partial"]
-- ORDER BY started_at DESC;

-- Get run-to-run comparison
-- SELECT run_id, trace_sha256, status,
--        array::len(phases_enabled) as phase_count,
--        finished_at - started_at as duration
-- FROM projection_run
-- WHERE trace_sha256 = $trace_sha
-- ORDER BY started_at DESC
-- LIMIT 10;

-- Find all runs with a specific configuration
-- SELECT * FROM projection_run
-- WHERE config_hash = $config_hash;

-- Get phase failure breakdown for a run
-- SELECT phase_results FROM projection_run
-- WHERE run_id = $run_id;

-- ============================================================================
-- UPDATED TABLE SCHEMAS (with projection_run_id stamping)
-- ============================================================================

-- All existing projection tables should add a projection_run_id field:
--
-- ALTER TABLE identity ADD projection_run_id string;
-- ALTER TABLE artifact ADD projection_run_id string;
-- ALTER TABLE dag_trace_node ADD projection_run_id string;
-- ALTER TABLE dag_trace_edge ADD projection_run_id string;
-- ALTER TABLE doc_file ADD projection_run_id string;
-- ALTER TABLE doc_chunk ADD projection_run_id string;
-- ALTER TABLE doc_heading ADD projection_run_id string;
-- ALTER TABLE doc_stats ADD projection_run_id string;
-- ALTER TABLE obsidian_link ADD projection_run_id string;
-- ALTER TABLE obsidian_file_link ADD projection_run_id string;
-- ALTER TABLE doc_link_unresolved ADD projection_run_id string;
-- ALTER TABLE facet ADD projection_run_id string;
-- ALTER TABLE has_facet ADD projection_run_id string;
-- ALTER TABLE doc_embedding ADD projection_run_id string;
-- ALTER TABLE doc_embedding_doc ADD projection_run_id string;
-- ALTER TABLE doc_title_embedding ADD projection_run_id string;
-- ALTER TABLE unresolved_link_suggestion ADD projection_run_id string;

-- Note: For embedding-related tables, projection_run_id is separate from
-- embed_run.run_id (which tracks the embedding computation run).
-- projection_run_id tracks the *projection* of that embedding into SurrealDB.

-- ============================================================================
-- USAGE PATTERN
-- ============================================================================

-- 1. Begin a projection run (create record with status="running")
-- INSERT INTO projection_run {
--     run_id: $run_id,
--     trace_sha256: $trace_sha,
--     started_at: time::now(),
--     projector_version: $version,
--     config_hash: $config_hash,
--     phases_enabled: $phases,
--     status: "running",
--     phase_results: {}
-- };

-- 2. During projection, stamp all records with projection_run_id
-- INSERT INTO doc_file {
--     doc_path: $path,
--     projection_run_id: $run_id,
--     ... other fields
-- };

-- 3. Complete the run (update with final status)
-- UPDATE projection_run SET
--     status = $final_status,
--     finished_at = time::now(),
--     phase_results = $results
-- WHERE run_id = $run_id;

-- 4. Query records from latest successful run
-- LET $latest_run = (
--     SELECT run_id FROM projection_run
--     WHERE trace_sha256 = $trace_sha AND status = "complete"
--     ORDER BY started_at DESC
--     LIMIT 1
-- ).run_id;
--
-- SELECT * FROM doc_file WHERE projection_run_id = $latest_run;

-- 5. Garbage collection (remove old runs and their records)
-- LET $old_runs = SELECT run_id FROM projection_run
--                 WHERE started_at < time::now() - 30d;
--
-- DELETE FROM doc_file WHERE projection_run_id IN $old_runs;
-- DELETE FROM projection_run WHERE run_id IN $old_runs;

-- ============================================================================
-- BENEFITS
-- ============================================================================
--
-- 1. Auditability: Every DB row traceable to which projection run created it
-- 2. Lineage: Full chain from trace → run → config → projector version
-- 3. Retry: Deterministic retry by stable run identity
-- 4. Diff: Compare DB state between runs
-- 5. Cleanup: Garbage collection by run_id
-- 6. Debugging: Query "what projection runs happened today?"
-- 7. Monitoring: Track projection success/failure rates over time
