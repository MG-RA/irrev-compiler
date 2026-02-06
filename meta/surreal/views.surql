-- Surrealist-friendly "views" (query templates) for the Irreversibility vault projections.
-- Namespace/DB: set in Surrealist; these queries assume the default projection schema:
--   doc_file, doc_chunk, doc_heading, doc_stats, obsidian_link, obsidian_file_link, doc_link_unresolved

-- 1) Frontmatter overview (role/type/facets/status)
SELECT doc_path, title, fm_role, fm_type, fm_facets, fm_status_date, fm_canonical
FROM doc_file
ORDER BY doc_path;

-- 2) Role distribution
SELECT fm_role, count() AS n
FROM doc_file
WHERE fm_present = true
GROUP BY fm_role
ORDER BY n DESC;

-- 3) Facet distribution (best-effort; SCHEMALESS array)
SELECT name AS facet, array::len(<-has_facet) AS n
FROM facet
ORDER BY n DESC;

-- 3b) Docs for a facet (replace FACET)
-- LET $f = "implicit-constraint";
-- SELECT <-has_facet<-doc_file.doc_path AS doc FROM facet WHERE name = $f;

-- 4) Top hubs (by inbound links)
SELECT doc_path, in_links, out_links, missing_out, heading_missing_out
FROM doc_stats
ORDER BY in_links DESC
LIMIT 50;

-- 5) Unresolved hygiene summary
SELECT resolution_kind, count() AS n
FROM doc_link_unresolved
GROUP BY resolution_kind
ORDER BY n DESC;

-- 6) Missing targets (grouped)
SELECT raw_target, count() AS n
FROM doc_link_unresolved
WHERE resolution_kind = "missing"
GROUP BY raw_target
ORDER BY n DESC
LIMIT 50;

-- 7) Heading-missing details (with resolved doc)
SELECT from_doc_path, line, raw_target, raw_heading, resolved_doc_path
FROM doc_link_unresolved
WHERE resolution_kind = "heading_missing"
ORDER BY from_doc_path, line;

-- 8) Show a doc's outgoing note links (replace PATH)
-- LET $p = "irrev-vault/index.md";
-- SELECT ->obsidian_link->doc_file.doc_path AS out, ->obsidian_link.line AS line
-- FROM doc_file WHERE doc_path = $p;

-- 9) Show a doc's incoming note links (replace PATH)
-- LET $p = "irrev-vault/concepts/admissibility.md";
-- SELECT <-obsidian_link<-doc_file.doc_path AS inbound, <-obsidian_link.line AS line
-- FROM doc_file WHERE doc_path = $p;

-- 10) Asset/file embeds from a doc (replace PATH)
-- LET $p = "irrev-vault/meta/Concept Graphs.md";
-- SELECT ->obsidian_file_link.to_file_path AS file, ->obsidian_file_link.line AS line
-- FROM doc_file WHERE doc_path = $p;

-- 11) Embedding runs (latest first)
SELECT kind, model, dim_target, dim_actual, created_at_utc, parse_sha256, snapshot_sha256
FROM embed_run
ORDER BY created_at_utc DESC
LIMIT 20;

-- 12) Unresolved link suggestions (latest run only)
-- LET $run = (SELECT run_id, created_at_utc FROM embed_run ORDER BY created_at_utc DESC LIMIT 1)[0].run_id;
-- SELECT from_doc_path, line, raw_target, resolution_kind, recommended_doc_path, candidates
-- FROM unresolved_link_suggestion
-- WHERE run_id = $run
-- ORDER BY from_doc_path, line
-- LIMIT 200;

-- 13) Suggested repairs for a specific doc (replace PATH)
-- LET $run = (SELECT run_id, created_at_utc FROM embed_run ORDER BY created_at_utc DESC LIMIT 1)[0].run_id;
-- LET $p = "irrev-vault/meta/Ineluctability under Irreversibility.md";
-- SELECT line, raw_target, resolution_kind, recommended_doc_path, candidates
-- FROM unresolved_link_suggestion
-- WHERE run_id = $run AND from_doc_path = $p
-- ORDER BY line;

-- 14) Title-embedding semantic neighbors for a doc title (replace PATH)
-- LET $p = "irrev-vault/concepts/admissibility.md";
-- LET $e = (SELECT embedding FROM doc_title_embedding WHERE doc_path = $p LIMIT 1)[0].embedding;
-- SELECT doc_path, vector::similarity::cosine(embedding, $e) AS sim
-- FROM doc_title_embedding
-- WHERE dim_target = 256
-- ORDER BY sim DESC
-- LIMIT 30;
