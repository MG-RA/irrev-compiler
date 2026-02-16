use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

#[derive(Debug, Clone)]
pub struct BookAst {
    pub title: String,
    pub intro_paragraphs: Vec<String>,
    pub has_cycles: bool,
    pub cycle_nodes: Vec<BookContentsEntry>,
    pub contents: Vec<BookContentsSection>,
    pub orientation_pages: Vec<BookSupplementalPage>,
    pub invariants: Vec<BookInvariantSection>,
    pub supplemental_pages: Vec<BookSupplementalPage>,
    pub layers: Vec<BookLayerSection>,
    pub unclassified: Vec<BookConceptSection>,
    pub appendix_files: Vec<String>,
    pub appendix_note: String,
}

#[derive(Debug, Clone)]
pub struct BookSupplementalPage {
    pub title: String,
    pub markdown_body: String,
}

#[derive(Debug, Clone)]
pub struct BookContentsSection {
    pub label: String,
    pub entries: Vec<BookContentsEntry>,
}

#[derive(Debug, Clone)]
pub struct BookContentsEntry {
    pub id: String,
    pub anchor: String,
}

#[derive(Debug, Clone)]
pub struct BookLayerSection {
    pub label: String,
    pub interlude: BookInvariantInterlude,
    pub concepts: Vec<BookConceptSection>,
}

#[derive(Debug, Clone)]
pub struct BookInvariantInterlude {
    pub reader_contract: String,
    pub invariant_counts: Vec<InvariantCounts>,
    pub core_spine_concepts: Vec<InvariantConceptList>,
    pub navigational_matrix: Option<BookNavigationalMatrix>,
    pub audit_hooks: Vec<BookAuditHook>,
}

#[derive(Debug, Clone)]
pub struct InvariantCounts {
    pub invariant: String,
    pub declared: u32,
    pub observed: u32,
    pub core: u32,
    pub inferred: u32,
}

#[derive(Debug, Clone)]
pub struct InvariantConceptList {
    pub invariant: String,
    pub concepts: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct BookNavigationalMatrix {
    pub marker_legend: String,
    pub per_invariant: Vec<InvariantConceptList>,
}

#[derive(Debug, Clone)]
pub struct BookAuditHook {
    pub label: String,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct BookInvariantSection {
    pub id: String,
    pub title: String,
    pub markdown_body: String,
}

#[derive(Debug, Clone)]
pub struct BookConceptSection {
    pub id: String,
    pub anchor: String,
    pub title: String,
    pub markdown_body: String,
}

#[derive(Debug, Clone)]
pub struct LayerInvariantMatrixView {
    pub invariant_ids: Vec<String>,
    pub cells: BTreeMap<String, BTreeMap<String, Vec<String>>>,
    pub diagnostic_note: String,
    pub marker_legend: String,
}

#[derive(Debug, Clone)]
pub struct InvariantGapAuditView {
    pub unassigned_note: String,
    pub declared_all: Vec<String>,
    pub declared_only: Vec<String>,
    pub declared_infrastructure: Vec<String>,
    pub mismatch: Vec<String>,
    pub inferred_only: Vec<String>,
    pub unassigned: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenderProfile {
    Hybrid,
    Diagnostic,
}

impl RenderProfile {
    pub fn as_str(self) -> &'static str {
        match self {
            RenderProfile::Hybrid => "hybrid",
            RenderProfile::Diagnostic => "diagnostic",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConceptClassification {
    Aligned,
    DeclaredOnly,
    ObservedOnly,
    InferredOnly,
    StructuralOnly,
    Mismatch,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum IncludedReason {
    CanonicalSeed,
    DependencyClosure,
}

#[derive(Debug, Clone)]
pub struct SourceConcept {
    pub id: String,
    pub anchor: String,
    pub title: String,
    pub canonical_path: String,
    pub layer: Option<String>,
    pub layer_label: String,
    pub canonical: bool,
    pub declared_invariants: Vec<String>,
    pub frontmatter: BTreeMap<String, serde_json::Value>,
    pub source_markdown_body: String,
    pub book_markdown_body: String,
}

#[derive(Debug, Clone)]
pub struct BookGraphInput {
    pub concepts_by_id: HashMap<String, SourceConcept>,
    pub deps: HashMap<String, BTreeSet<String>>,
    pub included: HashSet<String>,
    pub seed_ids: BTreeSet<String>,
    pub included_reason: HashMap<String, IncludedReason>,
    pub ordered: Vec<String>,
    pub has_cycles: bool,
    pub cycle_nodes: Vec<String>,
    pub by_layer: BTreeMap<String, Vec<String>>,
    pub layer_order: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RefCounts {
    pub invariant: u32,
    pub diagnostic: u32,
}

#[derive(Debug, Clone)]
pub struct SpineEvidenceRow {
    pub id: String,
    pub primary_spine: String,
    pub core_in: Vec<String>,
    pub footprint_in: Vec<String>,
    pub refs: BTreeMap<String, RefCounts>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConceptBookRecord {
    pub id: String,
    pub title: String,
    pub canonical_path: String,
    pub layer: Option<String>,
    pub layer_label: String,
    pub canonical: bool,
    pub declared_invariants: Vec<String>,
    pub observed_invariants: Vec<String>,
    pub inferred_invariants: Vec<String>,
    pub dependency_of_core_invariants: Vec<String>,
    pub core_in: Vec<String>,
    pub footprint_in: Vec<String>,
    pub ref_counts: BTreeMap<String, RefCounts>,
    pub primary_spine: String,
    pub classification: ConceptClassification,
    pub included_reason: IncludedReason,
    pub dependency_path: Vec<String>,
    pub frontmatter_hash: String,
    pub content_hash: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct InvariantLayerSummary {
    pub declared: u32,
    pub observed: u32,
    pub core: u32,
    pub inferred: u32,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct LayerInvariantMatrix {
    pub cells: BTreeMap<String, BTreeMap<String, Vec<String>>>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct GapSummary {
    pub declared_only: Vec<String>,
    pub declared_infrastructure: Vec<String>,
    pub mismatch: Vec<String>,
    pub inferred_only: Vec<String>,
    pub structural_only: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct BookAnalytics {
    pub records: Vec<ConceptBookRecord>,
    pub records_by_id: HashMap<String, usize>,
    pub layer_invariant_summaries: BTreeMap<String, BTreeMap<String, InvariantLayerSummary>>,
    pub layer_core_concepts: BTreeMap<String, BTreeMap<String, Vec<String>>>,
    pub matrix: LayerInvariantMatrix,
    pub hybrid_matrix: LayerInvariantMatrix,
    pub gaps: GapSummary,
}

impl BookAnalytics {
    pub fn get(&self, id: &str) -> Option<&ConceptBookRecord> {
        self.records_by_id
            .get(id)
            .and_then(|idx| self.records.get(*idx))
    }
}
