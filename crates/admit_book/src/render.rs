use chrono::Utc;
use std::fs;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::markdown_latex::md_to_latex;
use crate::{BookAst, BookInvariantInterlude, InvariantGapAuditView, LayerInvariantMatrixView};

pub fn default_latex_template() -> &'static str {
    r#"\documentclass[11pt,openany]{book}
\usepackage{irrevbook}
\title{{{TITLE}}}
\date{{{GENERATED_AT_UTC}}}
\begin{document}
\frontmatter
\maketitle
\tableofcontents

\mainmatter
\part{Ontology}
{{BODY}}

\backmatter
{{APPENDICES}}
\end{document}
"#
}

fn invariants_intro_markdown() -> &'static str {
    "These are not extensions of the ontology. They are guardrails on interpretation.\n\nThese constraints bind the lens itself: if they fail, the framework mutates into ideology. Treat them as conservation laws for method, not optional commentary."
}

fn invariants_intro_latex() -> &'static str {
    "These are not extensions of the ontology. They are guardrails on interpretation.\n\nThese constraints bind the lens itself: if they fail, the framework mutates into ideology. Treat them as conservation laws for method, not optional commentary."
}

fn has_signal(value: &str) -> bool {
    let low = value.trim().to_ascii_lowercase();
    !(low.is_empty() || low == "(none)")
}

fn interlude_summary_lines(interlude: &BookInvariantInterlude) -> Vec<String> {
    let declared: u32 = interlude.invariant_counts.iter().map(|c| c.declared).sum();
    let observed: u32 = interlude.invariant_counts.iter().map(|c| c.observed).sum();
    let core: u32 = interlude.invariant_counts.iter().map(|c| c.core).sum();
    let inferred: u32 = interlude.invariant_counts.iter().map(|c| c.inferred).sum();
    let tracked_core = interlude
        .core_spine_concepts
        .iter()
        .filter(|c| !c.concepts.is_empty())
        .count();

    let mut out = vec![
        format!(
            "Layer footprint: declared={}, observed={}, core={}, inferred={}.",
            declared, observed, core, inferred
        ),
        if tracked_core == 0 {
            "No invariant has a core spine concept at this layer; read this section as scaffolding rather than terminal evidence.".to_string()
        } else {
            format!(
                "Core spine evidence appears in {} invariant track(s) at this layer.",
                tracked_core
            )
        },
    ];

    let pressure: Vec<String> = interlude
        .audit_hooks
        .iter()
        .filter(|h| has_signal(&h.value))
        .map(|h| format!("{}: {}", h.label, h.value))
        .collect();
    if pressure.is_empty() {
        out.push("No immediate gap signal is detected by the audit hooks.".to_string());
    } else {
        out.push(format!(
            "Primary audit pressure: {}.",
            pressure
                .iter()
                .take(2)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        ));
    }
    out
}

fn slugify_path_segment(input: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in input.chars() {
        let c = ch.to_ascii_lowercase();
        if c.is_ascii_alphanumeric() {
            out.push(c);
            last_dash = false;
            continue;
        }
        if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    let trimmed = out.trim_matches('-').to_string();
    if trimmed.is_empty() {
        "item".to_string()
    } else {
        trimmed
    }
}

fn render_interlude_markdown(interlude: &BookInvariantInterlude) -> String {
    let mut out = String::new();
    out.push_str(interlude.reader_contract.trim());
    out.push_str("\n\n");

    let summary_lines = interlude_summary_lines(interlude);
    out.push_str("Interpretation cues:\n");
    for line in summary_lines {
        out.push_str(&format!("- {}\n", line));
    }
    out.push('\n');

    for c in &interlude.invariant_counts {
        out.push_str(&format!(
            "- `{}`: declared={}, observed={}, core={}, inferred={}\n",
            c.invariant, c.declared, c.observed, c.core, c.inferred
        ));
    }
    out.push('\n');

    out.push_str("Core spine concepts at this layer:\n");
    for list in &interlude.core_spine_concepts {
        if list.concepts.is_empty() {
            out.push_str(&format!("- `{}`: (none)\n", list.invariant));
        } else {
            out.push_str(&format!(
                "- `{}`: {}\n",
                list.invariant,
                list.concepts.join(", ")
            ));
        }
    }
    out.push('\n');

    if let Some(matrix) = &interlude.navigational_matrix {
        out.push_str("Layer navigational matrix:\n");
        out.push_str(&format!("- markers: {}\n", matrix.marker_legend));
        for list in &matrix.per_invariant {
            if list.concepts.is_empty() {
                out.push_str(&format!("- `{}`: (none)\n", list.invariant));
            } else {
                out.push_str(&format!(
                    "- `{}`: {}\n",
                    list.invariant,
                    list.concepts.join(", ")
                ));
            }
        }
        out.push('\n');
    }

    out.push_str("Audit hooks:\n");
    for hook in &interlude.audit_hooks {
        out.push_str(&format!("- {}: {}\n", hook.label, hook.value));
    }
    out
}

pub fn render_markdown(ast: &BookAst) -> String {
    let mut out = String::new();
    out.push_str(&format!("# {}\n\n", ast.title));
    for paragraph in &ast.intro_paragraphs {
        out.push_str(paragraph.trim());
        out.push_str("\n\n");
    }

    if ast.has_cycles {
        out.push_str("## Cycles\n\n");
        out.push_str("The concept graph contains cycles; those concepts are included, but no total order can satisfy all dependency edges.\n\n");
        for item in &ast.cycle_nodes {
            out.push_str(&format!("- [{}](#{})\n", item.id, item.anchor));
        }
        out.push('\n');
    }

    out.push_str("## Contents\n\n");
    for section in &ast.contents {
        out.push_str(&format!("- {}\n", section.label));
        for entry in &section.entries {
            out.push_str(&format!("  - [{}](#{})\n", entry.id, entry.anchor));
        }
    }
    if !ast.invariants.is_empty() {
        out.push_str("- [Invariants](#invariants)\n");
        for inv in &ast.invariants {
            out.push_str(&format!("  - [{}](#invariant-{})\n", inv.title, inv.id));
        }
    }
    if !ast.orientation_pages.is_empty() {
        out.push_str("- Orientation\n");
        for page in &ast.orientation_pages {
            let slug = page
                .title
                .to_lowercase()
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                .collect::<String>();
            out.push_str(&format!("  - [{}](#{})\n", page.title, slug));
        }
    }
    if !ast.supplemental_pages.is_empty() {
        out.push_str("- Supplemental\n");
        for page in &ast.supplemental_pages {
            let slug = page
                .title
                .to_lowercase()
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                .collect::<String>();
            out.push_str(&format!("  - [{}](#{})\n", page.title, slug));
        }
    }
    out.push_str("\n---\n\n");

    if !ast.orientation_pages.is_empty() {
        for page in &ast.orientation_pages {
            out.push_str(&format!("## {}\n\n", page.title));
            out.push_str(page.markdown_body.trim_end());
            out.push_str("\n\n---\n\n");
        }
    }

    for layer in &ast.layers {
        out.push_str(&format!("## {}\n\n", layer.label));
        out.push_str("### Invariant Interlude\n\n");
        out.push_str(&render_interlude_markdown(&layer.interlude));
        out.push_str("\n\n");

        for concept in &layer.concepts {
            out.push_str(&format!("<a id=\"{}\"></a>\n\n", concept.anchor));
            out.push_str(concept.markdown_body.trim_end());
            out.push_str("\n\n---\n\n");
        }

        if layer.label == "Primitives" && !ast.invariants.is_empty() {
            out.push_str("## Invariants\n\n");
            out.push_str(invariants_intro_markdown());
            out.push_str("\n\n");
            for inv in &ast.invariants {
                out.push_str(&format!("<a id=\"invariant-{}\"></a>\n\n", inv.id));
                out.push_str(&format!("### {}\n\n", inv.title));
                out.push_str(inv.markdown_body.trim_end());
                out.push_str("\n\n---\n\n");
            }
        }
    }

    if !ast.unclassified.is_empty() {
        out.push_str("## Unclassified\n\n");
        for concept in &ast.unclassified {
            out.push_str(&format!("<a id=\"{}\"></a>\n\n", concept.anchor));
            out.push_str(concept.markdown_body.trim_end());
            out.push_str("\n\n---\n\n");
        }
    }

    if !ast.supplemental_pages.is_empty() {
        for page in &ast.supplemental_pages {
            out.push_str(&format!("## {}\n\n", page.title));
            out.push_str(page.markdown_body.trim_end());
            out.push_str("\n\n---\n\n");
        }
    }

    out.push_str("## Appendices\n\n");
    for file in &ast.appendix_files {
        out.push_str(&format!("- `{}`\n", file));
    }
    out.push('\n');
    out.push_str(ast.appendix_note.trim());
    out.push('\n');
    out
}

fn render_interlude_latex(interlude: &BookInvariantInterlude) -> String {
    let mut out = String::new();
    out.push_str("\\begin{irrevinterlude}\n");
    out.push_str(&format!(
        "\\irrevcontract{{{}}}\n",
        latex_escape(&interlude.reader_contract)
    ));

    out.push_str("Interpretation cues:\n\n");
    out.push_str("\\begin{itemize}\n");
    for line in interlude_summary_lines(interlude) {
        out.push_str(&format!(
            "\\item {}\n",
            latex_escape_with_breaks(line.trim())
        ));
    }
    out.push_str("\\end{itemize}\n\n");

    out.push_str("\\begin{itemize}\n");
    for c in &interlude.invariant_counts {
        out.push_str(&format!(
            "\\irrevinvariantcount{{{}}}{{{}}}{{{}}}{{{}}}{{{}}}\n",
            latex_escape(&c.invariant),
            c.declared,
            c.observed,
            c.core,
            c.inferred
        ));
    }
    out.push_str("\\end{itemize}\n\n");

    out.push_str("Core spine concepts at this layer:\n\n");
    out.push_str("\\begin{itemize}\n");
    for list in &interlude.core_spine_concepts {
        out.push_str(&format!(
            "\\irrevspine{{{}}}{{{}}}\n",
            latex_escape(&list.invariant),
            latex_escape_concept_list(&list.concepts)
        ));
    }
    out.push_str("\\end{itemize}\n\n");

    if let Some(matrix) = &interlude.navigational_matrix {
        out.push_str("Layer navigational matrix:\n\n");
        out.push_str(&format!(
            "markers: {}.\n\n",
            latex_escape(&matrix.marker_legend)
        ));
        out.push_str("\\begin{itemize}\n");
        for list in &matrix.per_invariant {
            out.push_str(&format!(
                "\\irrevnavrow{{{}}}{{{}}}\n",
                latex_escape(&list.invariant),
                latex_escape_concept_list(&list.concepts)
            ));
        }
        out.push_str("\\end{itemize}\n\n");
    }

    out.push_str("Audit hooks:\n\n");
    out.push_str("\\begin{itemize}\n");
    for hook in &interlude.audit_hooks {
        out.push_str(&format!(
            "\\irrevaudit{{{}}}{{{}}}\n",
            latex_escape_with_breaks(&hook.label),
            latex_escape_with_breaks(&hook.value)
        ));
    }
    out.push_str("\\end{itemize}\n\n");
    out.push_str("\\end{irrevinterlude}\n\n");
    out
}

fn apply_latex_template(
    ast: &BookAst,
    template: &str,
    body: &str,
    appendices_latex: Option<&str>,
) -> String {
    template
        .replace("{{TITLE}}", &latex_escape(&ast.title))
        .replace(
            "{{GENERATED_AT_UTC}}",
            &latex_escape(&Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)),
        )
        .replace("{{BODY}}", body)
        .replace("{{APPENDICES}}", appendices_latex.unwrap_or(""))
}

fn include_input_line(module_root: &str, rel_path: &str) -> String {
    let root = module_root.trim_matches('/');
    let rel = rel_path.replace('\\', "/");
    format!("\\input{{{root}/{rel}}}\n")
}

pub fn render_latex_modular(
    ast: &BookAst,
    template: &str,
    appendices_latex: Option<&str>,
    module_root: &str,
) -> (String, Vec<(String, String)>) {
    let mut modules: Vec<(String, String)> = Vec::new();
    let mut body = String::new();

    let mut intro = String::new();
    for paragraph in &ast.intro_paragraphs {
        intro.push_str(&md_to_latex(paragraph.trim()));
        intro.push('\n');
    }
    if ast.has_cycles {
        intro.push_str("\\chapter*{Cycles}\n");
        intro.push_str("\\addcontentsline{toc}{chapter}{Cycles}\n");
        intro.push_str("The concept graph contains cycles; those concepts are included, but no total order can satisfy all dependency edges.\n\n");
        intro.push_str("\\begin{itemize}\n");
        for item in &ast.cycle_nodes {
            intro.push_str(&format!("\\item {}\n", latex_escape(&item.id)));
        }
        intro.push_str("\\end{itemize}\n\n");
    }
    if !intro.trim().is_empty() {
        let path = "00-intro.tex".to_string();
        body.push_str(&include_input_line(module_root, &path));
        modules.push((path, intro));
    }

    if !ast.orientation_pages.is_empty() {
        let part_path = "01-orientation/00-part.tex".to_string();
        body.push_str(&include_input_line(module_root, &part_path));
        modules.push((part_path, "\\part{Orientation}\n\n".to_string()));
        for (idx, page) in ast.orientation_pages.iter().enumerate() {
            let path = format!(
                "01-orientation/{:02}-{}.tex",
                idx + 1,
                slugify_path_segment(&page.title)
            );
            let mut content = String::new();
            content.push_str(&format!("\\chapter{{{}}}\n\n", latex_escape(&page.title)));
            content.push_str(&md_to_latex(page.markdown_body.trim_end()));
            content.push_str("\n\n");
            body.push_str(&include_input_line(module_root, &path));
            modules.push((path, content));
        }
    }

    for (layer_idx, layer) in ast.layers.iter().enumerate() {
        let layer_dir = format!(
            "02-layers/{:02}-{}",
            layer_idx + 1,
            slugify_path_segment(&layer.label)
        );
        let chapter_path = format!("{layer_dir}/00-chapter.tex");
        let mut chapter = String::new();
        chapter.push_str(&format!("\\chapter{{{}}}\n\n", latex_escape(&layer.label)));
        chapter.push_str(&render_interlude_latex(&layer.interlude));
        body.push_str(&include_input_line(module_root, &chapter_path));
        modules.push((chapter_path, chapter));

        for (concept_idx, concept) in layer.concepts.iter().enumerate() {
            let path = format!(
                "{layer_dir}/{:03}-{}.tex",
                concept_idx + 1,
                slugify_path_segment(&concept.id)
            );
            let content = format!(
                "\\begin{{irrevconcept}}{{{}}}{{{}}}\n{}\n\\end{{irrevconcept}}\n\n",
                sanitize_label(&concept.id),
                latex_escape(&concept.title),
                md_to_latex(concept.markdown_body.trim_end())
            );
            body.push_str(&include_input_line(module_root, &path));
            modules.push((path, content));
        }

        if layer.label == "Primitives" && !ast.invariants.is_empty() {
            let path = format!("{layer_dir}/900-invariants.tex");
            let mut invariants = String::new();
            invariants.push_str("\\chapter{Invariants}\n\n");
            invariants.push_str(invariants_intro_latex());
            invariants.push_str("\n\n");
            for inv in &ast.invariants {
                invariants.push_str(&format!(
                    "\\section{{{}}}\\label{{invariant:{}}}\n{}\n\n",
                    latex_escape(&inv.title),
                    sanitize_label(&inv.id),
                    md_to_latex(inv.markdown_body.trim_end())
                ));
            }
            body.push_str(&include_input_line(module_root, &path));
            modules.push((path, invariants));
        }
    }

    if !ast.unclassified.is_empty() {
        let chapter_path = "04-unclassified/00-chapter.tex".to_string();
        body.push_str(&include_input_line(module_root, &chapter_path));
        modules.push((chapter_path, "\\chapter{Unclassified}\n\n".to_string()));
        for (idx, concept) in ast.unclassified.iter().enumerate() {
            let path = format!(
                "04-unclassified/{:03}-{}.tex",
                idx + 1,
                slugify_path_segment(&concept.id)
            );
            let content = format!(
                "\\begin{{irrevconcept}}{{{}}}{{{}}}\n{}\n\\end{{irrevconcept}}\n\n",
                sanitize_label(&concept.id),
                latex_escape(&concept.title),
                md_to_latex(concept.markdown_body.trim_end())
            );
            body.push_str(&include_input_line(module_root, &path));
            modules.push((path, content));
        }
    }

    if !ast.supplemental_pages.is_empty() {
        let part_path = "05-supplemental/00-part.tex".to_string();
        body.push_str(&include_input_line(module_root, &part_path));
        modules.push((
            part_path,
            "\\part{Projections and Extensions}\n\n".to_string(),
        ));
        for (idx, page) in ast.supplemental_pages.iter().enumerate() {
            let path = format!(
                "05-supplemental/{:02}-{}.tex",
                idx + 1,
                slugify_path_segment(&page.title)
            );
            let mut content = String::new();
            content.push_str(&format!("\\chapter{{{}}}\n\n", latex_escape(&page.title)));
            content.push_str(&md_to_latex(page.markdown_body.trim_end()));
            content.push_str("\n\n");
            body.push_str(&include_input_line(module_root, &path));
            modules.push((path, content));
        }
    }

    (
        apply_latex_template(ast, template, &body, appendices_latex),
        modules,
    )
}

pub fn render_latex(ast: &BookAst, template: &str, appendices_latex: Option<&str>) -> String {
    let mut body = String::new();

    for paragraph in &ast.intro_paragraphs {
        body.push_str(&md_to_latex(paragraph.trim()));
        body.push('\n');
    }

    if ast.has_cycles {
        body.push_str("\\chapter*{Cycles}\n");
        body.push_str("\\addcontentsline{toc}{chapter}{Cycles}\n");
        body.push_str("The concept graph contains cycles; those concepts are included, but no total order can satisfy all dependency edges.\n\n");
        body.push_str("\\begin{itemize}\n");
        for item in &ast.cycle_nodes {
            body.push_str(&format!("\\item {}\n", latex_escape(&item.id)));
        }
        body.push_str("\\end{itemize}\n\n");
    }

    if !ast.orientation_pages.is_empty() {
        body.push_str("\\part{Orientation}\n\n");
        for page in &ast.orientation_pages {
            body.push_str(&format!("\\chapter{{{}}}\n\n", latex_escape(&page.title)));
            body.push_str(&md_to_latex(page.markdown_body.trim_end()));
            body.push_str("\n\n");
        }
    }

    for layer in &ast.layers {
        body.push_str(&format!("\\chapter{{{}}}\n\n", latex_escape(&layer.label)));
        body.push_str(&render_interlude_latex(&layer.interlude));

        for concept in &layer.concepts {
            body.push_str(&format!(
                "\\begin{{irrevconcept}}{{{}}}{{{}}}\n{}\n\\end{{irrevconcept}}\n\n",
                sanitize_label(&concept.id),
                latex_escape(&concept.title),
                md_to_latex(concept.markdown_body.trim_end())
            ));
        }

        if layer.label == "Primitives" && !ast.invariants.is_empty() {
            body.push_str("\\chapter{Invariants}\n\n");
            body.push_str(invariants_intro_latex());
            body.push_str("\n\n");
            for inv in &ast.invariants {
                body.push_str(&format!(
                    "\\section{{{}}}\\label{{invariant:{}}}\n{}\n\n",
                    latex_escape(&inv.title),
                    sanitize_label(&inv.id),
                    md_to_latex(inv.markdown_body.trim_end())
                ));
            }
        }
    }

    if !ast.unclassified.is_empty() {
        body.push_str("\\chapter{Unclassified}\n\n");
        for concept in &ast.unclassified {
            body.push_str(&format!(
                "\\begin{{irrevconcept}}{{{}}}{{{}}}\n{}\n\\end{{irrevconcept}}\n\n",
                sanitize_label(&concept.id),
                latex_escape(&concept.title),
                md_to_latex(concept.markdown_body.trim_end())
            ));
        }
    }

    if !ast.supplemental_pages.is_empty() {
        body.push_str("\\part{Projections and Extensions}\n\n");
        for page in &ast.supplemental_pages {
            body.push_str(&format!("\\chapter{{{}}}\n\n", latex_escape(&page.title)));
            body.push_str(&md_to_latex(page.markdown_body.trim_end()));
            body.push_str("\n\n");
        }
    }

    apply_latex_template(ast, template, &body, appendices_latex)
}

pub fn render_spine_index_appendix(spine_markdown: &str) -> String {
    let mut out = String::new();
    out.push_str("# Spine Index Appendix\n\n");
    out.push_str("Generated from invariant and diagnostic evidence.\n\n");
    out.push_str(spine_markdown.trim_end());
    out.push('\n');
    out
}

pub fn render_layer_invariant_matrix(view: &LayerInvariantMatrixView) -> String {
    let mut out = String::new();
    out.push_str("# Layer x Invariant Matrix (Generated)\n\n");
    out.push_str(view.diagnostic_note.trim());
    out.push_str("\n\n");
    out.push_str(view.marker_legend.trim());
    out.push_str("\n\n");

    let mut header = String::from("| Layer");
    for inv in &view.invariant_ids {
        header.push_str(" | ");
        header.push_str(inv);
    }
    header.push_str(" |\n");
    out.push_str(&header);
    out.push_str("| ---");
    for _ in &view.invariant_ids {
        out.push_str(" | ---");
    }
    out.push_str(" |\n");

    for (layer, cells) in &view.cells {
        let mut row = format!("| {}", layer);
        for inv in &view.invariant_ids {
            let cell = cells.get(inv).cloned().unwrap_or_default().join(", ");
            if cell.is_empty() {
                row.push_str(" | -");
            } else {
                row.push_str(" | ");
                row.push_str(&cell);
            }
        }
        row.push_str(" |\n");
        out.push_str(&row);
    }
    out
}

pub fn render_invariant_gap_audit(view: &InvariantGapAuditView) -> String {
    fn write_section(out: &mut String, title: &str, items: &[String]) {
        out.push_str(title);
        out.push_str("\n\n");
        if items.is_empty() {
            out.push_str("- (none)\n\n");
        } else {
            for id in items {
                out.push_str(&format!("- [[{}]]\n", id));
            }
            out.push('\n');
        }
    }

    let mut out = String::new();
    out.push_str("# Invariant Gap Audit (Generated)\n\n");
    out.push_str(view.unassigned_note.trim());
    out.push_str("\n\n");
    write_section(&mut out, "## Declared-only (all)", &view.declared_all);
    write_section(&mut out, "## Declared-only (true gap)", &view.declared_only);
    write_section(
        &mut out,
        "## Declared infrastructure (dependency-of-core)",
        &view.declared_infrastructure,
    );
    write_section(&mut out, "## Mismatch", &view.mismatch);
    write_section(&mut out, "## Inferred-only", &view.inferred_only);
    out.push_str("## Unassigned\n\n");
    if view.unassigned.is_empty() {
        out.push_str("- (none)\n");
    } else {
        for id in &view.unassigned {
            out.push_str(&format!("- [[{}]]\n", id));
        }
    }
    out
}

pub fn compile_pdf(tex: &str, extra_files: &[(&str, &[u8])]) -> Result<Vec<u8>, String> {
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("clock error: {e}"))?
        .as_millis();
    let scratch = std::env::temp_dir().join(format!("admit-book-{stamp}-{}", std::process::id()));
    fs::create_dir_all(&scratch).map_err(|e| format!("mkdir {}: {e}", scratch.display()))?;
    let tex_path = scratch.join("book.tex");
    let pdf_path = scratch.join("book.pdf");
    fs::write(&tex_path, tex).map_err(|e| format!("write {}: {e}", tex_path.display()))?;
    for (name, bytes) in extra_files {
        let extra_path = scratch.join(name);
        if let Some(parent) = extra_path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir {}: {e}", parent.display()))?;
        }
        fs::write(&extra_path, bytes)
            .map_err(|e| format!("write {}: {e}", extra_path.display()))?;
    }

    let output = Command::new("tectonic")
        .arg("--reruns")
        .arg("2")
        .arg("--outdir")
        .arg(&scratch)
        .arg(&tex_path)
        .output()
        .map_err(|e| format!("failed to run `tectonic` binary: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("tectonic failed: {}", stderr.trim()));
    }
    let pdf = fs::read(&pdf_path).map_err(|e| format!("read {}: {e}", pdf_path.display()))?;
    let _ = fs::remove_dir_all(&scratch);
    Ok(pdf)
}

fn normalize_common_mojibake(input: &str) -> String {
    input
        .replace("âEUR''", "---")
        .replace("âEUR”", "---")
        .replace("âEUR\"", "---")
        .replace("â€”", "---")
        .replace("â€“", "--")
        .replace("â€œ", "``")
        .replace("â€", "''")
        .replace("â€˜", "`")
        .replace("â€™", "'")
        .replace("â€¦", "...")
}

pub(crate) fn latex_escape(input: &str) -> String {
    let normalized = normalize_common_mojibake(input);
    let mut out = String::with_capacity(normalized.len());
    for c in normalized.chars() {
        match c {
            '\\' => out.push_str("\\textbackslash{}"),
            '{' => out.push_str("\\{"),
            '}' => out.push_str("\\}"),
            '$' => out.push_str("\\$"),
            '&' => out.push_str("\\&"),
            '#' => out.push_str("\\#"),
            '^' => out.push_str("\\^{}"),
            '_' => out.push_str("\\_"),
            '%' => out.push_str("\\%"),
            '~' => out.push_str("\\~{}"),
            '\u{2014}' => out.push_str("---"),
            '\u{2013}' => out.push_str("--"),
            '\u{201C}' => out.push_str("``"),
            '\u{201D}' => out.push_str("''"),
            '\u{2018}' => out.push('`'),
            '\u{2019}' => out.push('\''),
            '\u{2192}' => out.push_str("$\\rightarrow$"),
            '\u{20AC}' => out.push_str("EUR"),
            _ => out.push(c),
        }
    }
    out
}

fn latex_escape_concept_list(values: &[String]) -> String {
    if values.is_empty() {
        return "(none)".to_string();
    }
    values
        .iter()
        .map(|v| latex_escape(v))
        .collect::<Vec<_>>()
        .join(", \\allowbreak ")
}

fn latex_escape_with_breaks(input: &str) -> String {
    latex_escape(input)
        .replace(", ", ", \\allowbreak ")
        .replace("/", "/\\allowbreak ")
}

pub(crate) fn sanitize_label(input: &str) -> String {
    input
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | ':' | '.' | '_') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

/// Render appendix content from markdown strings into LaTeX chapters.
pub fn render_latex_appendices(spine_md: &str, matrix_md: &str) -> String {
    let mut out = String::new();
    out.push_str("\\appendix\n");

    out.push_str("\\chapter{Spine Index}\n");
    out.push_str(&md_to_latex(spine_md));
    out.push('\n');

    out.push_str("\\chapter{Layer \\texttimes{} Invariant Matrix}\n");
    out.push_str(&md_to_latex(matrix_md));
    out.push('\n');

    out
}
