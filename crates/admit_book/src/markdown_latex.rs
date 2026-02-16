use crate::{latex_escape, sanitize_label};

// Supports only the markdown features that appear in vault concept bodies.
pub fn md_to_latex(input: &str) -> String {
    let lines: Vec<&str> = input.lines().collect();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;

    // Stack of open list environments: (depth_chars, "itemize"|"enumerate")
    let mut list_stack: Vec<(usize, &'static str)> = Vec::new();

    while i < lines.len() {
        let line = lines[i];

        // Fenced code block
        if line.trim_start().starts_with("```") {
            close_lists(&mut out, &mut list_stack);
            let lang = line.trim_start().trim_start_matches('`').trim();
            let lang_label = if lang.is_empty() { "text" } else { lang };
            out.push_str(&format!(
                "\\irrevcodelabel{{{}}}\n",
                latex_escape(lang_label)
            ));
            out.push_str("\\begin{irrevcode}\n");
            i += 1;
            while i < lines.len() {
                if lines[i].trim_start().starts_with("```") {
                    break;
                }
                // Verbatim: no escaping
                out.push_str(lines[i]);
                out.push('\n');
                i += 1;
            }
            out.push_str("\\end{irrevcode}\n\\medskip\n\n");
            i += 1;
            continue;
        }

        // Obsidian callout: > [!kind]
        if line.starts_with("> [!") {
            close_lists(&mut out, &mut list_stack);
            let kind = line
                .trim_start_matches("> [!")
                .split(']')
                .next()
                .unwrap_or("note")
                .to_lowercase();
            out.push_str(&format!(
                "\\begin{{irrevcallout}}{{{}}}\n",
                latex_escape(&kind)
            ));
            i += 1;
            let mut callout_lines: Vec<String> = Vec::new();
            while i < lines.len() && lines[i].starts_with('>') {
                let content = lines[i]
                    .strip_prefix("> ")
                    .unwrap_or(lines[i].strip_prefix('>').unwrap_or(lines[i]));
                callout_lines.push(content.to_string());
                i += 1;
            }
            let callout_body = callout_lines.join("\n");
            out.push_str(&md_to_latex(&callout_body));
            out.push_str("\\end{irrevcallout}\n\n");
            continue;
        }

        if line.trim().is_empty() {
            close_lists(&mut out, &mut list_stack);
            out.push('\n');
            i += 1;
            continue;
        }

        if is_markdown_table_header(line, lines.get(i + 1).copied()) {
            close_lists(&mut out, &mut list_stack);
            let (table_latex, next_i) = render_markdown_table(&lines, i);
            out.push_str(&table_latex);
            i = next_i;
            continue;
        }

        if line.starts_with('#') {
            close_lists(&mut out, &mut list_stack);
            let level = line.chars().take_while(|&c| c == '#').count();
            let text = line[level..].trim();
            let cmd = if level >= 4 {
                "\\subsection*"
            } else {
                "\\section*"
            };
            out.push_str(&format!("{}{{{}}}\n", cmd, latex_escape(text)));
            i += 1;
            continue;
        }

        if let Some((depth, content)) = parse_unordered_item(line) {
            handle_list_item(&mut out, &mut list_stack, depth, "itemize", content);
            i += 1;
            while i < lines.len() {
                let next = lines[i];
                if next.trim().is_empty() {
                    break;
                }
                if parse_unordered_item(next).is_some() || parse_ordered_item(next).is_some() {
                    break;
                }
                if next.starts_with('#') || next.starts_with("```") || next.starts_with("> [!") {
                    break;
                }
                out.push_str(&format!(" {}", inline_to_latex(next.trim())));
                i += 1;
            }
            out.push('\n');
            continue;
        }

        if let Some((depth, content)) = parse_ordered_item(line) {
            handle_list_item(&mut out, &mut list_stack, depth, "enumerate", content);
            i += 1;
            while i < lines.len() {
                let next = lines[i];
                if next.trim().is_empty() {
                    break;
                }
                if parse_unordered_item(next).is_some() || parse_ordered_item(next).is_some() {
                    break;
                }
                if next.starts_with('#') || next.starts_with("```") || next.starts_with("> [!") {
                    break;
                }
                out.push_str(&format!(" {}", inline_to_latex(next.trim())));
                i += 1;
            }
            out.push('\n');
            continue;
        }

        if line.trim() == "---" || line.trim() == "***" || line.trim() == "___" {
            close_lists(&mut out, &mut list_stack);
            i += 1;
            continue;
        }

        close_lists(&mut out, &mut list_stack);
        out.push_str(&inline_to_latex(line));
        out.push('\n');
        i += 1;
    }

    close_lists(&mut out, &mut list_stack);
    out
}

fn parse_unordered_item(line: &str) -> Option<(usize, &str)> {
    let indent = line.len() - line.trim_start().len();
    let trimmed = line.trim_start();
    if trimmed.starts_with("- ") {
        Some((indent, &trimmed[2..]))
    } else {
        None
    }
}

fn parse_ordered_item(line: &str) -> Option<(usize, &str)> {
    let indent = line.len() - line.trim_start().len();
    let trimmed = line.trim_start();
    let mut chars = trimmed.chars();
    let first = chars.next()?;
    if !first.is_ascii_digit() {
        return None;
    }
    let rest = &trimmed[1..];
    let after_digits = rest.trim_start_matches(|c: char| c.is_ascii_digit());
    if after_digits.starts_with(". ") {
        Some((indent, &after_digits[2..]))
    } else {
        None
    }
}

fn is_markdown_table_header(line: &str, next: Option<&str>) -> bool {
    let Some(header) = parse_table_cells(line) else {
        return false;
    };
    if header.len() < 2 {
        return false;
    }
    let Some(next_line) = next else {
        return false;
    };
    is_markdown_table_separator(next_line)
}

fn parse_table_cells(line: &str) -> Option<Vec<&str>> {
    let trimmed = line.trim();
    if !trimmed.starts_with('|') || !trimmed.ends_with('|') {
        return None;
    }
    let cells: Vec<&str> = trimmed
        .split('|')
        .skip(1)
        .take(trimmed.matches('|').count().saturating_sub(1))
        .map(|c| c.trim())
        .collect();
    if cells.is_empty() {
        return None;
    }
    Some(cells)
}

fn is_markdown_table_separator(line: &str) -> bool {
    let Some(cells) = parse_table_cells(line) else {
        return false;
    };
    cells.into_iter().all(|cell| {
        let t = cell.trim();
        !t.is_empty() && t.chars().all(|ch| matches!(ch, '-' | ':' | ' '))
    })
}

fn render_markdown_table(lines: &[&str], start: usize) -> (String, usize) {
    let header = parse_table_cells(lines[start]).unwrap_or_default();
    let cols = header.len().max(1);

    let first_col = if cols == 1 { 0.95 } else { 0.22 };
    let rest_col = if cols <= 1 {
        0.0
    } else {
        (0.95 - first_col) / (cols as f64 - 1.0)
    };
    let mut colspec = String::new();
    for idx in 0..cols {
        let width = if idx == 0 { first_col } else { rest_col };
        colspec.push_str(&format!("|p{{{width:.3}\\linewidth}}"));
    }
    colspec.push('|');

    let mut out = String::new();
    out.push_str(&format!("\\begin{{longtable}}{{{}}}\n\\hline\n", colspec));
    out.push_str(
        &header
            .iter()
            .map(|c| format!("\\textbf{{{}}}", inline_to_latex(c)))
            .collect::<Vec<_>>()
            .join(" & "),
    );
    out.push_str(" \\\\\n\\hline\n");

    let mut i = start + 2;
    while i < lines.len() {
        let Some(cells) = parse_table_cells(lines[i]) else {
            break;
        };
        let mut normalized: Vec<String> = cells.iter().map(|c| inline_to_latex(c)).collect();
        while normalized.len() < cols {
            normalized.push("-".to_string());
        }
        if normalized.len() > cols {
            normalized.truncate(cols);
        }
        out.push_str(&normalized.join(" & "));
        out.push_str(" \\\\\n\\hline\n");
        i += 1;
    }
    out.push_str("\\end{longtable}\n\n");
    (out, i)
}

fn close_lists(out: &mut String, stack: &mut Vec<(usize, &'static str)>) {
    while let Some((_, env)) = stack.pop() {
        out.push_str(&format!("\\end{{{}}}\n", env));
    }
}

fn handle_list_item(
    out: &mut String,
    stack: &mut Vec<(usize, &'static str)>,
    depth: usize,
    env: &'static str,
    content: &str,
) {
    while let Some(&(d, e)) = stack.last() {
        if d > depth || (d == depth && e != env) {
            out.push_str(&format!("\\end{{{}}}\n", e));
            stack.pop();
        } else {
            break;
        }
    }

    let need_open = match stack.last() {
        None => true,
        Some(&(d, _)) => d < depth,
    };
    if need_open {
        out.push_str(&format!("\\begin{{{}}}\n", env));
        stack.push((depth, env));
    }

    out.push_str(&format!("\\item {}", inline_to_latex(content)));
}

fn inline_to_latex(input: &str) -> String {
    let tokens = tokenize_inline(input);
    render_inline_tokens(&tokens)
}

#[derive(Debug)]
enum InlineToken<'a> {
    Text(&'a str),
    Bold(Vec<InlineToken<'a>>),
    Italic(Vec<InlineToken<'a>>),
    Code(&'a str),
    Link { text: &'a str, href: &'a str },
}

fn tokenize_inline(input: &str) -> Vec<InlineToken<'_>> {
    let mut tokens = Vec::new();
    let mut pos = 0;
    let bytes = input.as_bytes();

    while pos < bytes.len() {
        if bytes[pos] == b'`' {
            let start = pos + 1;
            if let Some(end) = input[start..].find('`') {
                let code = &input[start..start + end];
                tokens.push(InlineToken::Code(code));
                pos = start + end + 1;
                continue;
            }
        }

        if pos + 1 < bytes.len() && bytes[pos] == b'*' && bytes[pos + 1] == b'*' {
            let start = pos + 2;
            if let Some(end) = find_closing_double_star(input, start) {
                let inner = &input[start..end];
                let inner_tokens = tokenize_inline(inner);
                tokens.push(InlineToken::Bold(inner_tokens));
                pos = end + 2;
                continue;
            }
        }

        if bytes[pos] == b'*' && (pos + 1 >= bytes.len() || bytes[pos + 1] != b'*') {
            let start = pos + 1;
            if let Some(end) = input[start..].find(|c: char| c == '*') {
                let inner = &input[start..start + end];
                let inner_tokens = tokenize_inline(inner);
                tokens.push(InlineToken::Italic(inner_tokens));
                pos = start + end + 1;
                continue;
            }
        }

        if bytes[pos] == b'[' {
            if let Some((text, href, consumed)) = parse_md_link(input, pos) {
                tokens.push(InlineToken::Link { text, href });
                pos += consumed;
                continue;
            }
        }

        let start = pos;
        pos += 1;
        while pos < bytes.len() && !matches!(bytes[pos], b'`' | b'*' | b'[') {
            pos += 1;
        }
        tokens.push(InlineToken::Text(&input[start..pos]));
    }

    tokens
}

fn find_closing_double_star(input: &str, start: usize) -> Option<usize> {
    let mut i = start;
    let bytes = input.as_bytes();
    while i + 1 < bytes.len() {
        if bytes[i] == b'`' {
            if let Some(end) = input[i + 1..].find('`') {
                i = i + 1 + end + 1;
                continue;
            }
        }
        if bytes[i] == b'*' && bytes[i + 1] == b'*' {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn parse_md_link(input: &str, pos: usize) -> Option<(&str, &str, usize)> {
    let rest = &input[pos..];
    let bracket_end = rest.find(']')?;
    let text = &rest[1..bracket_end];
    let after_bracket = &rest[bracket_end + 1..];
    if !after_bracket.starts_with('(') {
        return None;
    }
    let paren_end = after_bracket.find(')')?;
    let href = &after_bracket[1..paren_end];
    let consumed = bracket_end + 1 + paren_end + 1;
    Some((text, href, consumed))
}

fn render_inline_tokens(tokens: &[InlineToken<'_>]) -> String {
    let mut out = String::new();
    for token in tokens {
        match token {
            InlineToken::Text(t) => out.push_str(&latex_escape(t)),
            InlineToken::Code(c) => {
                out.push_str("\\texttt{");
                out.push_str(&latex_escape(c));
                out.push('}');
            }
            InlineToken::Bold(inner) => {
                out.push_str("\\textbf{");
                out.push_str(&render_inline_tokens(inner));
                out.push('}');
            }
            InlineToken::Italic(inner) => {
                out.push_str("\\textit{");
                out.push_str(&render_inline_tokens(inner));
                out.push('}');
            }
            InlineToken::Link { text, href } => {
                if let Some(anchor) = href.strip_prefix('#') {
                    let label = if let Some(id) = anchor.strip_prefix("concept-") {
                        format!("concept:{}", sanitize_label(id))
                    } else {
                        out.push_str(&latex_escape(text));
                        continue;
                    };
                    out.push_str(&format!("\\hyperref[{}]{{{}}}", label, latex_escape(text)));
                } else {
                    out.push_str(&latex_escape(text));
                }
            }
        }
    }
    out
}
