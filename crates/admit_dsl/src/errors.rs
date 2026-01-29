use chumsky::error::Simple;
use std::fmt::Display;

use crate::span::{LineIndex, Span};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ParseError {
    pub message: String,
    pub span: Span,
}

pub(crate) fn to_parse_error<T: Display + std::hash::Hash + std::cmp::Eq>(
    err: Simple<T>,
    file: &str,
    line_index: &LineIndex,
) -> ParseError {
    let span = err.span();
    let (line, col) = line_index.line_col(span.start);
    ParseError {
        message: err.to_string(),
        span: Span {
            file: file.to_string(),
            start: span.start,
            end: span.end,
            line,
            col,
        },
    }
}
