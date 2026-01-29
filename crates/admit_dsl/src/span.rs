use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Span {
    pub file: String,
    pub start: usize,
    pub end: usize,
    pub line: u32,
    pub col: u32,
}

#[derive(Debug)]
pub(crate) struct LineIndex {
    starts: Vec<usize>,
}

impl LineIndex {
    pub(crate) fn new(source: &str) -> Self {
        let mut starts = vec![0];
        for (idx, ch) in source.char_indices() {
            if ch == '\n' {
                starts.push(idx + 1);
            }
        }
        Self { starts }
    }

    pub(crate) fn line_col(&self, offset: usize) -> (u32, u32) {
        let mut lo = 0usize;
        let mut hi = self.starts.len();
        while lo + 1 < hi {
            let mid = (lo + hi) / 2;
            if self.starts[mid] <= offset {
                lo = mid;
            } else {
                hi = mid;
            }
        }
        let line = lo as u32 + 1;
        let col = (offset - self.starts[lo]) as u32 + 1;
        (line, col)
    }
}

pub(crate) fn make_span(file: &str, span: std::ops::Range<usize>, line_index: &LineIndex) -> Span {
    let (line, col) = line_index.line_col(span.start);
    Span {
        file: file.to_string(),
        start: span.start,
        end: span.end,
        line,
        col,
    }
}
