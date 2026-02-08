use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathSegment {
    Key(String),
    Index(u64),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectPathErrorCode {
    ParseError,
    TypeMismatch,
    KeyNotFound,
    IndexOutOfRange,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SelectPathErrorOutput {
    pub code: SelectPathErrorCode,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub at_segment_index: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SelectPathOutput {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<SelectPathErrorOutput>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SelectPathInput {
    pub value: Value,
    pub path: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SelectPathWitness {
    pub schema_id: String,
    pub schema_version: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", alias = "court_version")]
    pub engine_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
    pub input: SelectPathInput,
    pub output: SelectPathOutput,
}

impl SelectPathWitness {
    pub fn new(input: SelectPathInput, output: SelectPathOutput) -> Self {
        SelectPathWitness {
            schema_id: "select-path-witness/0".to_string(),
            schema_version: 0,
            created_at: None,
            engine_version: None,
            input_id: None,
            config_hash: None,
            input,
            output,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectPathError {
    pub code: SelectPathErrorCode,
    pub at_segment_index: Option<u64>,
}

impl SelectPathError {
    fn parse_error() -> Self {
        SelectPathError {
            code: SelectPathErrorCode::ParseError,
            at_segment_index: None,
        }
    }

    fn eval_error(code: SelectPathErrorCode, index: usize) -> Self {
        SelectPathError {
            code,
            at_segment_index: Some(index as u64),
        }
    }

    fn to_output(self) -> SelectPathOutput {
        SelectPathOutput {
            ok: false,
            value: None,
            error: Some(SelectPathErrorOutput {
                code: self.code,
                at_segment_index: self.at_segment_index,
                message: None,
            }),
        }
    }
}

impl SelectPathOutput {
    pub fn ok(value: Value) -> Self {
        SelectPathOutput {
            ok: true,
            value: Some(value),
            error: None,
        }
    }
}

pub fn select_path(value: &Value, path: &str) -> SelectPathOutput {
    let segments = match parse_path(path) {
        Ok(segments) => segments,
        Err(err) => return err.to_output(),
    };

    let mut current = value;
    for (index, segment) in segments.iter().enumerate() {
        match segment {
            PathSegment::Key(key) => {
                let obj = match current.as_object() {
                    Some(obj) => obj,
                    None => {
                        return SelectPathError::eval_error(
                            SelectPathErrorCode::TypeMismatch,
                            index,
                        )
                        .to_output();
                    }
                };

                match obj.get(key) {
                    Some(next) => current = next,
                    None => {
                        return SelectPathError::eval_error(
                            SelectPathErrorCode::KeyNotFound,
                            index,
                        )
                        .to_output();
                    }
                }
            }
            PathSegment::Index(idx) => {
                let arr = match current.as_array() {
                    Some(arr) => arr,
                    None => {
                        return SelectPathError::eval_error(
                            SelectPathErrorCode::TypeMismatch,
                            index,
                        )
                        .to_output();
                    }
                };

                let idx = *idx as usize;
                if idx >= arr.len() {
                    return SelectPathError::eval_error(
                        SelectPathErrorCode::IndexOutOfRange,
                        index,
                    )
                    .to_output();
                }
                current = &arr[idx];
            }
        }
    }

    SelectPathOutput::ok(current.clone())
}

pub fn parse_path(path: &str) -> Result<Vec<PathSegment>, SelectPathError> {
    if path.is_empty() {
        return Ok(Vec::new());
    }

    let bytes = path.as_bytes();
    let mut i = 0usize;
    let mut segments = Vec::new();

    while i < bytes.len() {
        match bytes[i] {
            b'.' => {
                i += 1;
                let start = i;
                while i < bytes.len() && is_ident_char(bytes[i]) {
                    i += 1;
                }
                if start == i {
                    return Err(SelectPathError::parse_error());
                }
                if !is_ident_start(bytes[start]) {
                    return Err(SelectPathError::parse_error());
                }
                let key = &path[start..i];
                segments.push(PathSegment::Key(key.to_string()));
            }
            b'[' => {
                i += 1;
                if i >= bytes.len() {
                    return Err(SelectPathError::parse_error());
                }
                if bytes[i] == b'"' {
                    i += 1;
                    let (key, next) = parse_json_string(path, i)?;
                    i = next;
                    if i >= bytes.len() || bytes[i] != b']' {
                        return Err(SelectPathError::parse_error());
                    }
                    i += 1;
                    if is_identifier_safe(&key) {
                        return Err(SelectPathError::parse_error());
                    }
                    segments.push(PathSegment::Key(key));
                } else if bytes[i].is_ascii_digit() {
                    let start = i;
                    while i < bytes.len() && bytes[i].is_ascii_digit() {
                        i += 1;
                    }
                    if i >= bytes.len() || bytes[i] != b']' {
                        return Err(SelectPathError::parse_error());
                    }
                    let digits = &path[start..i];
                    if digits.len() > 1 && digits.starts_with('0') {
                        return Err(SelectPathError::parse_error());
                    }
                    let index: u64 = digits.parse().map_err(|_| SelectPathError::parse_error())?;
                    i += 1;
                    segments.push(PathSegment::Index(index));
                } else {
                    return Err(SelectPathError::parse_error());
                }
            }
            _ => return Err(SelectPathError::parse_error()),
        }
    }

    Ok(segments)
}

fn parse_json_string(input: &str, start: usize) -> Result<(String, usize), SelectPathError> {
    let mut out = String::new();
    let mut i = start;

    while i < input.len() {
        let ch = input[i..]
            .chars()
            .next()
            .ok_or_else(SelectPathError::parse_error)?;
        let len = ch.len_utf8();
        match ch {
            '"' => {
                i += len;
                return Ok((out, i));
            }
            '\\' => {
                i += len;
                if i >= input.len() {
                    return Err(SelectPathError::parse_error());
                }
                let esc = input[i..]
                    .chars()
                    .next()
                    .ok_or_else(SelectPathError::parse_error)?;
                let esc_len = esc.len_utf8();
                match esc {
                    '"' => {
                        out.push('"');
                        i += esc_len;
                    }
                    '\\' => {
                        out.push('\\');
                        i += esc_len;
                    }
                    '/' => {
                        return Err(SelectPathError::parse_error());
                    }
                    'b' => {
                        out.push('\u{0008}');
                        i += esc_len;
                    }
                    'f' => {
                        out.push('\u{000C}');
                        i += esc_len;
                    }
                    'n' => {
                        out.push('\n');
                        i += esc_len;
                    }
                    'r' => {
                        out.push('\r');
                        i += esc_len;
                    }
                    't' => {
                        out.push('\t');
                        i += esc_len;
                    }
                    'u' => {
                        let hex_start = i + esc_len;
                        let hex_end = hex_start + 4;
                        if hex_end > input.len() {
                            return Err(SelectPathError::parse_error());
                        }
                        let hex = &input[hex_start..hex_end];
                        if !hex.as_bytes().iter().all(|b| is_upper_hex_digit(*b)) {
                            return Err(SelectPathError::parse_error());
                        }
                        let value = u16::from_str_radix(hex, 16)
                            .map_err(|_| SelectPathError::parse_error())?;
                        if value > 0x1F {
                            return Err(SelectPathError::parse_error());
                        }
                        if matches!(value, 0x08 | 0x09 | 0x0A | 0x0C | 0x0D) {
                            return Err(SelectPathError::parse_error());
                        }
                        if let Some(ch) = char::from_u32(value as u32) {
                            out.push(ch);
                        } else {
                            return Err(SelectPathError::parse_error());
                        }
                        i = hex_end;
                    }
                    _ => return Err(SelectPathError::parse_error()),
                }
            }
            c if c <= '\u{1F}' => return Err(SelectPathError::parse_error()),
            _ => {
                out.push(ch);
                i += len;
            }
        }
    }

    Err(SelectPathError::parse_error())
}

fn is_ident_char(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'
}

fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_lowercase() || byte == b'_'
}

fn is_identifier_safe(key: &str) -> bool {
    let mut bytes = key.as_bytes().iter().copied();
    let first = match bytes.next() {
        Some(b) => b,
        None => return false,
    };
    if !is_ident_start(first) {
        return false;
    }
    bytes.all(is_ident_char)
}

fn is_upper_hex_digit(byte: u8) -> bool {
    byte.is_ascii_digit() || (b'A'..=b'F').contains(&byte)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parse_accepts_canonical_paths() {
        let segments = parse_path(r#".foo[0]["bar-baz"]"#).expect("parse");
        assert_eq!(
            segments,
            vec![
                PathSegment::Key("foo".to_string()),
                PathSegment::Index(0),
                PathSegment::Key("bar-baz".to_string())
            ]
        );

        let segments = parse_path(r#"["notIdent"][0]"#).expect("parse");
        assert_eq!(
            segments,
            vec![
                PathSegment::Key("notIdent".to_string()),
                PathSegment::Index(0)
            ]
        );

        let segments = parse_path("").expect("parse");
        assert!(segments.is_empty());
    }

    #[test]
    fn parse_rejects_non_canonical_paths() {
        let cases = [
            r#"["foo"]"#,
            r#".foo["bar"]"#,
            r#".foo[01]"#,
            r#".foo[ 0 ]"#,
            r#".foo."#,
            r#".foo[]"#,
            r#".foo["unterminated]"#,
            r#"['bar']"#,
            r#"["a\/b"]"#,
        ];

        for case in cases {
            assert!(
                parse_path(case).is_err(),
                "expected parse_error for {}",
                case
            );
        }
    }

    #[test]
    fn evaluation_errors_include_segment_index() {
        let value = json!({ "foo": "x" });
        let output = select_path(&value, ".foo[0]");
        let err = output.error.expect("error");
        assert_eq!(err.code, SelectPathErrorCode::TypeMismatch);
        assert_eq!(err.at_segment_index, Some(1));

        let value = json!({ "foo": [1] });
        let output = select_path(&value, ".foo[2]");
        let err = output.error.expect("error");
        assert_eq!(err.code, SelectPathErrorCode::IndexOutOfRange);
        assert_eq!(err.at_segment_index, Some(1));

        let value = json!({ "foo": {} });
        let output = select_path(&value, ".foo.bar");
        let err = output.error.expect("error");
        assert_eq!(err.code, SelectPathErrorCode::KeyNotFound);
        assert_eq!(err.at_segment_index, Some(1));
    }
}
