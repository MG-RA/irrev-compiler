use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Debug, Clone)]
pub struct OllamaEmbedConfig {
    pub endpoint: String,
    pub model: String,
    pub timeout_ms: u64,
    pub batch_size: usize,
    pub max_chars: usize,
}

impl Default for OllamaEmbedConfig {
    fn default() -> Self {
        Self {
            endpoint: "http://127.0.0.1:11434".to_string(),
            model: "qwen3-embedding:0.6b".to_string(),
            timeout_ms: 60_000,
            batch_size: 16,
            max_chars: 8_000,
        }
    }
}

#[derive(Debug, Clone)]
pub struct OllamaEmbedder {
    cfg: OllamaEmbedConfig,
}

impl OllamaEmbedder {
    pub fn new(cfg: OllamaEmbedConfig) -> Self {
        Self { cfg }
    }

    pub fn cfg(&self) -> &OllamaEmbedConfig {
        &self.cfg
    }

    pub fn embed_texts(&self, inputs: &[String]) -> Result<Vec<Vec<f32>>, String> {
        if inputs.is_empty() {
            return Ok(Vec::new());
        }

        // Prefer the newer /api/embed endpoint if available (supports batching).
        if inputs.len() > 1 {
            if let Ok(v) = self.embed_via_api_embed(inputs) {
                return Ok(v);
            }
        }

        // Fall back to the older /api/embeddings endpoint (single prompt).
        let mut out = Vec::with_capacity(inputs.len());
        for text in inputs {
            out.push(self.embed_via_api_embeddings(text)?);
        }
        Ok(out)
    }

    fn clamp_input(&self, s: &str) -> String {
        if s.len() <= self.cfg.max_chars {
            return s.to_string();
        }
        s.chars().take(self.cfg.max_chars).collect()
    }

    fn embed_via_api_embed(&self, inputs: &[String]) -> Result<Vec<Vec<f32>>, String> {
        let clamped: Vec<String> = inputs.iter().map(|s| self.clamp_input(s)).collect();
        let payload = serde_json::json!({
            "model": self.cfg.model,
            "input": clamped,
        });
        let body = serde_json::to_vec(&payload).map_err(|err| format!("json encode: {}", err))?;
        let json = http_post_json(&self.cfg.endpoint, "/api/embed", &body, self.cfg.timeout_ms)?;

        // Accept multiple response shapes:
        // - { embeddings: [[...], ...] }
        // - { data: [ { embedding: [...] }, ... ] }
        if let Some(arr) = json.get("embeddings").and_then(|v| v.as_array()) {
            return parse_embedding_matrix(arr);
        }
        if let Some(arr) = json.get("data").and_then(|v| v.as_array()) {
            let mut out = Vec::with_capacity(arr.len());
            for item in arr {
                let emb = item
                    .get("embedding")
                    .and_then(|v| v.as_array())
                    .ok_or_else(|| "ollama /api/embed: missing data[i].embedding".to_string())?;
                out.push(parse_embedding_vec(emb)?);
            }
            return Ok(out);
        }

        Err(format!(
            "ollama /api/embed: unrecognized response shape: {}",
            json
        ))
    }

    fn embed_via_api_embeddings(&self, input: &str) -> Result<Vec<f32>, String> {
        let payload = serde_json::json!({
            "model": self.cfg.model,
            "prompt": self.clamp_input(input),
        });
        let body = serde_json::to_vec(&payload).map_err(|err| format!("json encode: {}", err))?;
        let json = http_post_json(
            &self.cfg.endpoint,
            "/api/embeddings",
            &body,
            self.cfg.timeout_ms,
        )?;
        let arr = json
            .get("embedding")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "ollama /api/embeddings: missing embedding".to_string())?;
        parse_embedding_vec(arr)
    }
}

fn parse_embedding_matrix(arr: &[serde_json::Value]) -> Result<Vec<Vec<f32>>, String> {
    let mut out = Vec::with_capacity(arr.len());
    for row in arr {
        let row = row
            .as_array()
            .ok_or_else(|| "ollama embeddings: expected array of arrays".to_string())?;
        out.push(parse_embedding_vec(row)?);
    }
    Ok(out)
}

fn parse_embedding_vec(arr: &[serde_json::Value]) -> Result<Vec<f32>, String> {
    let mut out = Vec::with_capacity(arr.len());
    for v in arr {
        let f = v
            .as_f64()
            .ok_or_else(|| "ollama embedding: expected float".to_string())?;
        out.push(f as f32);
    }
    Ok(out)
}

fn http_post_json(
    endpoint: &str,
    path: &str,
    body: &[u8],
    timeout_ms: u64,
) -> Result<serde_json::Value, String> {
    let url = endpoint.trim_end_matches('/');
    let (host, port) = parse_http_host_port(url)?;

    let mut stream = TcpStream::connect((host.as_str(), port))
        .map_err(|err| format!("connect {}:{}: {}", host, port, err))?;
    stream
        .set_read_timeout(Some(Duration::from_millis(timeout_ms)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_millis(timeout_ms)))
        .ok();

    let req = format!(
        "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        path,
        host,
        port,
        body.len()
    );
    stream
        .write_all(req.as_bytes())
        .map_err(|err| format!("write request: {}", err))?;
    stream
        .write_all(body)
        .map_err(|err| format!("write body: {}", err))?;

    let (status, body_bytes) = read_http_response(stream)?;
    let body_text = String::from_utf8_lossy(&body_bytes);
    if status < 200 || status >= 300 {
        return Err(format!("http {}: {}", status, body_text));
    }
    serde_json::from_str(&body_text).map_err(|err| format!("json decode: {}", err))
}

fn parse_http_host_port(endpoint: &str) -> Result<(String, u16), String> {
    let e = endpoint.trim();
    let e = e.strip_prefix("http://").ok_or_else(|| {
        "ollama endpoint must start with http:// (https not supported in v0)".to_string()
    })?;
    let e = e.trim_end_matches('/');
    if let Some((h, p)) = e.split_once(':') {
        let port: u16 = p.parse().map_err(|_| "invalid port".to_string())?;
        return Ok((h.to_string(), port));
    }
    Ok((e.to_string(), 80))
}

fn read_http_response(stream: TcpStream) -> Result<(u16, Vec<u8>), String> {
    let mut reader = BufReader::new(stream);
    let mut status_line = String::new();
    reader
        .read_line(&mut status_line)
        .map_err(|err| format!("read status line: {}", err))?;
    let status = parse_status_code(status_line.trim_end())?;

    let mut headers: BTreeMap<String, String> = BTreeMap::new();
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|err| format!("read header line: {}", err))?;
        if line == "\r\n" || line.is_empty() {
            break;
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }

    let mut body = Vec::new();
    if let Some(te) = headers.get("transfer-encoding") {
        if te.to_ascii_lowercase().contains("chunked") {
            body = read_chunked_body(&mut reader)?;
            return Ok((status, body));
        }
    }

    if let Some(cl) = headers.get("content-length") {
        let len: usize = cl
            .parse()
            .map_err(|_| "invalid content-length".to_string())?;
        body.resize(len, 0);
        reader
            .read_exact(&mut body)
            .map_err(|err| format!("read body: {}", err))?;
        return Ok((status, body));
    }

    reader
        .read_to_end(&mut body)
        .map_err(|err| format!("read body: {}", err))?;
    Ok((status, body))
}

fn read_chunked_body(reader: &mut BufReader<TcpStream>) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    loop {
        let mut line = String::new();
        reader
            .read_line(&mut line)
            .map_err(|err| format!("read chunk size: {}", err))?;
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let size_hex = line.split(';').next().unwrap_or(line);
        let size = usize::from_str_radix(size_hex, 16)
            .map_err(|_| format!("invalid chunk size: {}", line))?;
        if size == 0 {
            // Consume trailing headers if present.
            loop {
                let mut trailer = String::new();
                reader
                    .read_line(&mut trailer)
                    .map_err(|err| format!("read chunk trailer: {}", err))?;
                if trailer == "\r\n" || trailer.is_empty() {
                    break;
                }
            }
            break;
        }
        let mut buf = vec![0u8; size];
        reader
            .read_exact(&mut buf)
            .map_err(|err| format!("read chunk: {}", err))?;
        out.extend_from_slice(&buf);
        // Consume CRLF after chunk.
        let mut crlf = [0u8; 2];
        reader
            .read_exact(&mut crlf)
            .map_err(|err| format!("read chunk crlf: {}", err))?;
    }
    Ok(out)
}

fn parse_status_code(head: &str) -> Result<u16, String> {
    let mut parts = head.split_whitespace();
    let _http = parts.next().ok_or_else(|| "bad status line".to_string())?;
    let code = parts.next().ok_or_else(|| "bad status line".to_string())?;
    code.parse::<u16>()
        .map_err(|_| "bad status code".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_model_is_qwen_0_6b() {
        let cfg = OllamaEmbedConfig::default();
        assert_eq!(cfg.model, "qwen3-embedding:0.6b");
    }

    #[test]
    fn clamp_input_truncates() {
        let mut cfg = OllamaEmbedConfig::default();
        cfg.max_chars = 3;
        let e = OllamaEmbedder::new(cfg);
        assert_eq!(e.clamp_input("abcdef"), "abc");
        assert_eq!(e.clamp_input("ab"), "ab");
    }
}
