//! Just enough HTTP/1.1 for the console: strict parsing of small requests (no chunked
//! bodies, no proxies, no line folding, bounded sizes) and plain responses with a length.
//! What it doesn't accept it refuses, and the connection is closed.

use std::io::{BufRead, Read, Write};

/// The request line, and all header lines together.
const MAX_LINE: u64 = 8 * 1024;
const MAX_HEADERS_BYTES: usize = 16 * 1024;
const MAX_HEADERS: usize = 64;
/// Only the login sends a body: a password and a code.
pub const MAX_BODY: usize = 8 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    pub method: String,
    /// The path, without the query.
    pub path: String,
    pub query: String,
    /// Names in lower case.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// The client may send another request on this connection.
    pub keep_alive: bool,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }

    /// The value of `name` in the query string (no percent-decoding: the console's own
    /// parameters are plain).
    pub fn param(&self, name: &str) -> Option<&str> {
        self.query.split('&').find_map(|kv| kv.split_once('=').filter(|(k, _)| *k == name).map(|(_, v)| v))
    }
}

#[derive(Debug)]
pub enum ReadError {
    /// The client closed the connection (or stayed silent) before a new request.
    Closed,
    /// A request this server refuses: the status to answer before closing.
    Bad(u16, &'static str),
    Io(std::io::Error),
}

impl From<std::io::Error> for ReadError {
    fn from(e: std::io::Error) -> Self {
        ReadError::Io(e)
    }
}

fn line(r: &mut impl BufRead, budget: &mut usize) -> Result<Option<String>, ReadError> {
    let mut buf = Vec::new();
    let n = r.take(MAX_LINE.min(*budget as u64 + 1)).read_until(b'\n', &mut buf)?;
    if n == 0 {
        return Ok(None);
    }
    if buf.last() != Some(&b'\n') {
        return Err(if n as u64 >= MAX_LINE || n > *budget { ReadError::Bad(431, "request header too large") } else { ReadError::Closed });
    }
    *budget = budget.saturating_sub(n);
    buf.pop();
    if buf.last() == Some(&b'\r') {
        buf.pop();
    }
    String::from_utf8(buf).map(Some).map_err(|_| ReadError::Bad(400, "not UTF-8"))
}

fn token(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Reads one request.
pub fn read_request(r: &mut impl BufRead) -> Result<Request, ReadError> {
    let mut budget = MAX_HEADERS_BYTES;
    // a blank line or two before a request is allowed (RFC 9112, 2.2)
    let mut first = None;
    for _ in 0..3 {
        match line(r, &mut budget)? {
            None => return Err(ReadError::Closed),
            Some(l) if l.is_empty() => continue,
            Some(l) => {
                first = Some(l);
                break;
            }
        }
    }
    let first = first.ok_or(ReadError::Bad(400, "no request line"))?;
    let mut parts = first.split(' ');
    let (Some(method), Some(target), Some(version), None) = (parts.next(), parts.next(), parts.next(), parts.next()) else {
        return Err(ReadError::Bad(400, "bad request line"));
    };
    if !method.bytes().all(|b| b.is_ascii_uppercase()) || method.is_empty() {
        return Err(ReadError::Bad(400, "bad method"));
    }
    let http10 = match version {
        "HTTP/1.1" => false,
        "HTTP/1.0" => true,
        _ => return Err(ReadError::Bad(505, "HTTP/1.1 only")),
    };
    if !target.starts_with('/') || target.len() > 2048 || !target.bytes().all(|b| (0x21..0x7f).contains(&b)) {
        return Err(ReadError::Bad(400, "bad request target"));
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        let l = line(r, &mut budget)?.ok_or(ReadError::Closed)?;
        if l.is_empty() {
            break;
        }
        if l.starts_with([' ', '\t']) {
            return Err(ReadError::Bad(400, "folded header line"));
        }
        let (name, value) = l.split_once(':').ok_or(ReadError::Bad(400, "header line without a colon"))?;
        if !token(name) {
            return Err(ReadError::Bad(400, "bad header name"));
        }
        let value = value.trim_matches([' ', '\t']);
        if value.chars().any(|c| c.is_control() && c != '\t') {
            return Err(ReadError::Bad(400, "control character in a header"));
        }
        if headers.len() >= MAX_HEADERS {
            return Err(ReadError::Bad(431, "too many headers"));
        }
        headers.push((name.to_ascii_lowercase(), value.to_string()));
    }
    let count = |n: &str| headers.iter().filter(|(h, _)| h == n).count();
    if count("transfer-encoding") > 0 {
        return Err(ReadError::Bad(501, "no Transfer-Encoding in requests"));
    }
    let hosts = count("host");
    if count("content-length") > 1 || hosts > 1 || (hosts == 0 && !http10) {
        return Err(ReadError::Bad(400, "Host and Content-Length once each"));
    }
    let length = match headers.iter().find(|(h, _)| h == "content-length") {
        None => 0,
        Some((_, v)) => {
            if v.is_empty() || !v.bytes().all(|b| b.is_ascii_digit()) {
                return Err(ReadError::Bad(400, "bad Content-Length"));
            }
            v.parse::<usize>().ok().filter(|n| *n <= MAX_BODY).ok_or(ReadError::Bad(413, "request body too large"))?
        }
    };
    let mut body = vec![0u8; length];
    r.read_exact(&mut body)?;
    let connection = headers.iter().find(|(h, _)| h == "connection").map(|(_, v)| v.to_ascii_lowercase()).unwrap_or_default();
    let keep_alive = !http10 && !connection.split(',').any(|t| t.trim() == "close");
    Ok(Request { method: method.into(), path: path.into(), query: query.into(), headers, body, keep_alive })
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(&'static str, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, content_type: &str, body: Vec<u8>) -> Self {
        Response { status, headers: vec![("Content-Type", content_type.into())], body }
    }

    pub fn json(status: u16, v: &serde_json::Value) -> Self {
        Self::new(status, "application/json", serde_json::to_vec(v).unwrap_or_default())
    }

    pub fn text(status: u16, text: &str) -> Self {
        Self::new(status, "text/plain; charset=utf-8", text.as_bytes().to_vec())
    }

    pub fn error(status: u16, msg: &str) -> Self {
        Self::json(status, &serde_json::json!({ "error": msg }))
    }

    pub fn with(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }
}

pub fn reason(status: u16) -> &'static str {
    match status {
        200 => "OK",
        204 => "No Content",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        413 => "Content Too Large",
        415 => "Unsupported Media Type",
        429 => "Too Many Requests",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        501 => "Not Implemented",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "",
    }
}

/// Writes `resp`; the body compressed when the client takes gzip and it is worth it.
pub fn write_response(w: &mut impl Write, mut resp: Response, keep_alive: bool, head: bool, gzip: bool) -> std::io::Result<()> {
    if gzip && resp.body.len() > 1024 {
        let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
        gz.write_all(&resp.body)?;
        resp.body = gz.finish()?;
        resp.headers.push(("Content-Encoding", "gzip".into()));
        resp.headers.push(("Vary", "Accept-Encoding".into()));
    }
    let mut head_text = format!("HTTP/1.1 {} {}\r\n", resp.status, reason(resp.status));
    for (n, v) in &resp.headers {
        head_text.push_str(&format!("{n}: {v}\r\n"));
    }
    head_text.push_str(&format!("Content-Length: {}\r\n", resp.body.len()));
    head_text.push_str(if keep_alive { "Connection: keep-alive\r\n\r\n" } else { "Connection: close\r\n\r\n" });
    let mut out = head_text.into_bytes();
    if !head {
        out.extend_from_slice(&resp.body);
    }
    w.write_all(&out)?;
    w.flush()
}

/// Whether the client accepts gzip.
pub fn takes_gzip(req: &Request) -> bool {
    req.header("accept-encoding").is_some_and(|v| v.split(',').any(|e| e.split(';').next().is_some_and(|e| e.trim() == "gzip")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(raw: &str) -> Result<Request, ReadError> {
        read_request(&mut std::io::BufReader::new(raw.as_bytes()))
    }

    fn bad(raw: &str) -> u16 {
        match parse(raw) {
            Err(ReadError::Bad(s, _)) => s,
            other => panic!("expected a refusal for {raw:?}, got {other:?}"),
        }
    }

    #[test]
    fn requests() {
        let r = parse("GET /api/v1/cluster?x=1&y=2 HTTP/1.1\r\nHost: a\r\nCookie: k=v\r\n\r\n").unwrap();
        assert_eq!((r.method.as_str(), r.path.as_str(), r.param("y")), ("GET", "/api/v1/cluster", Some("2")));
        assert_eq!(r.header("cookie"), Some("k=v"));
        assert!(r.keep_alive);
        let r = parse("POST /api/login HTTP/1.1\nHost: a\nContent-Length: 5\nConnection: close\n\nhello").unwrap();
        assert_eq!(r.body, b"hello");
        assert!(!r.keep_alive);
        assert!(!parse("GET / HTTP/1.0\r\n\r\n").unwrap().keep_alive);
        assert!(matches!(parse(""), Err(ReadError::Closed)));
        assert!(matches!(parse("GET / HTTP/1.1\r\nHost: a\r\n"), Err(ReadError::Closed)), "cut short");
    }

    #[test]
    fn refusals() {
        assert_eq!(bad("GET http://example.org/ HTTP/1.1\r\nHost: a\r\n\r\n"), 400);
        assert_eq!(bad("GET / HTTP/2\r\n\r\n"), 505);
        assert_eq!(bad("get / HTTP/1.1\r\nHost: a\r\n\r\n"), 400);
        assert_eq!(bad("GET /a b HTTP/1.1\r\nHost: a\r\n\r\n"), 400);
        assert_eq!(bad("GET / HTTP/1.1\r\n\r\n"), 400, "no Host");
        assert_eq!(bad("GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n"), 400);
        assert_eq!(bad("POST / HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n"), 501);
        assert_eq!(bad("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nab"), 400);
        assert_eq!(bad("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: +5\r\n\r\nhello"), 400);
        assert_eq!(bad("POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 999999\r\n\r\n"), 413);
        assert_eq!(bad("GET / HTTP/1.1\r\nHost: a\r\n folded\r\n\r\n"), 400);
        assert_eq!(bad("GET / HTTP/1.1\r\nHost: a\r\nBad Name: x\r\n\r\n"), 400);
        assert_eq!(bad("GET / HTTP/1.1\r\nHost: a\r\nX: a\u{1}b\r\n\r\n"), 400);
        assert_eq!(bad(&format!("GET /{} HTTP/1.1\r\n\r\n", "a".repeat(9000))), 431);
        let many: String = (0..70).map(|i| format!("X-{i}: y\r\n")).collect();
        assert_eq!(bad(&format!("GET / HTTP/1.1\r\nHost: a\r\n{many}\r\n")), 431);
        let big: String = (0..20).map(|i| format!("X-{i}: {}\r\n", "y".repeat(1000))).collect();
        assert_eq!(bad(&format!("GET / HTTP/1.1\r\nHost: a\r\n{big}\r\n")), 431);
    }

    #[test]
    fn responses() {
        let mut out = Vec::new();
        write_response(&mut out, Response::text(404, "no"), false, false, false).unwrap();
        assert_eq!(
            String::from_utf8(out).unwrap(),
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 2\r\nConnection: close\r\n\r\nno"
        );
        let mut out = Vec::new();
        write_response(&mut out, Response::text(200, &"x".repeat(5000)), true, false, true).unwrap();
        let text = String::from_utf8_lossy(&out);
        assert!(text.contains("Content-Encoding: gzip") && text.contains("Connection: keep-alive"));
    }
}
