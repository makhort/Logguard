//! The few Matrix client-server API calls the bot makes
//! (<https://spec.matrix.org/v1.16/client-server-api/>), over reqwest with rustls.
//!
//! The access token goes in the `Authorization` header only, never into a URL, and no error
//! carries a request header. Identifiers (`!room:server`, `@user:server`) are percent-encoded
//! into paths, so none can change the path.

use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{json, Value};

/// Every call (an upload of a few MB included) finishes within this.
const CALL_TIMEOUT: Duration = Duration::from_secs(60);
/// The largest reply read: the admin's device list is a few KB.
const MAX_REPLY: usize = 16 << 20;

#[derive(Clone)]
pub struct Api {
    http: reqwest::Client,
    /// The homeserver's client URL, without a trailing slash.
    base: String,
    token: Option<String>,
}

/// Why a call failed.
#[derive(Debug, Clone, PartialEq)]
pub enum ApiError {
    /// The homeserver answered with an error (`errcode` empty when its reply has none: the
    /// first step of user-interactive authentication).
    Matrix { status: u16, errcode: String, error: String, retry_after_ms: Option<u64>, uia: Option<Uia> },
    /// No usable answer: network, TLS, a timeout, or a reply that isn't the API's JSON.
    Transport(String),
}

/// A user-interactive authentication the homeserver asks for
/// (<https://spec.matrix.org/v1.16/client-server-api/#user-interactive-authentication-api>).
#[derive(Debug, Clone, PartialEq)]
pub struct Uia {
    pub session: String,
    /// Whether the account's password alone will do.
    pub password: bool,
    /// A web page where the account's owner approves the request instead (Matrix
    /// Authentication Service's `org.matrix.cross_signing_reset`).
    pub url: Option<String>,
}

impl Uia {
    fn parse(body: &Value) -> Option<Uia> {
        let session = body.get("session")?.as_str()?.to_string();
        let flows = body.get("flows").and_then(Value::as_array).into_iter().flatten();
        let password = flows.filter_map(|f| f.get("stages")?.as_array()).any(|s| s.len() == 1 && s[0] == "m.login.password");
        let url = body
            .get("params")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .find_map(|(_, p)| p.get("url")?.as_str().filter(|u| u.starts_with("https://")).map(String::from));
        Some(Uia { session, password, url })
    }
}

impl ApiError {
    /// The access token is unknown (logged out, the device deleted): only `login` helps.
    pub fn unknown_token(&self) -> bool {
        matches!(self, ApiError::Matrix { status: 401, errcode, .. } if errcode == "M_UNKNOWN_TOKEN" || errcode == "M_MISSING_TOKEN")
    }

    /// Rate limited: how long the homeserver wants us to wait (5 s if it doesn't say).
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            ApiError::Matrix { status: 429, retry_after_ms, .. } => Some(Duration::from_millis(retry_after_ms.unwrap_or(5000))),
            ApiError::Matrix { errcode, retry_after_ms, .. } if errcode == "M_LIMIT_EXCEEDED" => {
                Some(Duration::from_millis(retry_after_ms.unwrap_or(5000)))
            }
            _ => None,
        }
    }

    /// The homeserver will never take this request as it is (malformed, too large): retrying
    /// it would hold up what comes after.
    pub fn permanent(&self) -> bool {
        match self {
            ApiError::Matrix { status: 413, .. } => true,
            ApiError::Matrix { status: 400, errcode, .. } => {
                matches!(errcode.as_str(), "M_BAD_JSON" | "M_NOT_JSON" | "M_TOO_LARGE" | "M_INVALID_PARAM")
            }
            _ => false,
        }
    }

    /// The room is gone for the bot (it was removed, or the room id is wrong).
    pub fn not_in_room(&self) -> bool {
        matches!(self, ApiError::Matrix { status: 403 | 404, errcode, .. } if errcode == "M_FORBIDDEN" || errcode == "M_NOT_FOUND")
    }

    /// The user-interactive authentication the homeserver asks for.
    pub fn uia(&self) -> Option<&Uia> {
        match self {
            ApiError::Matrix { status: 401, uia: Some(u), .. } => Some(u),
            _ => None,
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ApiError::Matrix { status, errcode, error, retry_after_ms, .. } => {
                write!(f, "homeserver {status}")?;
                if !errcode.is_empty() {
                    write!(f, " {errcode}")?;
                }
                if !error.is_empty() {
                    write!(f, ": {error}")?;
                }
                if let Some(ms) = retry_after_ms {
                    write!(f, " (retry after {} s)", ms.div_ceil(1000))?;
                }
                Ok(())
            }
            ApiError::Transport(e) => f.write_str(e),
        }
    }
}

impl std::error::Error for ApiError {}

/// reqwest's error and its causes, without the request URL.
fn transport(e: reqwest::Error) -> ApiError {
    let e = e.without_url();
    let mut text = e.to_string();
    let mut source = std::error::Error::source(&e);
    while let Some(s) = source {
        text += &format!(": {s}");
        source = s.source();
    }
    ApiError::Transport(text)
}

#[derive(Deserialize)]
struct ErrorBody {
    #[serde(default)]
    errcode: String,
    #[serde(default)]
    error: String,
    retry_after_ms: Option<u64>,
}

/// A reply's JSON, or the error it describes.
pub fn decode<T: DeserializeOwned>(http_status: u16, body: &[u8]) -> Result<T, ApiError> {
    if (200..300).contains(&http_status) {
        return serde_json::from_slice(body).map_err(|e| ApiError::Transport(format!("HTTP {http_status}, not the expected JSON: {e}")));
    }
    match serde_json::from_slice::<Value>(body).and_then(|v| Ok((serde_json::from_value::<ErrorBody>(v.clone())?, v))) {
        Ok((e, v)) => Err(ApiError::Matrix {
            status: http_status,
            errcode: e.errcode,
            error: e.error.chars().take(300).collect(),
            retry_after_ms: e.retry_after_ms,
            uia: Uia::parse(&v),
        }),
        Err(_) => Err(ApiError::Transport(format!("HTTP {http_status} without the API's JSON"))),
    }
}

/// `s` percent-encoded for one path segment: everything but unreserved characters.
pub fn path_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 3);
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out += &format!("%{b:02X}");
        }
    }
    out
}

/// Checks the homeserver's address: HTTPS, or plain HTTP to this machine.
pub fn check_homeserver(url: &str) -> Result<reqwest::Url, String> {
    let u = reqwest::Url::parse(url).map_err(|e| e.to_string())?;
    let local = matches!(u.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    match u.scheme() {
        "https" => {}
        "http" if local => {}
        s => return Err(format!("{s}:// is not allowed: https, or http to localhost only")),
    }
    if u.query().is_some() || u.fragment().is_some() || !u.username().is_empty() || u.password().is_some() {
        return Err("no credentials, query or fragment".into());
    }
    Ok(u)
}

/// Whether `s` is a Matrix user id: `@localpart:server` (older servers allowed any printable
/// ASCII in the local part).
pub fn valid_user_id(s: &str) -> bool {
    let Some((local, server)) = s.strip_prefix('@').and_then(|r| r.split_once(':')) else { return false };
    !local.is_empty()
        && !server.is_empty()
        && s.len() <= 255
        && local.bytes().all(|b| b.is_ascii_graphic())
        && server.bytes().all(|b| b.is_ascii_alphanumeric() || b".-:[]".contains(&b))
}

#[derive(Debug, Clone, Deserialize)]
pub struct LoginReply {
    pub user_id: String,
    pub access_token: String,
    pub device_id: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WhoAmI {
    pub user_id: String,
    #[serde(default)]
    pub device_id: Option<String>,
}

impl Api {
    pub fn new(homeserver: &str, token: Option<String>) -> Result<Api, String> {
        let url = check_homeserver(homeserver)?;
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(CALL_TIMEOUT)
            // the client API doesn't redirect; a redirect would carry the token elsewhere
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("logguard-matrix-bot/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| transport(e).to_string())?;
        Ok(Api { http, base: url.as_str().trim_end_matches('/').to_string(), token })
    }

    pub fn with_token(&self, token: String) -> Api {
        Api { token: Some(token), ..self.clone() }
    }

    async fn reply<T: DeserializeOwned>(resp: Result<reqwest::Response, reqwest::Error>) -> Result<T, ApiError> {
        let mut resp = resp.map_err(transport)?;
        let status = resp.status().as_u16();
        let mut body = Vec::new();
        while let Some(chunk) = resp.chunk().await.map_err(transport)? {
            if body.len() + chunk.len() > MAX_REPLY {
                return Err(ApiError::Transport(format!("HTTP {status}: reply larger than {} MB", MAX_REPLY >> 20)));
            }
            body.extend_from_slice(&chunk);
        }
        decode(status, &body)
    }

    fn request(&self, method: reqwest::Method, path: &str) -> reqwest::RequestBuilder {
        let req = self.http.request(method, format!("{}{path}", self.base));
        match &self.token {
            Some(t) => req.bearer_auth(t),
            None => req,
        }
    }

    async fn call<T: DeserializeOwned>(&self, method: reqwest::Method, path: &str, body: Option<&Value>) -> Result<T, ApiError> {
        let mut req = self.request(method, path);
        if let Some(b) = body {
            req = req.json(b);
        }
        Self::reply(req.send().await).await
    }

    async fn post<T: DeserializeOwned>(&self, path: &str, body: &Value) -> Result<T, ApiError> {
        self.call(reqwest::Method::POST, path, Some(body)).await
    }

    async fn put<T: DeserializeOwned>(&self, path: &str, body: &Value) -> Result<T, ApiError> {
        self.call(reqwest::Method::PUT, path, Some(body)).await
    }

    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        self.call(reqwest::Method::GET, path, None).await
    }

    /// A new device for the bot, by password.
    pub async fn login(&self, user: &str, password: &str, device_name: &str) -> Result<LoginReply, ApiError> {
        let body = json!({
            "type": "m.login.password",
            "identifier": { "type": "m.id.user", "user": user },
            "password": password,
            "initial_device_display_name": device_name,
        });
        self.post("/_matrix/client/v3/login", &body).await
    }

    /// Ends this token's session (the homeserver deletes its device).
    pub async fn logout(&self) -> Result<Value, ApiError> {
        self.post("/_matrix/client/v3/logout", &json!({})).await
    }

    pub async fn whoami(&self) -> Result<WhoAmI, ApiError> {
        self.get("/_matrix/client/v3/account/whoami").await
    }

    /// Publishes device keys (and one-time keys, if any).
    pub async fn upload_keys(&self, body: &Value) -> Result<Value, ApiError> {
        self.post("/_matrix/client/v3/keys/upload", body).await
    }

    /// The device and cross-signing keys of `users`.
    pub async fn query_keys(&self, users: &[&str]) -> Result<Value, ApiError> {
        let devices: serde_json::Map<String, Value> = users.iter().map(|u| (u.to_string(), json!([]))).collect();
        self.post("/_matrix/client/v3/keys/query", &json!({ "device_keys": devices, "timeout": 10000 })).await
    }

    /// One one-time key (or fallback key) of each of `user`'s `devices`.
    pub async fn claim_keys(&self, user: &str, devices: &[&str]) -> Result<Value, ApiError> {
        let wanted: serde_json::Map<String, Value> = devices.iter().map(|d| (d.to_string(), json!("signed_curve25519"))).collect();
        self.post("/_matrix/client/v3/keys/claim", &json!({ "one_time_keys": { user: wanted }, "timeout": 10000 })).await
    }

    /// The account's cross-signing keys; the homeserver asks for the password first
    /// (`auth` None gets the session to answer with).
    pub async fn upload_cross_signing(&self, mut body: Value, auth: Option<Value>) -> Result<Value, ApiError> {
        if let Some(a) = auth {
            body["auth"] = a;
        }
        self.post("/_matrix/client/v3/keys/device_signing/upload", &body).await
    }

    pub async fn upload_signatures(&self, body: &Value) -> Result<Value, ApiError> {
        self.post("/_matrix/client/v3/keys/signatures/upload", body).await
    }

    pub async fn create_room(&self, body: &Value) -> Result<String, ApiError> {
        let v: Value = self.post("/_matrix/client/v3/createRoom", body).await?;
        v.get("room_id").and_then(Value::as_str).map(String::from).ok_or_else(|| ApiError::Transport("createRoom: no room_id".into()))
    }

    pub async fn invite(&self, room: &str, user: &str) -> Result<Value, ApiError> {
        self.post(&format!("/_matrix/client/v3/rooms/{}/invite", path_segment(room)), &json!({ "user_id": user })).await
    }

    pub async fn leave(&self, room: &str) -> Result<Value, ApiError> {
        self.post(&format!("/_matrix/client/v3/rooms/{}/leave", path_segment(room)), &json!({})).await
    }

    /// A state event's content; `None` when the room has none of that type and key.
    pub async fn state(&self, room: &str, kind: &str, key: &str) -> Result<Option<Value>, ApiError> {
        let path = format!("/_matrix/client/v3/rooms/{}/state/{}/{}", path_segment(room), path_segment(kind), path_segment(key));
        match self.get(&path).await {
            Ok(v) => Ok(Some(v)),
            Err(ApiError::Matrix { status: 404, errcode, .. }) if errcode == "M_NOT_FOUND" => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// A room event; returns its event id.
    pub async fn send_event(&self, room: &str, kind: &str, txn: &str, content: &Value) -> Result<String, ApiError> {
        let path = format!("/_matrix/client/v3/rooms/{}/send/{}/{}", path_segment(room), path_segment(kind), path_segment(txn));
        let v: Value = self.put(&path, content).await?;
        Ok(v.get("event_id").and_then(Value::as_str).unwrap_or_default().to_string())
    }

    /// To-device messages: `messages` is `{user: {device: content}}`.
    pub async fn send_to_device(&self, kind: &str, txn: &str, messages: &Value) -> Result<Value, ApiError> {
        let path = format!("/_matrix/client/v3/sendToDevice/{}/{}", path_segment(kind), path_segment(txn));
        self.put(&path, &json!({ "messages": messages })).await
    }

    /// Uploads a file; returns its `mxc://` URI.
    pub async fn upload(&self, data: Vec<u8>, filename: &str, content_type: &str) -> Result<String, ApiError> {
        let path = format!("/_matrix/media/v3/upload?filename={}", path_segment(filename));
        let req = self.request(reqwest::Method::POST, &path).header(reqwest::header::CONTENT_TYPE, content_type).body(data);
        let v: Value = Self::reply(req.send().await).await?;
        v.get("content_uri").and_then(Value::as_str).map(String::from).ok_or_else(|| ApiError::Transport("upload: no content_uri".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errors() {
        let e = decode::<Value>(401, br#"{"errcode":"M_UNKNOWN_TOKEN","error":"Invalid access token passed.","soft_logout":false}"#)
            .unwrap_err();
        assert!(e.unknown_token() && e.retry_after().is_none() && !e.permanent());
        let e = decode::<Value>(429, br#"{"errcode":"M_LIMIT_EXCEEDED","error":"Too Many Requests","retry_after_ms":2001}"#).unwrap_err();
        assert_eq!(e.retry_after(), Some(Duration::from_millis(2001)));
        assert!(e.to_string().contains("retry after 3 s"), "{e}");
        let e = decode::<Value>(401, br#"{"session":"xyz","flows":[{"stages":["m.login.password"]}],"params":{}}"#).unwrap_err();
        assert_eq!(e.uia(), Some(&Uia { session: "xyz".into(), password: true, url: None }));
        assert!(!e.unknown_token());
        // Matrix Authentication Service: approved in the account's web page
        let e = decode::<Value>(
            401,
            br#"{"session":"s","flows":[{"stages":["org.matrix.cross_signing_reset"]}],
                 "params":{"org.matrix.cross_signing_reset":{"url":"https://account.example.org/reset"}},"msg":"..."}"#,
        )
        .unwrap_err();
        let uia = e.uia().unwrap();
        assert!(!uia.password);
        assert_eq!(uia.url.as_deref(), Some("https://account.example.org/reset"));
        assert!(decode::<Value>(413, br#"{"errcode":"M_TOO_LARGE","error":"Upload request body is too large"}"#).unwrap_err().permanent());
        assert!(decode::<Value>(403, br#"{"errcode":"M_FORBIDDEN","error":"not in room"}"#).unwrap_err().not_in_room());
        assert!(matches!(decode::<Value>(502, b"<html>Bad Gateway</html>"), Err(ApiError::Transport(_))));
        assert!(matches!(decode::<LoginReply>(200, br#"{"user_id":"@b:x"}"#), Err(ApiError::Transport(_))));
    }

    #[test]
    fn paths_and_ids() {
        assert_eq!(path_segment("!abc:example.org"), "%21abc%3Aexample.org");
        assert_eq!(path_segment("@bot:example.org"), "%40bot%3Aexample.org");
        assert_eq!(path_segment("../x?y#z"), "..%2Fx%3Fy%23z");
        assert_eq!(path_segment(""), "");
        assert!(valid_user_id("@logguard-bot:example.org"));
        assert!(valid_user_id("@admin:matrix.example.org:8448"));
        assert!(valid_user_id("@Admin:example.org"), "a historical user id");
        for bad in ["admin:example.org", "@:example.org", "@admin", "@a b:example.org", "@a:exa/mple", "@a\n:example.org"] {
            assert!(!valid_user_id(bad), "{bad}");
        }
        assert!(check_homeserver("https://matrix-client.matrix.org").is_ok());
        assert!(check_homeserver("http://127.0.0.1:8008").is_ok());
        assert!(check_homeserver("http://matrix.org").is_err());
        assert!(check_homeserver("https://u:p@matrix.org").is_err());
        let _ = rustls::crypto::ring::default_provider().install_default();
        let api = Api::new("https://matrix.example.org/", None).unwrap();
        assert_eq!(api.base, "https://matrix.example.org");
    }
}
