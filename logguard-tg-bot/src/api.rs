//! The few Telegram Bot API methods the bot uses (<https://core.telegram.org/bots/api>),
//! over reqwest with rustls.
//!
//! The token is part of every request URL (`https://api.telegram.org/bot<token>/<method>`),
//! so no error leaves this module with the URL in it, and the token is checked for its
//! shape (`<digits>:<letters, digits, _ and ->`) before it goes into a path.

use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

/// Seconds a `getUpdates` call waits for news on Telegram's side.
pub const POLL_SECS: u64 = 50;
/// Every other call (an upload of a few MB included) finishes within this.
const CALL_TIMEOUT: Duration = Duration::from_secs(60);
/// The largest reply read: 100 updates are well below this.
const MAX_REPLY: usize = 16 << 20;

#[derive(Clone)]
pub struct Api {
    http: reqwest::Client,
    /// `<api url>/bot<token>/`
    base: String,
}

/// Why a call failed.
#[derive(Debug, Clone, PartialEq)]
pub enum ApiError {
    /// Telegram answered with `ok: false`.
    Telegram { code: i64, description: String, retry_after: Option<u64> },
    /// No usable answer: network, TLS, a timeout, or a reply that isn't the API's JSON.
    Transport(String),
}

impl ApiError {
    /// The token is wrong or was revoked (401; 404 is what a malformed one gets).
    pub fn bad_token(&self) -> bool {
        matches!(self, ApiError::Telegram { code: 401 | 404, .. })
    }

    /// Someone else is taking the updates: another instance, `logguard-tg-bot pair`, or a webhook.
    pub fn conflict(&self) -> bool {
        matches!(self, ApiError::Telegram { code: 409, .. })
    }

    /// Telegram will never take this request as it is (400 Bad Request: an entity out of
    /// place, an empty or too long text; 413: a file too large): retrying it would block what
    /// comes after. Not "chat not found", which is a wrong ADMIN_CHAT_ID and goes for every
    /// message.
    pub fn permanent(&self) -> bool {
        match self {
            ApiError::Telegram { code: 400, description, .. } => !description.to_lowercase().contains("chat not found"),
            ApiError::Telegram { code: 413, .. } => true,
            _ => false,
        }
    }

    /// Flood control: how long Telegram wants us to wait.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            ApiError::Telegram { retry_after: Some(s), .. } => Some(Duration::from_secs(*s)),
            _ => None,
        }
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ApiError::Telegram { code, description, retry_after: Some(s) } => {
                write!(f, "Telegram {code}: {description} (retry after {s} s)")
            }
            ApiError::Telegram { code, description, .. } => write!(f, "Telegram {code}: {description}"),
            ApiError::Transport(e) => f.write_str(e),
        }
    }
}

impl std::error::Error for ApiError {}

/// reqwest's error and its causes, without the request URL (it holds the token).
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
struct Envelope<T> {
    ok: bool,
    result: Option<T>,
    description: Option<String>,
    error_code: Option<i64>,
    parameters: Option<ResponseParameters>,
}

#[derive(Deserialize)]
struct ResponseParameters {
    retry_after: Option<u64>,
}

/// The result in a reply (`{"ok": true, "result": ...}`), or the error it describes.
pub fn decode<T: DeserializeOwned>(http_status: u16, body: &[u8]) -> Result<T, ApiError> {
    match serde_json::from_slice::<Envelope<T>>(body) {
        Ok(Envelope { ok: true, result: Some(r), .. }) => Ok(r),
        Ok(Envelope { ok: true, result: None, .. }) => Err(ApiError::Transport("reply without a result".into())),
        Ok(e) => Err(ApiError::Telegram {
            code: e.error_code.unwrap_or(i64::from(http_status)),
            description: e.description.unwrap_or_default(),
            retry_after: e.parameters.and_then(|p| p.retry_after),
        }),
        Err(e) => Err(ApiError::Transport(format!("HTTP {http_status}, not the Bot API's JSON: {e}"))),
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct User {
    pub id: i64,
    #[serde(default)]
    pub is_bot: bool,
    #[serde(default)]
    pub username: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Chat {
    pub id: i64,
    /// private, group, supergroup or channel
    #[serde(rename = "type")]
    pub kind: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Message {
    pub message_id: i64,
    #[serde(default)]
    pub from: Option<User>,
    pub chat: Chat,
    /// Unix time it was sent.
    pub date: i64,
    #[serde(default)]
    pub text: Option<String>,
}

/// Only messages are asked for (`allowed_updates`); anything else that still arrives has
/// no `message` and is skipped.
#[derive(Debug, Clone, Deserialize)]
pub struct Update {
    pub update_id: i64,
    #[serde(default)]
    pub message: Option<Message>,
}

/// The updates in a `getUpdates` result, one by one: one this code can't read (a shape it
/// doesn't know) becomes an update without a message, so it is still confirmed and can't
/// stop the polling. Without an `update_id` it is dropped.
pub fn updates(result: Vec<serde_json::Value>) -> Vec<Update> {
    result
        .into_iter()
        .filter_map(|v| {
            let id = v.get("update_id")?.as_i64()?;
            Some(serde_json::from_value::<Update>(v).unwrap_or(Update { update_id: id, message: None }))
        })
        .collect()
}

/// A formatting span, in UTF-16 code units as the API counts them.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct Entity {
    #[serde(rename = "type")]
    pub kind: &'static str,
    pub offset: usize,
    pub length: usize,
}

/// Whether `token` looks like a bot token: it goes into the URL path, so nothing that could
/// change the path (`/`, `..`, `?`) may get there.
pub fn valid_token(token: &str) -> bool {
    let Some((id, secret)) = token.split_once(':') else { return false };
    !id.is_empty()
        && id.bytes().all(|b| b.is_ascii_digit())
        && secret.len() >= 20
        && secret.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// Checks the API's address: HTTPS, or plain HTTP to this machine (a local Bot API server).
pub fn check_api_url(url: &str) -> Result<reqwest::Url, String> {
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

impl Api {
    pub fn new(api_url: &str, token: &str) -> Result<Api, String> {
        if !valid_token(token) {
            return Err("the token doesn't look like a bot token (<digits>:<35 or so letters, digits, _ and ->)".into());
        }
        let url = check_api_url(api_url)?;
        let http = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(CALL_TIMEOUT)
            // the API never redirects; a redirect would carry the message (and its body) elsewhere
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("logguard-tg-bot/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(|e| transport(e).to_string())?;
        Ok(Api { http, base: format!("{}/bot{token}/", url.as_str().trim_end_matches('/')) })
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

    async fn call<T: DeserializeOwned>(&self, method: &str, params: &impl Serialize) -> Result<T, ApiError> {
        Self::reply(self.http.post(format!("{}{method}", self.base)).json(params).send().await).await
    }

    pub async fn get_me(&self) -> Result<User, ApiError> {
        self.call("getMe", &serde_json::json!({})).await
    }

    /// Long polling: waits up to `timeout` seconds for messages after `offset` (which also
    /// confirms everything before it).
    pub async fn get_updates(&self, offset: i64, timeout: u64) -> Result<Vec<Update>, ApiError> {
        let params = serde_json::json!({ "offset": offset, "timeout": timeout, "allowed_updates": ["message"] });
        let req = self.http.post(format!("{}getUpdates", self.base)).json(&params).timeout(Duration::from_secs(timeout + 20));
        Self::reply::<Vec<serde_json::Value>>(req.send().await).await.map(updates)
    }

    /// Leaves a group or channel someone added the bot to.
    pub async fn leave_chat(&self, chat: i64) -> Result<bool, ApiError> {
        self.call("leaveChat", &serde_json::json!({ "chat_id": chat })).await
    }

    /// A text message, without link previews (a URL in a log line is not fetched).
    pub async fn send_message(&self, chat: i64, text: &str, entities: &[Entity], protect: bool) -> Result<Message, ApiError> {
        let mut params = serde_json::json!({
            "chat_id": chat,
            "text": text,
            "link_preview_options": { "is_disabled": true },
        });
        if !entities.is_empty() {
            params["entities"] = serde_json::to_value(entities).unwrap_or_default();
        }
        if protect {
            params["protect_content"] = true.into();
        }
        self.call("sendMessage", &params).await
    }

    /// A file, uploaded (multipart/form-data), with a caption of at most 1024 characters.
    pub async fn send_document(&self, chat: i64, filename: &str, data: Vec<u8>, caption: &str) -> Result<Message, ApiError> {
        let part = reqwest::multipart::Part::bytes(data).file_name(filename.to_string());
        let form =
            reqwest::multipart::Form::new().text("chat_id", chat.to_string()).text("caption", caption.to_string()).part("document", part);
        Self::reply(self.http.post(format!("{}sendDocument", self.base)).multipart(form).send().await).await
    }

    /// Possible for 48 hours after sending: the bot's own messages and, in a private chat,
    /// the other side's.
    pub async fn delete_message(&self, chat: i64, message_id: i64) -> Result<bool, ApiError> {
        self.call("deleteMessage", &serde_json::json!({ "chat_id": chat, "message_id": message_id })).await
    }

    /// The command menu, shown in this chat only.
    pub async fn set_commands(&self, chat: i64, commands: &[(&str, &str)]) -> Result<bool, ApiError> {
        let commands: Vec<_> = commands.iter().map(|(c, d)| serde_json::json!({ "command": c, "description": d })).collect();
        let params = serde_json::json!({ "commands": commands, "scope": { "type": "chat", "chat_id": chat } });
        self.call("setMyCommands", &params).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11";

    #[test]
    fn replies_and_errors() {
        let ok: User = decode(200, br#"{"ok":true,"result":{"id":42,"is_bot":true,"first_name":"b","username":"lg_bot"}}"#).unwrap();
        assert_eq!((ok.id, ok.username.as_deref()), (42, Some("lg_bot")));
        let flood = decode::<bool>(
            429,
            br#"{"ok":false,"error_code":429,"description":"Too Many Requests: retry after 7","parameters":{"retry_after":7}}"#,
        )
        .unwrap_err();
        assert_eq!(flood.retry_after(), Some(Duration::from_secs(7)));
        assert!(flood.to_string().contains("retry after 7 s"));
        let unauthorized = decode::<bool>(401, br#"{"ok":false,"error_code":401,"description":"Unauthorized"}"#).unwrap_err();
        assert!(unauthorized.bad_token() && !unauthorized.conflict());
        let conflict =
            decode::<bool>(409, br#"{"ok":false,"error_code":409,"description":"Conflict: terminated by other getUpdates request"}"#)
                .unwrap_err();
        assert!(conflict.conflict());
        // no error_code: the HTTP status
        assert!(matches!(decode::<bool>(502, br#"{"ok":false}"#), Err(ApiError::Telegram { code: 502, .. })));
        assert!(matches!(decode::<bool>(502, b"<html>Bad Gateway</html>"), Err(ApiError::Transport(_))));
        assert!(matches!(decode::<bool>(200, br#"{"ok":true}"#), Err(ApiError::Transport(_))));
    }

    #[test]
    fn updates_parse() {
        let body = br#"{"ok":true,"result":[
            {"update_id":10,"message":{"message_id":5,"from":{"id":7,"is_bot":false,"first_name":"A"},"chat":{"id":7,"type":"private"},"date":1760000000,"text":"/status"}},
            {"update_id":11,"edited_message":{"message_id":5}}
        ]}"#;
        let u: Vec<Update> = decode(200, body).unwrap();
        assert_eq!(u.len(), 2);
        let m = u[0].message.as_ref().unwrap();
        assert_eq!((m.chat.id, m.chat.kind.as_str(), m.from.as_ref().unwrap().id, m.text.as_deref()), (7, "private", 7, Some("/status")));
        assert!(u[1].message.is_none());
    }

    #[test]
    fn unknown_updates_are_skipped_not_stuck() {
        let v: Vec<serde_json::Value> = decode(
            200,
            br#"{"ok":true,"result":[
            {"update_id":20,"message":{"message_id":"not a number","chat":{"id":7,"type":"private"},"date":1}},
            {"update_id":21,"message":{"message_id":3,"chat":{"id":7,"type":"private"},"date":1,"text":"/help"}},
            {"no_id":true},
            {"update_id":22,"my_chat_member":{"chat":{"id":7}}}
        ]}"#,
        )
        .unwrap();
        let u = updates(v);
        assert_eq!(u.iter().map(|u| u.update_id).collect::<Vec<_>>(), [20, 21, 22], "each still confirmed");
        assert!(u[0].message.is_none() && u[2].message.is_none());
        assert_eq!(u[1].message.as_ref().unwrap().text.as_deref(), Some("/help"));
        let bad = |d: &str| ApiError::Telegram { code: 400, description: d.into(), retry_after: None };
        assert!(bad("Bad Request: can't parse entities").permanent());
        assert!(!bad("Bad Request: chat not found").permanent(), "a wrong ADMIN_CHAT_ID: every message would go");
        assert!(!ApiError::Telegram { code: 429, description: String::new(), retry_after: Some(3) }.permanent());
        assert!(ApiError::Telegram { code: 413, description: "Request Entity Too Large".into(), retry_after: None }.permanent());
        assert!(!ApiError::Transport("timeout".into()).permanent());
    }

    #[test]
    fn tokens_and_urls() {
        assert!(valid_token(TOKEN));
        for bad in [
            "",
            "123456",
            ":ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
            "12a:ABC-DEF1234ghIkl-zyx57W2v1u123ew11",
            "1:short",
            "1:ABC-DEF1234ghIkl-zyx57W2v1u12/../x",
            "1:ABC-DEF1234ghIkl-zyx57W2v1u12?x=1",
        ] {
            assert!(!valid_token(bad), "{bad}");
        }
        assert!(check_api_url("https://api.telegram.org").is_ok());
        assert!(check_api_url("http://127.0.0.1:8081").is_ok());
        assert!(check_api_url("http://localhost:8081/").is_ok());
        assert!(check_api_url("http://api.telegram.org").is_err());
        assert!(check_api_url("https://user:pw@api.telegram.org").is_err());
        assert!(check_api_url("https://api.telegram.org/?x=1").is_err());
        assert!(check_api_url("ftp://localhost").is_err());
        let api = Api::new("https://api.telegram.org/", TOKEN).unwrap();
        assert_eq!(api.base, format!("https://api.telegram.org/bot{TOKEN}/"));
        assert!(Api::new("https://api.telegram.org", "nope").is_err());
    }

    #[tokio::test]
    async fn errors_never_carry_the_token() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        // nothing listens on port 1
        let api = Api::new("http://127.0.0.1:1", TOKEN).unwrap();
        let e = api.get_me().await.unwrap_err();
        assert!(matches!(e, ApiError::Transport(_)), "{e:?}");
        let text = e.to_string();
        assert!(!text.contains("ABC-DEF") && !text.contains("123456"), "{text}");
    }

    #[test]
    fn entities_serialize_as_the_api_wants() {
        let e = Entity { kind: "pre", offset: 3, length: 9 };
        assert_eq!(serde_json::to_value(&e).unwrap(), serde_json::json!({"type": "pre", "offset": 3, "length": 9}));
    }
}
