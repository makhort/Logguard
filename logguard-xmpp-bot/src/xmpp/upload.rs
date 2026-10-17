//! Sending the outbox to the admin: HTTP File Upload (XEP-0363) of files encrypted as
//! OMEMO media (XEP-0454), announced in OMEMO messages. Nothing is ever sent unencrypted.

use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_xmpp::jid::Jid;
use tokio_xmpp::minidom::Element;
use tokio_xmpp::parsers::http_upload::{SlotRequest, SlotResult};
use tokio_xmpp::parsers::ns;
use tokio_xmpp::IqRequest;

use super::{Session, MAX_BACKLOG};
use crate::commands::{Attachment, Reply};
use crate::outbox;

/// A whole upload (connect, TLS, body, answer).
const PUT_TIMEOUT: Duration = Duration::from_secs(120);
/// Largest HTTP response head read; the body is not needed.
const MAX_RESPONSE_HEAD: usize = 16 * 1024;

/// The upload service and its size limit, if it states one.
#[derive(Clone, Debug, PartialEq)]
pub struct UploadService {
    pub jid: Jid,
    pub max_size: Option<u64>,
}

/// Whether a disco#info result is an upload service, and its max-file-size.
fn upload_service_of(jid: Jid, info: &Element) -> Option<UploadService> {
    let has_feature = info.children().any(|c| c.is("feature", ns::DISCO_INFO) && c.attr("var") == Some(ns::HTTP_UPLOAD));
    if !has_feature {
        return None;
    }
    let max_size = info
        .children()
        .filter(|x| x.is("x", ns::DATA_FORMS))
        .flat_map(|x| x.children())
        .find(|f| f.is("field", ns::DATA_FORMS) && f.attr("var") == Some("max-file-size"))
        .and_then(|f| f.get_child("value", ns::DATA_FORMS))
        .and_then(|v| v.text().trim().parse().ok());
    Some(UploadService { jid, max_size })
}

/// The request head of an HTTP PUT of `len` bytes. Only the headers XEP-0363 allows are
/// passed on, and only without line breaks.
fn put_head(url: &url::Url, len: usize, headers: &[(String, String)]) -> Result<String, String> {
    let host = url.host_str().ok_or("upload URL without host")?;
    let host = match url.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    };
    let mut path = url.path().to_string();
    if let Some(q) = url.query() {
        path = format!("{path}?{q}");
    }
    let mut head = format!(
        "PUT {path} HTTP/1.1\r\nHost: {host}\r\nContent-Length: {len}\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n"
    );
    for (name, value) in headers {
        if !["Authorization", "Cookie", "Expires"].iter().any(|h| h.eq_ignore_ascii_case(name)) {
            continue;
        }
        if value.contains(['\r', '\n']) {
            return Err(format!("upload slot header {name} has a line break"));
        }
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    head.push_str("\r\n");
    Ok(head)
}

/// The status code of an HTTP response head.
fn status_of(head: &str) -> Option<u16> {
    let line = head.lines().next()?;
    let mut parts = line.split_whitespace();
    parts.next().filter(|v| v.starts_with("HTTP/1."))?;
    parts.next()?.parse().ok()
}

/// HTTPS PUT, the certificate verified against the URL's host with the system's roots
/// (the server's certificate comes from Let's Encrypt).
async fn http_put(put_url: &str, headers: &[(String, String)], body: &[u8]) -> Result<(), String> {
    let url = url::Url::parse(put_url).map_err(|e| format!("upload URL {put_url}: {e}"))?;
    if url.scheme() != "https" {
        return Err(format!("upload URL {put_url} is not https"));
    }
    let head = put_head(&url, body.len(), headers)?;
    let host = url.host_str().ok_or("upload URL without host")?.trim_matches(['[', ']']).to_string();
    let port = url.port_or_known_default().unwrap_or(443);

    let mut roots = tokio_xmpp::rustls::RootCertStore::empty();
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    let config = tokio_xmpp::rustls::ClientConfig::builder().with_root_certificates(roots).with_no_client_auth();
    let name = tokio_xmpp::rustls::pki_types::ServerName::try_from(host.clone()).map_err(|e| format!("{host}: {e}"))?;
    let tcp = tokio::net::TcpStream::connect((host.as_str(), port)).await.map_err(|e| format!("connecting to {host}:{port}: {e}"))?;
    let mut tls =
        tokio_rustls::TlsConnector::from(Arc::new(config)).connect(name, tcp).await.map_err(|e| format!("TLS with {host}: {e}"))?;
    tls.write_all(head.as_bytes()).await.map_err(|e| e.to_string())?;
    tls.write_all(body).await.map_err(|e| e.to_string())?;
    tls.flush().await.map_err(|e| e.to_string())?;
    let mut answer = Vec::new();
    let mut buf = [0u8; 4096];
    while !answer.windows(4).any(|w| w == b"\r\n\r\n") && answer.len() < MAX_RESPONSE_HEAD {
        let n = tls.read(&mut buf).await.map_err(|e| format!("reading the answer: {e}"))?;
        if n == 0 {
            break;
        }
        answer.extend_from_slice(&buf[..n]);
    }
    let head = String::from_utf8_lossy(&answer);
    match status_of(&head) {
        Some(200..=299) => Ok(()),
        Some(code) => Err(format!("upload refused: HTTP {code}")),
        None => Err("no HTTP answer to the upload".into()),
    }
}

impl Session {
    /// Runs `fut` while still reading the XMPP stream into the backlog (see
    /// [`Session::iq_within`]): an upload takes a while.
    async fn alongside<F: Future>(&mut self, fut: F) -> F::Output {
        tokio::pin!(fut);
        loop {
            tokio::select! {
                out = &mut fut => return out,
                e = self.client.next(), if self.backlog.len() < MAX_BACKLOG => match e {
                    Some(e) => self.backlog.push_back(e),
                    None => return fut.await,
                },
            }
        }
    }

    /// The server's upload service: the configured one, else the first item of the domain
    /// whose disco#info has the HTTP File Upload feature. Remembered once found.
    async fn upload_service(&mut self) -> Result<UploadService, String> {
        if let Some(s) = &self.upload.service {
            return Ok(s.clone());
        }
        let candidates: Vec<Jid> = match &self.upload.configured {
            Some(j) => vec![j.clone()],
            None => {
                let domain: Jid = self.bot.domain.parse().map_err(|e| format!("domain: {e}"))?;
                let query = Element::builder("query", ns::DISCO_ITEMS).build();
                let items = self.iq(Some(domain.clone()), IqRequest::Get(query)).await.map_err(|e| format!("disco#items: {}", e.text))?;
                let mut list = vec![domain];
                if let Some(items) = items {
                    list.extend(items.children().filter(|c| c.is("item", ns::DISCO_ITEMS)).filter_map(|c| c.attr("jid")?.parse().ok()));
                }
                list
            }
        };
        for jid in candidates {
            let query = Element::builder("query", ns::DISCO_INFO).build();
            if let Ok(Some(info)) = self.iq(Some(jid.clone()), IqRequest::Get(query)).await {
                if let Some(s) = upload_service_of(jid, &info) {
                    log::info!("HTTP upload service: {} (max {:?} bytes)", s.jid, s.max_size);
                    self.upload.service = Some(s.clone());
                    return Ok(s);
                }
            }
        }
        Err("the server has no HTTP File Upload service (mod_http_upload)".into())
    }

    /// Encrypts and uploads `plain` as `filename`; returns the aesgcm:// URL.
    async fn upload_encrypted(&mut self, filename: &str, plain: &[u8]) -> Result<String, String> {
        let service = self.upload_service().await?;
        let sealed = outbox::seal(plain);
        let size = sealed.data.len() as u64;
        if service.max_size.is_some_and(|m| size > m) {
            return Err(format!("{size} bytes is more than the upload service takes ({:?})", service.max_size));
        }
        let request = SlotRequest { filename: filename.into(), size, content_type: Some("application/octet-stream".into()) };
        let slot = self.iq(Some(service.jid.clone()), IqRequest::Get(request.into())).await.map_err(|e| {
            // a stale service (the server's configuration changed): find it again next time
            self.upload.service = None;
            format!("upload slot: {}", e.text)
        })?;
        let slot = SlotResult::try_from(slot.ok_or("empty upload slot")?).map_err(|e| format!("upload slot: {e}"))?;
        let headers: Vec<(String, String)> = slot.put.headers.iter().map(|h| (h.name.as_str().to_string(), h.value.clone())).collect();
        let put = slot.put.url.clone();
        let result = self.alongside(tokio::time::timeout(PUT_TIMEOUT, http_put(&put, &headers, &sealed.data))).await;
        result.map_err(|_| "upload timed out".to_string())??;
        outbox::aesgcm_url(&slot.get.url, &sealed.iv, &sealed.key)
    }

    /// Uploads `plain` encrypted and sends `bare` a line saying what it is (`intro`), then
    /// the file's aesgcm:// URL. Both OMEMO-encrypted, for `bare`'s trusted devices (and
    /// `also`, the device that asked); without one, nothing is sent.
    async fn send_file(&mut self, bare: &str, also: Option<u32>, filename: &str, plain: &[u8], intro: String) -> Result<(), String> {
        let to: Jid = bare.parse().map_err(|e| format!("JID {bare}: {e}"))?;
        let url = self.upload_encrypted(filename, plain).await?;
        self.send_encrypted(to.clone(), bare, also, &Reply::from(intro)).await?;
        self.send_encrypted(to, bare, also, &Reply::from(url)).await
    }

    /// A command's file for the user who sent it (`/export`), from the device that asked.
    pub(super) async fn send_attachment(&mut self, sender: &str, device: u32, attachment: &Attachment) {
        let t = self.bot.language_of(sender).texts();
        let intro = t
            .export_file
            .replace("{file}", &attachment.filename)
            .replace("{kb}", &attachment.data.len().div_ceil(1024).to_string())
            .replace("{days}", &self.bot.retention.files.to_string());
        match self.send_file(sender, Some(device), &attachment.filename, &attachment.data, intro).await {
            Ok(()) => log::info!("{sender}: {} sent (OMEMO media)", attachment.filename),
            Err(e) => {
                log::warn!("{sender}: {} not sent: {e}", attachment.filename);
                let to: Result<Jid, _> = sender.parse();
                if let Ok(to) = to {
                    let _ = self.send_encrypted(to, sender, Some(device), &Reply::from(t.export_file_failed)).await;
                }
            }
        }
    }

    /// Sends one outbox file to the admin: a line saying what it is, then the file.
    /// Both OMEMO-encrypted; without a trusted admin device nothing is sent.
    async fn send_outbox_file(&mut self, path: &Path) -> Result<(), String> {
        let admin = self.bot.admin_jid.clone();
        let filename = path.file_name().and_then(|n| n.to_str()).ok_or("file name is not UTF-8")?.to_string();
        let plain = std::fs::read(path).map_err(|e| format!("reading: {e}"))?;
        let summary = outbox::summary(&String::from_utf8_lossy(&plain));
        let intro = format!(
            "📎 {filename} ({} KB), encrypted. The server deletes its (encrypted) copy after {} days.\n{summary}",
            plain.len().div_ceil(1024),
            self.bot.retention.files
        );
        self.send_file(&admin, None, &filename, &plain, intro).await
    }

    /// Sends what the outbox holds (while online) and deletes it; deletes unsent files
    /// older than the retention time.
    pub(super) async fn deliver_outbox(&mut self) {
        let dir = self.upload.outbox.clone();
        let pending = match outbox::scan(&dir, self.upload.max_age, std::time::SystemTime::now()) {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => return log::warn!("outbox {}: {e}", dir.display()),
        };
        for path in pending.expired {
            match std::fs::remove_file(&path) {
                Ok(()) => log::warn!(
                    "outbox: {} not sent within {} days (or too large), deleted",
                    path.display(),
                    self.upload.max_age.as_secs() / 86400
                ),
                Err(e) => log::error!("outbox: deleting {}: {e}", path.display()),
            }
        }
        if pending.ready.is_empty() || !self.online {
            return;
        }
        if self.omemo.is_none() {
            return log::warn!("outbox: {} file(s) waiting, but OMEMO is off and files go out encrypted only", pending.ready.len());
        }
        for path in pending.ready {
            match self.send_outbox_file(&path).await {
                Ok(()) => {
                    log::info!("outbox: {} sent to the admin (OMEMO media)", path.display());
                    if let Err(e) = std::fs::remove_file(&path) {
                        log::error!("outbox: deleting {} after sending: {e}", path.display());
                    }
                }
                Err(e) => {
                    log::warn!("outbox: {} not sent ({e}); trying again later", path.display());
                    break;
                }
            }
        }
    }
}

impl Session {
    /// Sends logguard's alert messages in the outbox to the admin, OMEMO-encrypted (see
    /// [`outbox`]). Without OMEMO, a connection or a trusted admin device, they stay, and
    /// logguard sends them itself after its grace time.
    pub(super) async fn deliver_messages(&mut self) {
        if !self.online || self.omemo.is_none() {
            return;
        }
        let dir = self.upload.outbox.clone();
        let waiting = match outbox::scan_messages(&dir) {
            Ok(w) => w,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return,
            Err(e) => return log::warn!("outbox {}: {e}", dir.display()),
        };
        for path in waiting {
            let sending = outbox::claimed(&path, "sending");
            match std::fs::rename(&path, &sending) {
                Ok(()) => {}
                // logguard took it back in the meantime
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => {
                    log::warn!("outbox: can't take {}: {e}", path.display());
                    continue;
                }
            }
            let message = std::fs::read_to_string(&sending).ok().as_deref().and_then(outbox::parse_message);
            let admin_bare = self.bot.admin_jid.clone();
            let Some((to, text)) = message.filter(|(to, _)| *to == admin_bare) else {
                log::warn!("outbox: {} is not a message for the admin; left to logguard", path.display());
                let _ = std::fs::rename(&sending, outbox::claimed(&path, "rejected"));
                continue;
            };
            let sent = match to.parse::<Jid>() {
                Ok(jid) => self.send_encrypted(jid, &admin_bare, None, &Reply::from(text)).await,
                Err(e) => Err(format!("admin JID: {e}")),
            };
            match sent {
                Ok(()) => {
                    log::info!("outbox: alert {} sent to the admin (OMEMO)", path.display());
                    if let Err(e) = std::fs::remove_file(&sending) {
                        log::error!("outbox: deleting {} after sending: {e}", sending.display());
                    }
                }
                Err(e) => {
                    log::warn!("outbox: alert {} not sent ({e}); logguard sends it if this goes on", path.display());
                    let _ = std::fs::rename(&sending, &path);
                    break;
                }
            }
        }
    }
}

/// Outbox settings and what was found out about the server.
pub struct UploadCtx {
    pub outbox: std::path::PathBuf,
    pub max_age: Duration,
    /// UPLOAD_SERVICE, if set.
    pub configured: Option<Jid>,
    pub service: Option<UploadService>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_ejabberds_upload_service() {
        let info: Element = "<query xmlns='http://jabber.org/protocol/disco#info'>\
             <identity category='store' type='file' name='HTTP File Upload'/>\
             <feature var='urn:xmpp:http:upload:0'/><feature var='http://jabber.org/protocol/disco#info'/>\
             <x xmlns='jabber:x:data' type='result'>\
               <field var='FORM_TYPE' type='hidden'><value>urn:xmpp:http:upload:0</value></field>\
               <field var='max-file-size'><value>524288000</value></field></x></query>"
            .parse()
            .unwrap();
        let jid: Jid = "upload.example.org".parse().unwrap();
        assert_eq!(upload_service_of(jid.clone(), &info), Some(UploadService { jid: jid.clone(), max_size: Some(524_288_000) }));
        let plain: Element = "<query xmlns='http://jabber.org/protocol/disco#info'><feature var='urn:xmpp:ping'/></query>".parse().unwrap();
        assert_eq!(upload_service_of(jid, &plain), None);
    }

    #[test]
    fn slot_request_and_result() {
        let el: Element = SlotRequest {
            filename: "abuse-report-2026-10-19.txt".into(),
            size: 1040,
            content_type: Some("application/octet-stream".into()),
        }
        .into();
        assert!(el.is("request", ns::HTTP_UPLOAD));
        assert_eq!((el.attr("filename"), el.attr("size")), (Some("abuse-report-2026-10-19.txt"), Some("1040")));
        let slot: Element = "<slot xmlns='urn:xmpp:http:upload:0'>\
             <put url='https://example.org:5443/upload/0a1b/abuse-report.txt'><header name='Authorization'>Basic x</header></put>\
             <get url='https://example.org:5443/upload/0a1b/abuse-report.txt'/></slot>"
            .parse()
            .unwrap();
        let slot = SlotResult::try_from(slot).unwrap();
        assert_eq!(slot.put.headers[0].name.as_str(), "Authorization");
        assert!(slot.get.url.starts_with("https://"));
    }

    #[test]
    fn put_request_head() {
        let url = url::Url::parse("https://example.org:5443/upload/0a1b/r%C3%A9port.txt?v=1").unwrap();
        let headers = vec![
            ("Authorization".to_string(), "Basic abc".to_string()),
            ("X-Evil".to_string(), "1".to_string()),
            ("cookie".to_string(), "c=1".to_string()),
        ];
        let head = put_head(&url, 1040, &headers).unwrap();
        assert!(head.starts_with("PUT /upload/0a1b/r%C3%A9port.txt?v=1 HTTP/1.1\r\nHost: example.org:5443\r\nContent-Length: 1040\r\n"));
        assert!(head.contains("Authorization: Basic abc\r\n") && head.contains("cookie: c=1\r\n"));
        assert!(!head.contains("X-Evil"), "XEP-0363 allows Authorization, Cookie and Expires only");
        assert!(head.ends_with("\r\n\r\n"));
        let default_port = url::Url::parse("https://example.org/u/f").unwrap();
        assert!(put_head(&default_port, 1, &[]).unwrap().contains("Host: example.org\r\n"));
        let injected = vec![("Authorization".to_string(), "x\r\nX-Other: y".to_string())];
        assert!(put_head(&url, 1, &injected).is_err());
    }

    #[test]
    fn http_status() {
        assert_eq!(status_of("HTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n"), Some(201));
        assert_eq!(status_of("HTTP/1.0 413 Payload Too Large\r\n"), Some(413));
        assert_eq!(status_of("SSH-2.0-OpenSSH\r\n"), None);
        assert_eq!(status_of(""), None);
    }
}
