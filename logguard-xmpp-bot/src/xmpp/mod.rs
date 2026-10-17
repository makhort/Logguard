//! The XMPP side: login, presence and vCard, and turning chat messages into commands.

use std::collections::{BTreeMap, VecDeque};
use std::io::Cursor;
use std::path::Path;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use futures::StreamExt;
use sasl::common::{ChannelBinding, Credentials};
use sha1::{Digest, Sha1};
use tokio::signal::unix::{signal, SignalKind};
use tokio::sync::Notify;
use tokio_xmpp::connect::{DirectTlsServerConnector, DnsConfig, ServerConnector, StartTlsServerConnector};
use tokio_xmpp::jid::{BareJid, Jid};
use tokio_xmpp::minidom::Element;
use tokio_xmpp::parsers::caps::{self, Caps};
use tokio_xmpp::parsers::delay::Delay;
use tokio_xmpp::parsers::disco::{DiscoInfoResult, Identity};
use tokio_xmpp::parsers::displayed_markers::Displayed;
use tokio_xmpp::parsers::hashes::Algo;
use tokio_xmpp::parsers::iq::Iq;
use tokio_xmpp::parsers::legacy_omemo::Encrypted;
use tokio_xmpp::parsers::message::{Lang, Message, MessageType};
use tokio_xmpp::parsers::presence::{Presence, Type as PresenceType};
use tokio_xmpp::parsers::receipts::Received;
use tokio_xmpp::parsers::roster::{Ask, Roster, Subscription};
use tokio_xmpp::parsers::stanza_error::{DefinedCondition, ErrorType, StanzaError};
use tokio_xmpp::parsers::{ns, vcard_update};
use tokio_xmpp::xmlstream::{FallibleStreamElement, PendingFeaturesRecv, Timeouts};
use tokio_xmpp::{client_login, Client, Error, Event, IqRequest, Stanza};

use crate::commands::{Bot, Reply, Response};
use crate::ctl::{running_as_root, Ejabberdctl, RunAs};
use crate::i18n::Texts;
use crate::state::State;

mod omemo;
mod pep;
mod upload;
use crate::{Args, OmemoMode, OmemoTrust, Tls};

const BOT_FULL_NAME: &str = "Bot";
const BOT_TITLE: &str = "Account Administration Bot";
const BOT_ROLE: &str = "Chatbot";
const BOT_NOTE: &str = "Your account managment helper";
const AVATAR_MAX_SIZE: u32 = 512;
pub(crate) const HINTS: &str = "urn:xmpp:hints";
/// Connections that got through TLS but never online, in a row: then the password is
/// wrong (changed while the bot runs). mod_fail2ban bans after 5 failed logins (the
/// startup check is one of them).
const MAX_FAILED_LOGINS: u32 = 3;
/// A command delivered later than this (from offline storage, after the bot was down) is
/// not run: "/restart 5 confirm" an hour late is not what anyone wants.
const STALE_AFTER_SECS: i64 = 120;
/// Message ids remembered to drop redeliveries (stream resumption resends what the server
/// had no acknowledgement for).
const RECENT_IDS: usize = 500;
/// Stanzas held while waiting for an IQ answer; more wait in the client's own queue.
const MAX_BACKLOG: usize = 1000;

/// A login that retrying will not fix: wrong password, or no SCRAM-SHA-256. The process
/// then exits with [`LoginRefused::EXIT_CODE`], which the systemd unit does not restart.
#[derive(Debug)]
pub struct LoginRefused(String);

impl LoginRefused {
    pub const EXIT_CODE: u8 = 78; // EX_CONFIG
}

impl std::fmt::Display for LoginRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for LoginRefused {}

/// TLS to a fixed host and port, direct or via STARTTLS. With `channel_binding` off,
/// SCRAM runs without -PLUS even on TLS 1.3.
#[derive(Clone, Debug)]
struct Connector {
    dns: DnsConfig,
    direct_tls: bool,
    channel_binding: bool,
    /// Connections since the last time online (see [`MAX_FAILED_LOGINS`]); shared with
    /// the main loop, which resets it, and by the clones tokio-xmpp makes.
    attempts: Arc<AtomicU32>,
    gave_up: Arc<Notify>,
}

impl ServerConnector for Connector {
    // the same TLS-over-TCP stream type for both
    type Stream = <StartTlsServerConnector as ServerConnector>::Stream;

    async fn connect(
        &self,
        jid: &Jid,
        ns: &'static str,
        timeouts: Timeouts,
    ) -> Result<(PendingFeaturesRecv<Self::Stream>, ChannelBinding), Error> {
        let (stream, cb) = if self.direct_tls {
            DirectTlsServerConnector(self.dns.clone()).connect(jid, ns, timeouts).await?
        } else {
            StartTlsServerConnector(self.dns.clone()).connect(jid, ns, timeouts).await?
        };
        // Only connections that reached the server count: while ejabberd restarts, TCP
        // connects fail and the client may keep retrying.
        if self.attempts.fetch_add(1, Ordering::SeqCst) >= MAX_FAILED_LOGINS {
            // tokio-xmpp would retry the login forever; the main loop stops instead
            self.gave_up.notify_one();
            std::future::pending::<()>().await;
        }
        Ok((stream, if self.channel_binding { cb } else { ChannelBinding::None }))
    }
}

/// The mechanism tokio-xmpp will pick: SCRAM-SHA-256-PLUS when there is a channel
/// binding, else SCRAM-SHA-256.
fn mechanism(channel_binding: bool) -> &'static str {
    if channel_binding {
        "SCRAM-SHA-256-PLUS"
    } else {
        "SCRAM-SHA-256"
    }
}

/// One login before the client starts. The client retries a failed login forever
/// (backing off to 30 s), which would trip mod_fail2ban; a bad password or a server
/// without SCRAM-SHA-256 should stop the bot instead. Leaves channel binding on only when
/// the server offers SCRAM-SHA-256-PLUS and accepts our (tls-exporter) binding.
async fn check_login(connector: &mut Connector, jid: &Jid, password: &str) -> Result<()> {
    loop {
        let (pending, cb) = connector.connect(jid, ns::JABBER_CLIENT, Timeouts::default()).await?;
        let (features, stream) =
            pending.recv_features::<FallibleStreamElement>().await.map_err(|e| anyhow::anyhow!("reading stream features: {e}"))?;
        let offered = features.sasl_mechanisms;
        let have_cb = !matches!(cb, ChannelBinding::None);
        let mech = mechanism(have_cb);
        if have_cb && !offered.contains(mech) {
            // Without this, tokio-xmpp would move on to SCRAM-SHA-1-PLUS or PLAIN.
            connector.channel_binding = false;
            continue;
        }
        if !offered.contains(mech) {
            let msg = format!("the server offers no {mech} (it offers: {offered:?}); refusing weaker mechanisms");
            return Err(LoginRefused(msg).into());
        }
        let creds = Credentials::default()
            .with_username(jid.node().map(|n| n.as_str()).unwrap_or_default())
            .with_password(password)
            .with_channel_binding(cb);
        match client_login(stream, offered, creds).await {
            Ok(_) => {
                log::info!("Login check passed with {mech}");
                return Ok(());
            }
            Err(Error::Auth(e)) if have_cb => {
                log::warn!("{mech} failed ({e}); retrying without channel binding");
                connector.channel_binding = false;
            }
            Err(Error::Auth(e)) => return Err(LoginRefused(format!("login as {jid} with {mech} failed: {e}")).into()),
            Err(e) => bail!("login as {jid}: {e}"),
        }
    }
}

/// The bot's picture as a JPEG of at most 512×512.
struct Avatar {
    jpeg: Vec<u8>,
    /// SHA-1 of the JPEG: the id of XEP-0153 and XEP-0084 avatars.
    sha1: [u8; 20],
    width: u32,
    height: u32,
}

impl Avatar {
    fn id(&self) -> String {
        self.sha1.iter().map(|b| format!("{b:02x}")).collect()
    }
}

fn prepare_avatar(path: &Path) -> Result<Avatar> {
    let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let mut img = image::load_from_memory(&raw)?;
    if img.width() > AVATAR_MAX_SIZE || img.height() > AVATAR_MAX_SIZE {
        img = img.resize(AVATAR_MAX_SIZE, AVATAR_MAX_SIZE, image::imageops::FilterType::Lanczos3);
    }
    let mut jpeg = Cursor::new(Vec::new());
    image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpeg, 85).encode_image(&img.to_rgb8())?;
    let jpeg = jpeg.into_inner();
    let sha1 = Sha1::digest(&jpeg).into();
    Ok(Avatar { jpeg, sha1, width: img.width(), height: img.height() })
}

const AVATAR_DATA: &str = "urn:xmpp:avatar:data";
const MAM: &str = "urn:xmpp:mam:2";
const AVATAR_METADATA: &str = "urn:xmpp:avatar:metadata";

/// XEP-0084 payloads: the image, and the metadata pointing at it.
fn avatar_items(avatar: &Avatar) -> (Element, Element) {
    use base64::Engine;
    use pep::n;
    let data = Element::builder("data", AVATAR_DATA).append(base64::engine::general_purpose::STANDARD.encode(&avatar.jpeg)).build();
    let info = Element::builder("info", AVATAR_METADATA)
        .attr(n("bytes"), avatar.jpeg.len().to_string())
        .attr(n("id"), avatar.id())
        .attr(n("type"), "image/jpeg")
        .attr(n("width"), avatar.width.to_string())
        .attr(n("height"), avatar.height.to_string())
        .build();
    (data, Element::builder("metadata", AVATAR_METADATA).append(info).build())
}

fn vcard(args: &Args, jid: &BareJid, avatar: Option<&[u8]>) -> Element {
    use base64::Engine;
    let el = |name: &str, text: &str| Element::builder(name, ns::VCARD).append(text).build();
    let mut b = Element::builder("vCard", ns::VCARD)
        .append(el("VERSION", "3.0"))
        .append(el("FN", BOT_FULL_NAME))
        .append(el("NICKNAME", jid.node().map(|n| n.as_str()).unwrap_or_default()))
        .append(el("TITLE", BOT_TITLE))
        .append(el("ROLE", BOT_ROLE))
        .append(el("URL", &format!("https://{}/", args.domain)))
        .append(el("NOTE", BOT_NOTE))
        .append(el("SORT-STRING", &args.name))
        .append(Element::builder("N", ns::VCARD).append(el("GIVEN", BOT_FULL_NAME)));
    if let Some(org) = &args.org_name {
        b = b.append(Element::builder("ORG", ns::VCARD).append(el("ORGNAME", org)).append(el("ORGUNIT", &args.domain)));
    }
    if let Some(jpeg) = avatar {
        let b64 = base64::engine::general_purpose::STANDARD.encode(jpeg);
        b = b.append(Element::builder("PHOTO", ns::VCARD).append(el("TYPE", "image/jpeg")).append(el("BINVAL", &b64)));
    }
    b.build()
}

/// Whether `current` has every field of `wanted` with the same text (BINVAL compared
/// without whitespace, which servers may re-wrap). Extra fields on the server are fine.
fn vcard_matches(current: &Element, wanted: &Element) -> bool {
    wanted.children().all(|w| {
        let Some(c) = current.get_child(w.name(), w.ns().as_str()) else {
            return false;
        };
        if w.children().next().is_some() {
            vcard_matches(c, w)
        } else if w.name() == "BINVAL" {
            let strip = |s: String| s.split_whitespace().collect::<String>();
            strip(c.text()) == strip(w.text())
        } else {
            c.text().trim() == w.text().trim()
        }
    })
}

/// XEP-0334 hint on every message of the bot: not into the MAM archive (mod_mam has
/// `default: always`), on either side. Offline storage still delivers it: ejabberd skips
/// that only for `no-store`.
pub(crate) fn no_archive() -> Element {
    Element::builder("no-permanent-store", HINTS).build()
}

/// Not into offline storage either.
fn no_store() -> Element {
    Element::builder("no-store", HINTS).build()
}

/// A plain-text reply. One holding a secret skips offline storage too: the user just
/// wrote, so is online, and the secret then never sits in the server's database.
fn chat(to: Jid, reply: Reply) -> Message {
    let mut hints = vec![no_archive()];
    if reply.secret {
        hints.push(no_store());
    }
    Message::new_with_type(MessageType::Chat, Some(to)).with_body(Lang::default(), reply.text).with_payloads(hints)
}

/// What the bot tells others it supports (XEP-0030), and in its presence (XEP-0115).
fn disco_info(name: &str) -> DiscoInfoResult {
    DiscoInfoResult {
        node: None,
        identities: vec![Identity::new("client", "bot", "en", name)],
        features: [ns::DISCO_INFO, ns::PING, ns::RECEIPTS, ns::DISPLAYED_MARKERS].into_iter().map(String::from).collect(),
        extensions: vec![],
    }
}

fn caps_of(node: &str, disco: &DiscoInfoResult) -> Caps {
    let hash = caps::hash_caps(&caps::compute_disco(disco), Algo::Sha_1).expect("SHA-1 is supported");
    Caps::new(node, hash)
}

/// The answer to an IQ request: pings, disco#info and roster pushes (only from our own
/// account: anyone else's is spoofed) are answered, everything else is "not supported".
fn iq_reply(iq: Iq, bot_jid: &str, disco: &DiscoInfoResult) -> Option<Iq> {
    let from_self = |from: &Option<Jid>| from.as_ref().is_none_or(|f| f.to_string().to_lowercase() == bot_jid);
    enum Answer {
        Empty,
        Payload(Element),
        NotSupported,
    }
    let (from, id, answer) = match iq {
        Iq::Get { from, id, payload, .. } => {
            let answer = if payload.is("ping", ns::PING) {
                Answer::Empty
            } else if payload.is("query", ns::DISCO_INFO) {
                let mut info = disco.clone();
                info.node = payload.attr("node").map(String::from);
                Answer::Payload(info.into())
            } else {
                Answer::NotSupported
            };
            (from, id, answer)
        }
        Iq::Set { from, id, payload, .. } => {
            let answer = if payload.is("query", ns::ROSTER) && from_self(&from) { Answer::Empty } else { Answer::NotSupported };
            (from, id, answer)
        }
        _ => return None,
    };
    Some(match answer {
        Answer::Empty => Iq::Result { from: None, to: from, id, payload: None },
        Answer::Payload(p) => Iq::Result { from: None, to: from, id, payload: Some(p) },
        Answer::NotSupported => {
            let error = StanzaError {
                type_: ErrorType::Cancel,
                by: None,
                defined_condition: DefinedCondition::ServiceUnavailable,
                texts: BTreeMap::new(),
                other: None,
            };
            Iq::Error { from: None, to: from, id, error, payload: None }
        }
    })
}

/// What the bot does for a user, given its roster item (subscription, pending request of
/// ours) if any: (approve theirs, ask for ours). Both directions are needed: ejabberd sends
/// the bot's PEP items (avatar, OMEMO keys) when the user's presence reaches the bot.
fn subscription_steps(item: Option<(Subscription, Ask)>) -> (bool, bool) {
    let (sub, ask) = item.unwrap_or((Subscription::None, Ask::None));
    let approve = matches!(sub, Subscription::None | Subscription::To);
    let request = matches!(sub, Subscription::None | Subscription::From) && ask != Ask::Subscribe;
    (approve, request)
}

/// How long ago a delayed (XEP-0203) message was sent, in seconds.
fn delayed_by(m: &Message, now: chrono::DateTime<chrono::Utc>) -> Option<i64> {
    let delay = m.payloads.iter().find(|p| p.is("delay", ns::DELAY)).and_then(|p| Delay::try_from(p.clone()).ok())?;
    Some((now - delay.stamp.0.with_timezone(&chrono::Utc)).num_seconds())
}

/// The reply instead of running a command that arrived too late, if it did.
fn stale_reply(m: &Message, now: chrono::DateTime<chrono::Utc>, t: &Texts) -> Option<String> {
    let secs = delayed_by(m, now).filter(|&s| s > STALE_AFTER_SECS)?;
    Some(t.not_run_late.replace("{time}", &crate::i18n::duration(t, secs)))
}

/// XEP-0184 receipt and XEP-0333 displayed marker for `m`, as far as it asks for them.
fn acknowledgements(m: &Message, to: &Jid) -> Vec<Message> {
    let Some(id) = &m.id else { return vec![] };
    let ack = |payload: Element| {
        Message::new_with_type(MessageType::Chat, Some(to.clone())).with_payloads(vec![payload, no_archive(), no_store()])
    };
    let mut acks = Vec::new();
    if m.payloads.iter().any(|p| p.is("request", ns::RECEIPTS)) {
        acks.push(ack(Received { id: id.0.clone() }.into()));
    }
    if m.payloads.iter().any(|p| p.is("markable", ns::DISPLAYED_MARKERS)) {
        acks.push(ack(Displayed { id: id.clone() }.into()));
    }
    acks
}

struct Session {
    client: Client,
    bot: Bot<Ejabberdctl>,
    vcard: Element,
    avatar: Option<Avatar>,
    omemo: Option<omemo::OmemoCtx>,
    disco: DiscoInfoResult,
    caps: Caps,
    /// Events that came in while waiting for an IQ answer (see [`Session::iq_within`]).
    backlog: VecDeque<Event>,
    /// (sender, message id) of the latest messages.
    recent: VecDeque<(String, String)>,
    upload: upload::UploadCtx,
    /// Bound and not disconnected since.
    online: bool,
}

impl Session {
    async fn send(&mut self, stanza: impl Into<Stanza>) {
        if let Err(e) = self.client.send_stanza(stanza.into()).await {
            log::error!("sending: {e}");
        }
    }

    async fn on_online(&mut self) {
        // presence first: it also makes the server hand over pending subscription requests
        let mut presence = Presence::new(PresenceType::None);
        presence.payloads.push(self.caps.clone().into());
        if let Some(a) = &self.avatar {
            let update = vcard_update::VCardUpdate { photo: Some(vcard_update::Photo { data: Some(a.sha1) }) };
            presence.payloads.push(update.into());
        }
        self.send(presence).await;
        self.disable_own_archive().await;
        self.update_vcard().await;
        self.publish_avatar().await;
        self.omemo_publish().await;
        self.complete_subscriptions().await;
    }

    /// XEP-0313 preferences: archive nothing for the bot's account. Its replies carry a
    /// no-archive hint anyway; this also covers what users send to the bot.
    async fn disable_own_archive(&mut self) {
        let prefs = Element::builder("prefs", MAM).attr(pep::n("default"), "never").build();
        match self.iq(None, IqRequest::Set(prefs)).await {
            Ok(_) => log::info!("message archive of the bot's account: never"),
            Err(e) => log::warn!("setting the bot's archive preferences: {}", e.text),
        }
    }

    /// Stores the vCard unless the server already has it: on example.org a vCard set
    /// takes ~10 s (cause not visible in ejabberd's info log), on every reconnect.
    async fn update_vcard(&mut self) {
        let started = std::time::Instant::now();
        let get = Element::builder("vCard", ns::VCARD).build();
        if let Ok(Some(current)) = self.iq(None, IqRequest::Get(get)).await {
            if vcard_matches(&current, &self.vcard) {
                log::info!("vCard unchanged (checked in {} ms)", started.elapsed().as_millis());
                return;
            }
        }
        let started = std::time::Instant::now();
        match self.iq_within(None, IqRequest::Set(self.vcard.clone()), Duration::from_secs(60)).await {
            Ok(_) => log::info!("vCard set in {} ms", started.elapsed().as_millis()),
            Err(e) => log::error!("Failed to set vCard: {}", e.text),
        }
    }

    /// The XEP-0084 avatar, which is what Conversations shows for contacts (it uses the
    /// vCard photo only for servers). Skipped when the published one is already current.
    async fn publish_avatar(&mut self) {
        let Some(avatar) = &self.avatar else { return };
        let id = avatar.id();
        let (data, metadata) = avatar_items(avatar);
        if let Ok(Some(current)) = self.iq(None, IqRequest::Get(pep::items_request(AVATAR_METADATA))).await {
            if pep::first_item_id(&current) == Some(id.as_str()) {
                log::info!("avatar already published");
                return;
            }
        }
        // data before metadata: clients fetch the data when the metadata arrives
        let result = match self.publish(AVATAR_DATA, &id, data).await {
            Ok(()) => self.publish(AVATAR_METADATA, &id, metadata).await,
            Err(e) => Err(e),
        };
        match result {
            Ok(()) => log::info!("avatar published"),
            Err(e) => log::error!("publishing the avatar: {e}"),
        }
    }

    /// Approves subscription requests from the admin and allowed users, so they get the
    /// bot's presence and PEP notifications (avatar, OMEMO device list).
    async fn on_presence(&mut self, p: Presence) {
        if p.type_ != PresenceType::Subscribe {
            return;
        }
        let Some(from) = p.from else { return };
        let bare = from.to_bare();
        let sender = bare.to_string().to_lowercase();
        if bare.domain().as_str() != self.bot.domain || !self.bot.may_use(&sender) {
            log::info!("subscription request from {sender} left unanswered");
            return;
        }
        let mut approval = Presence::new(PresenceType::Subscribed);
        approval.to = Some(bare.clone().into());
        self.send(approval).await;
        log::info!("subscription of {sender} approved");
        self.subscribe_to(bare).await;
    }

    /// Asks for the user's presence. ejabberd sends a contact's PEP items (avatar, OMEMO
    /// device list) when that contact's presence reaches the publisher's account, which
    /// only happens with a subscription in that direction too.
    async fn subscribe_to(&mut self, jid: BareJid) {
        let mut request = Presence::new(PresenceType::Subscribe);
        request.to = Some(jid.clone().into());
        self.send(request).await;
        log::info!("asked {jid} for a presence subscription");
    }

    /// Makes the subscription mutual with the admin and every allowed user of our domain,
    /// whether or not they ever added the bot as a contact: the bot approves them (which
    /// also answers a request that came before they were allowed) and asks for theirs
    /// (see [`Session::subscribe_to`]). Users who added the bot accept that automatically
    /// in Conversations; others see the request once.
    async fn complete_subscriptions(&mut self) {
        let roster = match self.iq(None, IqRequest::Get(Element::builder("query", ns::ROSTER).build())).await {
            Ok(Some(el)) => match Roster::try_from(el) {
                Ok(r) => r,
                Err(e) => return log::warn!("roster: {e}"),
            },
            Ok(None) => return,
            Err(e) => return log::warn!("fetching the roster: {}", e.text),
        };
        let mut users: Vec<String> = self.bot.state.users_with_bot_access().iter().map(|j| j.to_lowercase()).collect();
        users.push(self.bot.admin_jid.clone());
        for user in users {
            let Ok(jid) = user.parse::<BareJid>() else { continue };
            if jid.domain().as_str() != self.bot.domain {
                continue;
            }
            let item = roster.items.iter().find(|i| i.jid.to_string().to_lowercase() == user);
            let (approve, ask) = subscription_steps(item.map(|i| (i.subscription.clone(), i.ask.clone())));
            if approve {
                let mut approval = Presence::new(PresenceType::Subscribed);
                approval.to = Some(jid.clone().into());
                self.send(approval).await;
                log::info!("subscription of {jid} approved");
            }
            if ask {
                self.subscribe_to(jid).await;
            }
        }
    }

    /// Runs a command; if it changed who may use the bot (/allow, /deny, /remove),
    /// sets up the subscriptions of newly allowed users.
    pub(super) async fn run_command(&mut self, sender: &str, device: Option<&str>, body: &str) -> Option<Response> {
        let before = self.bot.state.users_with_bot_access().to_vec();
        let response = self.bot.process_from(sender, device, body, chrono::Utc::now()).await;
        if self.bot.state.users_with_bot_access().iter().any(|j| !before.contains(j)) {
            self.complete_subscriptions().await;
        }
        response
    }

    /// Whether `sender`'s message `id` was handled already; remembers it if not.
    fn seen_before(&mut self, sender: &str, id: &str) -> bool {
        if self.recent.iter().any(|(s, i)| s == sender && i == id) {
            return true;
        }
        if self.recent.len() >= RECENT_IDS {
            self.recent.pop_front();
        }
        self.recent.push_back((sender.to_owned(), id.to_owned()));
        false
    }

    async fn on_message(&mut self, m: Message) {
        if !matches!(m.type_, MessageType::Chat | MessageType::Normal) {
            return;
        }
        let Some(from) = m.from.clone() else { return };
        // exactly our domain: the Python bot's suffix test let "evil<domain>" through
        if from.domain().as_str() != self.bot.domain {
            return;
        }
        let sender = from.to_bare().to_string().to_lowercase();
        if !self.bot.may_use(&sender) {
            return;
        }
        if let Some(id) = &m.id {
            if self.seen_before(&sender, &id.0) {
                log::info!("{sender}: message {} delivered again, ignored", id.0);
                return;
            }
        }
        for ack in acknowledgements(&m, &from) {
            self.send(ack).await;
        }
        let t = self.bot.language_of(&sender).texts();
        let stale = stale_reply(&m, chrono::Utc::now(), t);
        if stale.is_some() {
            log::info!("{sender}: delayed command not run ({}s late)", delayed_by(&m, chrono::Utc::now()).unwrap_or(0));
        }
        // before the body: an encrypted message's body is only a fallback text
        if let Some(el) = m.payloads.iter().find(|p| p.is("encrypted", crate::omemo::NS)) {
            match Encrypted::try_from(el.clone()) {
                Ok(encrypted) => self.on_encrypted(from, &sender, encrypted, stale).await,
                Err(e) => log::warn!("{sender}: malformed OMEMO element: {e}"),
            }
            return;
        }
        let Some((_, body)) = m.get_best_body_cloned(vec![]) else { return };
        if let Some(text) = stale {
            self.send(chat(from, text.into())).await;
            return;
        }
        if body.trim() == "/omemo" {
            let info = self.omemo_info(&sender).await;
            self.send(chat(from, info.into())).await;
            return;
        }
        if self.omemo.as_ref().is_some_and(|c| c.required) {
            log::info!("{sender}: unencrypted message refused");
            self.send(chat(from, t.omemo_required.into())).await;
            return;
        }
        let device = from.resource().map(|r| r.as_str().to_owned());
        let Some(response) = self.run_command(&sender, device.as_deref(), &body).await else {
            return;
        };
        let command = body.split_whitespace().next().unwrap_or("");
        log::info!("{sender}: {command}");
        self.send(chat(from.clone(), response.reply)).await;
        if response.attachment.is_some() {
            // files go out encrypted only
            self.send(chat(from, t.export_file_needs_omemo.into())).await;
        }
        if let Some(note) = response.notify_admin {
            self.notify_admin(note).await;
        }
    }
}

pub async fn run(args: Args) -> Result<()> {
    let _ = tokio_xmpp::rustls::crypto::ring::default_provider().install_default();

    let run_as = if running_as_root() {
        let r = RunAs::lookup(&args.ejabberd_user).map_err(|e| crate::ConfigError(format!("EJABBERD_USER: {e}")))?;
        log::info!("ejabberdctl runs as {}", r.name);
        Some(r)
    } else {
        None
    };
    let ctl = Ejabberdctl { path: args.ejabberdctl.clone(), run_as, db: args.ejabberd_db.clone(), sqlite3: args.sqlite3.clone() };
    if let Err(e) = ctl.check().await {
        bail!("ejabberdctl not found or not accessible: {e}");
    }
    let state = State::load(&args.state_path)?;
    let bot_jid = args.jid.split('/').next().unwrap_or(&args.jid).to_lowercase();
    let invite_url = args.invite_url.clone().unwrap_or_else(|| format!("https://{}:5281/invites", args.domain));
    let retention = crate::commands::Retention {
        messages: args.retention_message_days,
        files: args.retention_file_days,
        max_file_mb: args.upload_max_mb,
        accounts: args.retention_account_days,
        rooms: args.retention_room_days,
        reports: args.abuse_report_days,
        security: args.security_record_days,
    };
    // JIDs arrive with their domain in lower case (nodeprep/nameprep): compare with that
    let domain = args.domain.trim().to_lowercase();
    let announce_languages = crate::i18n::parse_languages(&args.announce_languages)
        .map_err(|e| crate::ConfigError(format!("ANNOUNCE_LANGUAGES {}: {e}", args.announce_languages)))?;
    let bot = Bot { domain, retention, invite_url, admin_jid: args.admin.to_lowercase(), bot_jid, state, ctl, announce_languages };

    let jid: Jid = args.jid.parse().with_context(|| format!("--jid {}", args.jid))?;
    let jid: Jid = match jid.try_into_full() {
        Ok(full) => full.into(),
        Err(bare) => bare.with_resource_str("bot")?.into(),
    };
    let password = args.password.clone().unwrap_or_default();

    let avatar = match &args.avatar_path {
        Some(p) => match prepare_avatar(p) {
            Ok(a) => Some(a),
            Err(e) => {
                log::error!("avatar {}: {e:#}; going without", p.display());
                None
            }
        },
        None => None,
    };

    // local files first: a broken store should not cost a login
    let omemo = match args.omemo {
        OmemoMode::Off => None,
        mode => {
            let state_dir = args.state_path.parent().unwrap_or(Path::new("."));
            let store_path = args.omemo_store.clone().unwrap_or_else(|| state_dir.join("omemo.json"));
            let trust_file = args.omemo_trust_file.clone().unwrap_or_else(|| state_dir.join("omemo-trust.txt"));
            let store = crate::omemo::Omemo::open(&store_path, chrono::Utc::now().timestamp())?;
            log::info!(
                "OMEMO {}: device {}, fingerprint {}",
                if mode == OmemoMode::Required { "required" } else { "on" },
                store.device_id(),
                crate::omemo::trust::pretty(&store.fingerprint())
            );
            let strict = args.omemo_trust == OmemoTrust::Pinned;
            if !crate::omemo::trust::Pins::load(&trust_file, strict).has_pins(&args.admin.to_lowercase()) {
                let which = if strict { "none" } else { "any" };
                log::warn!("no OMEMO key pinned for {} in {}: {which} of its devices is trusted", args.admin, trust_file.display());
            }
            Some(omemo::OmemoCtx::new(mode == OmemoMode::Required, strict, store, trust_file))
        }
    };
    let attempts = Arc::new(AtomicU32::new(0));
    let gave_up = Arc::new(Notify::new());
    let mut connector = Connector {
        dns: DnsConfig::no_srv(&args.server, args.port),
        direct_tls: match args.tls {
            Tls::Direct => true,
            Tls::Starttls => false,
            Tls::Auto => args.port == 5223,
        },
        channel_binding: true,
        attempts: attempts.clone(),
        gave_up: gave_up.clone(),
    };
    check_login(&mut connector, &jid, &password).await?;
    attempts.store(0, Ordering::SeqCst);

    let vcard = vcard(&args, &jid.to_bare(), avatar.as_ref().map(|a| a.jpeg.as_slice()));
    let disco = disco_info(&args.name);
    let caps = caps_of(&format!("https://{}/logguard-xmpp-bot", args.domain), &disco);
    let client = Client::new_with_connector(jid, password, connector, Timeouts::default());
    let upload = upload::UploadCtx {
        outbox: args.outbox_dir.clone().unwrap_or_else(|| args.state_path.parent().unwrap_or(Path::new(".")).join("outbox")),
        max_age: Duration::from_secs(u64::from(args.outbox_max_days) * 86400),
        configured: match &args.upload_service {
            Some(s) => Some(s.parse().map_err(|e| crate::ConfigError(format!("UPLOAD_SERVICE {s}: {e}")))?),
            None => None,
        },
        service: None,
    };
    let mut session = Session {
        client,
        bot,
        vcard,
        avatar,
        omemo,
        disco,
        caps,
        backlog: VecDeque::new(),
        recent: VecDeque::new(),
        upload,
        online: false,
    };

    let mut sigterm = signal(SignalKind::terminate())?;
    let mut sigint = signal(SignalKind::interrupt())?;
    // key rotation checks; the first tick is immediate (the keys were just refreshed)
    let mut maintenance = tokio::time::interval(Duration::from_secs(6 * 3600));
    // state.json cleanup; the first tick is now
    let mut prune = tokio::time::interval(Duration::from_secs(24 * 3600));
    // files for the admin (logguard's weekly report); also checked right after login
    let mut outbox = tokio::time::interval(Duration::from_secs(300));
    // logguard's alerts: it sends one the bot hasn't taken within 2 minutes itself, unencrypted
    let mut alerts = tokio::time::interval(Duration::from_secs(5));
    alerts.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let recovered = crate::outbox::recover(&session.upload.outbox);
    if recovered > 0 {
        log::info!("outbox: {recovered} alert(s) left half-sent at the last stop, sending again");
    }
    let mut result = Ok(());
    loop {
        let event = match session.backlog.pop_front() {
            Some(e) => Some(e),
            None => tokio::select! {
                e = session.client.next() => e,
                _ = maintenance.tick() => {
                    session.omemo_maintenance().await;
                    continue;
                }
                _ = prune.tick() => {
                    session.bot.prune_state(chrono::Utc::now()).await;
                    continue;
                }
                _ = outbox.tick() => {
                    session.deliver_outbox().await;
                    continue;
                }
                _ = alerts.tick() => {
                    session.deliver_messages().await;
                    continue;
                }
                _ = gave_up.notified() => {
                    let msg = format!(
                        "{MAX_FAILED_LOGINS} logins in a row failed (password changed?); stopping before mod_fail2ban bans this address"
                    );
                    result = Err(LoginRefused(msg).into());
                    break;
                }
                _ = sigterm.recv() => break,
                _ = sigint.recv() => break,
            },
        };
        match event {
            None => break,
            Some(Event::Online { bound_jid, resumed, .. }) => {
                attempts.store(0, Ordering::SeqCst);
                session.online = true;
                if resumed {
                    log::info!("Stream resumed as {bound_jid}");
                } else {
                    log::info!("Online as {bound_jid}");
                    session.on_online().await;
                    session.deliver_messages().await;
                    session.deliver_outbox().await;
                }
            }
            Some(Event::Disconnected(e)) => {
                session.online = false;
                log::warn!("Disconnected: {e}; reconnecting");
            }
            Some(Event::Stanza(Stanza::Message(m))) => session.on_message(m).await,
            Some(Event::Stanza(Stanza::Iq(iq))) => {
                if let Some(reply) = iq_reply(iq, &session.bot.bot_jid, &session.disco) {
                    session.send(reply).await;
                }
            }
            Some(Event::Stanza(Stanza::Presence(p))) => session.on_presence(p).await,
        }
    }
    log::info!("Shutting down");
    let _ = tokio::time::timeout(Duration::from_secs(5), session.client.send_end()).await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iq_answers() {
        let disco = disco_info("Admin Bot");
        let reply = |iq| iq_reply(iq, "bot@example.org", &disco);
        let from: Jid = "admin@example.org/phone".parse().unwrap();
        let ping = Iq::Get { from: Some(from.clone()), to: None, id: "1".into(), payload: Element::builder("ping", ns::PING).build() };
        assert!(matches!(reply(ping), Some(Iq::Result { id, payload: None, .. }) if id == "1"));
        let version =
            Iq::Get { from: Some(from.clone()), to: None, id: "2".into(), payload: Element::builder("query", "jabber:iq:version").build() };
        assert!(matches!(reply(version), Some(Iq::Error { error, .. })
            if error.defined_condition == DefinedCondition::ServiceUnavailable));

        let query = Element::builder("query", ns::DISCO_INFO).attr(pep::n("node"), "n#v").build();
        let Some(Iq::Result { payload: Some(p), .. }) =
            reply(Iq::Get { from: Some(from.clone()), to: None, id: "3".into(), payload: query })
        else {
            panic!("no disco#info result")
        };
        let info = DiscoInfoResult::try_from(p).unwrap();
        assert_eq!(info.node.as_deref(), Some("n#v"));
        assert!(info.features.contains(ns::RECEIPTS) && info.features.contains(ns::DISPLAYED_MARKERS));

        // roster pushes: acknowledged from our own account only
        let push = |from: Option<&str>| Iq::Set {
            from: from.map(|f| f.parse().unwrap()),
            to: None,
            id: "4".into(),
            payload: Element::builder("query", ns::ROSTER).build(),
        };
        assert!(matches!(reply(push(None)), Some(Iq::Result { .. })));
        assert!(matches!(reply(push(Some("bot@example.org"))), Some(Iq::Result { .. })));
        assert!(matches!(reply(push(Some("admin@example.org/phone"))), Some(Iq::Error { .. })));
    }

    #[test]
    fn subscriptions_become_mutual() {
        use Subscription as S;
        assert_eq!(subscription_steps(None), (true, true), "never added the bot");
        assert_eq!(subscription_steps(Some((S::None, Ask::None))), (true, true));
        assert_eq!(subscription_steps(Some((S::From, Ask::None))), (false, true));
        assert_eq!(subscription_steps(Some((S::From, Ask::Subscribe))), (false, false), "already asked");
        assert_eq!(subscription_steps(Some((S::To, Ask::None))), (true, false));
        assert_eq!(subscription_steps(Some((S::Both, Ask::None))), (false, false));
    }

    #[test]
    fn late_commands_are_not_run() {
        let now = chrono::Utc::now();
        let mut m = Message::new_with_type(MessageType::Chat, None);
        let t = &crate::i18n::EN;
        assert_eq!(stale_reply(&m, now, t), None);
        let delay = |secs: i64| {
            let stamp = (now - chrono::Duration::seconds(secs)).to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
            Element::builder("delay", ns::DELAY).attr(pep::n("stamp"), stamp).build()
        };
        m.payloads = vec![delay(30)];
        assert_eq!(stale_reply(&m, now, t), None);
        m.payloads = vec![delay(3 * 3600)];
        assert!(stale_reply(&m, now, t).unwrap().contains("sent 3 h ago"), "{:?}", stale_reply(&m, now, t));
        let uk = stale_reply(&m, now, &crate::i18n::UK).unwrap();
        assert!(uk.contains("надіслано 3 год тому"), "{uk}");
    }

    #[test]
    fn receipts_and_markers_when_asked() {
        let to: Jid = "admin@example.org/phone".parse().unwrap();
        let mut m = Message::new_with_type(MessageType::Chat, None);
        m.id = Some(tokio_xmpp::parsers::message::Id("abc".into()));
        assert!(acknowledgements(&m, &to).is_empty());
        m.payloads = vec![Element::builder("request", ns::RECEIPTS).build(), Element::builder("markable", ns::DISPLAYED_MARKERS).build()];
        let acks: Vec<Element> = acknowledgements(&m, &to).into_iter().map(Element::from).collect();
        assert_eq!(acks.len(), 2);
        assert_eq!(acks[0].get_child("received", ns::RECEIPTS).unwrap().attr("id"), Some("abc"));
        assert_eq!(acks[1].get_child("displayed", ns::DISPLAYED_MARKERS).unwrap().attr("id"), Some("abc"));
        assert!(acks.iter().all(|a| a.has_child("no-store", HINTS) && a.get_child("body", "jabber:client").is_none()));
    }

    #[test]
    fn replies_are_not_archived() {
        let m: Element = chat("admin@example.org".parse().unwrap(), "list".into()).into();
        assert!(m.has_child("no-permanent-store", HINTS));
        assert!(!m.has_child("store", HINTS));
        assert!(!m.has_child("no-store", HINTS), "ordinary replies wait in offline storage");
        let secret = Reply { text: "Password: x".into(), secret: true };
        let m: Element = chat("admin@example.org".parse().unwrap(), secret).into();
        assert!(m.has_child("no-store", HINTS));
    }

    #[test]
    fn avatar_is_shrunk_to_a_jpeg() {
        let dir = std::env::temp_dir().join(format!("logguard-xmpp-bot-avatar-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("a.png");
        image::RgbaImage::from_pixel(1000, 600, image::Rgba([200, 30, 30, 255])).save(&path).unwrap();
        let a = prepare_avatar(&path).unwrap();
        let img = image::load_from_memory(&a.jpeg).unwrap();
        assert_eq!((img.width(), img.height()), (512, 307));
        assert_eq!((a.width, a.height), (512, 307));
        assert_eq!(a.sha1, <[u8; 20]>::from(Sha1::digest(&a.jpeg)));
    }

    #[test]
    fn vcard_comparison() {
        let wanted: Element = "<vCard xmlns='vcard-temp'><FN>Bot</FN><N><GIVEN>Bot</GIVEN></N>\
             <PHOTO><TYPE>image/jpeg</TYPE><BINVAL>QUJDREVG</BINVAL></PHOTO></vCard>"
            .parse()
            .unwrap();
        let same: Element = "<vCard xmlns='vcard-temp'><N><GIVEN>Bot</GIVEN></N><FN> Bot </FN><X-EXTRA>x</X-EXTRA>\
             <PHOTO><BINVAL>QUJD\nREVG</BINVAL><TYPE>image/jpeg</TYPE></PHOTO></vCard>"
            .parse()
            .unwrap();
        assert!(vcard_matches(&same, &wanted));
        let other_photo: Element = "<vCard xmlns='vcard-temp'><FN>Bot</FN><N><GIVEN>Bot</GIVEN></N>\
             <PHOTO><TYPE>image/jpeg</TYPE><BINVAL>QUJDREVH</BINVAL></PHOTO></vCard>"
            .parse()
            .unwrap();
        assert!(!vcard_matches(&other_photo, &wanted));
        let empty: Element = "<vCard xmlns='vcard-temp'/>".parse().unwrap();
        assert!(!vcard_matches(&empty, &wanted));
    }

    /// Conversations takes the metadata item whose id equals an <info id>, without url,
    /// of a type it knows; the data must hash to that id.
    #[test]
    fn xep0084_items() {
        let jpeg = vec![0xFF, 0xD8, 0xFF, 0xD9];
        let a = Avatar { sha1: Sha1::digest(&jpeg).into(), jpeg, width: 5, height: 7 };
        let (data, metadata) = avatar_items(&a);
        assert_eq!(data.text(), "/9j/2Q==");
        let info = metadata.get_child("info", AVATAR_METADATA).unwrap();
        assert_eq!(info.attr("id"), Some(a.id().as_str()));
        assert_eq!(a.id().len(), 40);
        assert_eq!(info.attr("type"), Some("image/jpeg"));
        assert_eq!(info.attr("bytes"), Some("4"));
        assert_eq!((info.attr("width"), info.attr("height")), (Some("5"), Some("7")));
        assert!(info.attr("url").is_none());
    }
}
