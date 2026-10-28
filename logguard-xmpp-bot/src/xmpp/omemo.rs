//! OMEMO over XMPP for the bot: publishing its device list and bundle (PEP, open access
//! as Conversations expects), fetching other devices' ones, decrypting commands and
//! encrypting replies to the sender's trusted devices.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use tokio_xmpp::jid::Jid;
use tokio_xmpp::minidom::Element;
use tokio_xmpp::parsers::legacy_omemo::{Bundle, DeviceList, Encrypted};
use tokio_xmpp::parsers::message::{Lang, Message, MessageType};
use tokio_xmpp::IqRequest;

use super::pep::{first_item, items_request, n};
use super::{chat, no_archive, Session};
use crate::commands::Reply;
use crate::omemo::session::SessionError;
use crate::omemo::trust::{pretty, Pins, Trust};
use crate::omemo::{self, Omemo, OmemoError};

const EME: &str = "urn:xmpp:eme:0";
const FALLBACK_BODY: &str = "I sent you an OMEMO encrypted message but your client doesn't seem to support that.";
/// How long a fetched device list is used before fetching it again.
const DEVICE_LIST_TTL: Duration = Duration::from_secs(600);
/// How long a device without a bundle (an abandoned one, usually) is left out.
const NO_BUNDLE_TTL: Duration = Duration::from_secs(3600);
/// Republishing our keys because a message was not for this device (or used an unknown
/// prekey) happens at most this often: every such message would otherwise cost two PEP
/// publishes.
const REPUBLISH_EVERY: Duration = Duration::from_secs(600);
/// Broken sessions rebuilt per run, in all and per user: each costs a bundle fetch, and a
/// sender can make up any number of device ids.
const MAX_HEALED: usize = 256;
const MAX_HEALED_PER_JID: usize = 8;

pub struct OmemoCtx {
    /// Refuse unencrypted commands.
    pub required: bool,
    /// Trust pinned keys only (no blind trust).
    pub strict: bool,
    pub store: Omemo,
    pub trust_file: PathBuf,
    devices: HashMap<String, (Vec<u32>, Instant)>,
    /// Devices whose bundle could not be fetched, and when.
    no_bundle: HashMap<(String, u32), Instant>,
    /// Devices whose broken session we already tried to rebuild in this run.
    healed: HashSet<(String, u32)>,
    /// When our keys were last republished after a message not meant for us.
    republished: Option<Instant>,
}

impl OmemoCtx {
    pub fn new(required: bool, strict: bool, store: Omemo, trust_file: PathBuf) -> Self {
        OmemoCtx {
            required,
            strict,
            store,
            trust_file,
            devices: HashMap::new(),
            no_bundle: HashMap::new(),
            healed: HashSet::new(),
            republished: None,
        }
    }

    /// The trust file as it is now (it is read for every decision, so edits apply at once).
    pub fn pins(&self) -> Pins {
        Pins::load(&self.trust_file, self.strict)
    }
}

fn encrypted_chat(to: Jid, encrypted: Encrypted) -> Message {
    let eme = Element::builder("encryption", EME).attr(n("name"), "OMEMO").attr(n("namespace"), omemo::NS).build();
    Message::new_with_type(MessageType::Chat, Some(to)).with_body(Lang::default(), FALLBACK_BODY.into()).with_payloads(vec![
        encrypted.into(),
        eme,
        no_archive(),
    ])
}

/// An `<encrypted>` without payload and body, as Conversations sends it (its `<store/>`
/// replaced by the bot's no-archive hint; offline storage still delivers it).
fn key_transport(to: Jid, encrypted: Encrypted) -> Message {
    Message::new_with_type(MessageType::Chat, Some(to)).with_payloads(vec![encrypted.into(), no_archive()])
}

impl Session {
    /// Our device list (just this device) and bundle.
    pub(super) async fn omemo_publish(&mut self) {
        let Some(ctx) = &self.omemo else { return };
        let list = DeviceList { devices: vec![tokio_xmpp::parsers::legacy_omemo::Device { id: ctx.store.device_id() }] };
        match self.publish(omemo::DEVICELIST_NODE, "current", list.into()).await {
            Ok(()) => log::info!("OMEMO device list published"),
            Err(e) => log::error!("publishing the OMEMO device list: {e}"),
        }
        self.omemo_publish_bundle().await;
    }

    pub(super) async fn omemo_publish_bundle(&mut self) {
        let Some(ctx) = &mut self.omemo else { return };
        if let Err(e) = ctx.store.refresh_keys(chrono::Utc::now().timestamp()) {
            log::error!("{e}");
        }
        let node = omemo::bundle_node(ctx.store.device_id());
        let bundle: Element = ctx.store.bundle().into();
        match self.publish(&node, "current", bundle).await {
            Ok(()) => log::info!("OMEMO bundle published"),
            Err(e) => log::error!("publishing the OMEMO bundle: {e}"),
        }
    }

    /// Rotates keys when due (the main loop calls this a few times a day).
    pub(super) async fn omemo_maintenance(&mut self) {
        let Some(ctx) = &mut self.omemo else { return };
        match ctx.store.refresh_keys(chrono::Utc::now().timestamp()) {
            Ok(true) => self.omemo_publish_bundle().await,
            Ok(false) => {}
            Err(e) => log::error!("{e}"),
        }
    }

    /// `jid`'s devices, from a cached list unless it is stale or lacks `include`.
    async fn devices_of(&mut self, jid: &str, include: Option<u32>) -> Vec<u32> {
        let cached = self.omemo.as_ref().and_then(|c| c.devices.get(jid).cloned());
        let fresh = cached
            .as_ref()
            .filter(|(list, at)| at.elapsed() < DEVICE_LIST_TTL && include.is_none_or(|d| list.contains(&d)))
            .map(|(list, _)| list.clone());
        let mut list = match fresh {
            Some(list) => list,
            None => {
                let to = jid.parse::<Jid>().ok();
                match self.iq(to, IqRequest::Get(items_request(omemo::DEVICELIST_NODE))).await {
                    Ok(Some(result)) => {
                        let list: Vec<u32> = first_item(&result)
                            .and_then(|el| DeviceList::try_from(el.clone()).ok())
                            .map(|l| l.devices.iter().map(|d| d.id).collect())
                            .unwrap_or_default();
                        if let Some(ctx) = &mut self.omemo {
                            ctx.devices.insert(jid.to_owned(), (list.clone(), Instant::now()));
                        }
                        list
                    }
                    Ok(None) => Vec::new(),
                    Err(e) => {
                        log::warn!("fetching {jid}'s OMEMO devices: {}", e.text);
                        cached.map(|(l, _)| l).unwrap_or_default()
                    }
                }
            }
        };
        if let Some(d) = include {
            if !list.contains(&d) {
                list.push(d);
            }
        }
        list
    }

    async fn fetch_bundle(&mut self, jid: &str, device: u32) -> Result<Bundle, String> {
        let to = jid.parse::<Jid>().ok();
        let result = self.iq(to, IqRequest::Get(items_request(&omemo::bundle_node(device)))).await.map_err(|e| e.text)?;
        let el = result.as_ref().and_then(first_item).ok_or("empty bundle node")?;
        Bundle::try_from(el.clone()).map_err(|e| e.to_string())
    }

    /// Encrypts `reply` for `bare`'s trusted devices (starting sessions as needed) and
    /// sends it to `to`. `also` is a device known to exist even if the device list
    /// fetch fails (the one that just wrote to us).
    pub(super) async fn send_encrypted(&mut self, to: Jid, bare: &str, also: Option<u32>, reply: &Reply) -> Result<(), String> {
        let targets = self.omemo_targets(bare, also).await?;
        let ctx = self.omemo.as_mut().ok_or("OMEMO is off")?;
        let encrypted = ctx.store.encrypt(bare, &targets, Some(&reply.text)).map_err(|e| e.to_string())?;
        self.send(encrypted_chat(to, encrypted)).await;
        Ok(())
    }

    /// `bare`'s trusted devices with a session, starting sessions as needed (see
    /// [`Session::send_encrypted`]); or why there are none.
    pub(super) async fn omemo_targets(&mut self, bare: &str, also: Option<u32>) -> Result<Vec<u32>, String> {
        let pins = self.omemo.as_ref().ok_or("OMEMO is off")?.pins();
        let devices = self.devices_of(bare, also).await;
        for &dev in &devices {
            let key = (bare.to_owned(), dev);
            let skip = self.omemo.as_ref().is_some_and(|c| {
                c.store.has_session(bare, dev) || (Some(dev) != also && c.no_bundle.get(&key).is_some_and(|t| t.elapsed() < NO_BUNDLE_TTL))
            });
            if skip {
                continue;
            }
            let bundle = match self.fetch_bundle(bare, dev).await {
                Ok(b) => b,
                Err(e) => {
                    log::warn!("{bare} device {dev}: no bundle: {e}; skipping it for an hour");
                    if let Some(c) = &mut self.omemo {
                        c.no_bundle.insert(key, Instant::now());
                    }
                    continue;
                }
            };
            let Some(ctx) = &mut self.omemo else { break };
            match Omemo::bundle_identity(&bundle) {
                Ok(ik) if pins.check(bare, &ik.fingerprint()).trusted() => {
                    if let Err(e) = ctx.store.start_session(bare, dev, &bundle) {
                        log::warn!("{bare} device {dev}: {e}");
                    }
                }
                Ok(ik) => log::info!("{bare} device {dev}: key {} not pinned, not encrypting for it", ik.fingerprint()),
                Err(e) => log::warn!("{bare} device {dev}: {e}"),
            }
        }
        let ctx = self.omemo.as_ref().ok_or("OMEMO is off")?;
        let found = devices.len();
        let targets: Vec<u32> = devices
            .into_iter()
            .filter(|&d| ctx.store.session_identity(bare, d).is_some_and(|ik| pins.check(bare, &ik.fingerprint()).trusted()))
            .collect();
        match (found, targets.is_empty()) {
            (0, _) => Err(format!("{bare} has no OMEMO device (none published)")),
            (n, true) => Err(format!("none of {bare}'s {n} OMEMO device(s) is trusted and reachable (not pinned, or no key bundle)")),
            _ => Ok(targets),
        }
    }

    /// What Conversations does on a broken session: start a new one from the device's
    /// bundle and send an empty (key transport) message, so that its next messages use it.
    /// Once per device and run, and only for a device we would trust.
    async fn heal(&mut self, jid: &str, device: u32) {
        let Some(ctx) = &mut self.omemo else { return };
        let per_jid = ctx.healed.iter().filter(|(j, _)| j == jid).count();
        if ctx.healed.len() >= MAX_HEALED || per_jid >= MAX_HEALED_PER_JID || !ctx.healed.insert((jid.to_owned(), device)) {
            return;
        }
        let pins = ctx.pins();
        let bundle = match self.fetch_bundle(jid, device).await {
            Ok(b) => b,
            Err(e) => {
                log::warn!("{jid} device {device}: cannot rebuild the session, no bundle: {e}");
                return;
            }
        };
        let Some(ctx) = &mut self.omemo else { return };
        match Omemo::bundle_identity(&bundle) {
            Ok(ik) if pins.check(jid, &ik.fingerprint()).trusted() => {}
            Ok(ik) => {
                log::info!("{jid} device {device}: key {} not pinned, not rebuilding the session", ik.fingerprint());
                return;
            }
            Err(e) => {
                log::warn!("{jid} device {device}: {e}");
                return;
            }
        }
        let result = ctx.store.start_session(jid, device, &bundle).and_then(|()| ctx.store.encrypt(jid, &[device], None));
        match (result, jid.parse::<Jid>()) {
            (Ok(encrypted), Ok(to)) => {
                log::info!("{jid} device {device}: new OMEMO session sent");
                self.send(key_transport(to, encrypted)).await;
            }
            (Err(e), _) => log::warn!("{jid} device {device}: rebuilding the session: {e}"),
            (_, Err(e)) => log::warn!("{jid}: {e}"),
        }
    }

    /// The admin alert of /abuse: encrypted when possible; in plain text only when
    /// OMEMO is not required.
    pub(super) async fn notify_admin(&mut self, note: String) {
        let Ok(admin) = self.admin_jid.parse::<Jid>() else {
            log::error!("admin JID {} is not a JID", self.admin_jid);
            return;
        };
        let reply = Reply::from(note);
        if self.omemo.is_some() {
            let bare = self.admin_jid.clone();
            match self.send_encrypted(admin.clone(), &bare, None, &reply).await {
                Ok(()) => return,
                Err(e) if self.omemo.as_ref().is_some_and(|c| c.required) => {
                    log::error!("admin alert not sent: cannot encrypt it ({e})");
                    return;
                }
                Err(e) => log::warn!("admin alert sent unencrypted: {e}"),
            }
        }
        self.send(chat(admin, reply)).await;
    }

    /// Bot and sender fingerprints, for /omemo.
    pub(super) async fn omemo_info(&mut self, sender: &str) -> String {
        let t = self.texts(sender);
        let Some(ctx) = &self.omemo else {
            return t.omemo_off.into();
        };
        let trust_file = ctx.trust_file.clone();
        let mut out = t.bot_device.replace("{id}", &ctx.store.device_id().to_string()).replace("{fp}", &pretty(&ctx.store.fingerprint()));
        let pins = ctx.pins();
        let devices = self.devices_of(sender, None).await;
        let Some(ctx) = &self.omemo else { return out };
        out.push_str(&t.your_devices.replace("{n}", &devices.len().to_string()));
        for d in devices {
            let line = match ctx.store.session_identity(sender, d) {
                Some(ik) => {
                    let fp = ik.fingerprint();
                    let trust = match pins.check(sender, &fp) {
                        Trust::Pinned => t.key_pinned,
                        Trust::Blind => t.key_blind,
                        Trust::Untrusted => t.key_untrusted,
                    };
                    format!("\n• {d}: `{}` — {trust}", pretty(&fp))
                }
                None => format!("\n• {d}: {}", t.no_session),
            };
            out.push_str(&line);
        }
        // where keys are pinned is the admin's business
        if sender == self.admin_jid {
            out.push_str(&format!("\n\nPinned keys: `{}` on the server.", trust_file.display()));
        }
        out
    }

    /// An `<encrypted>` message from `sender` (bare, lowercase), already allowed to use
    /// the bot. `stale`: the command came too late to be run, and this is the reply.
    pub(super) async fn on_encrypted(&mut self, from: Jid, sender: &str, encrypted: Encrypted, stale: Option<String>) {
        let t = self.texts(sender);
        let Some(ctx) = &mut self.omemo else {
            self.send(chat(from, t.omemo_off_send_plain.into())).await;
            return;
        };
        let trust_file = ctx.trust_file.clone();
        let pins = ctx.pins();
        // decrypted even when stale: that keeps the session in step. A key that isn't
        // trusted changes nothing in the store (it must not replace a trusted session).
        let result = ctx.store.decrypt_if(sender, &encrypted, |k| pins.check(sender, &k.fingerprint()).trusted());
        let decrypted = match result {
            Ok(d) => d,
            Err(OmemoError::OwnMessage) => return,
            // a redelivery (offline storage, MAM): already handled
            Err(OmemoError::Session(SessionError::Duplicate)) => return,
            Err(OmemoError::Untrusted { device_id, identity }) => {
                let fp = identity.fingerprint();
                log::warn!("{sender} device {device_id}: OMEMO key {fp} is not pinned; command refused");
                let intro = if sender == self.admin_jid {
                    format!(
                        "✗ This device's OMEMO key is not trusted by the bot:\n`{}`\nTo trust it, add this line to `{}` on the server:",
                        pretty(&fp),
                        trust_file.display()
                    )
                } else {
                    t.untrusted_key.replace("{fp}", &pretty(&fp))
                };
                let text = format!("{intro}\n```\n{sender} {fp}\n```");
                self.send(chat(from, text.into())).await;
                return;
            }
            Err(e) => {
                let sid = encrypted.header.sid;
                log::warn!("OMEMO message from {sender} device {sid}: {e}");
                let due = ctx.republished.is_none_or(|t| t.elapsed() >= REPUBLISH_EVERY);
                if due && matches!(e, OmemoError::NotForUs | OmemoError::UnknownPreKey(_)) {
                    // perhaps they have an old copy of our keys
                    ctx.republished = Some(Instant::now());
                    self.omemo_publish().await;
                }
                if !matches!(e, OmemoError::Save(_)) {
                    self.heal(sender, sid).await;
                }
                // a store that can't be saved: its error names server paths
                let error = match e {
                    OmemoError::Save(_) if sender != self.admin_jid => t.internal_error.to_string(),
                    _ => e.to_string(),
                };
                let text = t.decrypt_failed.replace("{error}", &error);
                self.send(chat(from, text.into())).await;
                return;
            }
        };
        if decrypted.used_pre_key {
            self.omemo_publish_bundle().await;
        }
        let Some(body) = decrypted.body else {
            return; // key transport: only sets up the session
        };
        // some clients pad the plaintext with blanks (Conversations' OMEMO_PADDING)
        let body = body.trim().to_string();
        let fp = decrypted.identity.fingerprint();
        // (untrusted keys were refused above)
        if pins.check(sender, &fp) == Trust::Blind && sender == self.admin_jid {
            log::warn!(
                "admin's OMEMO key is not pinned; trusting device {} ({fp}). Pin it in {}",
                decrypted.device_id,
                trust_file.display()
            );
        }
        let command = body.split_whitespace().next().unwrap_or("");
        log::info!("{sender}: {command} (OMEMO)");
        let (reply, note, attachment) = if let Some(text) = stale {
            (Reply::from(text), None, None)
        } else if body.trim() == "/omemo" {
            (Reply::from(self.omemo_info(sender).await), None, None)
        } else {
            let device = from.resource().map(|r| r.as_str().to_owned());
            match self.run_command(sender, device.as_deref(), &body).await {
                Some(r) => (r.reply, r.notify_admin, r.attachment),
                None => return,
            }
        };
        if let Err(e) = self.send_encrypted(from.clone(), sender, Some(decrypted.device_id), &reply).await {
            log::error!("encrypting the reply to {sender}: {e}");
            self.send(chat(from, t.encrypt_failed.into())).await;
        } else if let Some(attachment) = attachment {
            self.send_attachment(sender, decrypted.device_id, &attachment).await;
        }
        if let Some(note) = note {
            self.notify_admin(note).await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::xmpp::pep::{publish_open, DATA_FORMS, PUBSUB};

    #[test]
    fn publish_request_shape() {
        let el = publish_open(omemo::DEVICELIST_NODE, "current", Element::builder("list", omemo::NS).build());
        let publish = el.get_child("publish", PUBSUB).unwrap();
        assert_eq!(publish.attr("node"), Some(omemo::DEVICELIST_NODE));
        assert_eq!(publish.get_child("item", PUBSUB).unwrap().attr("id"), Some("current"));
        let x = el.get_child("publish-options", PUBSUB).unwrap().get_child("x", DATA_FORMS).unwrap();
        let values: Vec<String> = x.children().map(|f| f.get_child("value", DATA_FORMS).unwrap().text()).collect();
        assert_eq!(values, ["http://jabber.org/protocol/pubsub#publish-options", "open"]);
    }

    #[test]
    fn parses_a_device_list_result() {
        let result: Element = "<pubsub xmlns='http://jabber.org/protocol/pubsub'>\
             <items node='eu.siacs.conversations.axolotl.devicelist'><item id='current'>\
             <list xmlns='eu.siacs.conversations.axolotl'><device id='12345'/><device id='4223'/></list>\
             </item></items></pubsub>"
            .parse()
            .unwrap();
        let list = DeviceList::try_from(first_item(&result).unwrap().clone()).unwrap();
        assert_eq!(list.devices.iter().map(|d| d.id).collect::<Vec<_>>(), [12345, 4223]);
    }

    /// The message layout of XEP-0384 v0.3, as Conversations sends it.
    #[test]
    fn parses_a_conversations_style_message() {
        let m: Element = "<message xmlns='jabber:client' to='bot@example.org' type='chat'>\
             <encrypted xmlns='eu.siacs.conversations.axolotl'><header sid='27183'>\
             <key rid='31415'>BASE64ENCODED</key><key prekey='true' rid='12321'>BASE64ENCODED</key>\
             <iv>BASE64ENCODED</iv></header><payload>BASE64ENCODED</payload></encrypted>\
             <body>I sent you an OMEMO encrypted message but your client doesn’t seem to support that.</body>\
             <store xmlns='urn:xmpp:hints'/></message>"
            .replace("BASE64ENCODED", "AAEC")
            .parse()
            .unwrap();
        let m = Message::try_from(m).unwrap();
        let el = m.payloads.iter().find(|p| p.is("encrypted", omemo::NS)).unwrap();
        let e = Encrypted::try_from(el.clone()).unwrap();
        assert_eq!(e.header.sid, 27183);
        assert_eq!(e.header.keys.iter().map(|k| (k.rid, k.prekey)).collect::<Vec<_>>(), [(31415, false), (12321, true)]);
        assert_eq!(e.payload.unwrap().data, [0, 1, 2]);
    }

    /// Conversations reads the flag with getAttributeAsBoolean: "true" or "1".
    #[test]
    fn prekey_flag_serializes_as_conversations_reads_it() {
        use tokio_xmpp::parsers::legacy_omemo::{Header, Key, IV};
        let enc = Encrypted {
            header: Header {
                sid: 1,
                keys: vec![Key { rid: 2, prekey: true, data: vec![1] }, Key { rid: 3, prekey: false, data: vec![1] }],
                iv: IV { data: vec![1; 12] },
            },
            payload: None,
        };
        let el: Element = key_transport("a@example.org".parse().unwrap(), enc).into();
        let keys: Vec<Option<&str>> = el
            .get_child("encrypted", omemo::NS)
            .unwrap()
            .get_child("header", omemo::NS)
            .unwrap()
            .children()
            .filter(|k| k.name() == "key")
            .map(|k| k.attr("prekey"))
            .collect();
        assert!(matches!(keys[0], Some("true") | Some("1")), "{keys:?}");
        assert!(matches!(keys[1], None | Some("false") | Some("0")), "{keys:?}");
        assert!(el.get_child("body", "jabber:client").is_none());
        assert!(el.has_child("no-permanent-store", super::super::HINTS));
    }

    #[test]
    fn outgoing_message_has_eme_fallback_and_hint() {
        let enc = Encrypted {
            header: tokio_xmpp::parsers::legacy_omemo::Header {
                sid: 1,
                keys: vec![],
                iv: tokio_xmpp::parsers::legacy_omemo::IV { data: vec![1; 12] },
            },
            payload: None,
        };
        let el: Element = encrypted_chat("a@example.org".parse().unwrap(), enc).into();
        assert!(el.has_child("encrypted", omemo::NS));
        assert_eq!(el.get_child("encryption", EME).unwrap().attr("namespace"), Some(omemo::NS));
        assert!(el.has_child("no-permanent-store", super::super::HINTS));
        assert!(!el.has_child("store", super::super::HINTS));
        assert_eq!(el.get_child("body", "jabber:client").unwrap().text(), FALLBACK_BODY);
    }
}
