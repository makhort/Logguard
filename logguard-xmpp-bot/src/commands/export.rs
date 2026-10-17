//! /export's file: what ejabberd's database holds about the sender, as JSON (GDPR art. 15
//! and 20), sent OMEMO-encrypted.
//!
//! Only the sender's own data, and nothing the sender's account couldn't already see:
//! - every query matches the account exactly (`=`, never `LIKE`, whose `_` and `%` would
//!   match other names), and every row is checked again here: a row whose owner column
//!   isn't the sender's is dropped (and logged) before anything is written;
//! - left out are the server-side views of others: group chat archives and member lists,
//!   who subscribed to the sender's PEP nodes, and the accounts the sender's invitations
//!   created;
//! - secrets are left out too: password hashes, login and invitation tokens, push
//!   registration forms.

use serde_json::{json, Map, Value};

use crate::ctl::Ejabberd;

/// Which rows of a section belong to the sender: the value of `column` must be exactly
/// `value`, or (`with_resource`) `value` followed by `/resource`.
struct Owner {
    column: &'static str,
    value: String,
    with_resource: bool,
}

impl Owner {
    fn matches(&self, row: &Map<String, Value>) -> bool {
        let Some(v) = row.get(self.column).and_then(Value::as_str) else { return false };
        v == self.value || (self.with_resource && v.strip_prefix(&self.value).is_some_and(|r| r.starts_with('/')))
    }
}

struct Section {
    name: &'static str,
    sql: String,
    owners: Vec<Owner>,
}

/// An SQL string literal.
fn quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

/// A user name as ejabberd stores it (nodeprep'd): none of the characters nodeprep forbids,
/// no blanks or control characters. Anything else gets no database export at all.
pub fn plain_username(user: &str) -> bool {
    !user.is_empty() && user.len() <= 1023 && !user.chars().any(|c| c.is_whitespace() || c.is_control() || "\"&'/:<>@".contains(c))
}

/// `column` is `bare` or `bare/resource`, without wildcards.
fn bare_or_full(column: &str, bare: &str) -> String {
    let q = quote(bare);
    let prefix = quote(&format!("{bare}/"));
    format!("({column} = {q} OR substr({column}, 1, {}) = {prefix})", bare.len() + 1)
}

fn sections(user: &str, domain: &str) -> Vec<Section> {
    let bare = format!("{user}@{domain}");
    let (u, b) = (quote(user), quote(&bare));
    let by_user = |column: &'static str| vec![Owner { column, value: user.to_string(), with_resource: false }];
    let by_bare = |column: &'static str| vec![Owner { column, value: bare.clone(), with_resource: false }];
    let s = |name, sql: String, owners| Section { name, sql, owners };
    vec![
        // the hash types and when the account was made; not the hashes, salts or keys
        s("account", format!("SELECT username AS owner, type AS password_hash_type, iterationcount, created_at FROM users WHERE username = {u}"), by_user("owner")),
        s("last_activity", format!("SELECT username AS owner, seconds AS unix_time, state FROM last WHERE username = {u}"), by_user("owner")),
        // not askmessage: a contact's subscription request text
        s("contacts", format!("SELECT username AS owner, jid, nick, subscription, ask, server, type, created_at FROM rosterusers WHERE username = {u} ORDER BY jid"), by_user("owner")),
        s("contact_groups", format!("SELECT username AS owner, jid, grp AS group_name FROM rostergroups WHERE username = {u} ORDER BY jid"), by_user("owner")),
        s("vcard", format!("SELECT username AS owner, vcard, created_at FROM vcard WHERE username = {u}"), by_user("owner")),
        s("private_storage", format!("SELECT username AS owner, namespace, data, created_at FROM private_storage WHERE username = {u}"), by_user("owner")),
        s("privacy_lists", format!(
            "SELECT p.username AS owner, p.name AS list, d.t AS match_type, d.value, d.action, d.ord AS position, d.match_all, d.match_iq, \
             d.match_message, d.match_presence_in, d.match_presence_out FROM privacy_list p LEFT JOIN privacy_list_data d ON d.id = p.id \
             WHERE p.username = {u} ORDER BY p.name, d.ord"), by_user("owner")),
        s("default_privacy_list", format!("SELECT username AS owner, name FROM privacy_default_list WHERE username = {u}"), by_user("owner")),
        s("archive_settings", format!("SELECT username AS owner, def AS default_policy, always, never FROM archive_prefs WHERE username = {u}"), by_user("owner")),
        // the sender's own archive: what their clients download anyway. Group chat archives
        // are the rooms' (username = the room's JID), never matched here
        s("archived_messages", format!(
            "SELECT username AS owner, strftime('%Y-%m-%dT%H:%M:%fZ', timestamp / 1000000.0, 'unixepoch') AS time, kind, peer, bare_peer, nick, \
             origin_id, txt AS text, xml FROM archive WHERE username = {u} ORDER BY timestamp"), by_user("owner")),
        s("offline_messages", format!("SELECT username AS owner, xml, created_at FROM spool WHERE username = {u}"), by_user("owner")),
        // not the registration form (xml): it holds the push service's secret
        s("push_registrations", format!(
            "SELECT username AS owner, strftime('%Y-%m-%dT%H:%M:%fZ', timestamp / 1000000.0, 'unixepoch') AS registered, service, node \
             FROM push_session WHERE username = {u}"), by_user("owner")),
        s("pep_nodes", format!("SELECT host AS owner, node, plugin FROM pubsub_node WHERE host = {b} ORDER BY node"), by_bare("owner")),
        s("pep_node_options", format!(
            "SELECT n.host AS owner, n.node, o.name, o.val AS value FROM pubsub_node_option o JOIN pubsub_node n ON n.nodeid = o.nodeid \
             WHERE n.host = {b} ORDER BY n.node, o.name"), by_bare("owner")),
        // items on the sender's nodes published by the sender (PEP allows nobody else)
        s("pep_items", format!(
            "SELECT n.host AS owner, i.publisher, n.node, i.itemid, i.creation, i.modification, i.payload FROM pubsub_item i \
             JOIN pubsub_node n ON n.nodeid = i.nodeid WHERE n.host = {b} AND {} ORDER BY n.node", bare_or_full("i.publisher", &bare)),
            vec![Owner { column: "owner", value: bare.clone(), with_resource: false }, Owner { column: "publisher", value: bare.clone(), with_resource: true }]),
        // the sender's own subscriptions and affiliations; not who subscribed to the sender's nodes
        s("pubsub_subscriptions", format!(
            "SELECT s.jid AS owner, n.host, n.node, s.affiliation, s.subscriptions FROM pubsub_state s JOIN pubsub_node n ON n.nodeid = s.nodeid \
             WHERE {} ORDER BY n.host, n.node", bare_or_full("s.jid", &bare)),
            vec![Owner { column: "owner", value: bare.clone(), with_resource: true }]),
        s("room_nicknames", format!("SELECT jid AS owner, host AS service, nick, created_at FROM muc_registered WHERE jid = {b}"), by_bare("owner")),
        s("room_subscriptions", format!("SELECT jid AS owner, room, host AS service, nick, nodes, created_at FROM muc_room_subscribers WHERE jid = {b}"), by_bare("owner")),
        // whether each was used, not by whom; not the tokens
        s("invitations_created", format!(
            "SELECT username AS owner, type, created_at, expires, CASE WHEN invitee <> '' THEN 1 ELSE 0 END AS used FROM invite_token \
             WHERE username = {u} ORDER BY created_at"), by_user("owner")),
        // the client names of the sender's devices; not the tokens
        s("login_tokens", format!("SELECT username AS owner, ua AS client, type, created_at, expires FROM auth_fast_tokens WHERE username = {u}"), by_user("owner")),
        s("shared_roster_groups", format!("SELECT jid AS owner, grp AS group_name, created_at FROM sr_user WHERE jid = {b}"), by_bare("owner")),
        s("message_of_the_day_seen", format!("SELECT username AS owner, created_at FROM motd WHERE username = {u}"), by_user("owner")),
    ]
}

/// The sections of the export file read from the database: each an array of rows, or
/// `{"error": ...}` when it could not be read. Rows not the sender's are dropped.
pub async fn database_sections<E: Ejabberd>(ctl: &E, user: &str, domain: &str) -> Map<String, Value> {
    let mut out = Map::new();
    for section in sections(user, domain) {
        let rows = match ctl.query_db(&section.sql).await {
            Ok(text) => serde_json::from_str::<Vec<Map<String, Value>>>(&text).map_err(|e| format!("not JSON: {e}")),
            Err(e) => Err(e),
        };
        let value = match rows {
            Ok(rows) => {
                let total = rows.len();
                let own: Vec<Value> = rows
                    .into_iter()
                    .filter(|r| section.owners.iter().all(|o| o.matches(r)))
                    .map(|mut r| {
                        r.remove("owner");
                        Value::Object(r)
                    })
                    .collect();
                if own.len() != total {
                    log::error!("export for {user}: {} of {total} {} rows were not the user's; left out", total - own.len(), section.name);
                }
                Value::Array(own)
            }
            Err(e) => {
                log::warn!("export for {user}: {}: {e}", section.name);
                json!({ "error": "could not be read" })
            }
        };
        out.insert(section.name.to_string(), value);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoting_and_names() {
        assert_eq!(quote("o'brien"), "'o''brien'");
        assert!(plain_username("alice") && plain_username("a.b-c_d") && plain_username("анна"));
        for bad in ["", "a b", "a@b", "a/b", "a'b", "a:b", "a\nb", "a<b", "a\"b"] {
            assert!(!plain_username(bad), "{bad:?}");
        }
        assert_eq!(
            bare_or_full("jid", "al@x.org"),
            "(jid = 'al@x.org' OR substr(jid, 1, 9) = 'al@x.org/')",
            "a prefix test, not LIKE: '_' in a name matches only '_'"
        );
        for s in sections("a_b", "x.org") {
            assert!(!s.sql.contains(" LIKE "), "{}: no LIKE", s.name);
            assert!(!s.owners.is_empty(), "{}: every section has an owner check", s.name);
        }
    }

    #[test]
    fn owner_checks() {
        let row = |v: Value| v.as_object().unwrap().clone();
        let exact = Owner { column: "owner", value: "al@x.org".into(), with_resource: false };
        let full = Owner { column: "owner", value: "al@x.org".into(), with_resource: true };
        assert!(exact.matches(&row(json!({"owner": "al@x.org"}))));
        assert!(!exact.matches(&row(json!({"owner": "al@x.org/phone"}))));
        assert!(full.matches(&row(json!({"owner": "al@x.org/phone"}))));
        assert!(!full.matches(&row(json!({"owner": "al@x.org.evil/phone"}))));
        assert!(!full.matches(&row(json!({"owner": "alx@x.org"}))));
        assert!(!exact.matches(&row(json!({"other": "al@x.org"}))), "no owner column: not the user's");
    }
}
