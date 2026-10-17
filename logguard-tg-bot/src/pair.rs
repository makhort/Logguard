//! `logguard-tg-bot pair`: finds the admin's Telegram user id. It prints a one-time code; the admin
//! sends `/start <code>` to the bot (or opens the `t.me` link, which does that), and the
//! id of whoever sent the code from a private chat is printed as `ADMIN_CHAT_ID=…`.
//!
//! It reads the bot's updates itself, so the service must be stopped meanwhile (Telegram
//! answers a second reader with 409 Conflict).

use std::time::{Duration, Instant};

use anyhow::{bail, Result};

use crate::api::{Api, Message};

/// Whether `m` is the code, sent by a person from their private chat with the bot.
pub fn is_code(m: &Message, code: &str) -> bool {
    let from = m.from.as_ref();
    m.chat.kind == "private"
        && from.is_some_and(|u| u.id == m.chat.id && !u.is_bot)
        && m.text.as_deref().map(str::trim) == Some(format!("/start {code}").as_str())
}

pub async fn pair(api: &Api, within: Duration) -> Result<i64> {
    let me = api.get_me().await?;
    let name = me.username.unwrap_or_default();
    let code: String = rand::random::<[u8; 8]>().iter().map(|b| format!("{b:02x}")).collect();
    println!("From the Telegram account that is to get logguard's messages, within {} minutes, open", within.as_secs() / 60);
    println!("  https://t.me/{name}?start={code}");
    println!("and press Start, or send the bot @{name} this message:");
    println!("  /start {code}");
    let deadline = Instant::now() + within;
    let mut offset = 0;
    while Instant::now() < deadline {
        let updates = match api.get_updates(offset, 25).await {
            Ok(u) => u,
            Err(e) if e.conflict() => {
                bail!("{e}: something else reads this bot's updates. Stop the service first (systemctl stop logguard-tg-bot)")
            }
            Err(e) if e.bad_token() => bail!("Telegram refused the token: {e}"),
            Err(e) => {
                eprintln!("{e}; trying again");
                tokio::time::sleep(Duration::from_secs(5)).await;
                continue;
            }
        };
        for u in updates {
            offset = offset.max(u.update_id + 1);
            let Some(m) = u.message else { continue };
            if !is_code(&m, &code) {
                eprintln!("ignored a message from Telegram user {}", m.from.as_ref().map_or(0, |u| u.id));
                continue;
            }
            // confirm what was read, so the service doesn't see it again
            let _ = api.get_updates(offset, 0).await;
            let text = format!(
                "Paired: this chat (id {}) gets logguard's messages once ADMIN_CHAT_ID is set and logguard-tg-bot runs.",
                m.chat.id
            );
            if let Err(e) = api.send_message(m.chat.id, &text, &[], false).await {
                eprintln!("(the confirmation in Telegram failed: {e})");
            }
            return Ok(m.chat.id);
        }
    }
    bail!("no /start {code} arrived within {} minutes", within.as_secs() / 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{Chat, User};

    #[test]
    fn only_the_code_from_a_private_chat() {
        let m = |chat: i64, kind: &str, from: i64, text: &str| Message {
            message_id: 1,
            from: Some(User { id: from, is_bot: false, username: None }),
            chat: Chat { id: chat, kind: kind.into() },
            date: 0,
            text: Some(text.into()),
        };
        assert!(is_code(&m(7, "private", 7, "/start 0011aabb"), "0011aabb"));
        assert!(is_code(&m(7, "private", 7, " /start 0011aabb\n"), "0011aabb"));
        assert!(!is_code(&m(7, "private", 7, "/start 0011aabc"), "0011aabb"));
        assert!(!is_code(&m(7, "private", 7, "/start"), "0011aabb"));
        assert!(!is_code(&m(-5, "group", 7, "/start 0011aabb"), "0011aabb"));
    }
}
