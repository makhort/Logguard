//! `logguard-matrix-bot login`: a new device for the bot account, by its password, with fresh
//! identity keys, published; then the device signed by the account's self-signing key, so
//! clients show its messages as from a device its owner verified.
//!
//! Cross-signing keys are made on the first login (the homeserver takes the first upload
//! without asking for the password again; a replacement needs it, or an approval in the
//! account's web page). The master key's secret half is dropped once the self-signing key is
//! signed: the bot never needs it again. The password isn't kept.
//!
//! A previous device of the bot is logged out (deleted on the homeserver); the room, and the
//! admin's pinned keys, stay.

use std::path::Path;

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use vodozemac::olm::Account;
use vodozemac::Ed25519SecretKey;

use crate::api::Api;
use crate::crypto;
use crate::state::{Login, State};

/// What clients show as the session's name.
pub const DEVICE_NAME: &str = "logguard-matrix-bot";

/// Logs in as `user` and sets up the new device (see the module's text). `approve` is told
/// what to approve in a web page and returns once the person running it did.
pub async fn login(api: &Api, state_path: &Path, user: &str, password: &str, reset: bool, approve: &mut dyn FnMut(&str)) -> Result<State> {
    let mut state = State::load(state_path).with_context(|| format!("reading {}", state_path.display()))?;
    // first the new login: a wrong password leaves the working device alone
    let reply = api.login(user, password, DEVICE_NAME).await.context("logging in")?;
    if let Some(old) = &state.login {
        match api.with_token(old.access_token.clone()).logout().await {
            Ok(_) => log::info!("logged out the previous device {}", old.device_id),
            Err(e) => {
                log::warn!("the previous device {} wasn't logged out ({e}); remove it in a client if it is still listed", old.device_id)
            }
        }
    }
    // a new device: new identity keys, no sessions
    state.keys_published = false;
    state.device_signed = false;
    state.olm.clear();
    state.outbound = None;
    let login = Login { user_id: reply.user_id, device_id: reply.device_id, access_token: reply.access_token };
    let account = Account::new();
    state.login = Some(login.clone());
    state.account = Some(account.pickle());
    state.save(state_path)?;
    log::info!("logged in as {} on the new device {}", login.user_id, login.device_id);

    let api = api.with_token(login.access_token.clone());
    let keys = crypto::device_keys(&account, &login.user_id, &login.device_id);
    api.upload_keys(&json!({ "device_keys": keys })).await.context("publishing the device keys")?;
    state.keys_published = true;
    state.save(state_path)?;

    let own = api.query_keys(&[&login.user_id]).await.context("asking for the account's cross-signing keys")?;
    let server_master = crypto::user_keys(&own, &login.user_id).master.map(|k| k.to_base64());
    let ssk = match (&server_master, &state.master_key, &state.self_signing_key) {
        (Some(m), Some(mine), Some(ssk)) if m == mine && !reset => {
            Ed25519SecretKey::from_base64(ssk).map_err(|e| anyhow::anyhow!("the self-signing key in {}: {e}", state_path.display()))?
        }
        (Some(m), _, _) if !reset => {
            log::warn!(
                "the account has cross-signing keys the bot doesn't hold (master key {m}, made in another client?): its device stays \
                 unsigned, and clients mark its messages as from an unverified device. `login --reset-cross-signing` replaces them."
            );
            return Ok(state);
        }
        _ => {
            let (master, ssk) = (Ed25519SecretKey::new(), Ed25519SecretKey::new());
            upload_cross_signing(&api, crypto::cross_signing_keys(&login.user_id, &master, &ssk), user, password, approve).await?;
            state.master_key = Some(master.public_key().to_base64());
            state.self_signing_key = Some(ssk.to_base64());
            state.save(state_path)?;
            log::info!("made the account's cross-signing keys: master key {}", master.public_key().to_base64());
            ssk
        }
    };
    let reply = api.upload_signatures(&crypto::device_signature(&keys, &login.user_id, &login.device_id, &ssk)).await?;
    if reply.get("failures").and_then(Value::as_object).is_some_and(|f| !f.is_empty()) {
        bail!("the homeserver refused the device's signature: {}", reply["failures"]);
    }
    state.device_signed = true;
    state.save(state_path)?;
    log::info!("signed the device {} with the account's self-signing key", login.device_id);
    Ok(state)
}

/// Uploads the cross-signing keys, authenticating with the password, or by an approval in
/// the account's web page, when the homeserver asks.
async fn upload_cross_signing(api: &Api, body: Value, user: &str, password: &str, approve: &mut dyn FnMut(&str)) -> Result<()> {
    let e = match api.upload_cross_signing(body.clone(), None).await {
        Ok(_) => return Ok(()),
        Err(e) => e,
    };
    let Some(uia) = e.uia().cloned() else { return Err(e).context("uploading the cross-signing keys") };
    if uia.password {
        let auth = json!({
            "type": "m.login.password",
            "identifier": { "type": "m.id.user", "user": user },
            "password": password,
            "session": uia.session,
        });
        api.upload_cross_signing(body, Some(auth)).await.context("uploading the cross-signing keys")?;
        return Ok(());
    }
    let Some(url) = uia.url else {
        bail!("the homeserver wants an authentication the bot can't do to upload the cross-signing keys ({e})")
    };
    approve(&format!(
        "The homeserver wants the new cross-signing keys of {user} approved. Open, logged in as {user}:\n  {url}\nallow the reset there, then press Enter."
    ));
    api.upload_cross_signing(body, None).await.context("uploading the cross-signing keys after the approval")?;
    Ok(())
}
