"""Test oracle: an OMEMO peer built on omemo-dr (Gajim's OMEMO library).

The Rust tests drive it over stdin/stdout, one JSON object per line, to check that the
bot's OMEMO implementation interoperates with an independent one. omemo-dr is only used
here, at test time; nothing from it is part of the bot.

Requests: {"cmd": ..., ...}; replies: {"ok": ...} or {"error": "<exception class>: <text>"}.
Binary values are base64.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import traceback

from omemo_dr.const import NS_OMEMO_TMP
from omemo_dr.const import OMEMOTrust
from omemo_dr.session_manager import OMEMOSessionManager
from omemo_dr.state.sessionrecord import SessionRecord
from omemo_dr.state.store import Store
from omemo_dr.structs import IdentityInfo
from omemo_dr.structs import OMEMOBundle
from omemo_dr.structs import OMEMOConfig
from omemo_dr.structs import OMEMOMessage


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def unb64(data: str) -> bytes:
    return base64.b64decode(data)


class MemoryStore(Store):
    """Everything in dicts; every identity and device is trusted."""

    def __init__(self) -> None:
        self.device_id = None
        self.identity = None
        self.prekeys = {}
        self.signed_prekeys = {}
        self.sessions = {}
        self.identities = {}

    def set_our_identity(self, device_id, identity_key_pair):
        self.device_id = device_id
        self.identity = identity_key_pair

    def get_identity_key_pair(self):
        return self.identity

    def get_our_device_id(self):
        return self.device_id

    def save_identity(self, recipient_id, identity_key):
        self.identities.setdefault(recipient_id, set()).add(identity_key)

    def delete_identity(self, recipient_id, identity_key):
        self.identities.get(recipient_id, set()).discard(identity_key)

    def is_trusted_identity(self, recipient_id, identity_key):
        return True

    def set_trust(self, recipient_id, identity_key, trust):
        pass

    def set_identity_last_seen(self, recipient_id, identity_key):
        pass

    def get_identity_infos(self, recipient_ids):
        return []

    def get_pre_key_count(self):
        return len(self.prekeys)

    def load_pre_key(self, pre_key_id):
        return self.prekeys[pre_key_id]

    def load_pending_pre_keys(self):
        return list(self.prekeys.values())

    def get_current_pre_key_id(self):
        return max(self.prekeys) if self.prekeys else None

    def store_pre_key(self, pre_key_id, pre_key_record):
        self.prekeys[pre_key_id] = pre_key_record

    def contains_pre_key(self, pre_key_id):
        return pre_key_id in self.prekeys

    def remove_pre_key(self, pre_key_id):
        self.prekeys.pop(pre_key_id, None)

    def load_signed_pre_key(self, signed_pre_key_id):
        return self.signed_prekeys[signed_pre_key_id]

    def load_signed_pre_keys(self):
        return list(self.signed_prekeys.values())

    def store_signed_pre_key(self, signed_pre_key_id, signed_pre_key_record):
        self.signed_prekeys[signed_pre_key_id] = signed_pre_key_record

    def contains_signed_pre_key(self, signed_pre_key_id):
        return signed_pre_key_id in self.signed_prekeys

    def get_current_signed_pre_key_id(self):
        return max(self.signed_prekeys)

    def get_signed_pre_key_timestamp(self, signed_pre_key_id):
        return self.signed_prekeys[signed_pre_key_id].get_timestamp() // 1000

    def remove_old_signed_pre_keys(self, timestamp):
        current = self.get_current_signed_pre_key_id()
        for spk_id in list(self.signed_prekeys):
            if spk_id != current and self.get_signed_pre_key_timestamp(spk_id) < timestamp:
                del self.signed_prekeys[spk_id]

    def remove_signed_pre_key(self, signed_pre_key_id):
        self.signed_prekeys.pop(signed_pre_key_id, None)

    def load_session(self, recipient_id, device_id):
        serialized = self.sessions.get((recipient_id, device_id))
        if serialized is None:
            return SessionRecord()
        return SessionRecord(serialized=serialized)

    def store_session(self, recipient_id, device_id, session_record):
        self.sessions[(recipient_id, device_id)] = session_record.serialize()

    def contains_session(self, recipient_id, device_id):
        return (recipient_id, device_id) in self.sessions

    def get_inactive_sessions_keys(self, recipient_id):
        return []

    def delete_session(self, recipient_id, device_id):
        self.sessions.pop((recipient_id, device_id), None)

    def delete_all_sessions(self, recipient_id):
        for key in [k for k in self.sessions if k[0] == recipient_id]:
            del self.sessions[key]

    def get_active_device_tuples(self):
        return []

    def get_trust_for_identity(self, recipient_id, identity_key):
        return OMEMOTrust.VERIFIED

    def get_unacknowledged_count(self, recipient_id, device_id):
        return 0

    def set_active_state(self, address, devicelist):
        pass

    def set_inactive(self, address, device_id):
        pass

    def is_trusted(self, recipient_id, device_id):
        return True

    def needs_init(self):
        return self.identity is None


def bundle_to_json(bundle: OMEMOBundle) -> dict:
    return {
        "device_id": bundle.device_id,
        "ik": b64(bundle.ik),
        "spk": {"id": bundle.spk["id"], "key": b64(bundle.spk["key"])},
        "spk_signature": b64(bundle.spk_signature),
        "otpks": [{"id": k["id"], "key": b64(k["key"])} for k in bundle.otpks],
    }


def bundle_from_json(data: dict) -> OMEMOBundle:
    otpks = [{"id": k["id"], "key": unb64(k["key"])} for k in data["otpks"]]
    return OMEMOBundle(
        device_id=data["device_id"],
        ik=unb64(data["ik"]),
        namespace=NS_OMEMO_TMP,
        otpks=otpks,
        spk={"id": data["spk"]["id"], "key": unb64(data["spk"]["key"])},
        spk_signature=unb64(data["spk_signature"]),
    )


def message_to_json(message: OMEMOMessage) -> dict:
    return {
        "sid": message.sid,
        "iv": b64(message.iv),
        "keys": [
            {"rid": rid, "data": b64(key), "prekey": prekey}
            for rid, (key, prekey) in message.keys.items()
        ],
        "payload": None if message.payload is None else b64(message.payload),
    }


def message_from_json(data: dict) -> OMEMOMessage:
    return OMEMOMessage(
        sid=data["sid"],
        iv=unb64(data["iv"]),
        keys={k["rid"]: (unb64(k["data"]), k["prekey"]) for k in data["keys"]},
        payload=None if data["payload"] is None else unb64(data["payload"]),
    )


class Oracle:
    def __init__(self) -> None:
        self.store = MemoryStore()
        config = OMEMOConfig(
            default_prekey_amount=100,
            min_prekey_amount=80,
            spk_archive_seconds=86400 * 15,
            spk_cycle_seconds=86400 * 30,
            unacknowledged_count=2000,
        )
        self.manager = OMEMOSessionManager("oracle@example.org", self.store, config)

    def handle(self, req: dict):
        cmd = req["cmd"]
        m = self.manager
        if cmd == "identity":
            device_id, ik = m.get_our_identity()
            return {"device_id": device_id, "ik": b64(ik.serialize()), "fingerprint": m.get_our_fingerprint()}
        if cmd == "bundle":
            return bundle_to_json(m.get_bundle(NS_OMEMO_TMP))
        if cmd == "prekey_count":
            return self.store.get_pre_key_count()
        if cmd == "set_devices":
            m.update_devicelist(req["jid"], list(req["devices"]))
            return None
        if cmd == "build_session":
            m.build_session(req["jid"], bundle_from_json(req["bundle"]))
            return None
        if cmd == "encrypt":
            message = m.encrypt(req["jid"], req["text"], groupchat=False)
            if message is None:
                raise RuntimeError("nothing encrypted")
            return message_to_json(message)
        if cmd == "key_transport":
            message = m.encrypt_key_transport(req["jid"], list(req["devices"]))
            if message is None:
                raise RuntimeError("nothing encrypted")
            return message_to_json(message)
        if cmd == "decrypt":
            text, fingerprint, _trust = m.decrypt_message(message_from_json(req["message"]), req["jid"])
            return {"text": text, "fingerprint": fingerprint}
        if cmd == "verify_signature":
            # libsignal's curve25519_verify, as Conversations' bundle check does
            from omemo_dr.ecc.curve import Curve
            from omemo_dr.ecc.djbec import CurvePublicKey

            key = CurvePublicKey.from_bytes(unb64(req["key"]))
            return Curve.verify_signature(key, unb64(req["message"]), unb64(req["signature"]))
        if cmd == "sign":
            # libsignal's xed25519_sign with a fresh identity: returns key and signature
            from omemo_dr.ecc.curve import Curve

            pair = Curve.generate_key_pair()
            signature = Curve.calculate_signature(pair.get_private_key(), unb64(req["message"]))
            return {"key": b64(pair.get_public_key().serialize()), "signature": b64(signature)}
        raise ValueError(f"unknown command {cmd}")


def main() -> None:
    oracle = Oracle()
    for line in sys.stdin:
        if not line.strip():
            continue
        try:
            reply = {"ok": oracle.handle(json.loads(line))}
        except Exception as error:  # reported to the Rust side, which asserts on it
            if os.environ.get("ORACLE_DEBUG"):
                traceback.print_exc(file=sys.stderr)
            reply = {"error": f"{type(error).__name__}: {error}"}
        sys.stdout.write(json.dumps(reply) + "\n")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
