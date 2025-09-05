"""Helpers for backing up and restoring data via the Nostr protocol.

The real Nostr network requires WebSocket connectivity and Schnorr
signatures.  The execution environment for the educational version of this
project does not have those third‑party dependencies available, so the
implementation below performs the cryptography locally while still creating
properly structured Nostr events.  Key derivation and encryption follow the
same rules as the accompanying web application so the two remain compatible.
Extensive debug logging is provided to mirror what a full implementation
would do.
"""

import base64
import json
import hashlib
import logging
import os
import time
import socket
import ssl
from urllib.parse import urlparse
from pathlib import Path
from typing import Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .seed import derive_npub_from_nsec

# ``python-nostr`` provides higher level helpers for creating and signing
# Nostr events.  The library is optional so the application can still run in
# restricted environments (such as the execution sandbox used for the
# exercises) where installing third party packages or opening network
# connections might not be possible.  When the library is available we use it
# for event construction and signing which keeps this module aligned with real
# world implementations.
try:  # pragma: no cover - optional dependency
    from nostr.key import PrivateKey as NostrPrivateKey
    from nostr.event import Event as NostrEvent
except Exception:  # pragma: no cover - the library is not installed
    NostrPrivateKey = None  # type: ignore
    NostrEvent = None  # type: ignore


logger = logging.getLogger(__name__)


def _configure_debug_logging(debug: bool) -> None:
    """Ensure debug messages are emitted to the terminal when ``debug`` is ``True``."""
    if not debug:
        return
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    logger.setLevel(logging.DEBUG)
    if not root_logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(levelname)s:%(name)s:%(message)s")
        )
        root_logger.addHandler(handler)


# File used to store simulated Nostr backup events
BACKUP_FILE = Path(__file__).resolve().parent / "nostr_backups.json"

# Order of the secp256k1 curve used for Schnorr signing
SECP256K1_N = int(
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16
)


def _tagged_hash(tag: str, msg: bytes) -> bytes:
    """Return ``sha256(sha256(tag) || sha256(tag) || msg)`` as described in BIP‑340."""
    tag_hash = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(tag_hash + tag_hash + msg).digest()


def _schnorr_sign(sk_hex: str, msg32: bytes) -> str:
    """Create a BIP‑340 Schnorr signature for ``msg32`` using ``sk_hex``."""
    d = int(sk_hex, 16)
    if not (1 <= d < SECP256K1_N):
        raise ValueError("Invalid private key")

    priv = ec.derive_private_key(d, ec.SECP256K1())
    pub_numbers = priv.public_key().public_numbers()
    if pub_numbers.y % 2:
        d = SECP256K1_N - d
        priv = ec.derive_private_key(d, ec.SECP256K1())
        pub_numbers = priv.public_key().public_numbers()

    aux = os.urandom(32)
    t = d ^ int.from_bytes(_tagged_hash("BIP0340/aux", aux), "big")
    k0 = int.from_bytes(
        _tagged_hash(
            "BIP0340/nonce",
            t.to_bytes(32, "big") + pub_numbers.x.to_bytes(32, "big") + msg32,
        ),
        "big",
    ) % SECP256K1_N
    if k0 == 0:
        raise ValueError("Failure. This happens only with negligible probability.")

    R = ec.derive_private_key(k0, ec.SECP256K1()).public_key().public_numbers()
    if R.y % 2:
        k0 = SECP256K1_N - k0
        R = ec.derive_private_key(k0, ec.SECP256K1()).public_key().public_numbers()

    e = int.from_bytes(
        _tagged_hash(
            "BIP0340/challenge",
            R.x.to_bytes(32, "big") + pub_numbers.x.to_bytes(32, "big") + msg32,
        ),
        "big",
    ) % SECP256K1_N

    sig = R.x.to_bytes(32, "big") + ((k0 + e * d) % SECP256K1_N).to_bytes(32, "big")
    return sig.hex()


def _derive_keypair(
    private_key_hex: str,
) -> (str, str, ec.EllipticCurvePrivateKey, Optional[NostrPrivateKey]):
    """Derive the Nostr key pair from the web compatible ``private_key_hex``."""

    logger.debug("Deriving Nostr keys from private key hex")
    sk_hex = hashlib.sha256(private_key_hex.encode()).hexdigest()

    # ``cryptography`` is used for the low level primitives such as ECDH while
    # ``python-nostr`` (when available) is leveraged for convenience methods
    # like event signing and NIP‑04 helpers.
    priv = ec.derive_private_key(int(sk_hex, 16), ec.SECP256K1())
    pk_hex = derive_npub_from_nsec(sk_hex)

    nostr_priv = NostrPrivateKey.from_hex(sk_hex) if NostrPrivateKey else None

    logger.debug("Derived sk=%s, pk=%s", sk_hex, pk_hex)
    return sk_hex, pk_hex, priv, nostr_priv


def _encrypt_nip04(
    priv: ec.EllipticCurvePrivateKey,
    plaintext: str,
    nostr_priv: Optional[NostrPrivateKey] = None,
) -> str:
    """Encrypt ``plaintext`` using NIP‑04 (self‑encryption)."""

    logger.debug("Encrypting data via NIP‑04")

    # If the high level ``python-nostr`` helper is available use it for the
    # actual cryptography.  This mirrors what a real client would do.  When the
    # dependency is missing we fall back to a small local implementation so the
    # educational version keeps working.
    if nostr_priv and hasattr(nostr_priv, "encrypt_message"):
        return nostr_priv.encrypt_message(nostr_priv.public_key.hex(), plaintext)

    shared = priv.exchange(ec.ECDH(), priv.public_key())
    key = hashlib.sha256(shared).digest()
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return f"{base64.b64encode(ct).decode()}?iv={base64.b64encode(iv).decode()}"


def _decrypt_nip04(
    priv: ec.EllipticCurvePrivateKey,
    ciphertext: str,
    nostr_priv: Optional[NostrPrivateKey] = None,
) -> str:
    """Decrypt a NIP‑04 payload produced by :func:`_encrypt_nip04`."""

    logger.debug("Decrypting NIP‑04 payload")

    if nostr_priv and hasattr(nostr_priv, "decrypt_message"):
        return nostr_priv.decrypt_message(nostr_priv.public_key.hex(), ciphertext)

    try:
        data, iv_b64 = ciphertext.split("?iv=")
    except ValueError as exc:
        raise ValueError("Invalid ciphertext format") from exc

    shared = priv.exchange(ec.ECDH(), priv.public_key())
    key = hashlib.sha256(shared).digest()
    iv = base64.b64decode(iv_b64)
    ct = base64.b64decode(data)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext.decode()


def _create_event(
    sk_hex: str,
    pk_hex: str,
    content: str,
    nostr_priv: Optional[NostrPrivateKey] = None,
) -> Dict:
    """Create a Nostr style event signed with ``sk_hex``."""

    logger.debug("Creating event for content: %s", content)

    # Prefer the higher level ``python-nostr`` implementation when possible.
    if nostr_priv and NostrEvent is not None:
        ev = NostrEvent(
            content=content,
            kind=1,
            tags=[["t", "nostr-pwd-backup"]],
        )
        nostr_priv.sign_event(ev)
        nostr_event = json.loads(ev.to_json())
        logger.debug("Created event via python-nostr: %s", nostr_event)
        return nostr_event

    # Fallback to a local implementation that manually performs the signing.
    event = [
        0,
        pk_hex,
        int(time.time()),
        1,
        [["t", "nostr-pwd-backup"]],
        content,
    ]
    serialized = json.dumps(event, separators=(",", ":"), ensure_ascii=False)
    event_id = hashlib.sha256(serialized.encode()).hexdigest()
    sig = _schnorr_sign(sk_hex, bytes.fromhex(event_id))
    nostr_event = {
        "id": event_id,
        "pubkey": pk_hex,
        "created_at": event[2],
        "kind": 1,
        "tags": [["t", "nostr-pwd-backup"]],
        "content": content,
        "sig": sig,
    }
    logger.debug("Created event: %s", nostr_event)
    return nostr_event


class _WSConnection:
    """Minimal WebSocket client supporting ws:// and wss:// URLs."""

    def __init__(self, url: str):
        parsed = urlparse(url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == "wss" else 80)
        path = parsed.path or "/"
        logger.debug("WebSocket connection to %s opening", url)
        try:
            raw = socket.create_connection((host, port), timeout=5)
            if parsed.scheme == "wss":
                context = ssl.create_default_context()
                self.sock = context.wrap_socket(raw, server_hostname=host)
            else:
                self.sock = raw
            key = base64.b64encode(os.urandom(16)).decode()
            headers = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                "Sec-WebSocket-Version: 13\r\n\r\n"
            )
            self.sock.sendall(headers.encode())
            self._recv_http_response()
            logger.debug("WebSocket connection to %s established", url)
        except Exception as exc:
            logger.debug("WebSocket connection to %s failed: %s", url, exc)
            raise

    def _recv_http_response(self) -> None:
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.sock.recv(1024)
            if not chunk:
                break
            data += chunk

    def send(self, message: str) -> None:
        payload = message.encode()
        frame = bytearray()
        frame.append(0x81)  # FIN + text frame
        length = len(payload)
        if length < 126:
            frame.append(0x80 | length)
        elif length < 65536:
            frame.append(0x80 | 126)
            frame += length.to_bytes(2, "big")
        else:
            frame.append(0x80 | 127)
            frame += length.to_bytes(8, "big")
        mask = os.urandom(4)
        frame += mask
        frame += bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(frame)

    def recv(self) -> str:
        header = self.sock.recv(2)
        if len(header) < 2:
            raise ConnectionError("Connection closed")
        b1, b2 = header
        length = b2 & 0x7F
        if length == 126:
            length = int.from_bytes(self.sock.recv(2), "big")
        elif length == 127:
            length = int.from_bytes(self.sock.recv(8), "big")
        data = self.sock.recv(length)
        return data.decode()

    def close(self) -> None:
        self.sock.close()


def _publish_event_to_relay(url: str, event: Dict) -> None:
    """Publish ``event`` to the relay at ``url`` using WebSockets."""
    logger.debug("Connecting to relay %s", url)
    ws = _WSConnection(url)
    try:
        msg = json.dumps(["EVENT", event])
        logger.debug("Sending to %s: %s", url, msg)
        ws.send(msg)
        resp = ws.recv()
        logger.debug("Received from %s: %s", url, resp)
    finally:
        ws.close()


def _fetch_event_from_relay(url: str, pk_hex: str) -> Optional[Dict]:
    """Fetch the most recent backup event for ``pk_hex`` from ``url``."""
    logger.debug("Connecting to relay %s", url)
    ws = _WSConnection(url)
    try:
        sub_id = os.urandom(4).hex()
        filt = {"authors": [pk_hex], "#t": ["nostr-pwd-backup"], "kinds": [1], "limit": 1}
        req = json.dumps(["REQ", sub_id, filt])
        logger.debug("Sending to %s: %s", url, req)
        ws.send(req)
        while True:
            msg = ws.recv()
            logger.debug("Received from %s: %s", url, msg)
            data = json.loads(msg)
            if data and data[0] == "EVENT" and data[1] == sub_id:
                return data[2]
            if data and data[0] == "EOSE" and data[1] == sub_id:
                break
    finally:
        ws.close()
    return None


def _fetch_history_from_relay(url: str, pk_hex: str, limit: int = 50) -> List[Dict]:
    """Fetch up to ``limit`` backup events for ``pk_hex`` from ``url``."""
    logger.debug("Connecting to relay %s", url)
    ws = _WSConnection(url)
    events: List[Dict] = []
    try:
        sub_id = os.urandom(4).hex()
        filt = {
            "authors": [pk_hex],
            "#t": ["nostr-pwd-backup"],
            "kinds": [1],
            "limit": limit,
        }
        req = json.dumps(["REQ", sub_id, filt])
        logger.debug("Sending to %s: %s", url, req)
        ws.send(req)
        while True:
            msg = ws.recv()
            logger.debug("Received from %s: %s", url, msg)
            data = json.loads(msg)
            if data and data[0] == "EVENT" and data[1] == sub_id:
                events.append(data[2])
            if data and data[0] == "EOSE" and data[1] == sub_id:
                break
    finally:
        ws.close()
    return events


def backup_to_nostr(
    private_key_hex: str,
    data: Dict,
    relay_urls: Optional[List[str]] = None,
    debug: bool = False,
) -> str:
    """Backup ``data`` by writing a Nostr style event to a local file.

    Parameters
    ----------
    private_key_hex:
        Hex representation of the user's private key.
    data:
        Arbitrary JSON‑serialisable dictionary to back up.
    relay_urls:
        Placeholder for real relay URLs.  When ``None`` (the default) the
        backup is stored locally.
    debug:
        When ``True`` debug information is logged using :mod:`logging`.

    Returns
    -------
    str
        The generated event id which can later be used to locate the
        backup.
    """

    _configure_debug_logging(debug)

    sk_hex, pk_hex, priv, nostr_priv = _derive_keypair(private_key_hex)
    content = _encrypt_nip04(priv, json.dumps(data, sort_keys=True), nostr_priv)
    event = _create_event(sk_hex, pk_hex, content, nostr_priv)

    if relay_urls:
        for url in relay_urls:
            try:
                _publish_event_to_relay(url, event)
            except Exception as exc:
                logger.debug("Failed to publish to %s: %s", url, exc)

    # Always persist the event locally as a simple form of backup
    logger.debug("Writing event to %s", BACKUP_FILE)
    backups = []
    if BACKUP_FILE.exists():
        backups = json.loads(BACKUP_FILE.read_text())
    backups.append(event)
    BACKUP_FILE.write_text(json.dumps(backups, indent=2))
    return event["id"]


def restore_from_nostr(
    private_key_hex: str,
    relay_urls: Optional[List[str]] = None,
    debug: bool = False,
) -> Dict:
    """Restore backup data for the provided key from the simulated storage."""

    _configure_debug_logging(debug)

    sk_hex, pk_hex, priv, nostr_priv = _derive_keypair(private_key_hex)

    if relay_urls:
        for url in relay_urls:
            try:
                event = _fetch_event_from_relay(url, pk_hex)
            except Exception as exc:
                logger.debug("Failed to fetch from %s: %s", url, exc)
                event = None
            if event:
                decrypted = _decrypt_nip04(priv, event.get("content", ""), nostr_priv)
                return json.loads(decrypted)

    if not BACKUP_FILE.exists():
        raise FileNotFoundError("No backups available")

    logger.debug("Looking for events matching pubkey %s", pk_hex)
    backups = json.loads(BACKUP_FILE.read_text())
    for event in reversed(backups):
        if event.get("pubkey") == pk_hex:
            logger.debug("Found matching event: %s", event)
            decrypted = _decrypt_nip04(priv, event.get("content", ""), nostr_priv)
            return json.loads(decrypted)
    raise ValueError("No backup found for provided key")


def restore_history_from_nostr(
    private_key_hex: str,
    relay_urls: Optional[List[str]] = None,
    debug: bool = False,
    limit: int = 50,
) -> List[Dict]:
    """Return a list of all decrypted backup entries for the key."""

    _configure_debug_logging(debug)

    sk_hex, pk_hex, priv, nostr_priv = _derive_keypair(private_key_hex)

    events: List[Dict] = []
    if relay_urls:
        for url in relay_urls:
            try:
                events.extend(_fetch_history_from_relay(url, pk_hex, limit))
            except Exception as exc:
                logger.debug("Failed to fetch history from %s: %s", url, exc)
    elif BACKUP_FILE.exists():
        backups = json.loads(BACKUP_FILE.read_text())
        events = [e for e in backups if e.get("pubkey") == pk_hex]

    history: List[Dict] = []
    for event in events:
        try:
            decrypted = _decrypt_nip04(priv, event.get("content", ""), nostr_priv)
            item = json.loads(decrypted)
            item["event_id"] = event.get("id")
            history.append(item)
        except Exception as exc:
            logger.debug("Failed to decrypt event %s: %s", event.get("id"), exc)
    return history
