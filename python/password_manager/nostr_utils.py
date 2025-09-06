"""Helpers for backing up and restoring data via the Nostr protocol.

Backups are published to real Nostr relays for persistence, and a simple
in‑memory session cache is used as a temporary holding area. If the optional
``python-nostr`` library is available it is used for convenience; otherwise
local cryptographic primitives are used. When ``debug=True`` detailed logs
are emitted for all execution paths and errors.
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
from typing import Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .seed import derive_npub_from_nsec
from .bech32 import encode_nsec

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

# Optional CA bundle via certifi to avoid macOS certificate issues
try:  # pragma: no cover - optional dependency
    import certifi  # type: ignore
    _CERTIFI_CA = certifi.where()  # type: ignore[attr-defined]
except Exception:  # pragma: no cover
    certifi = None  # type: ignore
    _CERTIFI_CA = None


logger = logging.getLogger(__name__)


def _configure_debug_logging(debug: bool) -> None:
    """Ensure debug log messages are visible when ``debug`` is ``True``.

    Many GUI launch environments preconfigure logging with non-console handlers
    or higher levels, which can unintentionally suppress module debug output.
    To make behaviour predictable for users, when ``debug`` is enabled we:

    - Set the root logger level to DEBUG (non-destructive to existing handlers).
    - Attach a dedicated ``StreamHandler`` to this module's logger if one is
      not already present so messages always appear on the terminal.
    - Keep propagation disabled when adding our own handler to avoid duplicate
      messages when the application has also configured root handlers.
    """
    if not debug:
        return

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    logger.setLevel(logging.DEBUG)

    # If the application has not configured any root handlers, set up a simple
    # console handler there for completeness.
    if not root_logger.handlers:
        root_handler = logging.StreamHandler()
        root_handler.setFormatter(logging.Formatter("%(levelname)s:%(name)s:%(message)s"))
        root_logger.addHandler(root_handler)

    # Always ensure this module has a console stream handler so debug logs are
    # visible even in GUI contexts where the root handler may not print to the
    # terminal or might be at a higher level.
    has_stream = any(isinstance(h, logging.StreamHandler) for h in logger.handlers)
    if not has_stream:
        handler = logging.StreamHandler()
        handler.setLevel(logging.DEBUG)
        handler.setFormatter(logging.Formatter("%(levelname)s:%(name)s:%(message)s"))
        logger.addHandler(handler)
        # Avoid duplicate emission if root also handles this logger.
        logger.propagate = False


# In‑memory session cache of events by pubkey (hex)
_SESSION_EVENTS: Dict[str, List[Dict]] = {}

# Default public relays to use when not provided by the caller
DEFAULT_RELAYS: List[str] = [
    "wss://relay.damus.io",
    "wss://nos.lol",
    "wss://relay.snort.social",
]

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

    # Create a python-nostr PrivateKey if available, but guard against
    # versions that do not implement `from_hex`.
    if NostrPrivateKey:
        try:
            if hasattr(NostrPrivateKey, "from_nsec"):
                nostr_priv = NostrPrivateKey.from_nsec(encode_nsec(sk_hex))
            elif hasattr(NostrPrivateKey, "from_hex"):
                nostr_priv = NostrPrivateKey.from_hex(sk_hex)
            else:
                try:
                    nostr_priv = NostrPrivateKey(bytes.fromhex(sk_hex))  # type: ignore[arg-type]
                except Exception:
                    nostr_priv = None
        except Exception:
            nostr_priv = None
    else:
        nostr_priv = None

    logger.debug("Derived sk=%s, pk=%s", sk_hex, pk_hex)
    return sk_hex, pk_hex, priv, nostr_priv


def _encrypt_nip04(
    priv: ec.EllipticCurvePrivateKey,
    plaintext: str,
    nostr_priv: Optional[NostrPrivateKey] = None,
) -> str:
    """Encrypt ``plaintext`` using NIP‑04 (self‑encryption).

    Compatibility: mimic nostr-tools behavior by deriving the shared secret
    using the x-only public key with even-Y compression (02 || x) and AES-CBC
    with PKCS#7 padding. This ensures the web app can decrypt.
    """

    logger.debug("Encrypting data via NIP‑04 (local implementation)")

    # Derive peer public key as 02||x (even Y) from our own public key's x.
    pub_x = priv.public_key().public_numbers().x
    peer = ec.EllipticCurvePublicKey.from_encoded_point(
        ec.SECP256K1(), b"\x02" + pub_x.to_bytes(32, "big")
    )
    shared = priv.exchange(ec.ECDH(), peer)
    key = hashlib.sha256(shared).digest()
    iv = os.urandom(16)
    # Use PKCS#7 padding (block size 128 bits)
    padder = padding.PKCS7(128).padder()  # type: ignore[name-defined]
    data = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(data) + encryptor.finalize()
    return f"{base64.b64encode(ct).decode()}?iv={base64.b64encode(iv).decode()}"


def _decrypt_nip04(
    priv: ec.EllipticCurvePrivateKey,
    ciphertext: str,
    sender_pubkey_hex: str,
    nostr_priv: Optional[NostrPrivateKey] = None,
) -> str:
    """Decrypt a NIP‑04 payload produced by :func:`_encrypt_nip04` or nostr-tools.

    ``sender_pubkey_hex`` is the x-only pubkey (32-byte hex) of the event's sender.
    We reconstruct the full point as 02||x (even Y) to mirror nostr-tools ECDH.
    """

    logger.debug("Decrypting NIP‑04 payload (local implementation)")

    try:
        data, iv_b64 = ciphertext.split("?iv=")
    except ValueError as exc:
        raise ValueError("Invalid ciphertext format") from exc

    # Build peer key from x-only hex with even Y
    x_bytes = bytes.fromhex(sender_pubkey_hex)
    if len(x_bytes) != 32:
        raise ValueError("Invalid sender pubkey length")
    peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), b"\x02" + x_bytes)
    shared = priv.exchange(ec.ECDH(), peer)
    key = hashlib.sha256(shared).digest()
    iv = base64.b64decode(iv_b64)
    ct = base64.b64decode(data)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()  # type: ignore[name-defined]
    plaintext = unpadder.update(padded) + unpadder.finalize()
    return plaintext.decode()


def _create_event(
    sk_hex: str,
    pk_hex: str,
    content: str,
    nostr_priv: Optional[NostrPrivateKey] = None,
) -> Dict:
    """Create a Nostr style event signed with ``sk_hex``."""

    logger.debug("Creating event for content length: %d", len(content))

    # Prefer the higher level ``python-nostr`` implementation when possible.
    if nostr_priv and NostrEvent is not None:
        ev = NostrEvent(
            pk_hex,
            content,
            int(time.time()),
            1,
            [["t", "nostr-pwd-backup"]],
        )
        nostr_priv.sign_event(ev)
        nostr_event = {
            "id": ev.id,
            "pubkey": ev.public_key,
            "created_at": ev.created_at,
            "kind": ev.kind,
            "tags": ev.tags,
            "content": ev.content,
            "sig": ev.signature,
        }
        logger.debug("Created event via python-nostr id=%s", nostr_event["id"])
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
            raw = socket.create_connection((host, port), timeout=10)
            if parsed.scheme == "wss":
                insecure = os.environ.get("NOSTR_INSECURE_TLS") == "1"
                if insecure:
                    logger.debug("Using INSECURE TLS context for %s", url)
                    context = ssl._create_unverified_context()
                else:
                    # Create SSL context with proper certificate handling
                    context = ssl.create_default_context()

                    # Try using certifi CA bundle if available
                    if _CERTIFI_CA:
                        logger.debug("Using certifi CA bundle for TLS: %s", _CERTIFI_CA)
                        context = ssl.create_default_context(cafile=_CERTIFI_CA)

                    # Additional SSL context configuration for better compatibility
                    context.check_hostname = True
                    context.verify_mode = ssl.CERT_REQUIRED

                    # Load system certificates as fallback
                    try:
                        context.load_default_certs()
                    except Exception as e:
                        logger.debug("Failed to load default certs: %s", e)

                    # For macOS specifically - try loading system keychain
                    import platform
                    if platform.system() == 'Darwin':
                        try:
                            # Load macOS system certificates
                            context.load_verify_locations(capath='/System/Library/OpenSSL/certs')
                        except Exception as e:
                            logger.debug("Failed to load macOS system certs: %s", e)

                        try:
                            # Alternative macOS certificate paths
                            for cert_path in [
                                '/usr/local/etc/openssl/cert.pem',
                                '/opt/homebrew/etc/openssl/cert.pem',
                                '/etc/ssl/cert.pem'
                            ]:
                                if os.path.exists(cert_path):
                                    context.load_verify_locations(cafile=cert_path)
                                    logger.debug("Loaded certificates from %s", cert_path)
                                    break
                        except Exception as e:
                            logger.debug("Failed to load alternative cert paths: %s", e)

                self.sock = context.wrap_socket(raw, server_hostname=host)
            else:
                self.sock = raw

            # Ensure subsequent operations do not hang indefinitely
            try:
                self.sock.settimeout(10)  # Increased timeout
            except Exception:
                pass

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


def _publish_event_to_relay(url: str, event: Dict) -> bool:
    """Publish ``event`` to the relay at ``url`` using WebSockets.

    Returns True if the relay responds with an OK ack for the event id.
    """
    logger.debug("Connecting to relay %s", url)
    ws = _WSConnection(url)
    try:
        msg = json.dumps(["EVENT", event])
        logger.debug("Sending EVENT to %s (id=%s)", url, event.get("id"))
        ws.send(msg)
        ok = False
        try:
            resp = ws.recv()
            logger.debug("Received from %s: %s", url, resp)
            try:
                data = json.loads(resp)
                if (
                    isinstance(data, list)
                    and len(data) >= 3
                    and data[0] == "OK"
                    and data[1] == event.get("id")
                ):
                    ok = bool(data[2])
                    logger.debug(
                        "Relay %s OK ack for id=%s: %s", url, event.get("id"), ok
                    )
                else:
                    logger.debug("Relay %s unexpected reply: %s", url, data)
            except Exception:
                logger.debug("Relay %s non-JSON reply", url)
        except Exception as exc:
            logger.debug("No ack from %s (exception: %s)", url, exc)
        return ok
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
        logger.debug("Sending REQ to %s: %s", url, req)
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
        logger.debug("Sending REQ to %s: %s", url, req)
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
    """Backup ``data`` to Nostr relays; cache in session memory.

    - Publishes the encrypted event to provided ``relay_urls`` or defaults.
    - Always stores the event in a session cache keyed by pubkey for quick
      restore within the same runtime.
    - Detailed debug logs are emitted when ``debug=True``.
    """

    _configure_debug_logging(debug)

    sk_hex, pk_hex, priv, nostr_priv = _derive_keypair(private_key_hex)
    logger.debug("Preparing backup for pubkey=%s", pk_hex)
    content = _encrypt_nip04(priv, json.dumps(data, sort_keys=True), nostr_priv)
    event = _create_event(sk_hex, pk_hex, content, nostr_priv)
    urls = relay_urls or DEFAULT_RELAYS
    logger.debug("Publishing to relays: %s", urls)
    success_count = 0
    for url in urls:
        try:
            logger.debug("Publishing event id=%s to %s", event["id"], url)
            ok = _publish_event_to_relay(url, event)
            logger.debug("Publish result %s for %s", ok, url)
            if ok:
                success_count += 1
        except Exception as exc:
            logger.debug("Failed to publish to %s: %s", url, exc)

    _SESSION_EVENTS.setdefault(pk_hex, []).append(event)
    logger.debug(
        "Cached event in session (count=%d) successes=%d/%d id=%s",
        len(_SESSION_EVENTS[pk_hex]),
        success_count,
        len(urls),
        event["id"],
    )
    return event["id"]


def restore_from_nostr(
    private_key_hex: str,
    relay_urls: Optional[List[str]] = None,
    debug: bool = False,
) -> Dict:
    """Restore backup data by fetching the latest event from relays.

    Falls back to session cache when no relay data is available.
    """

    _configure_debug_logging(debug)

    sk_hex, pk_hex, priv, nostr_priv = _derive_keypair(private_key_hex)

    urls = relay_urls or DEFAULT_RELAYS
    logger.debug("Restoring from relays: %s", urls)
    for url in urls:
        try:
            event = _fetch_event_from_relay(url, pk_hex)
        except Exception as exc:
            logger.debug("Failed to fetch from %s: %s", url, exc)
            event = None
        if event:
            logger.debug("Found event on %s: %s", url, event.get("id"))
            decrypted = _decrypt_nip04(
                priv,
                event.get("content", ""),
                event.get("pubkey", pk_hex),
                nostr_priv,
            )
            return json.loads(decrypted)

    logger.debug("Falling back to session cache for pubkey=%s", pk_hex)
    events = _SESSION_EVENTS.get(pk_hex) or []
    if events:
        event = events[-1]
        decrypted = _decrypt_nip04(
            priv,
            event.get("content", ""),
            event.get("pubkey", pk_hex),
            nostr_priv,
        )
        return json.loads(decrypted)

    raise ValueError("No backup found for provided key on relays or session cache")


def restore_history_from_nostr(
    private_key_hex: str,
    relay_urls: Optional[List[str]] = None,
    debug: bool = False,
    limit: int = 50,
) -> List[Dict]:
    """Return a list of all decrypted backup entries for the key.

    Prefers relay history; falls back to session cache.
    """

    _configure_debug_logging(debug)

    sk_hex, pk_hex, priv, nostr_priv = _derive_keypair(private_key_hex)

    events: List[Dict] = []
    urls = relay_urls or DEFAULT_RELAYS
    logger.debug("Fetching history from relays: %s", urls)
    for url in urls:
        try:
            events.extend(_fetch_history_from_relay(url, pk_hex, limit))
        except Exception as exc:
            logger.debug("Failed to fetch history from %s: %s", url, exc)

    if not events:
        logger.debug("No relay history; falling back to session cache")
        events = _SESSION_EVENTS.get(pk_hex, [])[-limit:]

    history: List[Dict] = []
    for event in events:
        try:
            decrypted = _decrypt_nip04(
                priv,
                event.get("content", ""),
                event.get("pubkey", pk_hex),
                nostr_priv,
            )
            item = json.loads(decrypted)
            item["event_id"] = event.get("id")
            history.append(item)
        except Exception as exc:
            logger.debug("Failed to decrypt event %s: %s", event.get("id"), exc)
    return history
