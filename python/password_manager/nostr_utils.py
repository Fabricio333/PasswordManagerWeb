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
import sys
from pathlib import Path
from urllib.parse import urlparse
from typing import Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .seed import derive_npub_from_nsec

# ``encode_nsec`` is optional; the surrounding application can operate purely
# with hex keys.  When unavailable we simply skip creating the python-nostr
# helper instance that expects a bech32 encoded secret.
try:  # pragma: no cover - optional dependency
    from .bech32 import encode_nsec  # type: ignore[attr-defined]
except Exception:  # pragma: no cover - bech32 helper not present
    encode_nsec = None  # type: ignore

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

# Local JSON file used for unit tests and offline storage
# The project intentionally avoids creating separate cache files and only
# persists backup events to this single JSON file.
BACKUP_FILE = Path("backup.json")

# Tags used to classify different backup event types. ``NONCES_TAG`` remains
# only for backwards compatibility with older Python snapshots; the browser
# implementation stores nonce information under the standard ``BACKUP_TAG``.
BACKUP_TAG = "nostr-pwd-backup"
NONCES_TAG = "nostr-pwd-nonces"  # legacy


def _configure_debug_logging(debug: bool) -> None:
    """Ensure debug log messages are visible when ``debug`` is ``True``.

    Many GUI launch environments preconfigure logging with non-console handlers
    or higher levels, which can unintentionally suppress module debug output.
    To make behaviour predictable for users, when ``debug`` is enabled we:

    - Set the root logger level to DEBUG (non-destructive to existing handlers).
    - Attach a ``StreamHandler`` to this module's logger bound to the current
      ``sys.stderr`` so the output is visible to ``capsys`` during tests.
    - Allow records to propagate to the root logger so ``caplog`` can observe
      them while still emitting to the terminal.
    """
    if not debug:
        return

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    logger.setLevel(logging.DEBUG)

    # Ensure the root logger has a ``StreamHandler`` bound to the original
    # ``sys.__stderr__``. This avoids PyTest's captured streams from being
    # closed between tests while still displaying debug output to the terminal.
    if not any(isinstance(h, logging.StreamHandler) for h in root_logger.handlers):
        root_handler = logging.StreamHandler(sys.__stderr__)
        root_handler.setFormatter(
            logging.Formatter("%(levelname)s:%(name)s:%(message)s")
        )
        root_logger.addHandler(root_handler)

    # Remove any stream handlers directly attached to this module's logger so
    # that only the root logger emits records.
    for h in list(logger.handlers):
        if isinstance(h, logging.StreamHandler):
            logger.removeHandler(h)

    # Propagate so that ``caplog`` fixtures can capture these records.
    logger.propagate = True


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
            if hasattr(NostrPrivateKey, "from_nsec") and encode_nsec:
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

    When the optional ``python-nostr`` library is available the implementation
    is delegated to its :meth:`encrypt_message` helper which mirrors the web
    ``nip04.encrypt`` behaviour.  Otherwise a local compatible fallback using
    AES-CBC with PKCS#7 padding is used.
    """

    if nostr_priv:
        try:  # pragma: no cover - exercised when python-nostr is installed
            logger.debug("Encrypting data via NIP‑04 (python-nostr)")
            return nostr_priv.encrypt_message(
                plaintext, nostr_priv.public_key.hex()
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug(
                "python-nostr encrypt_message failed: %s; falling back to local implementation",
                exc,
            )

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
    if nostr_priv:
        try:  # pragma: no cover - exercised when python-nostr is installed
            logger.debug("Decrypting NIP‑04 payload (python-nostr)")
            return nostr_priv.decrypt_message(ciphertext, sender_pubkey_hex)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug(
                "python-nostr decrypt_message failed: %s; falling back to local implementation",
                exc,
            )

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
    tag: str = BACKUP_TAG,
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
            [["t", tag]],
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
        [["t", tag]],
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
        "tags": [["t", tag]],
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


def _fetch_event_from_relay(url: str, pk_hex: str, tag: str = BACKUP_TAG) -> Optional[Dict]:
    """Fetch the most recent event for ``pk_hex`` from ``url`` filtered by ``tag``."""
    logger.debug("Connecting to relay %s", url)
    ws = _WSConnection(url)
    try:
        sub_id = os.urandom(4).hex()
        filt = {"authors": [pk_hex], "#t": [tag], "kinds": [1], "limit": 1}
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


def _fetch_history_from_relay(url: str, pk_hex: str, limit: int = 50, tag: str = BACKUP_TAG) -> List[Dict]:
    """Fetch up to ``limit`` events for ``pk_hex`` from ``url`` filtered by ``tag``."""
    logger.debug("Connecting to relay %s", url)
    ws = _WSConnection(url)
    events: List[Dict] = []
    try:
        sub_id = os.urandom(4).hex()
        filt = {
            "authors": [pk_hex],
            "#t": [tag],
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
    return_status: bool = False,
    tag: str = BACKUP_TAG,
) -> object:
    """Backup ``data`` to Nostr relays; cache in session memory.

    - Publishes the encrypted event to provided ``relay_urls`` or defaults.
    - Always stores the event in a session cache keyed by pubkey for quick
      restore within the same runtime and persists to a local JSON file.
    - When no relays acknowledge the event, the local JSON file serves as an
      offline backup containing the same encrypted event format.
    - Detailed debug logs are emitted when ``debug=True``.

    Compatibility: by default returns the event id as ``str``. When
    ``return_status=True`` it returns a dict with keys ``event_id`` (str),
    ``published`` (bool), ``relays_ack`` (int) and ``relays_attempted`` (int).
    """

    _configure_debug_logging(debug)

    sk_hex, pk_hex, priv, nostr_priv = _derive_keypair(private_key_hex)
    logger.debug("Preparing backup for pubkey=%s", pk_hex)
    content = _encrypt_nip04(priv, json.dumps(data, sort_keys=True), nostr_priv)
    event = _create_event(sk_hex, pk_hex, content, nostr_priv, tag=tag)
    urls = relay_urls if relay_urls is not None else DEFAULT_RELAYS
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

    # Persist event to local backup file so tests and offline use can read it
    try:
        if BACKUP_FILE.exists():
            existing = json.loads(BACKUP_FILE.read_text())
            if not isinstance(existing, list):
                existing = []
        else:
            existing = []
        existing.append(event)
        BACKUP_FILE.write_text(json.dumps(existing))
    except Exception as exc:  # pragma: no cover - best effort
        logger.debug("Failed to write backup file %s: %s", BACKUP_FILE, exc)

    logger.debug(
        "Cached event in session (count=%d) successes=%d/%d id=%s",
        len(_SESSION_EVENTS[pk_hex]),
        success_count,
        len(urls),
        event["id"],
    )
    if success_count == 0:
        logger.debug("No relay acknowledgments; created local backup only")
    if return_status:
        return {
            "event_id": event["id"],
            "published": success_count > 0,
            "relays_ack": success_count,
            "relays_attempted": len(urls),
        }
    return event["id"]


def backup_nonces_to_nostr(
    private_key_hex: str,
    nonces: Dict[str, Dict[str, int]],
    relay_urls: Optional[List[str]] = None,
    debug: bool = False,
    return_status: bool = False,
) -> object:
    """Convenience wrapper to publish a nonces snapshot.

    ``nonces`` should be a mapping of ``{"user": {"site": nonce_int}}`` which
    will be encrypted and sent to relays using the same tag as the browser
    implementation (:data:`BACKUP_TAG`).
    """

    logger.debug("Backing up nonce snapshot: %s", nonces)
    for user, sites in nonces.items():
        for site, nonce in sites.items():
            logger.debug("nonce[%s][%s]=%s", user, site, nonce)

    return backup_to_nostr(
        private_key_hex,
        {"users": nonces},
        relay_urls=relay_urls,
        debug=debug,
        return_status=return_status,
        tag=BACKUP_TAG,
    )


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

    urls = relay_urls if relay_urls is not None else DEFAULT_RELAYS
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

    logger.debug("Falling back to local cache for pubkey=%s", pk_hex)

    # Prefer reading from the JSON backup file if it exists
    try:
        if BACKUP_FILE.exists():
            file_events = json.loads(BACKUP_FILE.read_text())
            for ev in reversed(file_events):
                if ev.get("pubkey") == pk_hex:
                    decrypted = _decrypt_nip04(
                        priv,
                        ev.get("content", ""),
                        ev.get("pubkey", pk_hex),
                        nostr_priv,
                    )
                    return json.loads(decrypted)
    except Exception as exc:  # pragma: no cover - best effort
        logger.debug("Failed to read backup file %s: %s", BACKUP_FILE, exc)

    # Finally fall back to the in-memory session cache
    logger.debug("Falling back to session cache for pubkey=%s", pk_hex)
    events = _SESSION_EVENTS.get(pk_hex) or []
    if events:
        ev = events[-1]
        decrypted = _decrypt_nip04(
            priv,
            ev.get("content", ""),
            ev.get("pubkey", pk_hex),
            nostr_priv,
        )
        return json.loads(decrypted)

    raise ValueError("No backup found for provided key on relays, file, or session cache")


def restore_history_from_nostr(
    private_key_hex: str,
    relay_urls: Optional[List[str]] = None,
    debug: bool = False,
    limit: int = 50,
) -> List[Dict]:
    """Return a list of decrypted backup entries for the key.

    Collects from relays, local backup file, and session cache, then
    de-duplicates by event id and returns the most recent ``limit`` items.
    Each returned dict includes original fields plus ``event_id`` and
    ``created_at`` (int). When available, an additional ``source`` key may be
    present with values: ``relay``, ``file``, or ``session``.
    """

    _configure_debug_logging(debug)

    sk_hex, pk_hex, priv, nostr_priv = _derive_keypair(private_key_hex)

    events: List[Dict] = []
    urls = relay_urls if relay_urls is not None else DEFAULT_RELAYS
    logger.debug("Fetching history from relays: %s", urls)
    for url in urls:
        try:
            # Fetch standard backup entries
            fetched = _fetch_history_from_relay(url, pk_hex, limit, tag=BACKUP_TAG)
            for ev in fetched:
                ev.setdefault("_source", "relay")
                ev.setdefault("_relay", url)
            events.extend(fetched)
            # Fetch legacy nonces snapshots for backwards compatibility
            fetched_nonces = _fetch_history_from_relay(
                url, pk_hex, limit, tag=NONCES_TAG
            )
            for ev in fetched_nonces:
                ev.setdefault("_source", "relay")
                ev.setdefault("_relay", url)
            events.extend(fetched_nonces)
        except Exception as exc:
            logger.debug("Failed to fetch history from %s: %s", url, exc)

    # Always consider local backup file as well (merge), best-effort
    logger.debug("Merging local backup file history if available")
    try:
        if BACKUP_FILE.exists():
            file_events = json.loads(BACKUP_FILE.read_text())
            if isinstance(file_events, list):
                for e in file_events:
                    if e.get("pubkey") == pk_hex:
                        e.setdefault("_source", "file")
                        events.append(e)
    except Exception as exc:  # pragma: no cover - best effort
        logger.debug("Failed to read backup file %s: %s", BACKUP_FILE, exc)

    # Include session cache entries too
    logger.debug("Merging session cache history")
    for e in _SESSION_EVENTS.get(pk_hex, []):
        ev = dict(e)
        ev.setdefault("_source", "session")
        events.append(ev)

    # De-duplicate by id, prefer relay over file over session
    def _pref_order(src: str) -> int:
        return {"relay": 3, "file": 2, "session": 1}.get(src, 0)

    dedup: Dict[str, Dict] = {}
    for ev in events:
        eid = ev.get("id")
        src = ev.get("_source", "")
        if not eid:
            continue
        existing = dedup.get(eid)
        if not existing or _pref_order(src) > _pref_order(existing.get("_source", "")):
            dedup[eid] = ev

    # Sort by created_at desc and keep the most recent "limit"
    events_sorted = sorted(
        dedup.values(), key=lambda e: int(e.get("created_at", 0)), reverse=True
    )[:limit]

    history: List[Dict] = []
    for event in events_sorted:
        try:
            decrypted = _decrypt_nip04(
                priv,
                event.get("content", ""),
                event.get("pubkey", pk_hex),
                nostr_priv,
            )
            item = json.loads(decrypted)
            item["event_id"] = event.get("id")
            if "created_at" in event:
                item["created_at"] = event.get("created_at")
            if event.get("_source"):
                item["source"] = event.get("_source")
            if event.get("_relay"):
                item["relay"] = event.get("_relay")
            history.append(item)
        except Exception as exc:
            logger.debug("Failed to decrypt event %s: %s", event.get("id"), exc)
    return history


def load_nonces(
    private_key_hex: str,
    relay_urls: Optional[List[str]] = None,
    debug: bool = False,
) -> Dict[str, Dict[str, int]]:
    """Load the latest per-user/site nonce mapping for the key.

    The returned structure mirrors the browser implementation and is of the
    form ``{"user": {"site": nonce_int}}``. Lookup order is:

    1. Most recent :data:`BACKUP_TAG` event from provided relays (legacy
       :data:`NONCES_TAG` events are also supported).
    2. Local backup file.
    3. In-memory session cache.

    When no data is found an empty dict is returned.
    """

    _configure_debug_logging(debug)

    sk_hex, pk_hex, priv, nostr_priv = _derive_keypair(private_key_hex)

    # Try relays
    urls = relay_urls if relay_urls is not None else DEFAULT_RELAYS
    logger.debug("Loading nonces from relays: %s", urls)
    for url in urls:
        event = None
        try:
            event = _fetch_event_from_relay(url, pk_hex, tag=BACKUP_TAG)
            if event is None:
                event = _fetch_event_from_relay(url, pk_hex, tag=NONCES_TAG)
        except Exception as exc:
            logger.debug("Failed to fetch nonces from %s: %s", url, exc)
            event = None
        if event:
            try:
                plaintext = _decrypt_nip04(
                    priv,
                    event.get("content", ""),
                    event.get("pubkey", pk_hex),
                    nostr_priv,
                )
                data = json.loads(plaintext)
                source = None
                if isinstance(data, dict):
                    if isinstance(data.get("users"), dict):
                        source = data["users"]
                    elif isinstance(data.get("nonces"), dict):  # legacy
                        source = data["nonces"]
                if isinstance(source, dict):
                    out: Dict[str, Dict[str, int]] = {}
                    for user, sites in source.items():
                        if not isinstance(sites, dict):
                            continue
                        coerced: Dict[str, int] = {}
                        for site, nonce in sites.items():
                            try:
                                coerced[site] = int(nonce)
                                logger.debug(
                                    "Relay %s nonce[%s][%s]=%d",
                                    url,
                                    user,
                                    site,
                                    coerced[site],
                                )
                            except Exception:
                                logger.debug(
                                    "Relay %s invalid nonce[%s][%s]=%r",
                                    url,
                                    user,
                                    site,
                                    nonce,
                                )
                                continue
                        if coerced:
                            out[user] = coerced
                            logger.debug(
                                "Relay %s aggregated nonces for %s: %s",
                                url,
                                user,
                                coerced,
                            )
                    if out:
                        logger.debug("Returning nonces from relay %s: %s", url, out)
                        return out
            except Exception as exc:
                logger.debug("Failed to decrypt/parse nonces: %s", exc)

    # Try local backup file
    logger.debug("Loading nonces from local backup file")
    try:
        if BACKUP_FILE.exists():
            file_events = json.loads(BACKUP_FILE.read_text())
            if isinstance(file_events, list):
                for ev in reversed(file_events):
                    if ev.get("pubkey") != pk_hex:
                        continue
                    tags = ev.get("tags") or []
                    if not any(
                        isinstance(t, list) and len(t) >= 2 and t[0] == "t" and t[1] in {BACKUP_TAG, NONCES_TAG}
                        for t in tags
                    ):
                        continue
                    plaintext = _decrypt_nip04(
                        priv,
                        ev.get("content", ""),
                        ev.get("pubkey", pk_hex),
                        nostr_priv,
                    )
                    data = json.loads(plaintext)
                    source = None
                    if isinstance(data, dict):
                        if isinstance(data.get("users"), dict):
                            source = data["users"]
                        elif isinstance(data.get("nonces"), dict):
                            source = data["nonces"]
                    if isinstance(source, dict):
                        out: Dict[str, Dict[str, int]] = {}
                        for user, sites in source.items():
                            if not isinstance(sites, dict):
                                continue
                            coerced: Dict[str, int] = {}
                            for site, nonce in sites.items():
                                try:
                                    coerced[site] = int(nonce)
                                    logger.debug(
                                        "File nonce[%s][%s]=%d",
                                        user,
                                        site,
                                        coerced[site],
                                    )
                                except Exception:
                                    logger.debug(
                                        "File invalid nonce[%s][%s]=%r",
                                        user,
                                        site,
                                        nonce,
                                    )
                                    continue
                            if coerced:
                                out[user] = coerced
                                logger.debug(
                                    "File aggregated nonces for %s: %s",
                                    user,
                                    coerced,
                                )
                        if out:
                            logger.debug("Returning nonces from file: %s", out)
                            return out
    except Exception as exc:  # pragma: no cover - best effort
        logger.debug("Failed to read/decrypt nonces from file: %s", exc)

    # Try session cache
    logger.debug("Loading nonces from session cache")
    for ev in reversed(_SESSION_EVENTS.get(pk_hex, [])):
        tags = ev.get("tags") or []
        if not any(
            isinstance(t, list) and len(t) >= 2 and t[0] == "t" and t[1] in {BACKUP_TAG, NONCES_TAG}
            for t in tags
        ):
            continue
        try:
            plaintext = _decrypt_nip04(
                priv,
                ev.get("content", ""),
                ev.get("pubkey", pk_hex),
                nostr_priv,
            )
            data = json.loads(plaintext)
            source = None
            if isinstance(data, dict):
                if isinstance(data.get("users"), dict):
                    source = data["users"]
                elif isinstance(data.get("nonces"), dict):
                    source = data["nonces"]
            if isinstance(source, dict):
                out: Dict[str, Dict[str, int]] = {}
                for user, sites in source.items():
                    if not isinstance(sites, dict):
                        continue
                    coerced: Dict[str, int] = {}
                    for site, nonce in sites.items():
                        try:
                            coerced[site] = int(nonce)
                            logger.debug(
                                "Session nonce[%s][%s]=%d",
                                user,
                                site,
                                coerced[site],
                            )
                        except Exception:
                            logger.debug(
                                "Session invalid nonce[%s][%s]=%r",
                                user,
                                site,
                                nonce,
                            )
                            continue
                    if coerced:
                        out[user] = coerced
                        logger.debug(
                            "Session aggregated nonces for %s: %s",
                            user,
                            coerced,
                        )
                if out:
                    logger.debug("Returning nonces from session: %s", out)
                    return out
        except Exception as exc:
            logger.debug("Failed to decrypt/parse nonces from session: %s", exc)

    logger.debug("No nonces found; returning empty mapping")
    return {}
