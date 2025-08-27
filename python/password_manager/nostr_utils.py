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
from pathlib import Path
from typing import Dict, List, Optional

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


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


def _derive_keypair(private_key_hex: str) -> (str, str, ec.EllipticCurvePrivateKey):
    """Derive the Nostr key pair from the web compatible ``private_key_hex``."""
    logger.debug("Deriving Nostr keys from private key hex")
    sk_hex = hashlib.sha256(private_key_hex.encode()).hexdigest()
    priv = ec.derive_private_key(int(sk_hex, 16), ec.SECP256K1())
    pk_numbers = priv.public_key().public_numbers()
    pk_hex = f"{pk_numbers.x:064x}"
    logger.debug("Derived sk=%s, pk=%s", sk_hex, pk_hex)
    return sk_hex, pk_hex, priv


def _encrypt_nip04(priv: ec.EllipticCurvePrivateKey, plaintext: str) -> str:
    """Encrypt ``plaintext`` using NIP‑04 (self‑encryption)."""
    logger.debug("Encrypting data via NIP‑04")
    shared = priv.exchange(ec.ECDH(), priv.public_key())
    key = hashlib.sha256(shared).digest()
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext.encode()) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(padded) + encryptor.finalize()
    return f"{base64.b64encode(ct).decode()}?iv={base64.b64encode(iv).decode()}"


def _decrypt_nip04(priv: ec.EllipticCurvePrivateKey, ciphertext: str) -> str:
    """Decrypt a NIP‑04 payload produced by :func:`_encrypt_nip04`."""
    logger.debug("Decrypting NIP‑04 payload")
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


def _create_event(sk_hex: str, pk_hex: str, content: str) -> Dict:
    """Create a Nostr style event signed with ``sk_hex``."""
    logger.debug("Creating event for content: %s", content)
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

    sk_hex, pk_hex, priv = _derive_keypair(private_key_hex)
    content = _encrypt_nip04(priv, json.dumps(data, sort_keys=True))
    event = _create_event(sk_hex, pk_hex, content)

    if relay_urls:
        logger.debug(
            "Relay URLs provided (%s) but network publishing is not "
            "implemented in this environment.",
            relay_urls,
        )

    # In this educational environment we simply append the event to a JSON
    # file.  A full implementation would publish the event to the provided
    # relay URLs using WebSockets.
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

    if relay_urls:
        logger.debug(
            "Relay URLs provided (%s) but network retrieval is not "
            "implemented in this environment.",
            relay_urls,
        )

    if not BACKUP_FILE.exists():
        raise FileNotFoundError("No backups available")

    sk_hex, pk_hex, priv = _derive_keypair(private_key_hex)
    logger.debug("Looking for events matching pubkey %s", pk_hex)

    backups = json.loads(BACKUP_FILE.read_text())
    for event in reversed(backups):
        if event.get("pubkey") == pk_hex:
            logger.debug("Found matching event: %s", event)
            decrypted = _decrypt_nip04(priv, event.get("content", ""))
            return json.loads(decrypted)
    raise ValueError("No backup found for provided key")
