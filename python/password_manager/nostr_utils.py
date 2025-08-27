import json
import hashlib
import time
from pathlib import Path
from typing import Dict

# File used to store simulated Nostr backup events
BACKUP_FILE = Path(__file__).resolve().parent / "nostr_backups.json"


def backup_to_nostr(private_key_hex: str, data: Dict) -> str:
    """Simulate backing up data to Nostr by writing to a local JSON file.

    Returns the event id that can later be used for restoration."""
    content = json.dumps(data, sort_keys=True)
    event_id = hashlib.sha256(content.encode()).hexdigest()
    pubkey = hashlib.sha256(private_key_hex.encode()).hexdigest()
    event = {
        "id": event_id,
        "pubkey": pubkey,
        "created_at": int(time.time()),
        "content": content,
    }

    backups = []
    if BACKUP_FILE.exists():
        backups = json.loads(BACKUP_FILE.read_text())
    backups.append(event)
    BACKUP_FILE.write_text(json.dumps(backups, indent=2))
    return event_id


def restore_from_nostr(private_key_hex: str) -> Dict:
    """Restore data for a given private key from the simulated Nostr storage."""
    if not BACKUP_FILE.exists():
        raise FileNotFoundError("No backups available")

    pubkey = hashlib.sha256(private_key_hex.encode()).hexdigest()
    backups = json.loads(BACKUP_FILE.read_text())
    for event in reversed(backups):
        if event.get("pubkey") == pubkey:
            return json.loads(event.get("content", "{}"))
    raise ValueError("No backup found for provided key")
