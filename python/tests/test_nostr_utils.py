import json
from password_manager.nostr_utils import backup_to_nostr, restore_from_nostr, BACKUP_FILE


def test_backup_and_restore(tmp_path, monkeypatch):
    temp_file = tmp_path / "backups.json"
    monkeypatch.setattr("password_manager.nostr_utils.BACKUP_FILE", temp_file)

    key = "deadbeef"
    data = {"foo": "bar"}

    event_id = backup_to_nostr(key, data, debug=True)
    assert temp_file.exists()
    assert isinstance(event_id, str)

    # Ensure the stored content is encrypted (not raw JSON)
    stored = json.loads(temp_file.read_text())[-1]
    assert stored["content"] != json.dumps(data, sort_keys=True)

    restored = restore_from_nostr(key, debug=True)
    assert restored == data
