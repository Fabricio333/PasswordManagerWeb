import json
from password_manager.nostr_utils import backup_to_nostr, restore_from_nostr, BACKUP_FILE


def test_backup_and_restore(tmp_path, monkeypatch):
    temp_file = tmp_path / "backups.json"
    monkeypatch.setattr("password_manager.nostr_utils.BACKUP_FILE", temp_file)

    key = "deadbeef"
    data = {"foo": "bar"}

    event_id = backup_to_nostr(key, data)
    assert temp_file.exists()
    assert isinstance(event_id, str)

    restored = restore_from_nostr(key)
    assert restored == data
