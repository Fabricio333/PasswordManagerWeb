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


def test_debug_logging(tmp_path, monkeypatch, capsys):
    """Debug logging should emit messages to the terminal when enabled."""
    temp_file = tmp_path / "backups.json"
    monkeypatch.setattr("password_manager.nostr_utils.BACKUP_FILE", temp_file)

    # Preconfigure logging to a non-debug level with an existing handler
    import logging

    handler = logging.StreamHandler()
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.WARNING)

    backup_to_nostr("deadbeef", {"foo": "bar"}, debug=True)

    captured = capsys.readouterr()
    assert "Deriving Nostr keys" in captured.err or captured.out
