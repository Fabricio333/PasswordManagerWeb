import json
from password_manager.nostr_utils import (
    backup_to_nostr,
    backup_nonces_to_nostr,
    restore_from_nostr,
    restore_history_from_nostr,
    load_nonces,
    BACKUP_FILE,
)
import password_manager.nostr_utils as nu
import time


def test_backup_and_restore(tmp_path, monkeypatch):
    temp_file = tmp_path / "backups.json"
    monkeypatch.setattr("password_manager.nostr_utils.BACKUP_FILE", temp_file)
    monkeypatch.setattr("password_manager.nostr_utils._SESSION_EVENTS", {})

    key = "deadbeef"
    data = {"foo": "bar"}

    event_id = backup_to_nostr(key, data, relay_urls=[], debug=True)
    assert temp_file.exists()
    assert isinstance(event_id, str)

    # Ensure the stored content is encrypted (not raw JSON)
    stored = json.loads(temp_file.read_text())[-1]
    assert stored["content"] != json.dumps(data, sort_keys=True)

    restored = restore_from_nostr(key, relay_urls=[], debug=True)
    assert restored == data


def test_debug_logging(tmp_path, monkeypatch, capsys):
    """Debug logging should emit messages to the terminal when enabled."""
    temp_file = tmp_path / "backups.json"
    monkeypatch.setattr("password_manager.nostr_utils.BACKUP_FILE", temp_file)
    monkeypatch.setattr("password_manager.nostr_utils._SESSION_EVENTS", {})

    # Preconfigure logging to a non-debug level with an existing handler
    import logging

    handler = logging.StreamHandler()
    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(logging.WARNING)

    backup_to_nostr("deadbeef", {"foo": "bar"}, relay_urls=[], debug=True)

    captured = capsys.readouterr()
    assert "Deriving Nostr keys" in captured.err or captured.out


def test_restore_history(tmp_path, monkeypatch):
    temp_file = tmp_path / "backups.json"
    monkeypatch.setattr("password_manager.nostr_utils.BACKUP_FILE", temp_file)
    monkeypatch.setattr("password_manager.nostr_utils._SESSION_EVENTS", {})
    key = "deadbeef"
    backup_to_nostr(key, {"foo": 1}, relay_urls=[], debug=True)
    time.sleep(0.1)
    backup_to_nostr(key, {"foo": 2}, relay_urls=[], debug=True)
    history = restore_history_from_nostr(key, relay_urls=[], debug=True)
    assert [h["foo"] for h in history] == [1, 2]


def test_backup_and_load_nonces(tmp_path, monkeypatch):
    temp_file = tmp_path / "backups.json"
    monkeypatch.setattr("password_manager.nostr_utils.BACKUP_FILE", temp_file)
    monkeypatch.setattr("password_manager.nostr_utils._SESSION_EVENTS", {})

    key = "deadbeef"
    nonces = {"alice": {"example.com": 1, "example.net": 2}}

    # Store the nonces snapshot (publishing to relays is best-effort)
    backup_nonces_to_nostr(key, nonces, relay_urls=[], debug=True)

    # Ensure they can be loaded back
    loaded = load_nonces(key, relay_urls=[], debug=True)
    assert loaded == nonces
    

def test_mock_relay_backup_and_restore(tmp_path, monkeypatch, capsys):
    temp_file = tmp_path / "backups.json"
    monkeypatch.setattr("password_manager.nostr_utils.BACKUP_FILE", temp_file)
    monkeypatch.setattr("password_manager.nostr_utils._SESSION_EVENTS", {})

    store = {}

    def fake_publish(url, event):
        store[event["id"]] = event
        nu.logger.debug("Sending EVENT to %s (id=%s)", url, event["id"])
        nu.logger.debug(
            "Received from %s: %s", url, json.dumps(["OK", event["id"], True, ""])
        )
        return True

    def fake_fetch(url, pk_hex, tag=nu.BACKUP_TAG):
        return next(reversed(store.values()), None)

    monkeypatch.setattr(
        "password_manager.nostr_utils._publish_event_to_relay", fake_publish
    )
    monkeypatch.setattr(
        "password_manager.nostr_utils._fetch_event_from_relay", fake_fetch
    )

    key = "cafebabe"
    data = {"hello": "world"}
    relay_url = "wss://example.com"
    backup_to_nostr(key, data, relay_urls=[relay_url], debug=True)
    assert store
    temp_file.unlink()  # ensure restore pulls from mocked relay
    restored = restore_from_nostr(key, relay_urls=[relay_url], debug=True)
    assert restored == data
    captured = capsys.readouterr()
    assert "Sending EVENT" in captured.err or captured.out
    assert "Received from" in captured.err or captured.out


def test_mock_relay_history(tmp_path, monkeypatch):
    temp_file = tmp_path / "backups.json"
    monkeypatch.setattr("password_manager.nostr_utils.BACKUP_FILE", temp_file)
    monkeypatch.setattr("password_manager.nostr_utils._SESSION_EVENTS", {})

    store = []

    def fake_publish(url, event):
        store.append(event)
        nu.logger.debug("Sending EVENT to %s (id=%s)", url, event["id"])
        nu.logger.debug(
            "Received from %s: %s", url, json.dumps(["OK", event["id"], True, ""])
        )
        return True

    def fake_fetch_history(url, pk_hex, limit=50, tag=nu.BACKUP_TAG):
        return store[:limit]

    monkeypatch.setattr(
        "password_manager.nostr_utils._publish_event_to_relay", fake_publish
    )
    monkeypatch.setattr(
        "password_manager.nostr_utils._fetch_history_from_relay",
        fake_fetch_history,
    )

    key = "cafebabe"
    relay_url = "wss://example.com"
    backup_to_nostr(key, {"n": 1}, relay_urls=[relay_url], debug=True)
    backup_to_nostr(key, {"n": 2}, relay_urls=[relay_url], debug=True)
    temp_file.unlink()
    history = restore_history_from_nostr(key, relay_urls=[relay_url], debug=True)
    assert [h["n"] for h in history] == [1, 2]


def test_connection_logging_success(tmp_path, monkeypatch, caplog):
    temp_file = tmp_path / "backups.json"
    monkeypatch.setattr("password_manager.nostr_utils.BACKUP_FILE", temp_file)
    monkeypatch.setattr("password_manager.nostr_utils._SESSION_EVENTS", {})

    class DummySuccess:
        def __init__(self, url):
            nu.logger.debug("WebSocket connection to %s opening", url)
            nu.logger.debug("WebSocket connection to %s established", url)
            self.last = None

        def send(self, message):
            self.last = json.loads(message)

        def recv(self):
            event = self.last[1]
            return json.dumps(["OK", event["id"], True, ""])

        def close(self):
            pass

    monkeypatch.setattr("password_manager.nostr_utils._WSConnection", DummySuccess)

    key = "facefeed"
    relay_url = "wss://example.com"
    with caplog.at_level("DEBUG"):
        backup_to_nostr(key, {"n": 1}, relay_urls=[relay_url], debug=True)
    assert any(
        f"WebSocket connection to {relay_url} established" in rec.message
        for rec in caplog.records
    )


def test_connection_logging_failure(tmp_path, monkeypatch, caplog):
    temp_file = tmp_path / "backups.json"
    monkeypatch.setattr("password_manager.nostr_utils.BACKUP_FILE", temp_file)
    monkeypatch.setattr("password_manager.nostr_utils._SESSION_EVENTS", {})

    class DummyFail:
        def __init__(self, url):
            nu.logger.debug("WebSocket connection to %s opening", url)
            nu.logger.debug("WebSocket connection to %s failed: boom", url)
            raise OSError("boom")

    monkeypatch.setattr("password_manager.nostr_utils._WSConnection", DummyFail)

    key = "facefeed"
    relay_url = "wss://example.com"
    with caplog.at_level("DEBUG"):
        backup_to_nostr(key, {"n": 1}, relay_urls=[relay_url], debug=True)
    assert any(
        f"WebSocket connection to {relay_url} failed" in rec.message
        for rec in caplog.records
    )
