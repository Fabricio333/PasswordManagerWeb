import json
from password_manager.nostr_utils import backup_to_nostr, restore_from_nostr, BACKUP_FILE
import threading
import time
import socket
import base64
import hashlib


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


GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _send_frame(conn, payload: bytes) -> None:
    header = bytearray()
    header.append(0x81)
    length = len(payload)
    if length < 126:
        header.append(length)
    elif length < 65536:
        header.append(126)
        header += length.to_bytes(2, "big")
    else:
        header.append(127)
        header += length.to_bytes(8, "big")
    conn.sendall(header + payload)


def _recv_frame(conn) -> str:
    header = conn.recv(2)
    if len(header) < 2:
        return ""
    b1, b2 = header
    length = b2 & 0x7F
    if length == 126:
        length = int.from_bytes(conn.recv(2), "big")
    elif length == 127:
        length = int.from_bytes(conn.recv(8), "big")
    mask = conn.recv(4)
    data = conn.recv(length)
    unmasked = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
    return unmasked.decode()


def _start_relay_server(stop_event, store):
    server = socket.socket()
    server.bind(("localhost", 8765))
    server.listen(1)
    conn, _ = server.accept()
    request = conn.recv(1024).decode()
    key = ""
    for line in request.split("\r\n"):
        if line.lower().startswith("sec-websocket-key"):
            key = line.split(":", 1)[1].strip()
            break
    accept = base64.b64encode(hashlib.sha1((key + GUID).encode()).digest()).decode()
    response = (
        "HTTP/1.1 101 Switching Protocols\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
    )
    conn.sendall(response.encode())
    while not stop_event.is_set():
        msg = _recv_frame(conn)
        if not msg:
            break
        data = json.loads(msg)
        if data[0] == "EVENT":
            store["event"] = data[1]
            _send_frame(conn, json.dumps(["OK", data[1]["id"], True, ""]).encode())
        elif data[0] == "REQ":
            sub_id = data[1]
            _send_frame(conn, json.dumps(["EVENT", sub_id, store["event"]]).encode())
            _send_frame(conn, json.dumps(["EOSE", sub_id]).encode())
            break
    conn.close()
    server.close()


def test_network_backup_and_restore(capsys):
    stop = threading.Event()
    store = {}
    thread = threading.Thread(target=_start_relay_server, args=(stop, store))
    thread.start()
    time.sleep(0.1)
    try:
        key = "cafebabe"
        data = {"hello": "world"}
        relay_url = "ws://localhost:8765"
        event_id = backup_to_nostr(key, data, relay_urls=[relay_url], debug=True)
        assert isinstance(event_id, str)
        restored = restore_from_nostr(key, relay_urls=[relay_url], debug=True)
        assert restored == data
        captured = capsys.readouterr()
        assert "Sending" in captured.err or captured.out
        assert "Received" in captured.err or captured.out
    finally:
        stop.set()
        thread.join()
