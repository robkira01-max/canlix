"""Tests for the SSE server and its integration with run_proxy."""

from __future__ import annotations

import io
import json
import socket
import threading
import time
import urllib.request

from canlix.runtime.sse_server import SseServer

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _free_port() -> int:
    """Pick an ephemeral port the OS has available right now."""
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _get(port: int, path: str, timeout: float = 2.0) -> tuple[int, bytes]:
    url = f"http://127.0.0.1:{port}{path}"
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, b""


def _sse_read_first_event(port: int, timeout: float = 3.0) -> str | None:
    """Connect to /events, read lines until a data: line or timeout, return raw data."""
    url = f"http://127.0.0.1:{port}/events"
    result: list[str | None] = [None]
    done = threading.Event()

    def _reader():
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                for raw in resp:
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                    if line.startswith("data:"):
                        result[0] = line[5:].strip()
                        done.set()
                        return
        except Exception:
            done.set()

    t = threading.Thread(target=_reader, daemon=True)
    t.start()
    done.wait(timeout + 0.5)
    return result[0]


# ---------------------------------------------------------------------------
# SseServer unit tests
# ---------------------------------------------------------------------------


def test_status_endpoint_returns_json():
    port = _free_port()
    srv = SseServer(port)
    srv.start()
    try:
        code, body = _get(port, "/status")
        assert code == 200
        data = json.loads(body)
        assert data["findings"] == 0
        assert "tool_calls" in data and "hosts_seen" in data
    finally:
        srv.stop()


def test_push_finding_increments_status_count():
    port = _free_port()
    srv = SseServer(port)
    srv.start()
    try:
        srv.push_finding({"rule_id": "RUN-001", "severity": "HIGH", "message": "test"})
        srv.push_finding({"rule_id": "RUN-002", "severity": "MEDIUM", "message": "test2"})
        _, body = _get(port, "/status")
        assert json.loads(body)["findings"] == 2
    finally:
        srv.stop()


def test_update_stats_reflected_in_status():
    port = _free_port()
    srv = SseServer(port)
    srv.start()
    try:
        srv.update_stats(tool_calls=42, hosts_seen=3)
        _, body = _get(port, "/status")
        data = json.loads(body)
        assert data["tool_calls"] == 42
        assert data["hosts_seen"] == 3
    finally:
        srv.stop()


def test_unknown_path_returns_404():
    port = _free_port()
    srv = SseServer(port)
    srv.start()
    try:
        code, _ = _get(port, "/nonexistent")
        assert code == 404
    finally:
        srv.stop()


def test_sse_stream_delivers_finding():
    port = _free_port()
    srv = SseServer(port)
    srv.start()

    received: list[dict] = []
    done = threading.Event()

    def _subscribe():
        url = f"http://127.0.0.1:{port}/events"
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                for raw in resp:
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                    if line.startswith("data:"):
                        received.append(json.loads(line[5:].strip()))
                        done.set()
                        return
        except Exception:
            done.set()

    t = threading.Thread(target=_subscribe, daemon=True)
    t.start()
    time.sleep(0.1)  # let the connection establish

    srv.push_finding({"rule_id": "RUN-001", "severity": "HIGH", "message": "injected secret"})
    done.wait(timeout=3)

    assert len(received) == 1
    assert received[0]["rule_id"] == "RUN-001"
    srv.stop()


def test_sse_stream_delivers_to_multiple_clients():
    port = _free_port()
    srv = SseServer(port)
    srv.start()

    results = [None, None]
    dones = [threading.Event(), threading.Event()]

    def _subscribe(idx: int):
        url = f"http://127.0.0.1:{port}/events"
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                for raw in resp:
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                    if line.startswith("data:"):
                        results[idx] = json.loads(line[5:].strip())
                        dones[idx].set()
                        return
        except Exception:
            dones[idx].set()

    for i in range(2):
        threading.Thread(target=_subscribe, args=(i,), daemon=True).start()

    # wait until both clients are registered in the server
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        with srv._lock:
            if len(srv._clients) == 2:
                break
        time.sleep(0.02)

    srv.push_finding({"rule_id": "RUN-003", "severity": "CRITICAL", "message": "broadcast"})

    for d in dones:
        d.wait(timeout=3)

    assert results[0] is not None and results[0]["rule_id"] == "RUN-003"
    assert results[1] is not None and results[1]["rule_id"] == "RUN-003"
    srv.stop()


def test_stop_unblocks_connected_client():
    port = _free_port()
    srv = SseServer(port)
    srv.start()

    finished = threading.Event()

    def _subscribe():
        url = f"http://127.0.0.1:{port}/events"
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                for _ in resp:
                    pass  # read until connection closes
        except Exception:
            pass
        finally:
            finished.set()

    t = threading.Thread(target=_subscribe, daemon=True)
    t.start()
    time.sleep(0.1)
    srv.stop()
    # client should unblock within 2 seconds after stop
    finished.wait(timeout=3)
    assert finished.is_set()


def test_get_stats_returns_copy():
    port = _free_port()
    srv = SseServer(port)
    srv.start()
    try:
        stats = srv.get_stats()
        stats["findings"] = 999  # mutate the copy
        assert srv.get_stats()["findings"] == 0  # original unchanged
    finally:
        srv.stop()


# ---------------------------------------------------------------------------
# Integration: run_proxy with http_port
# ---------------------------------------------------------------------------


def test_run_proxy_starts_sse_server(tmp_path):
    """run_proxy with http_port starts SSE; /status responds during the session."""
    import sys

    from canlix.runtime import RuntimeAnalyzer
    from canlix.runtime.proxy import run_proxy

    port = _free_port()
    # Use Python -c as the "MCP server" — exits immediately
    cmd = [sys.executable, "-c", "import sys; sys.exit(0)"]
    err_buf = io.StringIO()
    analyzer = RuntimeAnalyzer("test", allow_hosts=[], rate_limit=100)

    # We need the SSE server to be reachable during the proxy run.
    # The proxy blocks until the subprocess exits; run it on a thread.
    exit_code: list[int] = []

    def _run():
        exit_code.append(
            run_proxy(cmd, analyzer, http_port=port, err=err_buf, client_in=io.BytesIO(b""), client_out=io.BytesIO())
        )

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    # Poll until the SSE server is up (up to 2 s)
    deadline = time.monotonic() + 2.0
    code = None
    while time.monotonic() < deadline:
        try:
            code, _ = _get(port, "/status", timeout=0.3)
            if code == 200:
                break
        except Exception:
            pass
        time.sleep(0.05)

    t.join(timeout=5)
    # SSE server should have been started (200) or the proxy finished before we polled
    assert code == 200 or not t.is_alive()
    err_out = err_buf.getvalue()
    assert f"http://localhost:{port}/events" in err_out


def test_run_proxy_sse_delivers_finding(tmp_path):
    """Findings detected by the proxy appear on the SSE stream.

    Strategy: inject a C2S tools/call with a secret in its arguments via the
    client_in pipe.  _on_request detects the secret immediately (no pending
    response round-trip needed) and pushes a RUN-001 finding to SSE.
    The fake server just drains stdin and exits quietly.
    """
    import os
    import sys

    from canlix.runtime import RuntimeAnalyzer
    from canlix.runtime.proxy import run_proxy

    port = _free_port()
    FAKE_KEY = "sk-" + "a1b2c3d4" * 4

    # Minimal fake server: read stdin to EOF, write nothing, exit cleanly.
    server_script = "import sys; sys.stdin.read()\n"
    script_path = tmp_path / "fake_srv.py"
    script_path.write_text(server_script)
    cmd = [sys.executable, str(script_path)]

    received: list[dict] = []
    sub_done = threading.Event()

    def _subscribe():
        url = f"http://127.0.0.1:{port}/events"
        try:
            with urllib.request.urlopen(url, timeout=6) as resp:
                for raw in resp:
                    line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                    if line.startswith("data:"):
                        received.append(json.loads(line[5:].strip()))
                        sub_done.set()
                        return
        except Exception:
            sub_done.set()

    err_buf = io.StringIO()
    analyzer = RuntimeAnalyzer("test-srv", allow_hosts=[], rate_limit=100)

    # C2S message: client calls the fetch tool with an API key in arguments.
    # _on_request sees method="tools/call", finds FAKE_KEY via secret_kinds → RUN-001.
    c2s_msg = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "fetch", "arguments": {"url": "https://example.com", "token": FAKE_KEY}},
            }
        ).encode()
        + b"\n"
    )

    r_fd, w_fd = os.pipe()
    client_in = os.fdopen(r_fd, "rb")

    proxy_done = threading.Event()

    def _run():
        run_proxy(cmd, analyzer, http_port=port, err=err_buf, client_in=client_in, client_out=io.BytesIO())
        proxy_done.set()

    t = threading.Thread(target=_run, daemon=True)
    t.start()

    # Poll until the SSE server is accepting connections (up to 2 s).
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        try:
            code, _ = _get(port, "/status", timeout=0.3)
            if code == 200:
                break
        except Exception:
            pass
        time.sleep(0.05)

    sub_thread = threading.Thread(target=_subscribe, daemon=True)
    sub_thread.start()

    # Wait until the subscriber's queue is registered in the SSE server.
    # We poll the internal _clients list via the /status count trick: the SSE
    # server increments findings on push, but here we just sleep briefly.
    time.sleep(0.2)

    # Write the C2S message then close the pipe → proxy observes it → finding → SSE push.
    os.write(w_fd, c2s_msg)
    os.close(w_fd)

    sub_done.wait(timeout=5)
    proxy_done.wait(timeout=5)

    assert any(f.get("rule_id") == "RUN-001" for f in received), f"received={received}"
