"""Minimal SSE broadcast server for `canlix watch --http PORT`.

GET /events  — text/event-stream; each finding arrives as a named SSE event
GET /status  — application/json; current stats snapshot

Pure stdlib — no extra dependencies.
"""

from __future__ import annotations

import json
import queue
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import ThreadingMixIn
from typing import Any

_SENTINEL = object()  # signals a client to close its stream


class SseServer:
    """Thread-safe server that broadcasts findings to all connected SSE clients."""

    def __init__(self, port: int, host: str = "127.0.0.1") -> None:
        self._port = port
        self._host = host
        self._lock = threading.Lock()
        self._clients: list[queue.Queue] = []
        self._stats: dict[str, Any] = {"findings": 0, "tool_calls": 0, "hosts_seen": 0}
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    # ------------------------------------------------------------------
    # Public API — called from the proxy thread
    # ------------------------------------------------------------------

    def push_finding(self, finding_dict: dict) -> None:
        with self._lock:
            self._stats["findings"] += 1
            snapshot = list(self._clients)
        for q in snapshot:
            q.put(("finding", finding_dict))

    def update_stats(self, *, tool_calls: int, hosts_seen: int) -> None:
        with self._lock:
            self._stats["tool_calls"] = tool_calls
            self._stats["hosts_seen"] = hosts_seen

    def get_stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    @property
    def port(self) -> int:
        return self._port

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the HTTP server on a background daemon thread."""
        server_ref = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *_) -> None:  # silence access log to stderr
                pass

            def do_GET(self) -> None:
                if self.path == "/events":
                    _serve_sse(self, server_ref)
                elif self.path == "/status":
                    _serve_status(self, server_ref)
                else:
                    self.send_response(404)
                    self.end_headers()

        class _Server(ThreadingMixIn, HTTPServer):
            daemon_threads = True  # SSE handler threads die with the process

        self._server = _Server((self._host, self._port), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True, name="canlix-sse")
        self._thread.start()

    def stop(self) -> None:
        """Signal all clients to close, then shut the server down."""
        with self._lock:
            for q in self._clients:
                q.put(_SENTINEL)
        if self._server is not None:
            self._server.shutdown()
        if self._thread is not None:
            self._thread.join(timeout=3)


# ---------------------------------------------------------------------------
# Request handlers (module-level functions keep the Handler class lean)
# ---------------------------------------------------------------------------


def _serve_status(handler: BaseHTTPRequestHandler, server: SseServer) -> None:
    body = json.dumps(server.get_stats()).encode()
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


def _serve_sse(handler: BaseHTTPRequestHandler, server: SseServer) -> None:
    # Register the client queue before sending headers so that any finding
    # pushed after urlopen() returns on the client side is never lost.
    q: queue.Queue = queue.Queue()
    with server._lock:
        server._clients.append(q)

    handler.send_response(200)
    handler.send_header("Content-Type", "text/event-stream")
    handler.send_header("Cache-Control", "no-cache")
    handler.send_header("X-Accel-Buffering", "no")
    handler.end_headers()

    try:
        handler.wfile.write(b": connected\n\n")
        handler.wfile.flush()
    except OSError:
        with server._lock:
            try:
                server._clients.remove(q)
            except ValueError:
                pass
        return

    try:
        while True:
            try:
                item = q.get(timeout=15)
            except queue.Empty:
                # heartbeat — keeps the connection alive through proxies
                handler.wfile.write(b": ping\n\n")
                handler.wfile.flush()
                continue

            if item is _SENTINEL:
                break

            event_type, payload = item
            data = json.dumps(payload, separators=(",", ":"))
            msg = f"event: {event_type}\ndata: {data}\n\n".encode()
            handler.wfile.write(msg)
            handler.wfile.flush()
    except OSError:
        pass
    finally:
        with server._lock:
            try:
                server._clients.remove(q)
            except ValueError:
                pass
