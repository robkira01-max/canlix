"""Minimal MCP JSON-RPC transport clients (HTTP and stdio). Zero external dependencies."""

from __future__ import annotations

import json
import select
import subprocess
import urllib.error
import urllib.request
from abc import ABC, abstractmethod

PROTOCOL_VERSION = "2024-11-05"
_CLIENT_INFO = {"name": "mcpprobe", "version": "0.1.0"}


class MCPConnectionError(Exception):
    pass


class MCPClient(ABC):
    def __init__(self) -> None:
        self._next_id = 1

    def _id(self) -> int:
        i = self._next_id
        self._next_id += 1
        return i

    def initialize(self) -> dict:
        result = self.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": _CLIENT_INFO,
            },
        )
        self.notify("notifications/initialized", {})
        return result

    def list_tools(self) -> list[dict]:
        result = self.request("tools/list", {})
        return result.get("tools", [])

    def list_resources(self) -> list[dict]:
        try:
            result = self.request("resources/list", {})
            return result.get("resources", [])
        except MCPConnectionError:
            return []

    def call_tool(self, name: str, arguments: dict) -> dict:
        return self.request("tools/call", {"name": name, "arguments": arguments})

    @abstractmethod
    def request(self, method: str, params: dict) -> dict: ...

    @abstractmethod
    def notify(self, method: str, params: dict) -> None: ...

    def close(self) -> None:
        pass


class HttpMCPClient(MCPClient):
    """HTTP/Streamable-HTTP MCP transport — posts JSON-RPC 2.0 to a URL."""

    def __init__(self, url: str, timeout: float = 5.0) -> None:
        super().__init__()
        self.url = url
        self.timeout = timeout

    def request(self, method: str, params: dict) -> dict:
        req_id = self._id()
        payload = json.dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params}).encode()
        req = urllib.request.Request(
            self.url,
            payload,
            {"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                data = json.loads(resp.read().decode())
        except urllib.error.HTTPError as e:
            raise MCPConnectionError(f"HTTP {e.code}: {e.reason}") from e
        except urllib.error.URLError as e:
            raise MCPConnectionError(f"Connection failed: {e.reason}") from e
        except json.JSONDecodeError as e:
            raise MCPConnectionError(f"Invalid JSON response: {e}") from e

        if "error" in data:
            err = data["error"]
            raise MCPConnectionError(f"MCP error {err.get('code')}: {err.get('message')}")
        return data.get("result", {})

    def notify(self, method: str, params: dict) -> None:
        payload = json.dumps({"jsonrpc": "2.0", "method": method, "params": params}).encode()
        req = urllib.request.Request(self.url, payload, {"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as _:
                pass
        except Exception:
            pass  # Notifications are fire-and-forget; ignore errors


class StdioMCPClient(MCPClient):
    """Stdio MCP transport — starts a subprocess and exchanges newline-delimited JSON-RPC."""

    def __init__(self, command: str, args: list[str], timeout: float = 5.0) -> None:
        super().__init__()
        self.timeout = timeout
        try:
            self._proc = subprocess.Popen(
                [command, *args],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
        except FileNotFoundError as e:
            raise MCPConnectionError(f"Command not found: {command!r}") from e

    def _readline(self) -> bytes:
        rlist, _, _ = select.select([self._proc.stdout], [], [], self.timeout)
        if not rlist:
            raise MCPConnectionError(f"Timeout waiting for server response ({self.timeout}s)")
        line = self._proc.stdout.readline()
        if not line:
            raise MCPConnectionError("Server closed stdout unexpectedly")
        return line

    def request(self, method: str, params: dict) -> dict:
        req_id = self._id()
        msg = json.dumps({"jsonrpc": "2.0", "id": req_id, "method": method, "params": params})
        try:
            self._proc.stdin.write((msg + "\n").encode())
            self._proc.stdin.flush()
        except BrokenPipeError as e:
            raise MCPConnectionError("Server stdin closed unexpectedly") from e
        try:
            line = self._readline()
            resp = json.loads(line)
        except json.JSONDecodeError as e:
            raise MCPConnectionError(f"Invalid JSON from server: {e}") from e

        if "error" in resp:
            err = resp["error"]
            raise MCPConnectionError(f"MCP error {err.get('code')}: {err.get('message')}")
        return resp.get("result", {})

    def notify(self, method: str, params: dict) -> None:
        msg = json.dumps({"jsonrpc": "2.0", "method": method, "params": params})
        try:
            self._proc.stdin.write((msg + "\n").encode())
            self._proc.stdin.flush()
        except BrokenPipeError:
            pass  # Server may have already exited; notifications are fire-and-forget

    def close(self) -> None:
        if self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._proc.kill()
