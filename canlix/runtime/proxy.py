"""stdio MCP proxy: relays JSON-RPC lines unchanged while a RuntimeAnalyzer watches them.

stdout carries the protocol, so every diagnostic goes to stderr or to the trace file.
"""

from __future__ import annotations

import json
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import BinaryIO, TextIO

from canlix.models import Finding, Severity
from canlix.runtime.detectors import C2S, S2C, RuntimeAnalyzer
from canlix.runtime.redact import redact_obj

_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
KILLED_EXIT_CODE = 3


def _meets(sev: Severity, threshold: str | None) -> bool:
    if not threshold or threshold.upper() not in _ORDER:
        return False
    return _ORDER.index(sev.value) >= _ORDER.index(threshold.upper())


def finding_to_dict(f: Finding) -> dict:
    return {
        "rule_id": f.rule_id,
        "severity": f.severity.value,
        "confidence": f.confidence.value,
        "server": f.server_name,
        "message": f.message,
        "evidence": f.evidence,
        "remediation": f.remediation,
    }


class _Session:
    def __init__(
        self,
        analyzer: RuntimeAnalyzer,
        trace: TextIO | None,
        err: TextIO,
        kill_on: str | None,
        sse=None,  # SseServer | None — optional to avoid import cycle
    ) -> None:
        self.analyzer = analyzer
        self.trace = trace
        self.err = err
        self.kill_on = kill_on
        self.sse = sse
        self.killed = False
        self.child: subprocess.Popen | None = None
        self._lock = threading.Lock()

    def observe(self, direction: str, line: bytes) -> None:
        """Never raises: a bug in analysis must not break the relay."""
        try:
            try:
                message = json.loads(line)
            except ValueError:
                message = None
            ts = time.time()
            with self._lock:
                new = self.analyzer.observe(direction, message, ts)
                if self.trace is not None and message is not None:
                    self._write_trace({"ts": round(ts, 3), "dir": direction, "msg": redact_obj(message)})
                for f in new:
                    if self.trace is not None:
                        self._write_trace({"ts": round(ts, 3), "finding": finding_to_dict(f)})
                    print(f"[canlix] {f.severity.value} {f.rule_id}: {f.message}", file=self.err, flush=True)
                    if self.sse is not None:
                        self.sse.push_finding(finding_to_dict(f))
                    if _meets(f.severity, self.kill_on) and not self.killed and self.child is not None:
                        self.killed = True
                        print(f"[canlix] emergency stop: {f.rule_id} reached --kill-on {self.kill_on}", file=self.err)
                        self.child.terminate()
        except Exception as exc:  # noqa: BLE001
            print(f"[canlix] analysis error ignored: {type(exc).__name__}", file=self.err, flush=True)

    def _write_trace(self, record: dict) -> None:
        assert self.trace is not None
        self.trace.write(json.dumps(record, separators=(",", ":")) + "\n")
        self.trace.flush()


def run_proxy(
    command: list[str],
    analyzer: RuntimeAnalyzer,
    *,
    trace_path: Path | None = None,
    kill_on: str | None = None,
    client_in: BinaryIO | None = None,
    client_out: BinaryIO | None = None,
    err: TextIO | None = None,
    http_port: int | None = None,
) -> int:
    """Run command as an MCP server behind the proxy and return the exit code to use."""
    client_in = client_in or sys.stdin.buffer
    client_out = client_out or sys.stdout.buffer
    err = err or sys.stderr
    trace = trace_path.open("a", encoding="utf-8") if trace_path else None

    sse = None
    if http_port is not None:
        from canlix.runtime.sse_server import SseServer

        sse = SseServer(http_port)
        sse.start()
        print(f"[canlix] SSE events at http://localhost:{http_port}/events", file=err, flush=True)

    try:
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE)  # noqa: S603
    except OSError as exc:
        print(f"[canlix] cannot start server: {exc}", file=err)
        if trace:
            trace.close()
        if sse is not None:
            sse.stop()
        return 2

    session = _Session(analyzer, trace, err, kill_on, sse=sse)
    session.child = child
    assert child.stdin is not None and child.stdout is not None

    def pump_client_to_server() -> None:
        try:
            for line in client_in:
                session.observe(C2S, line)
                child.stdin.write(line)  # type: ignore[union-attr]
                child.stdin.flush()  # type: ignore[union-attr]
        except (BrokenPipeError, ValueError, OSError):
            pass
        finally:
            try:
                child.stdin.close()  # type: ignore[union-attr]
            except OSError:
                pass

    upstream = threading.Thread(target=pump_client_to_server, daemon=True)
    upstream.start()

    try:
        for line in child.stdout:
            session.observe(S2C, line)
            client_out.write(line)
            client_out.flush()
    except (BrokenPipeError, ValueError):
        child.terminate()

    code = child.wait()
    upstream.join(timeout=2)
    if trace:
        trace.close()

    n = len(analyzer.findings)
    if sse is not None:
        sse.update_stats(tool_calls=analyzer.tool_calls, hosts_seen=len(analyzer.hosts_seen))
        sse.stop()
    print(
        f"[canlix] session ended: {analyzer.tool_calls} tool call(s), {n} finding(s), "
        f"{len(analyzer.hosts_seen)} host(s) seen",
        file=err,
        flush=True,
    )
    return KILLED_EXIT_CODE if session.killed else code
