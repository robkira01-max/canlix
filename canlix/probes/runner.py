"""Probe session runner — connects to a server and runs all probes."""

from __future__ import annotations

import time

from canlix.probes.base import ProbeSession
from canlix.probes.metadata import run_metadata_probes
from canlix.probes.transport import MCPClient, MCPConnectionError


def probe_server(
    client: MCPClient,
    server_name: str,
    server_url: str,
    *,
    active: bool = False,
) -> ProbeSession:
    """Connect to a live MCP server and run security probes. Returns a ProbeSession."""
    session = ProbeSession(server_name=server_name, server_url=server_url)
    t0 = time.monotonic()

    try:
        server_info = client.initialize()
        session.protocol_version = server_info.get("protocolVersion", "")
        session.capabilities = server_info.get("capabilities", {})

        session.tools = client.list_tools()
        session.resources = client.list_resources()

        session.findings.extend(run_metadata_probes(session))

        if active:
            from canlix.probes.active import run_active_probes

            session.findings.extend(run_active_probes(client, session))

    except MCPConnectionError as exc:
        session.error = str(exc)
    finally:
        client.close()
        session.duration_ms = (time.monotonic() - t0) * 1000

    return session
