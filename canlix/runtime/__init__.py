"""Runtime analysis: observe live MCP traffic and flag anomalies."""

from canlix.runtime.detectors import RuntimeAnalyzer
from canlix.runtime.proxy import run_proxy

__all__ = ["RuntimeAnalyzer", "run_proxy"]
