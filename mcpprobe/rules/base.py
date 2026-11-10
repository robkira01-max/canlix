from __future__ import annotations

from typing import Callable

from mcpprobe.models import Finding, MCPServer

RuleFunc = Callable[[MCPServer], Finding | None]


def rule(fn: RuleFunc) -> RuleFunc:
    """Decorator — marks a function as a MCPProbe rule."""
    fn._is_rule = True  # type: ignore[attr-defined]
    return fn
