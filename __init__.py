"""kibisis — Hermes plugin. See envelope.py for the behaviour and README.md for why."""

from __future__ import annotations

import logging
from typing import Any, Optional

try:
    from . import kibisis as _kibisis
except ImportError:  # imported as a bare module (tests, the Claude Code hook)
    import kibisis as _kibisis  # type: ignore

logger = logging.getLogger("hermes.plugins.kibisis")


def _on_transform_tool_result(
    tool_name: str = "",
    args: Any = None,
    result: Any = None,
    **_: Any,
) -> Optional[str]:
    try:
        return _kibisis.transform(tool_name, args, result)
    except Exception as exc:  # noqa: BLE001 — framing must never break a tool result
        logger.debug("envelope: transform failed for %s: %s", tool_name, exc)
        return None


def register(ctx) -> None:
    _kibisis.configure(getattr(ctx, "get_config", None))
    ctx.register_hook("transform_tool_result", _on_transform_tool_result)
