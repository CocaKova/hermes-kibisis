"""kibisis — Hermes plugin. See envelope.py for the behaviour and README.md for why."""

from __future__ import annotations

import logging
from typing import Any, Optional

try:
    from . import kibisis as _kibisis
    from . import install_gate as _gate
except ImportError:  # imported as a bare module (tests, the Claude Code hook)
    import kibisis as _kibisis  # type: ignore
    import install_gate as _gate  # type: ignore

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


def _on_pre_tool_call(tool_name: str = "", args: Any = None, **_: Any) -> Optional[dict]:
    try:
        return _gate.pre_tool_call(tool_name, args)
    except Exception as exc:  # noqa: BLE001 — a gate bug must not turn into a block
        logger.warning("install gate: check failed for %s, letting it through: %s", tool_name, exc)
        return None


def _on_post_approval_response(**kw: Any) -> None:
    try:
        _gate.post_approval_response(**kw)
    except Exception:  # noqa: BLE001
        logger.debug("install gate: post_approval_response failed", exc_info=True)


def _slash(raw_args: str) -> str:
    return _gate.human_command(raw_args or "status")


def _cli_setup(sub) -> None:
    sub.add_argument("words", nargs="*", help="status | parked | bless <id> | drop <id> | seed <dir> | install-shims")


def _cli_handler(ns) -> int:
    print(_gate.human_command(" ".join(getattr(ns, "words", []) or ["status"])))
    return 0


def register(ctx) -> None:
    get = getattr(ctx, "get_config", None)
    _kibisis.configure(get)
    _gate.configure(get)
    ctx.register_hook("transform_tool_result", _on_transform_tool_result)
    ctx.register_hook("pre_tool_call", _on_pre_tool_call)
    ctx.register_hook("post_approval_response", _on_post_approval_response)
    try:
        ctx.register_command("kibisis", _slash, description="install gate: status | parked | bless <id> | drop <id> | seed <dir>", args_hint="parked | bless <id>")
    except Exception:  # noqa: BLE001 — older cores without slash-command registration
        logger.debug("kibisis: slash command not registered", exc_info=True)
    try:
        ctx.register_cli_command("kibisis", "kibisis install gate", _cli_setup, _cli_handler,
                                 description="status | parked | bless <id> | drop <id> | seed <dir> | install-shims")
    except Exception:  # noqa: BLE001
        logger.debug("kibisis: cli command not registered", exc_info=True)
