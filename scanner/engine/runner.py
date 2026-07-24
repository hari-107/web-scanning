"""Secure external-tool execution and detection.

Every command is run through :func:`run_command`, which:
  * takes an argument **list** (never a shell string) to avoid injection,
  * enforces a timeout,
  * captures stdout/stderr,
  * never raises on non-zero exit -- callers inspect the result.

:func:`tool_available` caches ``shutil.which`` lookups so the pipeline can
cheaply decide between a real tool and its pure-Python fallback.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass
from functools import lru_cache


@dataclass
class CommandResult:
    ok: bool
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    command: str = ""


@lru_cache(maxsize=64)
def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


@lru_cache(maxsize=64)
def tool_path(name: str) -> str | None:
    return shutil.which(name)


def run_command(args: list[str], timeout: int = 120,
                input_text: str | None = None) -> CommandResult:
    """Run ``args`` (a list) with a timeout; capture output; never raise.

    Using a list + ``shell=False`` means target-derived values are passed as
    literal argv entries and are never interpreted by a shell.
    """
    printable = " ".join(args)
    if not args or shutil.which(args[0]) is None:
        return CommandResult(False, 127, "", f"tool not found: {args[0] if args else ''}",
                             command=printable)
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
            shell=False,
            errors="replace",
        )
        return CommandResult(
            ok=proc.returncode == 0,
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
            command=printable,
        )
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout or ""
        if isinstance(out, bytes):
            out = out.decode("utf-8", "replace")
        return CommandResult(False, -1, out, "timed out", timed_out=True,
                             command=printable)
    except (OSError, ValueError) as exc:
        return CommandResult(False, -1, "", str(exc), command=printable)
