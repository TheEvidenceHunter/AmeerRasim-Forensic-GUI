"""Operating-system detection of a memory image."""

from __future__ import annotations

import subprocess
from typing import Optional

from .runner import VolConfig, build_command
from .results import ParseError, ResultTable, fmt, parse_vol_json


def os_from_banners(table: ResultTable) -> Optional[str]:
    text = " ".join(fmt(r.get("Banner")) for r in table.rows)
    if "Darwin Kernel" in text:
        return "mac"
    if "Linux version" in text:
        return "linux"
    return None


def detect_os(cfg: VolConfig, image: str, timeout: int = 600) -> Optional[str]:
    """Blocking; run it in a worker thread. windows.info first, then banners for Linux/macOS."""
    for plugin in ("windows.info", "banners.Banners"):
        try:
            proc = subprocess.run(
                build_command(cfg, image, plugin), capture_output=True, text=True, encoding="utf-8",
                errors="replace", timeout=timeout, cwd=cfg.workdir(),
            )
        except (OSError, subprocess.TimeoutExpired):
            return None
        if proc.returncode != 0:
            continue
        try:
            table = parse_vol_json(proc.stdout, plugin)
        except ParseError:
            continue
        if plugin == "windows.info":
            if len(table):
                return "windows"
        else:
            found = os_from_banners(table)
            if found:
                return found
    return None
