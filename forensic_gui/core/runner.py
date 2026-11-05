"""Command construction, progress parsing and error diagnosis for Volatility 3 runs."""

from __future__ import annotations

import os
import re
import shlex
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence, Tuple


@dataclass
class VolConfig:
    python: str = ""
    vol_path: str = ""
    symbol_dirs: str = ""  # semicolon separated, passed to -s
    cache_path: str = ""
    offline: bool = False
    parallelism: str = ""  # "", "threads", "processes"
    output_dir: str = ""  # -o, for plugins that dump files
    verbosity: int = 0

    def base_command(self) -> List[str]:
        """Interpreter + entry point (vol.py or an installed `vol` executable)."""
        vol = self.vol_path
        if vol.lower().endswith(".py"):
            return [self.python or default_python(), vol]
        return [vol]

    def workdir(self) -> Optional[str]:
        p = Path(self.vol_path)
        return str(p.parent) if p.is_file() else None


def default_python() -> str:
    """The interpreter to run Volatility with (never the frozen GUI executable)."""
    if getattr(sys, "frozen", False):
        return shutil.which("python3") or shutil.which("python") or "python"
    return sys.executable or shutil.which("python3") or "python"


def find_vol(extra_dirs: Sequence[str] = ()) -> str:
    """Locate vol.py next to the package, in the cwd, or an installed `vol` command."""
    here = Path(__file__).resolve()
    candidates = [here.parents[2], Path.cwd(), *(Path(d) for d in extra_dirs)]
    if getattr(sys, "frozen", False):
        candidates.insert(0, Path(getattr(sys, "_MEIPASS", ".")))
        candidates.insert(1, Path(sys.executable).parent)
    for d in candidates:
        f = Path(d) / "vol.py"
        if f.is_file():
            return str(f)
    return shutil.which("vol") or shutil.which("vol3") or ""


def vol_root_of(vol_path: str) -> str:
    """Directory that contains the `volatility3` package (for plugin discovery)."""
    p = Path(vol_path)
    if p.is_file() and (p.parent / "volatility3").is_dir():
        return str(p.parent)
    return ""


def split_args(text: str) -> List[str]:
    if not text.strip():
        return []
    return shlex.split(text, posix=(os.name != "nt"))


def build_command(
    cfg: VolConfig,
    image: str,
    plugin: str,
    pids: Optional[str] = None,
    extra_args: str = "",
    renderer: str = "json",
) -> List[str]:
    cmd = cfg.base_command()
    if cfg.verbosity:
        cmd.append("-" + "v" * min(cfg.verbosity, 5))
    if cfg.symbol_dirs:
        cmd += ["-s", cfg.symbol_dirs]
    if cfg.cache_path:
        cmd += ["--cache-path", cfg.cache_path]
    if cfg.offline:
        cmd.append("--offline")
    if cfg.parallelism:
        cmd += ["--parallelism", cfg.parallelism]
    if cfg.output_dir:
        cmd += ["-o", cfg.output_dir]
    cmd += ["-r", renderer, "-f", image, plugin]
    if pids and pids.strip():
        cmd.append("--pid")
        cmd += [p for p in re.split(r"[,\s]+", pids.strip()) if p]
    cmd += split_args(extra_args)
    return cmd


def display_command(cmd: Sequence[str]) -> str:
    return " ".join(shlex.quote(c) if os.name != "nt" else (f'"{c}"' if " " in c else c) for c in cmd)


_PROGRESS = re.compile(r"Progress:\s+([0-9]+(?:\.[0-9]+)?)\s*(.*)")


def parse_progress(chunk: str) -> Optional[Tuple[float, str]]:
    """Volatility writes '\\rProgress:  45.23\\t\\tScanning ...' to stderr."""
    last = None
    for m in _PROGRESS.finditer(chunk.replace("\r", "\n")):
        last = (min(100.0, float(m.group(1))), m.group(2).strip())
    return last


# ------------------------------------------------------------------ diagnosis
_DIAG = [
    (re.compile(r"symbol table requirement was not fulfilled|Unsatisfied requirement|"
                r"No suitable address space mapping found|Unable to validate the plugin requirements", re.I),
     "symbols"),
    (re.compile(r"ModuleNotFoundError|ImportError|No module named", re.I), "deps"),
    (re.compile(r"Cannot find the file|No such file|FileNotFoundError", re.I), "file"),
    (re.compile(r"PermissionError|Access is denied|Permission denied", re.I), "perm"),
    (re.compile(r"MemoryError|Cannot allocate memory", re.I), "memory"),
    (re.compile(r"yara", re.I), "yara"),
    (re.compile(r"unrecognized arguments|the following arguments are required|invalid choice", re.I), "args"),
]


def diagnose(stderr: str, exit_code: int) -> List[str]:
    """Return hint keys (translated in the UI) explaining a failed run."""
    if exit_code == 0:
        return []
    hints = []
    for rx, key in _DIAG:
        if rx.search(stderr or "") and key not in hints:
            hints.append(key)
    return hints or ["generic"]


def short_error(stderr: str, limit: int = 600) -> str:
    lines = [l for l in (stderr or "").replace("\r", "\n").splitlines() if l.strip() and "Progress:" not in l]
    return "\n".join(lines[-8:])[-limit:]
