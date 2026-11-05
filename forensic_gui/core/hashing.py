"""Streaming evidence hashing (chain-of-custody integrity)."""

from __future__ import annotations

import hashlib
import os
from typing import Callable, Dict, Optional, Sequence

CHUNK = 8 * 1024 * 1024
ALGOS = ("md5", "sha1", "sha256")


class Cancelled(Exception):
    pass


def hash_file(
    path: str,
    algos: Sequence[str] = ALGOS,
    progress: Optional[Callable[[int, int], None]] = None,
    cancelled: Optional[Callable[[], bool]] = None,
) -> Dict[str, str]:
    """Hash a (possibly huge) file in one pass. progress(done_bytes, total_bytes)."""
    total = os.path.getsize(path)
    hashers = {a: hashlib.new(a) for a in algos}
    done = 0
    with open(path, "rb") as f:
        while True:
            if cancelled and cancelled():
                raise Cancelled()
            block = f.read(CHUNK)
            if not block:
                break
            for h in hashers.values():
                h.update(block)
            done += len(block)
            if progress:
                progress(done, total)
    return {a: h.hexdigest() for a, h in hashers.items()}


def human_size(n: int) -> str:
    size = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.2f} {unit}"
        size /= 1024
    return f"{n} B"
