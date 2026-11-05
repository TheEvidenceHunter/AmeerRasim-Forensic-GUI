"""Parsing of Volatility's JSON renderer output into flat, sortable tables."""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional

# Columns shown first when present (case sensitive, as Volatility emits them).
PRIORITY = [
    "PID", "Pid", "TID", "PPID", "ImageFileName", "Name", "Process", "Process Name", "COMM", "Owner",
    "Proto", "LocalAddr", "LocalPort", "ForeignAddr", "ForeignPort", "Source Addr", "Source Port",
    "Destination Addr", "Destination Port", "State", "Offset", "Offset(V)", "OFFSET (V)", "Offset(P)",
    "Start VPN", "End VPN", "Protection", "Args", "ARGS", "Command", "Cmd", "Path", "Created", "CreateTime",
    "ExitTime", "Exit Time",
]
# Wide/noisy columns pushed to the end.
TAIL = {"Hexdump", "Disasm", "Notes", "File output", "Audit"}
TREE_COLUMNS = ["PID", "Pid", "Name", "Process", "Offset"]


class ParseError(ValueError):
    pass


def fmt(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "True" if v else "False"
    if isinstance(v, (list, dict)):
        return json.dumps(v, ensure_ascii=False)
    return str(v)


@dataclass
class ResultTable:
    plugin: str
    columns: List[str]
    rows: List[Dict[str, Any]]  # every row has a "__depth" key
    tree: bool = False
    tree_column: str = ""

    def __len__(self) -> int:
        return len(self.rows)

    def text(self, r: int, col: str) -> str:
        return fmt(self.rows[r].get(col))

    def to_csv(self) -> str:
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow(self.columns)
        for row in self.rows:
            w.writerow([fmt(row.get(c)) for c in self.columns])
        return buf.getvalue()

    def to_json(self) -> str:
        data = [{c: row.get(c) for c in self.columns} for row in self.rows]
        return json.dumps(data, indent=2, ensure_ascii=False, default=str)

    def find(self, needle: str, limit: int = 200) -> List[int]:
        n = needle.lower()
        hits = []
        for i, row in enumerate(self.rows):
            if any(n in fmt(row.get(c)).lower() for c in self.columns):
                hits.append(i)
                if len(hits) >= limit:
                    break
        return hits


def _order_columns(keys: Iterable[str]) -> List[str]:
    keys = list(keys)
    head = [k for k in PRIORITY if k in keys]
    tail = sorted((k for k in keys if k in TAIL and k not in head), key=lambda k: k.lower())
    mid = sorted((k for k in keys if k not in head and k not in TAIL), key=lambda k: k.lower())
    return head + mid + tail


def _flatten(nodes: List[Dict[str, Any]], depth: int, out: List[Dict[str, Any]], keys: Dict[str, None]):
    for node in nodes:
        if not isinstance(node, dict):
            continue
        children = node.get("__children") or []
        row = {k: v for k, v in node.items() if k != "__children"}
        row["__depth"] = depth
        for k in row:
            if k != "__depth":
                keys.setdefault(k, None)
        out.append(row)
        if children:
            _flatten(children, depth + 1, out, keys)


def parse_vol_json(text: str, plugin: str = "") -> ResultTable:
    """Parse the stdout of `vol -r json`. Tolerates leading blank lines / stray log text."""
    if not text or not text.strip():
        raise ParseError("empty output")
    m = re.search(r"(?m)^\s*\[", text)  # first line that opens the JSON array
    if not m:
        raise ParseError("no JSON array found in output")
    try:
        data, _ = json.JSONDecoder().raw_decode(text[m.end() - 1:])
    except json.JSONDecodeError as e:
        raise ParseError(f"invalid JSON: {e}") from e
    if not isinstance(data, list):
        raise ParseError("unexpected JSON shape")
    rows: List[Dict[str, Any]] = []
    keys: Dict[str, None] = {}
    _flatten(data, 0, rows, keys)
    columns = _order_columns(keys)
    tree = any(r["__depth"] > 0 for r in rows)
    tree_col = next((c for c in TREE_COLUMNS if c in columns), columns[0] if columns else "")
    return ResultTable(plugin=plugin, columns=columns, rows=rows, tree=tree, tree_column=tree_col)


def get(row: Dict[str, Any], *names: str, default: Any = None) -> Any:
    """Case-insensitive column lookup (Volatility column names vary between plugins)."""
    low = {k.lower(): v for k, v in row.items()}
    for n in names:
        v = low.get(n.lower())
        if v is not None:
            return v
    return default
