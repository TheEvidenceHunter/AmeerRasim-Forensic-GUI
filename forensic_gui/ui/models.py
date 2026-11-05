"""Item models: plugin result tables and findings."""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from PySide6.QtCore import QAbstractTableModel, QModelIndex, QSortFilterProxyModel, Qt
from PySide6.QtGui import QBrush, QColor

from ..core.findings import Finding, SEV_RANK
from ..core.results import ResultTable, fmt
from ..i18n import tr
from .theme import sev_color

RAW_ROLE = Qt.UserRole + 1
MAX_CELL = 160  # characters shown in a cell; full value is in the tooltip


# ------------------------------------------------------------------ filter language
_TOKEN = re.compile(r'(?:[^\s:"]+:)?"[^"]*"|\S+')


def parse_filter(text: str) -> List[Tuple[Optional[str], str]]:
    """'pid:4 name:"svc host" evil' -> [('pid','4'), ('name','svc host'), (None,'evil')] (all lowercase)."""
    terms: List[Tuple[Optional[str], str]] = []
    for tok in _TOKEN.findall(text or ""):
        col = None
        m = re.match(r'^([^\s:"]+):(.*)$', tok)
        if m:
            col, tok = m.group(1).lower(), m.group(2)
        terms.append((col, tok.strip('"').lower()))
    return [t for t in terms if t[1] or t[0]]


def _sort_key(v):
    if v is None or v == "":
        return (0, 0, "")
    if isinstance(v, bool):
        return (1, int(v), "")
    if isinstance(v, (int, float)):
        return (1, v, "")
    return (2, 0, str(v).lower())


class ResultTableModel(QAbstractTableModel):
    def __init__(self, table: ResultTable, parent=None):
        super().__init__(parent)
        self.table = table
        self.columns = list(table.columns)
        self._flags: Dict[int, str] = {}
        self._rowtext: Dict[int, str] = {}
        self._tree_col = self.columns.index(table.tree_column) if table.tree_column in self.columns else -1

    # ---- flagging from findings
    def set_flags(self, flags: Dict[int, str]) -> None:
        self._flags = flags
        if self.rowCount():
            self.dataChanged.emit(self.index(0, 0), self.index(self.rowCount() - 1, max(0, self.columnCount() - 1)))

    def flag(self, row: int) -> Optional[str]:
        return self._flags.get(row)

    # ---- model api
    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.table.rows)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.columns)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal and 0 <= section < len(self.columns):
            return self.columns[section]
        return None

    def display(self, row: int, col: int) -> str:
        r = self.table.rows[row]
        text = fmt(r.get(self.columns[col]))
        if col == self._tree_col and self.table.tree:
            depth = r.get("__depth", 0)
            text = ("    " * (depth - 1) + "└─ " if depth else "") + text
        return text

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        row, col = index.row(), index.column()
        if role == Qt.DisplayRole:
            t = self.display(row, col)
            return t if len(t) <= MAX_CELL else t[: MAX_CELL - 1] + "…"
        if role == Qt.ToolTipRole:
            t = self.display(row, col)
            return t[:2000] if len(t) > MAX_CELL else None
        if role == RAW_ROLE:
            return self.table.rows[row].get(self.columns[col])
        if role == Qt.BackgroundRole:
            sev = self._flags.get(row)
            if sev:
                c = QColor(sev_color(sev))
                c.setAlpha(46)
                return QBrush(c)
        if role == Qt.TextAlignmentRole:
            v = self.table.rows[row].get(self.columns[col])
            if isinstance(v, (int, float)) and not isinstance(v, bool):
                return int(Qt.AlignRight | Qt.AlignVCenter)
            return int(Qt.AlignLeft | Qt.AlignVCenter)
        return None

    # ---- search support
    def row_text(self, row: int) -> str:
        t = self._rowtext.get(row)
        if t is None:
            t = " \t ".join(fmt(self.table.rows[row].get(c)) for c in self.columns).lower()
            self._rowtext[row] = t
        return t

    def cell_lower(self, row: int, col_name: str) -> str:
        return fmt(self.table.rows[row].get(col_name)).lower()


# short names users type in filters -> real column names across plugins
COLUMN_ALIASES = {
    "name": ["name", "imagefilename", "process", "comm", "owner", "processname"],
    "proc": ["imagefilename", "process", "comm", "owner", "processname", "name"],
    "ip": ["localaddr", "foreignaddr", "sourceaddr", "destinationaddr"],
    "port": ["localport", "foreignport", "sourceport", "destinationport"],
    "cmd": ["args", "cmd", "command", "commandline"],
}


class ResultProxy(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._terms: List[Tuple[Optional[str], str]] = []
        self.setSortRole(RAW_ROLE)

    def set_filter_text(self, text: str) -> None:
        self._terms = parse_filter(text)
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, parent):
        if not self._terms:
            return True
        m: ResultTableModel = self.sourceModel()
        for col, term in self._terms:
            if col:
                wanted = COLUMN_ALIASES.get(col, [col])
                names = [c for c in m.columns
                         if any(c.lower().replace(" ", "") == w or c.lower().startswith(w) for w in wanted)]
                if not names:  # unknown column prefix -> treat whole token as plain text
                    if f"{col}:{term}" not in m.row_text(source_row):
                        return False
                elif not any(term in m.cell_lower(source_row, n) for n in names):
                    return False
            elif term not in m.row_text(source_row):
                return False
        return True

    def lessThan(self, left, right):
        return _sort_key(left.data(RAW_ROLE)) < _sort_key(right.data(RAW_ROLE))


# ------------------------------------------------------------------ findings
class FindingsModel(QAbstractTableModel):
    COLS = ["findings.sev", "findings.rule", "findings.pid", "findings.process", "findings.evidence",
            "findings.plugin", "findings.mitre"]

    def __init__(self, findings: List[Finding], parent=None):
        super().__init__(parent)
        self.findings = findings

    def set_findings(self, findings: List[Finding]) -> None:
        self.beginResetModel()
        self.findings = findings
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.findings)

    def columnCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self.COLS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return tr(self.COLS[section])
        return None

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        f = self.findings[index.row()]
        c = index.column()
        if role == Qt.DisplayRole:
            return [tr("sev." + f.severity), tr(f"rule.{f.rule}.title"), "" if f.pid is None else str(f.pid),
                    f.process, f.evidence, f.plugin.split(".")[-1] if f.plugin.count(".") > 2 else f.plugin,
                    f.mitre][c]
        if role == RAW_ROLE:
            return [SEV_RANK.get(f.severity, 9), tr(f"rule.{f.rule}.title"), f.pid or -1, f.process, f.evidence,
                    f.plugin, f.mitre][c]
        if role == Qt.ForegroundRole and c == 0:
            return QBrush(QColor(sev_color(f.severity)))
        if role == Qt.FontRole and c == 0:
            from PySide6.QtGui import QFont
            fnt = QFont()
            fnt.setBold(True)
            return fnt
        if role == Qt.ToolTipRole and c == 4:
            return f.evidence
        return None


class FindingsProxy(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.hidden: set = set()
        self.setSortRole(RAW_ROLE)

    def set_hidden(self, sevs: set) -> None:
        self.hidden = sevs
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, parent):
        return self.sourceModel().findings[source_row].severity not in self.hidden

    def lessThan(self, left, right):
        return _sort_key(left.data(RAW_ROLE)) < _sort_key(right.data(RAW_ROLE))
