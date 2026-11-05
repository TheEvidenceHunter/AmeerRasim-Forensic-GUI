"""Activity log: colored console + persisted audit trail."""

from __future__ import annotations

from datetime import datetime
from html import escape

from PySide6.QtWidgets import QHBoxLayout, QPlainTextEdit, QPushButton, QTabWidget, QTextEdit, QVBoxLayout, QWidget

from ..i18n import tr
from .widgets import label

COLORS = {"info": "#8b9bb0", "ok": "#34c98a", "warn": "#f2a93b", "error": "#ff5c6c", "audit": "#3b9cff"}


class LogPage(QWidget):
    def __init__(self, state, parent=None):
        super().__init__(parent)
        self.state = state
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 20)
        top = QHBoxLayout()
        self.title = label("", "title")
        self.btn_clear = QPushButton()
        self.btn_clear.clicked.connect(lambda: self.console.clear())
        top.addWidget(self.title)
        top.addStretch(1)
        top.addWidget(self.btn_clear)
        lay.addLayout(top)
        self.tabs = QTabWidget()
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.document().setMaximumBlockCount(5000)
        self.console.setStyleSheet("font-family: Consolas, 'DejaVu Sans Mono', monospace; font-size: 12px;")
        self.audit_view = QPlainTextEdit()
        self.audit_view.setReadOnly(True)
        self.audit_view.setStyleSheet("font-family: Consolas, 'DejaVu Sans Mono', monospace; font-size: 12px;")
        self.tabs.addTab(self.console, "")
        self.tabs.addTab(self.audit_view, "")
        self.tabs.currentChanged.connect(self._tab)
        lay.addWidget(self.tabs, 1)
        state.logLine.connect(self.add)
        state.caseChanged.connect(self._load_audit)
        self.retranslate()

    def retranslate(self):
        self.title.setText(tr("log.title"))
        self.btn_clear.setText(tr("btn.clear"))
        self.tabs.setTabText(0, tr("log.console"))
        self.tabs.setTabText(1, tr("log.audit"))

    def add(self, level: str, text: str):
        ts = datetime.now().strftime("%H:%M:%S")
        color = COLORS.get(level, COLORS["info"])
        body = escape(text).replace("\n", "<br>")
        self.console.append(f"<span style='color:#6b7a8d'>{ts}</span> <span style='color:{color}'>{body}</span>")

    def _tab(self, i):
        if i == 1:
            self._load_audit()

    def _load_audit(self):
        self.audit_view.setPlainText("\n".join(self.state.case.audit_lines()))
