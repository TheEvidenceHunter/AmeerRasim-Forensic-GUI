"""Findings page: prioritized, explained, MITRE-mapped leads."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QHeaderView, QPushButton, QSplitter, QTableView,
                               QTextBrowser, QVBoxLayout, QWidget)

from ..core.findings import SEVERITIES, counts
from ..i18n import is_rtl, tr
from .models import FindingsModel, FindingsProxy
from .theme import sev_color
from .widgets import label, mark


class FindingsPage(QWidget):
    gotoRequested = Signal(str, object)

    def __init__(self, state, parent=None):
        super().__init__(parent)
        self.state = state
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(10)
        self.title = label("", "title")
        lay.addWidget(self.title)
        self.disc = label("", "hint", wrap=True)
        lay.addWidget(self.disc)

        chips = QHBoxLayout()
        self.chips = {}
        for s in SEVERITIES:
            b = QPushButton()
            b.setCheckable(True)
            b.setChecked(True)
            mark(b, chip=True)
            b.toggled.connect(self._chips_changed)
            self.chips[s] = b
            chips.addWidget(b)
        chips.addStretch(1)
        self.btn_goto = QPushButton()
        self.btn_goto.setEnabled(False)
        self.btn_goto.clicked.connect(self._goto)
        chips.addWidget(self.btn_goto)
        lay.addLayout(chips)

        split = QSplitter(Qt.Vertical)
        self.model = FindingsModel([])
        self.proxy = FindingsProxy()
        self.proxy.setSourceModel(self.model)
        self.view = QTableView()
        self.view.setModel(self.proxy)
        self.view.setSortingEnabled(True)
        self.view.sortByColumn(0, Qt.AscendingOrder)
        self.view.setAlternatingRowColors(True)
        self.view.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.view.setSelectionMode(QAbstractItemView.SingleSelection)
        self.view.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.view.verticalHeader().setVisible(False)
        self.view.horizontalHeader().setStretchLastSection(True)
        self.view.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.view.selectionModel().selectionChanged.connect(self._selected)
        self.view.doubleClicked.connect(lambda *_: self._goto())
        split.addWidget(self.view)
        self.detail = QTextBrowser()
        self.detail.setOpenExternalLinks(True)
        split.addWidget(self.detail)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 1)
        lay.addWidget(split, 1)

        state.findingsChanged.connect(self.refresh)
        self.retranslate()
        self.refresh()

    def retranslate(self):
        self.title.setText(tr("findings.title"))
        self.disc.setText(tr("findings.disclaimer"))
        self.btn_goto.setText(tr("findings.goto"))
        self.model.headerDataChanged.emit(Qt.Horizontal, 0, self.model.columnCount() - 1)
        self.refresh()
        self._selected()

    def refresh(self):
        self.model.set_findings(self.state.findings)
        c = counts(self.state.findings)
        for s, b in self.chips.items():
            b.setText(f"{tr('sev.' + s)}  {c.get(s, 0)}")
            b.setStyleSheet(f"QPushButton[chip='true']:checked {{ border-color: {sev_color(s)}; }}")
        for i, w in enumerate((90, 280, 60, 150, 380, 150)):
            self.view.setColumnWidth(i, w)
        self._selected()

    def _chips_changed(self):
        self.proxy.set_hidden({s for s, b in self.chips.items() if not b.isChecked()})

    def _current(self):
        idx = self.view.currentIndex()
        if not idx.isValid() or not self.view.selectionModel().isRowSelected(idx.row(), idx.parent()):
            return None
        return self.model.findings[self.proxy.mapToSource(idx).row()]

    def _selected(self, *_):
        f = self._current()
        self.btn_goto.setEnabled(bool(f and f.row is not None))
        if not f:
            self.detail.setHtml(f"<p style='color:gray'>{tr('findings.none') if not self.state.findings else tr('findings.detail_hint')}</p>")
            return
        from html import escape
        rtl = is_rtl()
        self.detail.setHtml(
            f"<div dir='{'rtl' if rtl else 'ltr'}'>"
            f"<h3 style='color:{sev_color(f.severity)}'>{escape(tr('sev.' + f.severity))} — "
            f"{escape(tr(f'rule.{f.rule}.title'))}</h3>"
            f"<p><b>{escape(tr('findings.evidence'))}:</b> <code>{escape(f.evidence)}</code></p>"
            f"<p><b>{escape(tr('findings.process'))}:</b> {escape(f.process)} &nbsp; "
            f"<b>PID:</b> {'' if f.pid is None else f.pid} &nbsp; <b>MITRE:</b> "
            f"<a href='https://attack.mitre.org/techniques/{f.mitre.replace('.', '/')}/'>{escape(f.mitre)}</a></p>"
            f"<p><b>{escape(tr('findings.verify'))}:</b> {escape(tr(f'rule.{f.rule}.desc'))}</p></div>")

    def _goto(self):
        f = self._current()
        if f and f.row is not None:
            self.gotoRequested.emit(f.plugin, f.row)
