"""Dashboard: investigation overview and quick actions."""

from __future__ import annotations

import os

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import QGridLayout, QHBoxLayout, QPushButton, QVBoxLayout, QWidget

from ..core.findings import SEVERITIES, counts
from ..i18n import tr
from .theme import sev_color
from .widgets import StatCard, card, label, mark


class DashboardPage(QWidget):
    navigate = Signal(int)
    triage = Signal()

    def __init__(self, state, parent=None):
        super().__init__(parent)
        self.state = state
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(14)
        self.title = label("", "title")
        lay.addWidget(self.title)

        self.ev = card()
        el = QVBoxLayout(self.ev)
        el.setContentsMargins(18, 14, 18, 14)
        self.ev_head = label("", "muted")
        self.ev_name = label("", "h2")
        self.ev_meta = label("", "hint")
        self.ev_hash = label("", "hint")
        for w in (self.ev_head, self.ev_name, self.ev_meta, self.ev_hash):
            el.addWidget(w)
        lay.addWidget(self.ev)

        grid = QGridLayout()
        grid.setSpacing(12)
        self.s_proc, self.s_net, self.s_runs, self.s_find = StatCard(), StatCard(), StatCard(), StatCard()
        for i, w in enumerate((self.s_proc, self.s_net, self.s_runs, self.s_find)):
            grid.addWidget(w, 0, i)
        lay.addLayout(grid)

        self.sev_box = card()
        sl = QHBoxLayout(self.sev_box)
        sl.setContentsMargins(18, 12, 18, 12)
        self.sev_labels = {}
        for s in SEVERITIES:
            lb = label("", "")
            lb.setStyleSheet(f"color:{sev_color(s)}; font-weight:700; font-size:14px;")
            self.sev_labels[s] = lb
            sl.addWidget(lb)
        sl.addStretch(1)
        lay.addWidget(self.sev_box)

        self.lb_quick = label("", "h2")
        lay.addWidget(self.lb_quick)
        row = QHBoxLayout()
        self.b_open, self.b_triage, self.b_find = QPushButton(), QPushButton(), QPushButton()
        mark(self.b_triage, primary=True)
        self.b_open.clicked.connect(lambda: self.navigate.emit(1))
        self.b_triage.clicked.connect(self.triage.emit)
        self.b_find.clicked.connect(lambda: self.navigate.emit(4))
        for b in (self.b_open, self.b_triage, self.b_find):
            row.addWidget(b)
        row.addStretch(1)
        lay.addLayout(row)

        self.lb_top = label("", "h2")
        self.top = label("", "", wrap=True)
        self.top.setTextFormat(Qt.RichText)
        lay.addWidget(self.lb_top)
        lay.addWidget(self.top)
        lay.addStretch(1)

        for sig in (state.caseChanged, state.imageChanged, state.resultsChanged, state.findingsChanged):
            sig.connect(lambda *_: self.refresh())
        self.retranslate()

    def retranslate(self):
        self.title.setText(tr("dash.title"))
        self.ev_head.setText(tr("dash.evidence"))
        self.s_proc.title.setText(tr("dash.processes"))
        self.s_net.title.setText(tr("dash.connections"))
        self.s_runs.title.setText(tr("dash.plugins_done"))
        self.s_find.title.setText(tr("dash.findings"))
        self.lb_quick.setText(tr("dash.quick"))
        self.b_open.setText(tr("act.open_image"))
        self.b_triage.setText(tr("dash.start"))
        self.b_find.setText(tr("nav.findings"))
        self.lb_top.setText(tr("dash.top_findings"))
        self.refresh()

    def _count(self, suffixes):
        best = 0
        for name, t in self.state.results.items():
            if name.lower().split(".")[-1] in suffixes or any(name.lower().endswith("." + s) for s in suffixes):
                best = max(best, len(t))
        return best

    def refresh(self):
        c = self.state.case
        if c.image_path:
            self.ev_name.setText(os.path.basename(c.image_path))
            self.ev_meta.setText(f"{c.image_path}   ·   {tr('os.' + c.os_hint)}")
            self.ev_hash.setText(("✔ " + tr("dash.hashed") + f"   SHA-256: {c.hashes.get('sha256', '')[:24]}…")
                                 if c.hashes else "• " + tr("dash.not_hashed"))
        else:
            self.ev_name.setText(tr("dash.no_evidence"))
            self.ev_meta.setText("")
            self.ev_hash.setText("")
        self.s_proc.set(self._count({"pslist", "psscan", "pstree"}))
        self.s_net.set(self._count({"netscan", "netstat", "sockstat"}))
        self.s_runs.set(len(self.state.results))
        f = self.state.findings
        cnt = counts(f)
        worst = next((s for s in SEVERITIES if cnt[s]), "")
        self.s_find.set(len(f), color=sev_color(worst) if worst else "")
        for s, lb in self.sev_labels.items():
            lb.setText(f"{tr('sev.' + s)}: {cnt[s]}")
        from html import escape
        top = [x for x in f if x.severity in ("critical", "high")][:6]
        self.top.setText("<br>".join(
            f"<span style='color:{sev_color(x.severity)}'>●</span> <b>{escape(tr('rule.' + x.rule + '.title'))}</b>"
            f" — {escape(x.process)} {'' if x.pid is None else '(' + str(x.pid) + ')'}" for x in top)
            or f"<span style='color:gray'>{escape(tr('findings.none'))}</span>")
