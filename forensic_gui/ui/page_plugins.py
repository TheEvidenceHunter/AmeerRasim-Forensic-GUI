"""Analysis page: plugin library with presets, options and the live job queue."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QBrush, QColor
from PySide6.QtWidgets import (QAbstractItemView, QCheckBox, QHBoxLayout, QHeaderView, QLineEdit, QMessageBox,
                               QProgressBar, QPushButton, QSplitter, QTreeWidget, QTreeWidgetItem, QVBoxLayout,
                               QWidget)

from ..core import catalog
from ..i18n import language, tr
from . import jobs as J
from .widgets import h_row, label, mark

STATUS_COLOR = {J.QUEUED: "#8b9bb0", J.RUNNING: "#3b9cff", J.PARSING: "#3b9cff", J.OK: "#34c98a",
                J.FAILED: "#ff5c6c", J.CANCELLED: "#f2a93b"}


class PluginsPage(QWidget):
    def __init__(self, state, parent=None):
        super().__init__(parent)
        self.state = state
        self._rows = {}  # job id -> tree item
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 20, 24, 20)
        root.setSpacing(12)
        self.title = label("", "title")
        root.addWidget(self.title)
        self.hint = label("", "hint", wrap=True)
        root.addWidget(self.hint)

        self.preset_row = QHBoxLayout()
        self.preset_buttons = {}
        self.preset_row.setSpacing(8)
        root.addLayout(self.preset_row)

        split = QSplitter(Qt.Horizontal)
        split.setChildrenCollapsible(False)
        root.addWidget(split, 1)

        # ---- library
        left = QWidget()
        ll = QVBoxLayout(left)
        ll.setContentsMargins(0, 0, 0, 0)
        self.search = QLineEdit()
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._apply_filter)
        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        self.tree.setAlternatingRowColors(True)
        self.tree.itemChanged.connect(self._on_item_changed)
        self.tree.currentItemChanged.connect(self._show_desc)
        self.desc = label("", "hint", wrap=True)
        self.desc.setMinimumHeight(48)
        bar = QHBoxLayout()
        self.btn_clear_sel = QPushButton()
        self.btn_clear_sel.clicked.connect(self.clear_selection)
        self.lb_count = label("", "hint")
        bar.addWidget(self.btn_clear_sel)
        bar.addStretch(1)
        bar.addWidget(self.lb_count)
        ll.addWidget(self.search)
        ll.addWidget(self.tree, 1)
        ll.addWidget(self.desc)
        ll.addLayout(bar)
        split.addWidget(left)

        # ---- options + queue
        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        self.lb_opts = label("", "h2")
        self.pid = QLineEdit()
        self.extra = QLineEdit()
        for e in (self.pid, self.extra, self.search):
            e.setLayoutDirection(Qt.LeftToRight)  # CLI-ish input stays LTR even in Arabic
        self.lb_pid, self.lb_extra = label("", "muted"), label("", "muted")
        self.btn_run = QPushButton()
        mark(self.btn_run, primary=True)
        self.btn_run.clicked.connect(self.run_selected)
        rl.addWidget(self.lb_opts)
        rl.addWidget(self.lb_pid)
        rl.addWidget(self.pid)
        rl.addWidget(self.lb_extra)
        rl.addWidget(self.extra)
        rl.addWidget(self.btn_run)
        self.lb_queue = label("", "h2")
        rl.addSpacing(8)
        rl.addWidget(self.lb_queue)
        self.queue = QTreeWidget()
        self.queue.setRootIsDecorated(False)
        self.queue.setColumnCount(5)
        self.queue.setAlternatingRowColors(True)
        self.queue.header().setSectionResizeMode(0, QHeaderView.Stretch)
        self.queue.setTextElideMode(Qt.ElideMiddle)
        self.queue.setColumnWidth(2, 90)
        self.queue.setSelectionMode(QAbstractItemView.NoSelection)
        rl.addWidget(self.queue, 1)
        qb = QHBoxLayout()
        self.btn_cancel_cur, self.btn_cancel_all, self.btn_clear_done = QPushButton(), QPushButton(), QPushButton()
        mark(self.btn_cancel_all, danger=True)
        self.btn_cancel_cur.clicked.connect(state.jobs.cancel_current)
        self.btn_cancel_all.clicked.connect(state.jobs.cancel_all)
        self.btn_clear_done.clicked.connect(state.jobs.clear_finished)
        for b in (self.btn_cancel_cur, self.btn_cancel_all, self.btn_clear_done):
            qb.addWidget(b)
        rl.addLayout(qb)
        split.addWidget(right)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)

        state.osChanged.connect(lambda _: self.rebuild())
        state.imageChanged.connect(self._update_enabled)
        state.configChanged.connect(self.rebuild)
        state.jobs.jobChanged.connect(self._job_changed)
        state.jobs.queueChanged.connect(self._queue_changed)
        self.retranslate()

    # ------------------------------------------------------------ build
    def retranslate(self):
        self.title.setText(tr("plugins.title"))
        self.hint.setText(tr("plugins.select_hint"))
        self.search.setPlaceholderText(tr("plugins.search"))
        self.lb_opts.setText(tr("plugins.options"))
        self.lb_pid.setText(tr("plugins.pid"))
        self.lb_extra.setText(tr("plugins.extra"))
        self.pid.setPlaceholderText(tr("plugins.pid_hint"))
        self.extra.setPlaceholderText(tr("plugins.extra_hint"))
        self.btn_run.setText(tr("plugins.run_sel"))
        self.btn_clear_sel.setText(tr("plugins.clear_sel"))
        self.lb_queue.setText(tr("plugins.queue"))
        self.btn_cancel_cur.setText(tr("queue.cancel_current"))
        self.btn_cancel_all.setText(tr("queue.cancel_all"))
        self.btn_clear_done.setText(tr("queue.clear_done"))
        self.queue.setHeaderLabels([tr("queue.plugin"), tr("queue.status"), tr("queue.progress"), tr("queue.rows"),
                                    tr("queue.time")])
        self.rebuild()
        self._queue_changed()

    def _checked(self):
        out = []
        it = self.tree.invisibleRootItem()
        for i in range(it.childCount()):
            cat = it.child(i)
            for j in range(cat.childCount()):
                c = cat.child(j)
                if c.checkState(0) == Qt.Checked:
                    out.append(c.data(0, Qt.UserRole))
        return out

    def rebuild(self):
        keep = set(self._checked())
        lang = language()
        os_name = self.state.case.os_hint
        plugins = catalog.plugins_for_os(os_name)
        if self.state.vol_root:
            known = {p.name for p in plugins}
            plugins += [p for p in catalog.extra_plugins(self.state.vol_root)
                        if p.name not in known and (os_name == "auto" or p.os in (os_name, "any"))]
            gone = set(catalog.missing_from_install(self.state.vol_root, [p.name for p in plugins]))
            plugins = [p for p in plugins if p.name not in gone]
        self.tree.blockSignals(True)
        self.tree.clear()
        for cat in catalog.CATEGORIES:
            items = [p for p in plugins if p.category == cat]
            if not items:
                continue
            top = QTreeWidgetItem([tr("cat." + cat)])
            f = top.font(0)
            f.setBold(True)
            top.setFont(0, f)
            self.tree.addTopLevelItem(top)
            for p in sorted(items, key=lambda x: x.title(lang).lower()):
                tags = ("  ⏱" if p.slow else "") + ("  ⚠" if p.sensitive else "")
                child = QTreeWidgetItem([f"{p.title(lang)}   ·   {p.name}{tags}"])
                child.setFlags(child.flags() | Qt.ItemIsUserCheckable)
                child.setCheckState(0, Qt.Checked if p.name in keep else Qt.Unchecked)
                child.setData(0, Qt.UserRole, p.name)
                tip = p.desc(lang)
                if p.slow:
                    tip += "\n⏱ " + tr("plugins.slow")
                if p.sensitive:
                    tip += "\n⚠ " + tr("plugins.sensitive")
                child.setToolTip(0, tip)
                if p.sensitive:
                    child.setForeground(0, QBrush(QColor("#f2a93b")))
                top.addChild(child)
            top.setExpanded(cat in ("processes", "malware", "network", "info", "general"))
        self.tree.blockSignals(False)
        self._rebuild_presets()
        self._apply_filter(self.search.text())
        self._on_item_changed()
        self._update_enabled()

    def _rebuild_presets(self):
        while self.preset_row.count():
            w = self.preset_row.takeAt(0).widget()
            if w:
                w.hide()
                w.setParent(None)  # leave the page immediately; deleteLater alone can leave a ghost widget
                w.deleteLater()
        for key in catalog.presets_for_os(self.state.case.os_hint):
            b = QPushButton(tr("preset." + key))
            mark(b, chip=True)
            b.clicked.connect(lambda _=False, k=key: self.apply_preset(k))
            self.preset_row.addWidget(b)
        self.preset_row.addStretch(1)

    # ------------------------------------------------------------ interaction
    def apply_preset(self, key: str):
        want = set(catalog.PRESETS[key]["plugins"])
        self.tree.blockSignals(True)
        top = self.tree.invisibleRootItem()
        for i in range(top.childCount()):
            for j in range(top.child(i).childCount()):
                c = top.child(i).child(j)
                c.setCheckState(0, Qt.Checked if c.data(0, Qt.UserRole) in want else Qt.Unchecked)
        self.tree.blockSignals(False)
        self._on_item_changed()
        if self.state.case.os_hint == "auto" and catalog.PRESETS[key]["os"] != "auto":
            self.state.set_os(catalog.PRESETS[key]["os"])

    def clear_selection(self):
        self.tree.blockSignals(True)
        top = self.tree.invisibleRootItem()
        for i in range(top.childCount()):
            for j in range(top.child(i).childCount()):
                top.child(i).child(j).setCheckState(0, Qt.Unchecked)
        self.tree.blockSignals(False)
        self._on_item_changed()

    def _apply_filter(self, text: str):
        t = text.strip().lower()
        top = self.tree.invisibleRootItem()
        for i in range(top.childCount()):
            cat = top.child(i)
            vis = 0
            for j in range(cat.childCount()):
                c = cat.child(j)
                p = catalog.get(c.data(0, Qt.UserRole))
                hay = (c.text(0) + " " + (p.desc_en + " " + p.desc_ar if p else "")).lower()
                hide = bool(t) and t not in hay
                c.setHidden(hide)
                vis += not hide
            cat.setHidden(vis == 0)
            if t and vis:
                cat.setExpanded(True)

    def _on_item_changed(self, *_):
        n = len(self._checked())
        self.lb_count.setText(tr("plugins.count", n=n))
        self._update_enabled()

    def _show_desc(self, cur, _prev):
        if not cur or cur.parent() is None:
            self.desc.setText("")
            return
        p = catalog.get(cur.data(0, Qt.UserRole))
        self.desc.setText(p.desc(language()) if p else cur.data(0, Qt.UserRole))

    def _update_enabled(self):
        ok = bool(self.state.case.image_path) and bool(self._checked())
        self.btn_run.setEnabled(ok)
        self.btn_run.setToolTip("" if self.state.case.image_path else tr("plugins.need_image"))
        if not self.state.case.image_path:
            self.hint.setText(tr("plugins.need_image"))
        else:
            self.hint.setText(tr("plugins.select_hint"))

    def run_selected(self):
        names = self._checked()
        if not names:
            QMessageBox.information(self, tr("msg.info"), tr("plugins.nothing_selected"))
            return
        if not self.state.case.image_path:
            QMessageBox.information(self, tr("msg.info"), tr("plugins.need_image"))
            return
        if not self.state.cfg.vol_path:
            QMessageBox.warning(self, tr("msg.error"), tr("settings.vol_missing"))
            return
        if any((catalog.get(n) and catalog.get(n).sensitive) for n in names):
            r = QMessageBox.warning(self, tr("msg.confirm"), tr("plugins.sensitive_confirm"),
                                    QMessageBox.Ok | QMessageBox.Cancel, QMessageBox.Cancel)
            if r != QMessageBox.Ok:
                return
        self.state.run_plugins(names, self.pid.text(), self.extra.text())

    # ------------------------------------------------------------ queue view
    def _queue_changed(self):
        live = {j.id for j in self.state.jobs.jobs}
        for jid in list(self._rows):
            if jid not in live:
                it = self._rows.pop(jid)
                idx = self.queue.indexOfTopLevelItem(it)
                if idx >= 0:
                    self.queue.takeTopLevelItem(idx)
        for j in self.state.jobs.jobs:
            self._job_changed(j)
        busy = self.state.jobs.busy
        self.btn_cancel_cur.setEnabled(self.state.jobs.current is not None)
        self.btn_cancel_all.setEnabled(busy)

    def _job_changed(self, job):
        it = self._rows.get(job.id)
        if it is None:
            it = QTreeWidgetItem()
            self._rows[job.id] = it
            self.queue.addTopLevelItem(it)
            bar = QProgressBar()
            bar.setRange(0, 100)
            self.queue.setItemWidget(it, 2, bar)
        it.setText(0, job.plugin)
        it.setText(1, tr("status." + job.status))
        it.setForeground(1, QBrush(QColor(STATUS_COLOR.get(job.status, "#888"))))
        bar = self.queue.itemWidget(it, 2)
        if bar:
            bar.setValue(int(job.progress))
            if job.status == J.RUNNING and job.progress == 0:
                bar.setRange(0, 0)  # busy indicator until Volatility reports progress
            else:
                bar.setRange(0, 100)
                bar.setValue(int(job.progress))
        it.setText(3, str(job.rows) if job.status == J.OK else "")
        it.setText(4, f"{job.elapsed():.0f}s" if job.status != J.QUEUED else "")
        it.setToolTip(0, job.error or " ".join(job.cmd))
