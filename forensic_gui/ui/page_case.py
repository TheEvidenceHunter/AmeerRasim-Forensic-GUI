"""Case details and evidence (image selection, hashing, OS detection)."""

from __future__ import annotations

import os
from datetime import datetime

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (QComboBox, QFileDialog, QFormLayout, QGridLayout, QGroupBox, QHBoxLayout, QLabel,
                               QLineEdit, QPlainTextEdit, QProgressBar, QPushButton, QVBoxLayout, QWidget)

from ..core import detect
from ..core.hashing import Cancelled, hash_file, human_size
from ..i18n import tr
from .jobs import run_in_background
from .widgets import DropFrame, PathEdit, h_row, label, mark


class CasePage(QWidget):
    def __init__(self, state, parent=None):
        super().__init__(parent)
        self.state = state
        self._cancel_hash = False
        self._hashing = False
        self._detecting = False
        self._building = False
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(14)
        self.title = label("", "title")
        lay.addWidget(self.title)

        # ---- case box
        self.case_box = QGroupBox()
        form = QFormLayout(self.case_box)
        self.f_id, self.f_name, self.f_exam = QLineEdit(), QLineEdit(), QLineEdit()
        self.f_notes = QPlainTextEdit()
        self.f_notes.setFixedHeight(70)
        self.lb_id, self.lb_name, self.lb_exam, self.lb_notes = QLabel(), QLabel(), QLabel(), QLabel()
        form.addRow(self.lb_id, self.f_id)
        form.addRow(self.lb_name, self.f_name)
        form.addRow(self.lb_exam, self.f_exam)
        form.addRow(self.lb_notes, self.f_notes)
        self.lb_folder = label("", "hint")
        form.addRow(QLabel(), self.lb_folder)
        for w in (self.f_id, self.f_name, self.f_exam):
            w.textEdited.connect(self._push)
        self.f_notes.textChanged.connect(self._push)
        lay.addWidget(self.case_box)

        # ---- evidence box
        self.ev_box = QGroupBox()
        ev = QVBoxLayout(self.ev_box)
        self.drop = DropFrame()
        self.drop.fileDropped.connect(self._set_image)
        ev.addWidget(self.drop)
        self.path = PathEdit()
        self.path.setReadOnly(False)
        self.path.fileDropped.connect(self._set_image)
        self.path.editingFinished.connect(lambda: self._set_image(self.path.text()) if self.path.text() != self.state.case.image_path else None)
        self.btn_browse = QPushButton()
        self.btn_browse.clicked.connect(self._browse)
        ev.addWidget(h_row(self.path, self.btn_browse, spacing=8))
        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        self.v_size, self.v_mod = label(), label()
        self.lb_size, self.lb_mod, self.lb_os = label("", "muted"), label("", "muted"), label("", "muted")
        grid.addWidget(self.lb_size, 0, 0)
        grid.addWidget(self.v_size, 0, 1)
        grid.addWidget(self.lb_mod, 1, 0)
        grid.addWidget(self.v_mod, 1, 1)
        self.os_combo = QComboBox()
        self.os_combo.currentIndexChanged.connect(self._os_changed)
        self.btn_detect = QPushButton()
        self.btn_detect.clicked.connect(self.detect_os)
        grid.addWidget(self.lb_os, 2, 0)
        grid.addWidget(h_row(self.os_combo, self.btn_detect, stretch_last=True), 2, 1)
        grid.setColumnStretch(1, 1)
        ev.addLayout(grid)
        self.lb_detect = label("", "hint")
        ev.addWidget(self.lb_detect)

        # hashes
        self.hash_box = QGroupBox()
        hl = QGridLayout(self.hash_box)
        self.h_md5, self.h_sha1, self.h_sha256 = QLineEdit(), QLineEdit(), QLineEdit()
        for i, (name, w) in enumerate((("MD5", self.h_md5), ("SHA-1", self.h_sha1), ("SHA-256", self.h_sha256))):
            w.setReadOnly(True)
            w.setStyleSheet("font-family: Consolas, 'DejaVu Sans Mono', monospace;")
            hl.addWidget(label(name, "muted"), i, 0)
            hl.addWidget(w, i, 1)
        self.btn_hash = QPushButton()
        mark(self.btn_hash, primary=True)
        self.btn_hash.clicked.connect(self.toggle_hash)
        self.hash_bar = QProgressBar()
        self.hash_bar.setRange(0, 1000)
        self.hash_bar.setVisible(False)
        self.lb_hash = label("", "hint")
        hl.addWidget(self.btn_hash, 3, 0)
        hl.addWidget(self.hash_bar, 3, 1)
        hl.addWidget(self.lb_hash, 4, 1)
        ev.addWidget(self.hash_box)
        self.lb_ro = label("", "hint")
        ev.addWidget(self.lb_ro)
        lay.addWidget(self.ev_box)
        lay.addStretch(1)

        state.caseChanged.connect(self.refresh)
        state.imageChanged.connect(self.refresh)
        state.osChanged.connect(lambda _: self.refresh())
        self.retranslate()
        self.refresh()

    # ------------------------------------------------------------ i18n
    def retranslate(self):
        self.title.setText(tr("nav.case"))
        self.case_box.setTitle(tr("case.title"))
        self.ev_box.setTitle(tr("evidence.title"))
        self.hash_box.setTitle(tr("evidence.hash"))
        for lb, k in ((self.lb_id, "case.id"), (self.lb_name, "case.name"), (self.lb_exam, "case.examiner"),
                      (self.lb_notes, "case.notes"), (self.lb_size, "evidence.size"), (self.lb_mod, "evidence.modified"),
                      (self.lb_os, "evidence.os")):
            lb.setText(tr(k))
        self.btn_browse.setText(tr("btn.browse"))
        self.btn_detect.setText(tr("evidence.detect"))
        self.btn_hash.setText(tr("btn.cancel") if self._hashing else tr("evidence.hash_btn"))
        self.lb_ro.setText(tr("evidence.readonly"))
        self.path.setPlaceholderText(tr("evidence.drop"))
        self._fill_os_combo()
        self.refresh()

    def _fill_os_combo(self):
        self._building = True
        cur = self.state.case.os_hint
        self.os_combo.clear()
        for key in ("auto", "windows", "linux", "mac"):
            self.os_combo.addItem(tr("os." + key), key)
        self.os_combo.setCurrentIndex(max(0, self.os_combo.findData(cur)))
        self._building = False

    # ------------------------------------------------------------ state <-> widgets
    def refresh(self):
        c = self.state.case
        self._building = True
        for w, v in ((self.f_id, c.case_id), (self.f_name, c.name), (self.f_exam, c.examiner)):
            if w.text() != v and not w.hasFocus():
                w.setText(v)
        if self.f_notes.toPlainText() != c.notes and not self.f_notes.hasFocus():
            self.f_notes.setPlainText(c.notes)
        self.lb_folder.setText(f"{tr('case.folder')}: {c.folder}" if c.folder else "")
        self.path.setText(c.image_path)
        has = bool(c.image_path) and os.path.isfile(c.image_path)
        self.drop.set_text(c.image_path and os.path.basename(c.image_path) or tr("evidence.drop"))
        self.v_size.setText(human_size(c.image_size) if has else tr("common.none"))
        try:
            self.v_mod.setText(datetime.fromtimestamp(os.path.getmtime(c.image_path)).strftime("%Y-%m-%d %H:%M:%S")
                               if has else tr("common.none"))
        except OSError:
            self.v_mod.setText(tr("common.none"))
        self.os_combo.setCurrentIndex(max(0, self.os_combo.findData(c.os_hint)))
        self.h_md5.setText(c.hashes.get("md5", ""))
        self.h_sha1.setText(c.hashes.get("sha1", ""))
        self.h_sha256.setText(c.hashes.get("sha256", ""))
        self.btn_hash.setEnabled(has or self._hashing)
        self.btn_detect.setEnabled(has and not self._detecting)
        self._building = False

    def _push(self):
        if self._building:
            return
        c = self.state.case
        c.case_id, c.name, c.examiner = self.f_id.text(), self.f_name.text(), self.f_exam.text()
        c.notes = self.f_notes.toPlainText()

    # ------------------------------------------------------------ actions
    def _browse(self):
        f, _ = QFileDialog.getOpenFileName(self, tr("msg.select_image"), "",
                                           "Memory images (*.raw *.mem *.vmem *.dmp *.lime *.bin *.img *.elf *.vmss *.vmsn);;All files (*)")
        if f:
            self._set_image(f)

    def open_image_dialog(self):
        self._browse()

    def _set_image(self, path: str):
        path = path.strip().strip('"')
        if not path:
            return
        if self.state.set_image(path):
            self.lb_detect.setText("")

    def _os_changed(self):
        if self._building:
            return
        self.state.set_os(self.os_combo.currentData())

    def detect_os(self):
        c = self.state.case
        if not c.image_path or self._detecting:
            return
        if not self.state.cfg.vol_path:
            self.lb_detect.setText(tr("settings.vol_missing"))
            return
        self._detecting = True
        self.btn_detect.setEnabled(False)
        self.lb_detect.setText(tr("evidence.detecting"))
        cfg, img = self.state.cfg, c.image_path

        def done(found):
            self._detecting = False
            self.btn_detect.setEnabled(True)
            if found:
                self.state.set_os(found)
                self.lb_detect.setText(tr("evidence.detected", os=tr("os." + found)))
                self.state.audit(f"OS detected: {found}")
            else:
                self.lb_detect.setText(tr("evidence.detect_failed"))

        run_in_background(lambda: detect.detect_os(cfg, img), done, lambda e: done(None))

    def toggle_hash(self):
        if self._hashing:
            self._cancel_hash = True
            return
        c = self.state.case
        if not c.image_path:
            return
        self._hashing, self._cancel_hash = True, False
        self.btn_hash.setText(tr("btn.cancel"))
        self.hash_bar.setVisible(True)
        self.hash_bar.setValue(0)
        path = c.image_path

        # progress is polled from the GUI thread; the worker only writes a plain tuple
        progress = {"done": 0, "total": 1}
        from PySide6.QtCore import QTimer
        timer = QTimer(self)
        timer.setInterval(120)

        def tick():
            pct = progress["done"] / max(1, progress["total"])
            self.hash_bar.setValue(int(pct * 1000))
            self.lb_hash.setText(tr("evidence.hash_running", pct=f"{pct * 100:.0f}"))

        timer.timeout.connect(tick)
        timer.start()

        def work():
            return hash_file(path, progress=lambda d, t: progress.update(done=d, total=t),
                             cancelled=lambda: self._cancel_hash)

        def finish():
            timer.stop()
            self._hashing = False
            self.hash_bar.setVisible(False)
            self.btn_hash.setText(tr("evidence.hash_btn"))

        def ok(h):
            finish()
            self.lb_hash.setText(tr("evidence.hash_done"))
            self.state.set_hashes(h)

        def fail(e):
            finish()
            self.lb_hash.setText(tr("evidence.hash_cancelled") if isinstance(e, Cancelled) else str(e))

        run_in_background(work, ok, fail)
