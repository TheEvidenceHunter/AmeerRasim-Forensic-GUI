"""Settings: Volatility engine, interface and case defaults."""

from __future__ import annotations

import subprocess
from pathlib import Path

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (QCheckBox, QComboBox, QFileDialog, QFormLayout, QGroupBox, QLineEdit, QMessageBox,
                               QPushButton, QSpinBox, QVBoxLayout, QWidget)

from ..core import runner
from ..i18n import LANGS, language, tr
from .jobs import run_in_background
from .widgets import h_row, label, mark


class SettingsPage(QWidget):
    languageChanged = Signal(str)
    themeChanged = Signal(str)

    def __init__(self, state, parent=None):
        super().__init__(parent)
        self.state = state
        self._loading = False
        lay = QVBoxLayout(self)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(14)
        self.title = label("", "title")
        lay.addWidget(self.title)

        # engine
        self.g_vol = QGroupBox()
        f = QFormLayout(self.g_vol)
        self.vol, self.py, self.sym, self.cache, self.out = (QLineEdit() for _ in range(5))
        self.b_vol, self.b_py, self.b_sym, self.b_cache, self.b_out = (QPushButton("…") for _ in range(5))
        for b in (self.b_vol, self.b_py, self.b_sym, self.b_cache, self.b_out):
            b.setFixedWidth(40)
        self.b_vol.clicked.connect(lambda: self._pick_file(self.vol, "vol.py (vol.py);;All (*)"))
        self.b_py.clicked.connect(lambda: self._pick_file(self.py, "All (*)"))
        self.b_sym.clicked.connect(lambda: self._pick_dir(self.sym, append=True))
        self.b_cache.clicked.connect(lambda: self._pick_dir(self.cache))
        self.b_out.clicked.connect(lambda: self._pick_dir(self.out))
        self.lb = [label("", "") for _ in range(8)]
        self.offline = QCheckBox()
        self.parallel = QComboBox()
        self.verb = QSpinBox()
        self.verb.setRange(0, 5)
        f.addRow(self.lb[0], h_row(self.vol, self.b_vol))
        f.addRow(self.lb[1], h_row(self.py, self.b_py))
        f.addRow(self.lb[2], h_row(self.sym, self.b_sym))
        f.addRow(self.lb[3], h_row(self.cache, self.b_cache))
        f.addRow(self.lb[4], h_row(self.out, self.b_out))
        f.addRow(self.lb[5], self.parallel)
        f.addRow(self.lb[6], self.verb)
        f.addRow(QWidget(), self.offline)
        self.btn_test = QPushButton()
        mark(self.btn_test, primary=True)
        self.btn_test.clicked.connect(self.test_vol)
        f.addRow(QWidget(), self.btn_test)
        lay.addWidget(self.g_vol)

        # ui / case
        self.g_ui = QGroupBox()
        f2 = QFormLayout(self.g_ui)
        self.lang = QComboBox()
        for code, name in LANGS.items():
            self.lang.addItem(name, code)
        self.theme = QComboBox()
        self.cases = QLineEdit()
        self.b_cases = QPushButton("…")
        self.b_cases.setFixedWidth(40)
        self.b_cases.clicked.connect(lambda: self._pick_dir(self.cases))
        self.autosave = QCheckBox()
        self.lb_lang, self.lb_theme, self.lb_cases = label(""), label(""), label("")
        f2.addRow(self.lb_lang, self.lang)
        f2.addRow(self.lb_theme, self.theme)
        f2.addRow(self.lb_cases, h_row(self.cases, self.b_cases))
        f2.addRow(QWidget(), self.autosave)
        lay.addWidget(self.g_ui)
        lay.addStretch(1)

        for w in (self.vol, self.py, self.sym, self.cache, self.out):
            w.editingFinished.connect(self.apply)
        self.offline.toggled.connect(self.apply)
        self.parallel.currentIndexChanged.connect(self.apply)
        self.verb.valueChanged.connect(self.apply)
        self.cases.editingFinished.connect(self.apply)
        self.autosave.toggled.connect(self.apply)
        self.lang.currentIndexChanged.connect(self._lang)
        self.theme.currentIndexChanged.connect(self._theme)
        self.retranslate()

    # ------------------------------------------------------------ i18n / load
    def retranslate(self):
        self._loading = True
        self.title.setText(tr("settings.title"))
        self.g_vol.setTitle(tr("settings.group_vol"))
        self.g_ui.setTitle(tr("settings.group_ui") + " / " + tr("settings.group_case"))
        for lb, k in zip(self.lb, ("settings.vol", "settings.python", "settings.symbols", "settings.cache",
                                   "settings.output", "settings.parallel", "settings.verbosity")):
            lb.setText(tr(k))
        self.offline.setText(tr("settings.offline"))
        self.btn_test.setText(tr("settings.test"))
        self.lb_lang.setText(tr("settings.language"))
        self.lb_theme.setText(tr("settings.theme"))
        self.lb_cases.setText(tr("settings.cases_dir"))
        self.autosave.setText(tr("settings.autosave"))
        self.parallel.clear()
        for val, key in (("", "settings.none"), ("threads", "settings.threads"), ("processes", "settings.processes")):
            self.parallel.addItem(tr(key), val)
        self.theme.clear()
        self.theme.addItem(tr("act.theme_dark"), "dark")
        self.theme.addItem(tr("act.theme_light"), "light")
        c = self.state.cfg
        self.vol.setText(c.vol_path)
        self.py.setText(c.python)
        self.sym.setText(c.symbol_dirs)
        self.cache.setText(c.cache_path)
        self.out.setText(c.output_dir)
        self.offline.setChecked(c.offline)
        self.verb.setValue(c.verbosity)
        self.parallel.setCurrentIndex(max(0, self.parallel.findData(c.parallelism)))
        self.lang.setCurrentIndex(max(0, self.lang.findData(language())))
        self.theme.setCurrentIndex(max(0, self.theme.findData(self.state.pref("theme", "dark"))))
        self.cases.setText(str(self.state.cases_dir))
        self.autosave.setChecked(self.state.pref("autosave", True, bool))
        self._loading = False

    # ------------------------------------------------------------ actions
    def _pick_file(self, edit, flt):
        f, _ = QFileDialog.getOpenFileName(self, tr("msg.select_vol"), edit.text(), flt)
        if f:
            edit.setText(f)
            self.apply()

    def _pick_dir(self, edit, append=False):
        d = QFileDialog.getExistingDirectory(self, "", edit.text())
        if d:
            edit.setText(f"{edit.text()};{d}" if append and edit.text() else d)
            self.apply()

    def apply(self, *_):
        if self._loading:
            return
        try:
            self._apply()
        except RuntimeError:  # focus-out fired while the app is shutting down (QSettings already gone)
            pass

    def _apply(self):
        c = self.state.cfg
        c.vol_path, c.python = self.vol.text().strip(), self.py.text().strip() or runner.default_python()
        c.symbol_dirs, c.cache_path, c.output_dir = self.sym.text().strip(), self.cache.text().strip(), self.out.text().strip()
        c.offline, c.verbosity = self.offline.isChecked(), self.verb.value()
        c.parallelism = self.parallel.currentData() or ""
        self.state.set_pref("cases_dir", self.cases.text().strip())
        self.state.set_pref("autosave", self.autosave.isChecked())
        self.state.save_config()

    def _lang(self):
        if not self._loading:
            code = self.lang.currentData()
            self.state.set_pref("lang", code)
            self.languageChanged.emit(code)

    def _theme(self):
        if not self._loading:
            t = self.theme.currentData()
            self.state.set_pref("theme", t)
            self.themeChanged.emit(t)

    def test_vol(self):
        self.apply()
        c = self.state.cfg
        if not c.vol_path:
            QMessageBox.warning(self, tr("msg.error"), tr("settings.vol_missing"))
            return
        cmd = c.base_command() + ["--help"]
        self.btn_test.setEnabled(False)

        def work():
            p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                               timeout=180, cwd=c.workdir())
            return p.returncode, p.stdout, p.stderr

        def done(res):
            self.btn_test.setEnabled(True)
            code, out, err = res
            if code == 0 and "volatility" in (out + err).lower():
                QMessageBox.information(self, tr("msg.info"), tr("settings.test_ok"))
            else:
                QMessageBox.warning(self, tr("msg.error"), tr("settings.test_fail", err=runner.short_error(err or out)))

        def fail(e):
            self.btn_test.setEnabled(True)
            QMessageBox.warning(self, tr("msg.error"), tr("settings.test_fail", err=str(e)))

        run_in_background(work, done, fail)
