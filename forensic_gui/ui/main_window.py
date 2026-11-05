"""Main window: sidebar navigation, menus, status bar, theme/language switching."""

from __future__ import annotations

import webbrowser
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (QApplication, QFileDialog, QHBoxLayout, QLabel, QListWidget, QListWidgetItem,
                               QMainWindow, QMessageBox, QProgressBar, QStackedWidget, QVBoxLayout, QWidget)

from .. import APP_AUTHOR, APP_NAME, APP_SUBTITLE, __version__
from ..core import catalog
from ..core.report import build_html_report
from ..i18n import is_rtl, language, set_language, tr
from .page_case import CasePage
from .page_dashboard import DashboardPage
from .page_findings import FindingsPage
from .page_log import LogPage
from .page_plugins import PluginsPage
from .page_results import ResultsPage
from .page_settings import SettingsPage
from .state import AppState
from .theme import build_qss
from .widgets import label

NAV = ["nav.dashboard", "nav.case", "nav.plugins", "nav.results", "nav.findings", "nav.log", "nav.settings"]
NAV_ICONS = ["▣", "🗂", "⚙", "▦", "⚑", "☰", "⛭"]
DOCS_URL = "https://volatility3.readthedocs.io/"


class MainWindow(QMainWindow):
    def __init__(self, state: AppState):
        super().__init__()
        self.state = state
        self.resize(1360, 860)
        self.setMinimumSize(1000, 640)

        central = QWidget()
        self.setCentralWidget(central)
        h = QHBoxLayout(central)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)

        # ---- sidebar
        side = QWidget()
        side.setObjectName("sidebar")
        side.setFixedWidth(220)
        sl = QVBoxLayout(side)
        sl.setContentsMargins(8, 16, 8, 12)
        self.brand = QLabel("◈ " + APP_NAME)
        self.brand.setObjectName("brand")
        self.sub = label(APP_SUBTITLE, "hint")
        sl.addWidget(self.brand)
        sl.addWidget(self.sub)
        sl.addSpacing(10)
        self.nav = QListWidget()
        self.nav.setObjectName("nav")
        self.nav.setFocusPolicy(Qt.NoFocus)
        sl.addWidget(self.nav, 1)
        self.by = label(f"{__version__}  ·  {APP_AUTHOR}", "hint")
        sl.addWidget(self.by)
        h.addWidget(side)

        # ---- pages
        self.stack = QStackedWidget()
        h.addWidget(self.stack, 1)
        self.p_dash = DashboardPage(state)
        self.p_case = CasePage(state)
        self.p_plug = PluginsPage(state)
        self.p_res = ResultsPage(state)
        self.p_find = FindingsPage(state)
        self.p_log = LogPage(state)
        self.p_set = SettingsPage(state)
        self.pages = [self.p_dash, self.p_case, self.p_plug, self.p_res, self.p_find, self.p_log, self.p_set]
        for p in self.pages:
            self.stack.addWidget(p)
        self.nav.currentRowChanged.connect(self.stack.setCurrentIndex)

        self.p_dash.navigate.connect(self.go)
        self.p_dash.triage.connect(self.start_triage)
        self.p_find.gotoRequested.connect(self._goto_result)
        self.p_set.languageChanged.connect(self.set_lang)
        self.p_set.themeChanged.connect(self.set_theme)

        # ---- status bar
        sb = self.statusBar()
        self.st_msg = QLabel()
        self.st_bar = QProgressBar()
        self.st_bar.setFixedWidth(160)
        self.st_bar.setRange(0, 100)
        self.st_bar.setVisible(False)
        self.st_find = QLabel()
        sb.addWidget(self.st_msg, 1)
        sb.addPermanentWidget(self.st_bar)
        sb.addPermanentWidget(self.st_find)
        state.jobs.jobChanged.connect(self._status)
        state.jobs.queueChanged.connect(self._status)
        state.findingsChanged.connect(self._status)

        self._build_menus()
        self.setAcceptDrops(True)
        self.apply_theme(state.pref("theme", "dark"))
        self.retranslate()
        self.nav.setCurrentRow(0)
        self._warn_if_no_vol()

    # ------------------------------------------------------------ menus
    def _act(self, menu, key, slot, shortcut=None):
        a = QAction(self)
        a.setData(key)
        a.triggered.connect(slot)
        if shortcut:
            a.setShortcut(QKeySequence(shortcut))
        menu.addAction(a)
        self._actions.append(a)
        return a

    def _build_menus(self):
        self._actions = []
        mb = self.menuBar()
        self.m_file, self.m_view, self.m_tools, self.m_help = (mb.addMenu("") for _ in range(4))
        self._act(self.m_file, "act.new_case", self.new_case, "Ctrl+N")
        self._act(self.m_file, "act.open_case", self.open_case, "Ctrl+Shift+O")
        self._act(self.m_file, "act.save_case", self.save_case, "Ctrl+S")
        self.m_file.addSeparator()
        self._act(self.m_file, "act.open_image", self.open_image, "Ctrl+O")
        self.m_file.addSeparator()
        self._act(self.m_file, "act.export_report", self.export_report, "Ctrl+E")
        self._act(self.m_file, "act.export_csv", lambda: self.p_res.export("csv"))
        self._act(self.m_file, "act.export_json", lambda: self.p_res.export("json"))
        self.m_file.addSeparator()
        self._act(self.m_file, "act.quit", self.close, "Ctrl+Q")
        self._act(self.m_view, "act.theme_dark", lambda: self.set_theme("dark"))
        self._act(self.m_view, "act.theme_light", lambda: self.set_theme("light"))
        self._act(self.m_tools, "act.compute_hash", self.p_case.toggle_hash)
        self._act(self.m_tools, "act.detect_os", self.p_case.detect_os)
        self._act(self.m_tools, "act.run_selected", self.p_plug.run_selected, "F5")
        self._act(self.m_tools, "act.stop", self.state.jobs.cancel_all, "Ctrl+.")
        self._act(self.m_help, "act.docs", lambda: webbrowser.open(DOCS_URL))
        self._act(self.m_help, "act.about", self.about)

    # ------------------------------------------------------------ theme / language
    def apply_theme(self, name: str):
        QApplication.instance().setStyleSheet(build_qss(name, is_rtl()))

    def set_theme(self, name: str):
        self.state.set_pref("theme", name)
        self.apply_theme(name)

    def set_lang(self, code: str):
        set_language(code)
        QApplication.instance().setLayoutDirection(Qt.RightToLeft if is_rtl() else Qt.LeftToRight)
        self.apply_theme(self.state.pref("theme", "dark"))
        self.retranslate()

    def retranslate(self):
        self.setWindowTitle(f"{APP_NAME} — {tr('app.title')}")
        cur = self.nav.currentRow()
        self.nav.clear()
        for icon, key in zip(NAV_ICONS, NAV):
            self.nav.addItem(QListWidgetItem(f"{icon}   {tr(key)}"))
        self.nav.setCurrentRow(max(cur, 0))
        for m, k in ((self.m_file, "menu.file"), (self.m_view, "menu.view"), (self.m_tools, "menu.tools"),
                     (self.m_help, "menu.help")):
            m.setTitle(tr(k))
        for a in self._actions:
            a.setText(tr(a.data()))
        for p in self.pages:
            if hasattr(p, "retranslate"):
                p.retranslate()
        self._status()

    # ------------------------------------------------------------ navigation
    def go(self, index: int):
        self.nav.setCurrentRow(index)

    def _goto_result(self, plugin, row):
        self.go(3)
        self.p_res.goto(plugin, row)

    def start_triage(self):
        if not self.state.case.image_path:
            self.go(1)
            return
        osn = self.state.case.os_hint
        key = {"windows": "win_triage", "linux": "linux_triage", "mac": "mac_triage"}.get(osn)
        self.go(2)
        if key:
            self.p_plug.apply_preset(key)
        else:
            self.p_plug.apply_preset("win_quick")

    # ------------------------------------------------------------ file actions
    def new_case(self):
        if self._confirm_busy():
            self.state.new_case()
            self.go(1)

    def open_case(self):
        d = QFileDialog.getExistingDirectory(self, tr("msg.open_case_folder"), str(self.state.cases_dir))
        if not d:
            return
        try:
            self.state.load_case(d)
            self.state.log("ok", tr("msg.case_loaded", name=Path(d).name))
        except (OSError, ValueError, KeyError) as e:
            QMessageBox.warning(self, tr("msg.error"), str(e))

    def save_case(self):
        try:
            p = self.state.save_case()
            self.state.log("ok", tr("msg.case_saved", path=p))
            self.p_case.refresh()
        except OSError as e:
            QMessageBox.warning(self, tr("msg.error"), str(e))

    def open_image(self):
        self.go(1)
        self.p_case.open_image_dialog()

    def export_report(self):
        c = self.state.case
        if not self.state.results:
            QMessageBox.information(self, tr("msg.info"), tr("msg.no_results"))
            return
        c.ensure_folder(self.state.cases_dir)
        default = str(c.exports_dir / "report.html")
        path, _ = QFileDialog.getSaveFileName(self, tr("act.export_report"), default, "HTML (*.html)")
        if not path:
            return
        try:
            html = build_html_report(c, self.state.results, self.state.findings, language())
            Path(path).write_text(html, encoding="utf-8")
        except OSError as e:
            QMessageBox.warning(self, tr("msg.error"), str(e))
            return
        self.state.audit(f"Report exported: {path}")
        self.state.log("ok", tr("msg.exported", path=path))
        c.save()

    def about(self):
        QMessageBox.about(self, tr("act.about"), tr("msg.about", version=__version__, author=APP_AUTHOR))

    # ------------------------------------------------------------ status / events
    def _status(self, *_):
        jm = self.state.jobs
        cur = jm.current
        if cur:
            self.st_msg.setText(tr("status.busy", plugin=cur.plugin, pct=int(cur.progress)))
            self.st_bar.setVisible(True)
            self.st_bar.setRange(0, 0) if cur.progress == 0 else self.st_bar.setRange(0, 100)
            self.st_bar.setValue(int(cur.progress))
            n = jm.queued_count()
            if n:
                self.st_msg.setText(self.st_msg.text() + "   ·   " + tr("status.queue_left", n=n))
        else:
            self.st_msg.setText(tr("status.idle"))
            self.st_bar.setVisible(False)
        self.st_find.setText(f"{tr('nav.findings')}: {len(self.state.findings)}")

    def _warn_if_no_vol(self):
        if not self.state.cfg.vol_path:
            self.state.log("warn", tr("settings.vol_missing"))

    def _confirm_busy(self) -> bool:
        if not self.state.jobs.busy:
            return True
        r = QMessageBox.question(self, tr("msg.confirm"), tr("msg.close_job"))
        if r == QMessageBox.Yes:
            self.state.jobs.cancel_all()
            return True
        return False

    def closeEvent(self, e):
        if self._confirm_busy():
            self.state.jobs.cancel_all()
            e.accept()
        else:
            e.ignore()

    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()

    def dropEvent(self, e):
        for u in e.mimeData().urls():
            if u.isLocalFile() and Path(u.toLocalFile()).is_file():
                self.go(1)
                self.p_case._set_image(u.toLocalFile())
                break
