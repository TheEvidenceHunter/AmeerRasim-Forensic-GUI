"""Central application state shared by every page."""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Dict, List, Optional

from PySide6.QtCore import QObject, QSettings, QTimer, Signal

from .. import ORG_NAME
from ..core import catalog, findings as findings_mod, runner
from ..core.case import Case, default_cases_dir, set_cases_dir
from ..core.findings import Finding
from ..core.results import ParseError, ResultTable, parse_vol_json
from ..i18n import tr
from .jobs import JobManager, run_in_background


class AppState(QObject):
    caseChanged = Signal()
    imageChanged = Signal()
    osChanged = Signal(str)
    resultsChanged = Signal(str)
    findingsChanged = Signal()
    configChanged = Signal()
    logLine = Signal(str, str)  # level, text

    def __init__(self, settings: Optional[QSettings] = None):
        super().__init__()
        self.settings = settings or QSettings(ORG_NAME, "ForensicStudio")
        self.case = Case()
        self.results: Dict[str, ResultTable] = {}
        self.findings: List[Finding] = []
        self.flagged: Dict[str, Dict[int, str]] = {}
        self._analysis_gen = 0
        set_cases_dir(self.pref("cases_dir", ""))
        self.cfg = self._load_config()
        self.jobs = JobManager(lambda: self.cfg, self)
        self.jobs.resultReady.connect(self._on_result)
        self.jobs.jobFinished.connect(self._on_job_finished)
        self.jobs.log.connect(self.logLine)
        self._analysis_timer = QTimer(self)
        self._analysis_timer.setSingleShot(True)
        self._analysis_timer.setInterval(200)
        self._analysis_timer.timeout.connect(self._run_analysis)

    # ------------------------------------------------------------ settings
    def _load_config(self) -> runner.VolConfig:
        s = self.settings
        vol = s.value("vol_path", "", str) or runner.find_vol()
        return runner.VolConfig(
            python=s.value("python", "", str) or runner.default_python(),
            vol_path=vol,
            symbol_dirs=s.value("symbol_dirs", "", str),
            cache_path=s.value("cache_path", "", str),
            offline=s.value("offline", False, bool),
            parallelism=s.value("parallelism", "", str),
            output_dir=s.value("output_dir", "", str),
            verbosity=int(s.value("verbosity", 0)),
        )

    def save_config(self) -> None:
        s, c = self.settings, self.cfg
        for k, v in (("vol_path", c.vol_path), ("python", c.python), ("symbol_dirs", c.symbol_dirs),
                     ("cache_path", c.cache_path), ("offline", c.offline), ("parallelism", c.parallelism),
                     ("output_dir", c.output_dir), ("verbosity", c.verbosity)):
            s.setValue(k, v)
        self.configChanged.emit()

    def pref(self, key: str, default=None, type_=str):
        return self.settings.value(key, default, type_)

    def set_pref(self, key: str, value) -> None:
        self.settings.setValue(key, value)
        if key == "cases_dir":
            set_cases_dir(value)

    @property
    def cases_dir(self) -> Path:
        return Path(self.pref("cases_dir", str(default_cases_dir())))

    @property
    def vol_root(self) -> str:
        return runner.vol_root_of(self.cfg.vol_path)

    # ------------------------------------------------------------ log
    def log(self, level: str, text: str) -> None:
        self.logLine.emit(level, text)

    def audit(self, action: str) -> None:
        self.case.audit(action)
        self.log("audit", action)

    # ------------------------------------------------------------ case lifecycle
    def new_case(self) -> None:
        self.case = Case()
        self.results.clear()
        self.findings = []
        self.flagged = {}
        self.caseChanged.emit()
        self.findingsChanged.emit()
        self.imageChanged.emit()
        self.resultsChanged.emit("")

    def set_image(self, path: str) -> bool:
        path = os.path.abspath(path)
        if not os.path.isfile(path):
            self.log("error", tr("evidence.not_found", path=path))
            return False
        c = self.case
        c.image_path = path
        c.image_size = os.path.getsize(path)
        c.hashes = {}
        self.audit(f"Evidence selected: {path} ({c.image_size} bytes)")
        self.imageChanged.emit()
        return True

    def set_os(self, os_name: str) -> None:
        if self.case.os_hint != os_name:
            self.case.os_hint = os_name
            self.osChanged.emit(os_name)

    def set_hashes(self, hashes: Dict[str, str]) -> None:
        self.case.hashes = hashes
        self.audit("Evidence hashed: " + ", ".join(f"{k}={v}" for k, v in hashes.items()))
        self.imageChanged.emit()

    def save_case(self) -> Path:
        c = self.case
        c.ensure_folder(self.cases_dir)
        c.save()
        self.audit("Case saved")
        return Path(c.folder)

    def load_case(self, folder: str) -> None:
        case = Case.load(folder)
        saved = case.saved_results()

        def work():
            out = []
            for plugin, f in saved.items():
                try:
                    out.append((plugin, parse_vol_json(Path(f).read_text(encoding="utf-8"), plugin)))
                except (OSError, ParseError):
                    continue
            return out

        def done(items):
            self.case = case
            self.results = {}
            self.caseChanged.emit()
            self.imageChanged.emit()
            self.resultsChanged.emit("")
            for plugin, table in items:
                self.results[plugin] = table
                self.resultsChanged.emit(plugin)
            self.audit("Case opened")
            self._schedule_analysis()

        run_in_background(work, done, lambda e: self.log("error", str(e)))

    # ------------------------------------------------------------ results
    def _on_result(self, plugin: str, table: ResultTable, raw: str) -> None:
        self.results[plugin] = table
        if self.pref("autosave", True, bool):
            try:
                self.case.save_result(plugin, raw)
            except OSError as e:
                self.log("error", f"Could not save result: {e}")
        self.resultsChanged.emit(plugin)
        self._schedule_analysis()

    def _on_job_finished(self, job) -> None:
        """Record the run (with its real duration) in the case history and audit trail."""
        if job.status == "cancelled":
            self.audit(f"Plugin cancelled: {job.plugin}")
            return
        status = "ok" if job.status == "ok" else "failed"
        self.case.record_run(job.plugin, status, job.rows, job.seconds, job.error[:200])
        if status == "ok":
            self.audit(f"Plugin completed: {job.plugin} ({job.rows} rows, {job.seconds:.1f}s)")
        else:
            self.audit(f"Plugin failed: {job.plugin}")
        if self.pref("autosave", True, bool) and self.case.folder:
            try:
                self.case.save()
            except OSError:
                pass

    def _schedule_analysis(self) -> None:
        self._analysis_timer.start()

    def _run_analysis(self) -> None:
        self._analysis_gen += 1
        gen = self._analysis_gen
        snapshot = dict(self.results)
        run_in_background(
            lambda: findings_mod.analyze(snapshot),
            lambda res, g=gen: self._analysis_done(g, res),
            lambda e: self.log("error", f"Analysis failed: {e}"),
        )

    def _analysis_done(self, gen: int, res: List[Finding]) -> None:
        if gen != self._analysis_gen:
            return
        self.findings = res
        flagged: Dict[str, Dict[int, str]] = {}
        for f in res:
            if f.row is None:
                continue
            cur = flagged.setdefault(f.plugin, {}).get(f.row)
            if cur is None or findings_mod.SEV_RANK[f.severity] < findings_mod.SEV_RANK[cur]:
                flagged[f.plugin][f.row] = f.severity
        self.flagged = flagged
        self.findingsChanged.emit()

    # ------------------------------------------------------------ running plugins
    def run_plugins(self, names: List[str], pids: str = "", extra: str = "") -> int:
        """Queue plugins; returns how many were queued. Skips plugins missing from this Volatility."""
        if not self.case.image_path:
            return 0
        missing = catalog.missing_from_install(self.vol_root, names) if self.vol_root else []
        if missing:
            self.log("warn", tr("plugins.missing", names=", ".join(missing)))
        queued = 0
        single = len(names) - len(missing) == 1
        for name in names:
            if name in missing:
                continue
            info = catalog.get(name)
            self.jobs.enqueue(
                self.case.image_path, name,
                pids=pids if (info is None or info.pid) else "",
                extra=extra if single else "",
            )
            queued += 1
        if queued:
            self.audit("Queued: " + ", ".join(n for n in names if n not in missing))
        return queued
