"""Sequential Volatility job queue built on QProcess, plus a tiny background-worker helper."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, List, Optional

from PySide6.QtCore import QObject, QProcess, QProcessEnvironment, QRunnable, QThreadPool, QTimer, Signal

from ..core import runner
from ..core.results import ParseError, parse_vol_json
from ..i18n import tr

# ------------------------------------------------------------------ background worker
_ACTIVE: set = set()


class _WorkerSignals(QObject):
    done = Signal(object)
    failed = Signal(object)


class Worker(QRunnable):
    """Run fn() on the global thread pool; results arrive on the GUI thread via signals."""

    def __init__(self, fn: Callable, on_done: Callable, on_failed: Optional[Callable] = None):
        super().__init__()
        self._fn = fn
        self.signals = _WorkerSignals()
        self.signals.done.connect(on_done)
        if on_failed:
            self.signals.failed.connect(on_failed)
        self.signals.done.connect(self._release)
        self.signals.failed.connect(self._release)
        self.setAutoDelete(False)
        _ACTIVE.add(self)

    def _release(self, *_):
        _ACTIVE.discard(self)

    def run(self):
        try:
            res = self._fn()
        except Exception as e:  # noqa: BLE001
            self.signals.failed.emit(e)
        else:
            self.signals.done.emit(res)


def run_in_background(fn, on_done, on_failed=None) -> Worker:
    w = Worker(fn, on_done, on_failed)
    QThreadPool.globalInstance().start(w)
    return w


# ------------------------------------------------------------------ jobs
QUEUED, RUNNING, PARSING, OK, FAILED, CANCELLED = "queued", "running", "parsing", "ok", "failed", "cancelled"
FINISHED_STATES = (OK, FAILED, CANCELLED)


@dataclass
class Job:
    id: int
    plugin: str
    cmd: List[str]
    status: str = QUEUED
    progress: float = 0.0
    started: float = 0.0
    seconds: float = 0.0
    rows: int = 0
    error: str = ""
    cancel_requested: bool = False
    stdout: bytearray = field(default_factory=bytearray)
    stderr: str = ""

    def elapsed(self) -> float:
        if self.status in (RUNNING, PARSING):
            return time.monotonic() - self.started
        return self.seconds


class JobManager(QObject):
    jobChanged = Signal(object)
    queueChanged = Signal()
    resultReady = Signal(str, object, str)  # plugin, ResultTable, raw json text
    jobFinished = Signal(object)
    log = Signal(str, str)  # level, message
    busyChanged = Signal(bool)

    def __init__(self, get_config: Callable[[], runner.VolConfig], parent=None):
        super().__init__(parent)
        self._get_config = get_config
        self.jobs: List[Job] = []
        self._current: Optional[Job] = None
        self._proc: Optional[QProcess] = None
        self._next_id = 1
        self._stderr_tail = ""

    # ------------------------------------------------------------ public
    @property
    def busy(self) -> bool:
        return self._current is not None or any(j.status == QUEUED for j in self.jobs)

    @property
    def current(self) -> Optional[Job]:
        return self._current

    def queued_count(self) -> int:
        return sum(1 for j in self.jobs if j.status == QUEUED)

    def enqueue(self, image: str, plugin: str, pids: str = "", extra: str = "") -> Job:
        cmd = runner.build_command(self._get_config(), image, plugin, pids=pids, extra_args=extra)
        job = Job(self._next_id, plugin, cmd)
        self._next_id += 1
        self.jobs.append(job)
        self.queueChanged.emit()
        self.jobChanged.emit(job)
        self._pump()
        return job

    def cancel_current(self) -> None:
        if self._current and self._proc:
            self._current.cancel_requested = True
            self._proc.kill()

    def cancel_all(self) -> None:
        for j in self.jobs:
            if j.status == QUEUED:
                j.status = CANCELLED
                self.jobChanged.emit(j)
        self.cancel_current()
        self.queueChanged.emit()

    def clear_finished(self) -> None:
        self.jobs = [j for j in self.jobs if j.status not in FINISHED_STATES]
        self.queueChanged.emit()

    # ------------------------------------------------------------ internals
    def _pump(self) -> None:
        if self._current:
            return
        nxt = next((j for j in self.jobs if j.status == QUEUED), None)
        if not nxt:
            self.busyChanged.emit(False)
            return
        self._start(nxt)

    def _start(self, job: Job) -> None:
        cfg = self._get_config()
        self._current = job
        job.status = RUNNING
        job.started = time.monotonic()
        self._stderr_tail = ""
        proc = QProcess(self)
        self._proc = proc
        env = QProcessEnvironment.systemEnvironment()
        env.insert("PYTHONIOENCODING", "utf-8")
        env.insert("PYTHONUNBUFFERED", "1")
        proc.setProcessEnvironment(env)
        wd = cfg.workdir()
        if wd:
            proc.setWorkingDirectory(wd)
        proc.readyReadStandardOutput.connect(self._on_stdout)
        proc.readyReadStandardError.connect(self._on_stderr)
        proc.finished.connect(self._on_finished)
        proc.errorOccurred.connect(self._on_error)
        self.log.emit("info", tr("msg.started", cmd=runner.display_command(job.cmd)))
        self.jobChanged.emit(job)
        self.queueChanged.emit()
        self.busyChanged.emit(True)
        proc.start(job.cmd[0], job.cmd[1:])

    def _on_stdout(self) -> None:
        if self._proc and self._current:
            self._current.stdout += bytes(self._proc.readAllStandardOutput())

    def _on_stderr(self) -> None:
        if not (self._proc and self._current):
            return
        text = bytes(self._proc.readAllStandardError()).decode("utf-8", "replace")
        self._current.stderr += text
        if len(self._current.stderr) > 400_000:  # keep memory bounded on chatty runs
            self._current.stderr = self._current.stderr[-200_000:]
        prog = runner.parse_progress(text)
        if prog:
            self._current.progress = prog[0]
            self.jobChanged.emit(self._current)

    def _on_error(self, err) -> None:
        job = self._current
        if job and err == QProcess.ProcessError.FailedToStart:
            job.stderr += f"\nFailed to start: {job.cmd[0]}"
            self._finish(job, FAILED, -1)

    def _on_finished(self, exit_code, _status) -> None:
        job = self._current
        if not job or job.status in FINISHED_STATES:
            return
        self._on_stdout()
        if job.cancel_requested:
            self._finish(job, CANCELLED, exit_code)
        elif exit_code != 0:
            self._finish(job, FAILED, exit_code)
        else:
            job.status = PARSING
            self.jobChanged.emit(job)
            text = bytes(job.stdout).decode("utf-8", "replace")
            run_in_background(
                lambda: (parse_vol_json(text, job.plugin), text),
                lambda res, j=job: self._parsed(j, res),
                lambda err, j=job: self._parse_failed(j, err),
            )

    def _parsed(self, job: Job, res) -> None:
        table, text = res
        job.rows = len(table)
        job.stdout = bytearray()  # free the raw buffer
        self.resultReady.emit(job.plugin, table, text)
        self._finish(job, OK, 0)

    def _parse_failed(self, job: Job, err) -> None:
        job.error = str(err)
        self.log.emit("error", tr("msg.parse_failed", plugin=job.plugin, err=err))
        self._finish(job, FAILED, 0, parse_error=True)

    def _finish(self, job: Job, status: str, code: int, parse_error: bool = False) -> None:
        job.status = status
        job.seconds = time.monotonic() - job.started
        job.progress = 100.0 if status == OK else job.progress
        if status == FAILED and not parse_error:
            job.error = runner.short_error(job.stderr)
            self.log.emit("error", tr("msg.job_failed", plugin=job.plugin, code=code))
            if job.error:
                self.log.emit("error", job.error)
            for key in runner.diagnose(job.stderr, code or 1):
                self.log.emit("warn", tr("diag." + key))
        elif status == OK:
            self.log.emit("ok", tr("msg.job_done", plugin=job.plugin, rows=job.rows, sec=f"{job.seconds:.1f}"))
        if self._proc:
            self._proc.deleteLater()
            self._proc = None
        self._current = None
        self.jobChanged.emit(job)
        self.jobFinished.emit(job)
        self.queueChanged.emit()
        QTimer.singleShot(0, self._pump)
