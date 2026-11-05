"""End-to-end GUI test: real QProcess queue + fake vol.py, offscreen Qt."""
import os
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("PySide6")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PySide6.QtCore import QEventLoop, QSettings, Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from forensic_gui import i18n  # noqa: E402
from forensic_gui.core.report import build_html_report  # noqa: E402
from forensic_gui.ui.main_window import MainWindow  # noqa: E402
from forensic_gui.ui.state import AppState  # noqa: E402

FAKE = str(Path(__file__).with_name("fake_vol.py"))


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


def wait(app, cond, secs=20):
    t = time.time()
    while not cond() and time.time() - t < secs:
        app.processEvents(QEventLoop.AllEvents, 50)
    assert cond(), "timeout"


def test_full_pipeline(app, tmp_path):
    from forensic_gui.core.case import set_cases_dir
    st = AppState(QSettings(str(tmp_path / "s.ini"), QSettings.IniFormat))
    st.cfg.vol_path, st.cfg.python = FAKE, sys.executable
    st.set_pref("cases_dir", str(tmp_path / "cases"))
    w = MainWindow(st)
    w.show()
    img = tmp_path / "mem.raw"
    img.write_bytes(os.urandom(100_000))
    assert st.set_image(str(img))
    w.p_case.toggle_hash()
    wait(app, lambda: st.case.hashes)
    st.set_os("windows")
    assert st.run_plugins(["windows.pslist", "windows.cmdline", "windows.info"]) == 3
    st.jobs.enqueue(st.case.image_path, "windows.failme")
    wait(app, lambda: not st.jobs.busy)
    wait(app, lambda: st.findings)
    status = {j.plugin: j.status for j in st.jobs.jobs}
    assert status["windows.pslist"] == "ok" and status["windows.failme"] == "failed"
    assert {"masq_name", "office_child", "ps_encoded"} <= {f.rule for f in st.findings}
    # severity sort: first row must be the most severe
    fp = w.p_find
    sevs = [fp.proxy.index(r, 0).data() for r in range(fp.proxy.rowCount())]
    assert sevs[0] == i18n.tr("sev.high")
    # filters
    rv = w.p_res.views["windows.pslist"]
    assert rv.model.flag(1) == "high"
    rv.filter.setText("pid:700")
    assert rv.proxy.rowCount() == 1
    rv.filter.setText("name:system")
    assert rv.proxy.rowCount() == 1
    # results stored under the user's cases dir, reloadable
    st.save_case()
    folder = Path(st.case.folder)
    assert folder.parent == tmp_path / "cases" and (folder / "results" / "windows.pslist.json").is_file()
    st2 = AppState(QSettings(str(tmp_path / "s2.ini"), QSettings.IniFormat))
    st2.load_case(str(folder))
    wait(app, lambda: len(st2.results) == 3 and st2.findings)
    # every page renders in both languages and themes
    for lang in ("en", "ar"):
        w.set_lang(lang)
        for theme in ("dark", "light"):
            w.set_theme(theme)
            for i in range(len(w.pages)):
                w.go(i)
                app.processEvents()
    assert 'dir="rtl"' in build_html_report(st.case, st.results, st.findings, "ar")
    w.set_lang("en")
    set_cases_dir("")
