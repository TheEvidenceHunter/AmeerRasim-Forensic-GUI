"""Heuristic triage rules that turn plugin results into prioritized, MITRE-mapped leads.

These are *leads for an examiner to verify*, not verdicts - every rule has a documented
false-positive note in the UI (see i18n keys ``rule.<id>.desc``).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Tuple

from .results import ResultTable, fmt, get

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}


@dataclass
class Finding:
    rule: str  # i18n key suffix, e.g. "malfind_pe"
    severity: str
    plugin: str
    evidence: str
    mitre: str = ""
    pid: Optional[int] = None
    process: str = ""
    row: Optional[int] = None  # row index in the source plugin table (for jump-to)

    def key(self) -> Tuple:
        return (self.rule, self.pid, self.process.lower(), self.evidence[:120])


# ------------------------------------------------------------------ helpers
def _short(text: str, n: int = 260) -> str:
    text = " ".join(str(text).split())
    return text if len(text) <= n else text[: n - 1] + "…"


def _tables(ctx: Dict[str, ResultTable], suffix: str) -> Iterator[Tuple[str, ResultTable]]:
    """All tables whose plugin name ends with the given suffix (survives plugin renames)."""
    for name, t in ctx.items():
        if name.lower().split(".")[-1] == suffix or name.lower().endswith("." + suffix):
            yield name, t


def _to_int(v) -> Optional[int]:
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _is_true(v) -> bool:
    return v is True or (isinstance(v, str) and v.strip().lower() in ("true", "1", "yes"))


def _name(v) -> str:
    return str(v or "").strip().lower()


@dataclass
class Proc:
    pid: int
    ppid: Optional[int]
    name: str
    exited: bool
    path: str = ""
    plugin: str = ""
    row: Optional[int] = None


def _collect_processes(ctx: Dict[str, ResultTable]) -> Dict[int, Proc]:
    procs: Dict[int, Proc] = {}
    for suffix in ("pslist", "pstree", "psscan"):  # earlier sources win
        for plugin, t in _tables(ctx, suffix):
            for i, row in enumerate(t.rows):
                pid = _to_int(get(row, "PID", "Pid"))
                if pid is None or pid in procs:
                    continue
                name = get(row, "ImageFileName", "Name", "COMM", "Process") or ""
                ex = get(row, "ExitTime", "Exit Time")
                procs[pid] = Proc(
                    pid, _to_int(get(row, "PPID")), str(name), bool(ex), str(get(row, "Path", default="") or ""),
                    plugin, i,
                )
    return procs


# ------------------------------------------------------------------ rule tables
CRITICAL_NAMES = [
    "svchost.exe", "lsass.exe", "csrss.exe", "explorer.exe", "services.exe", "winlogon.exe",
    "smss.exe", "wininit.exe", "spoolsv.exe", "taskhost.exe", "taskhostw.exe", "dwm.exe", "conhost.exe",
]
SINGLE_INSTANCE = ["lsass.exe", "services.exe", "wininit.exe"]
EXPECTED_PARENT = {"svchost.exe": "services.exe", "lsass.exe": "wininit.exe", "services.exe": "wininit.exe"}
OFFICE_PARENTS = {"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe", "acrobat.exe",
                  "msaccess.exe", "mspub.exe", "onenote.exe", "foxitreader.exe"}
BROWSER_PARENTS = {"chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe", "brave.exe", "opera.exe"}
SHELL_CHILDREN = {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe",
                  "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe"}
NET_SUSPECT_PROCS = {"powershell.exe", "pwsh.exe", "cmd.exe", "rundll32.exe", "wscript.exe", "cscript.exe",
                     "mshta.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe", "msbuild.exe", "wmic.exe"}
BAD_PORTS = {4444, 4445, 1337, 31337, 5555, 6666, 6667, 9001, 9050, 12345, 1234, 8081, 2222}

# (rule id, regex, severity, MITRE). Applied to command lines / shell history.
CMD_RULES: List[Tuple[str, "re.Pattern", str, str]] = [
    ("ps_encoded", re.compile(r"powershell.*\s-(e|ec|en|enc|enco|encod\w*|encodedcommand)\s+[A-Za-z0-9+/=]{12,}", re.I),
     "high", "T1059.001"),
    ("ps_download", re.compile(r"(downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|"
                               r"invoke-expression|\biex\b|frombase64string)", re.I), "high", "T1059.001"),
    ("ps_stealth", re.compile(r"powershell.*(-w(indowstyle)?\s+hidden|\s-nop\b|\s-noni\b|-ep\s+bypass|"
                              r"executionpolicy\s+bypass)", re.I), "medium", "T1059.001"),
    ("lolbin_download", re.compile(r"(certutil.*(-urlcache|-decode|-encode)|bitsadmin.*/transfer|"
                                   r"curl\.exe.*http|esentutl.*/y)", re.I), "high", "T1105"),
    ("lolbin_proxy", re.compile(r"(mshta.*(http|javascript:|vbscript:)|regsvr32.*(/i:|scrobj|http)|"
                                r"rundll32.*(javascript:|http|\\appdata\\|\\temp\\)|msiexec.*/q.*http)", re.I),
     "high", "T1218"),
    ("shadow_delete", re.compile(r"(vssadmin.*delete\s+shadows|wmic.*shadowcopy.*delete|"
                                 r"bcdedit.*recoveryenabled\s+no|wbadmin.*delete)", re.I), "critical", "T1490"),
    ("wmic_exec", re.compile(r"wmic.*process\s+call\s+create", re.I), "high", "T1047"),
    ("cred_tool", re.compile(r"(mimikatz|sekurlsa|procdump.*lsass|comsvcs\.dll.*minidump|lazagne|"
                             r"ntdsutil.*ifm|reg\s+save\s+hklm\\(sam|security))", re.I), "critical", "T1003"),
    ("temp_path", re.compile(r"\\(users\\public|programdata|appdata\\local\\temp|windows\\temp|"
                             r"\$recycle\.bin)\\[^\s\"']+\.(exe|dll|bat|ps1|vbs|js|scr)", re.I), "medium", "T1204.002"),
]
LINUX_RULES: List[Tuple[str, "re.Pattern", str, str]] = [
    ("linux_pipe_sh", re.compile(r"(curl|wget)\b.*\|\s*(ba|z|da)?sh\b", re.I), "high", "T1059.004"),
    ("linux_revshell", re.compile(r"(\bnc\b.*\s-e\s|\bncat\b.*\s-e\s|/dev/tcp/|bash\s+-i\s*>&|"
                                  r"socat.*exec|python\d?\s+-c.*socket.*connect|perl\s+-e.*socket)", re.I),
     "critical", "T1059.004"),
    ("linux_tmp_exec", re.compile(r"(chmod\s+\+?[0-7x]+\s+/(tmp|dev/shm|var/tmp)|^\s*/(tmp|dev/shm|var/tmp)/\S+)", re.I),
     "medium", "T1036"),
    ("linux_antiforensic", re.compile(r"(history\s+-c|unset\s+HISTFILE|HISTSIZE=0|rm\s+-rf?\s+/var/log|"
                                      r"shred\s.*(log|history)|>\s*/var/log/\S+)", re.I), "high", "T1070.003"),
]


def _lev(a: str, b: str, cap: int = 3) -> int:
    """Levenshtein distance with an early cutoff."""
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


# ------------------------------------------------------------------ rules
Rule = Callable[[Dict[str, ResultTable], Dict[int, Proc]], Iterable[Finding]]


def rule_malfind(ctx, procs):
    for plugin, t in _tables(ctx, "malfind"):
        for i, row in enumerate(t.rows):
            pid = _to_int(get(row, "PID"))
            proc = str(get(row, "Process", default="") or "")
            prot = str(get(row, "Protection", default="") or "")
            dump = str(get(row, "Hexdump", default="") or "").lower().replace("\n", " ")
            is_pe = dump.strip().startswith("4d 5a")
            ev = f"{prot} @ {fmt(get(row, 'Start VPN', 'Start'))}-{fmt(get(row, 'End VPN', 'End'))}"
            if is_pe:
                yield Finding("malfind_pe", "critical", plugin, ev, "T1055", pid, proc, i)
            else:
                sev = "high" if "EXECUTE_READWRITE" in prot.upper() or "RWX" in prot.upper() or "rwx" in prot else "medium"
                yield Finding("malfind_rwx", sev, plugin, ev, "T1055", pid, proc, i)


def rule_masquerade(ctx, procs):
    targets = set(CRITICAL_NAMES)
    for p in procs.values():
        n = _name(p.name)
        if not n or n in targets or len(n) < 6:
            continue
        for t in targets:
            limit = 2 if len(t) >= 10 else 1  # allow transpositions on long names (scvhost.exe)
            if 0 < _lev(n, t) <= limit or (n.replace("0", "o").replace("1", "l") == t):
                yield Finding("masq_name", "high", p.plugin, f"{p.name} ~ {t}", "T1036.005", p.pid, p.name, p.row)
                break


def rule_single_instance(ctx, procs):
    for target in SINGLE_INSTANCE:
        live = [p for p in procs.values() if _name(p.name) == target and not p.exited]
        if len(live) > 1:
            for p in live:
                yield Finding("dup_single", "high", p.plugin, f"{target} x{len(live)}", "T1036.005", p.pid, p.name, p.row)


def rule_parentage(ctx, procs):
    for p in procs.values():
        n = _name(p.name)
        expected = EXPECTED_PARENT.get(n)
        if not expected or p.ppid is None or p.exited:
            continue
        parent = procs.get(p.ppid)
        if parent and _name(parent.name) != expected:
            yield Finding("bad_parent", "high", p.plugin, f"{p.name} <- {parent.name} ({parent.pid}), expected {expected}",
                          "T1036.005", p.pid, p.name, p.row)


def rule_office_child(ctx, procs):
    for p in procs.values():
        if _name(p.name) not in SHELL_CHILDREN or p.ppid is None:
            continue
        parent = procs.get(p.ppid)
        if not parent:
            continue
        pn = _name(parent.name)
        if pn in OFFICE_PARENTS:
            yield Finding("office_child", "high", p.plugin, f"{parent.name} -> {p.name}", "T1204.002", p.pid, p.name, p.row)
        elif pn in BROWSER_PARENTS:
            yield Finding("office_child", "medium", p.plugin, f"{parent.name} -> {p.name}", "T1189", p.pid, p.name, p.row)


def _command_sources(ctx) -> Iterator[Tuple[str, int, ResultTable, Dict, str, Optional[int], str, bool]]:
    """(plugin, row idx, table, row, text, pid, process, is_linux)."""
    for suffix, cols, linux in (("cmdline", ("Args",), False), ("pstree", ("Cmd",), False),
                                ("bash", ("Command",), True), ("psaux", ("ARGS",), True)):
        for plugin, t in _tables(ctx, suffix):
            is_linux = linux or plugin.lower().startswith(("linux", "mac"))
            for i, row in enumerate(t.rows):
                text = " ".join(str(get(row, c, default="") or "") for c in cols).strip()
                if text:
                    yield (plugin, i, t, row, text, _to_int(get(row, "PID", "Pid")),
                           str(get(row, "Process", "ImageFileName", "Name", "COMM", default="") or ""), is_linux)


def rule_commandlines(ctx, procs):
    for plugin, i, t, row, text, pid, proc, is_linux in _command_sources(ctx):
        rules = (LINUX_RULES + CMD_RULES) if is_linux else CMD_RULES
        for rid, rx, sev, mitre in rules:
            if rx.search(text):
                yield Finding(rid, sev, plugin, _short(text), mitre, pid, proc, i)


def _is_global(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr.strip("[]"))
    except ValueError:
        return False
    return ip.is_global and not ip.is_multicast


def rule_network(ctx, procs):
    for plugin, t in list(_tables(ctx, "netscan")) + list(_tables(ctx, "netstat")) + list(_tables(ctx, "sockstat")):
        for i, row in enumerate(t.rows):
            state = str(get(row, "State", default="") or "").upper()
            remote = str(get(row, "ForeignAddr", "Destination Addr", default="") or "")
            rport = _to_int(get(row, "ForeignPort", "Destination Port"))
            lport = _to_int(get(row, "LocalPort", "Source Port"))
            owner = str(get(row, "Owner", "Process Name", default="") or "")
            pid = _to_int(get(row, "PID"))
            if state == "ESTABLISHED" and _is_global(remote):
                ev = f"{owner or '?'} -> {remote}:{rport}"
                if _name(owner) in NET_SUSPECT_PROCS:
                    yield Finding("net_external", "high", plugin, ev, "T1071", pid, owner, i)
                elif rport in BAD_PORTS:
                    yield Finding("net_badport", "medium", plugin, ev, "T1571", pid, owner, i)
            elif state in ("LISTENING", "LISTEN") and lport in BAD_PORTS:
                yield Finding("net_badport", "medium", plugin, f"{owner or '?'} listening on {lport}", "T1571", pid, owner, i)


def rule_hidden_processes(ctx, procs):
    seen = set()
    for plugin, t in _tables(ctx, "psxview"):
        for i, row in enumerate(t.rows):
            in_list = _is_true(get(row, "pslist"))
            elsewhere = any(_is_true(get(row, c)) for c in ("psscan", "thrdscan", "csrss"))
            exited = bool(get(row, "Exit Time", "ExitTime"))
            pid = _to_int(get(row, "PID"))
            if not in_list and elsewhere and not exited and pid not in seen:
                seen.add(pid)
                yield Finding("hidden_proc", "high", plugin, f"{get(row, 'Name', default='?')} not in pslist", "T1014",
                              pid, str(get(row, "Name", default="") or ""), i)
    if seen:
        return
    ps = {p.pid for p in procs.values() if p.plugin.endswith("pslist")}
    for plugin, t in _tables(ctx, "psscan"):
        for i, row in enumerate(t.rows):
            pid = _to_int(get(row, "PID"))
            if ps and pid is not None and pid not in ps and not get(row, "ExitTime", "Exit Time"):
                yield Finding("hidden_proc", "high", plugin, f"{get(row, 'ImageFileName', default='?')} only in psscan",
                              "T1014", pid, str(get(row, "ImageFileName", default="") or ""), i)


# plugins whose rows are findings by themselves: suffix -> (rule, severity, MITRE, row filter)
def _spoofed(row) -> bool:
    return any(_is_true(get(row, c)) for c in
               ("PEB_ImageFilePath_Spoofed", "PEB_CommandLine_Spoofed", "Cmdline_Spoofed", "Comm_Spoofed", "Exe_Deleted"))


def _unknown_symbol(row) -> bool:
    sym = str(get(row, "Handler Symbol", "Symbol", "Module", default="") or "").strip().upper()
    return sym in ("", "UNKNOWN", "N/A", "NONE", "-")


ROW_RULES = {
    "hollowprocesses": ("hollow", "high", "T1055.012", lambda r: True),
    "pebmasquerade": ("peb_masq", "high", "T1036", _spoofed),
    "process_spoofing": ("proc_spoof", "high", "T1036", _spoofed),
    "processghosting": ("ghosting", "high", "T1055.013", lambda r: True),
    "etwpatch": ("etw_patch", "high", "T1562.006", lambda r: True),
    "suspicious_threads": ("susp_thread", "medium", "T1055", lambda r: True),
    "direct_system_calls": ("syscall_evasion", "medium", "T1106", lambda r: True),
    "indirect_system_calls": ("syscall_evasion", "medium", "T1106", lambda r: True),
    "skeleton_key_check": ("skeleton_key", "high", "T1556.001", lambda r: True),
    "hidden_modules": ("hidden_module", "high", "T1014", lambda r: True),
    "check_syscall": ("syscall_hook", "high", "T1014", _unknown_symbol),
    "check_idt": ("syscall_hook", "high", "T1014", _unknown_symbol),
    "check_afinfo": ("syscall_hook", "high", "T1014", _unknown_symbol),
    "check_sysctl": ("syscall_hook", "high", "T1014", _unknown_symbol),
    "check_trap_table": ("syscall_hook", "high", "T1014", _unknown_symbol),
}


def rule_row_plugins(ctx, procs):
    for suffix, (rid, sev, mitre, flt) in ROW_RULES.items():
        for plugin, t in _tables(ctx, suffix):
            for i, row in enumerate(t.rows):
                if not flt(row):
                    continue
                pid = _to_int(get(row, "PID", "Pid"))
                proc = str(get(row, "Process", "Name", "Comm", "EPROCESS_ImageFileName", "Module", default="") or "")
                ev = _short(" | ".join(f"{k}={fmt(v)}" for k, v in row.items()
                                       if k != "__depth" and v not in (None, "") and k not in ("Hexdump", "Disasm")), 220)
                yield Finding(rid, sev, plugin, ev, mitre, pid, proc, i)


RULES: List[Rule] = [
    rule_malfind, rule_masquerade, rule_single_instance, rule_parentage, rule_office_child,
    rule_commandlines, rule_network, rule_hidden_processes, rule_row_plugins,
]


def analyze(results: Dict[str, ResultTable]) -> List[Finding]:
    """Run every rule over the available results; never raises (a broken rule is skipped)."""
    procs = _collect_processes(results)
    out: Dict[Tuple, Finding] = {}
    for rule in RULES:
        try:
            for f in rule(results, procs):
                out.setdefault(f.key(), f)
        except Exception:  # noqa: BLE001 - heuristics must never break the UI
            continue
    return sorted(out.values(), key=lambda f: (SEV_RANK.get(f.severity, 9), f.pid or 0, f.rule))


def counts(findings: Iterable[Finding]) -> Dict[str, int]:
    c = {s: 0 for s in SEVERITIES}
    for f in findings:
        c[f.severity] = c.get(f.severity, 0) + 1
    return c
