"""Self-contained HTML investigation report (print-to-PDF friendly, RTL aware)."""

from __future__ import annotations

from datetime import datetime
from html import escape
from typing import Dict, Iterable, List

from .. import APP_NAME, APP_AUTHOR, __version__
from ..i18n import tr
from .findings import Finding, SEVERITIES, counts
from .hashing import human_size
from .results import ResultTable, fmt

CSS = """
:root{--ink:#14202e;--muted:#5b6b7c;--line:#d9e0e8;--bg:#f5f7fa;--card:#fff;--accent:#0e6ba8}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);
font:14px/1.55 -apple-system,"Segoe UI",Roboto,"Noto Sans Arabic",Arial,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:32px 24px 64px}
header{border-bottom:3px solid var(--accent);padding-bottom:14px;margin-bottom:22px}
h1{margin:0 0 4px;font-size:26px}h2{margin:34px 0 10px;font-size:19px;border-bottom:1px solid var(--line);padding-bottom:6px}
.sub{color:var(--muted)}.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 18px}
table{border-collapse:collapse;width:100%;background:var(--card);font-size:12.5px}
th,td{border:1px solid var(--line);padding:5px 8px;text-align:start;vertical-align:top;word-break:break-word}
th{background:#eaf1f8}td.k{width:190px;font-weight:600;background:#f7fafc}
.pill{display:inline-block;padding:1px 9px;border-radius:10px;font-size:11.5px;font-weight:700;color:#fff}
.critical{background:#b3002d}.high{background:#d9480f}.medium{background:#c98a00}.low{background:#2b8a3e}.info{background:#5b6b7c}
.stats{display:flex;gap:10px;flex-wrap:wrap}.stat{flex:1;min-width:120px;text-align:center;padding:12px;border-radius:8px;color:#fff}
.stat b{display:block;font-size:26px}code{font-family:Consolas,Menlo,monospace;font-size:12px}
.note{color:var(--muted);font-size:12px;margin:6px 0 0}.scroll{overflow-x:auto}
@media print{body{background:#fff}.wrap{padding:0}h2{break-after:avoid}table{page-break-inside:auto}tr{page-break-inside:avoid}}
"""


def _kv(rows: Iterable[tuple]) -> str:
    return "<table>" + "".join(
        f"<tr><td class=k>{escape(str(k))}</td><td>{escape(str(v)) or '&nbsp;'}</td></tr>" for k, v in rows
    ) + "</table>"


def build_html_report(
    case,
    results: Dict[str, ResultTable],
    findings: List[Finding],
    lang: str = "en",
    max_rows: int = 500,
) -> str:
    rtl = lang == "ar"
    c = counts(findings)
    out: List[str] = []
    w = out.append
    w(f'<!doctype html><html lang="{lang}" dir="{"rtl" if rtl else "ltr"}"><head><meta charset="utf-8">')
    w(f"<title>{escape(tr('report.title'))} - {escape(case.name or case.case_id or '')}</title>")
    w(f"<style>{CSS}</style></head><body><div class=wrap>")
    w(f"<header><h1>{escape(tr('report.title'))}</h1>"
      f"<div class=sub>{escape(case.name or '')} &middot; {escape(datetime.now().strftime('%Y-%m-%d %H:%M'))}"
      f" &middot; {escape(APP_NAME)} {escape(__version__)}</div></header>")

    w(f"<h2>{escape(tr('report.case'))}</h2>")
    w(_kv([
        (tr("case.id"), case.case_id), (tr("case.name"), case.name), (tr("case.examiner"), case.examiner),
        (tr("case.created"), case.created), (tr("case.notes"), case.notes),
    ]))

    w(f"<h2>{escape(tr('report.evidence'))}</h2>")
    w(_kv([
        (tr("evidence.file"), case.image_path),
        (tr("evidence.size"), human_size(case.image_size) if case.image_size else ""),
        ("MD5", case.hashes.get("md5", "")), ("SHA-1", case.hashes.get("sha1", "")),
        ("SHA-256", case.hashes.get("sha256", "")),
        (tr("evidence.os"), case.os_hint),
    ]))

    w(f"<h2>{escape(tr('report.summary'))}</h2><div class=stats>")
    colors = {"critical": "#b3002d", "high": "#d9480f", "medium": "#c98a00", "low": "#2b8a3e", "info": "#5b6b7c"}
    for s in SEVERITIES:
        w(f'<div class=stat style="background:{colors[s]}"><b>{c.get(s, 0)}</b>{escape(tr("sev." + s))}</div>')
    w("</div>")
    w(f"<p class=note>{escape(tr('report.disclaimer'))}</p>")

    w(f"<h2>{escape(tr('report.findings'))}</h2>")
    if findings:
        w("<div class=scroll><table><tr>"
          + "".join(f"<th>{escape(tr(k))}</th>" for k in
                    ("findings.sev", "findings.rule", "findings.pid", "findings.process", "findings.evidence",
                     "findings.plugin", "findings.mitre"))
          + "</tr>")
        for f in findings:
            w(f"<tr><td><span class='pill {f.severity}'>{escape(tr('sev.' + f.severity))}</span></td>"
              f"<td>{escape(tr('rule.' + f.rule + '.title'))}</td><td>{'' if f.pid is None else f.pid}</td>"
              f"<td>{escape(f.process)}</td><td><code>{escape(f.evidence)}</code></td>"
              f"<td>{escape(f.plugin)}</td><td>{escape(f.mitre)}</td></tr>")
        w("</table></div>")
    else:
        w(f"<p>{escape(tr('report.nofindings'))}</p>")

    w(f"<h2>{escape(tr('report.results'))}</h2>")
    for name, t in results.items():
        w(f"<h3>{escape(name)} <span class=sub>({len(t)} {escape(tr('results.rows'))})</span></h3>")
        cols = [col for col in t.columns if col not in ("Hexdump", "Disasm")]
        w("<div class=scroll><table><tr>" + "".join(f"<th>{escape(col)}</th>" for col in cols) + "</tr>")
        for r in t.rows[:max_rows]:
            w("<tr>" + "".join(f"<td>{escape(fmt(r.get(col)))}</td>" for col in cols) + "</tr>")
        w("</table></div>")
        if len(t) > max_rows:
            w(f"<p class=note>{escape(tr('report.truncated', shown=max_rows, total=len(t)))}</p>")

    w(f"<h2>{escape(tr('report.audit'))}</h2><div class=card><pre style='margin:0;white-space:pre-wrap'>")
    w(escape("\n".join(case.audit_lines()[-200:])))
    w("</pre></div>")
    w(f"<p class=note>{escape(APP_NAME)} &middot; {escape(APP_AUTHOR)}</p></div></body></html>")
    return "".join(out)
