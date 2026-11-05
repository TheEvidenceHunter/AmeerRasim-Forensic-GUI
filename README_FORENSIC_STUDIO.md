# Forensic Studio — Memory Forensics Workbench (استوديو الأدلة الجنائية)

A professional desktop front-end for **Volatility 3** by Ameer Rasim. English / العربية (full RTL), dark / light themes.

## Run
```bash
pip install -e ".[full,gui]"        # Volatility dependencies + PySide6
python forensic_studio.py [memory.raw]   # or: python -m forensic_gui   /   forensic-studio
```
Symbols: Windows images need ISF symbol tables (downloaded automatically unless *Offline mode* is on).

## What it does
| Area | Features |
|---|---|
| **Case & evidence** | Case ID / examiner / notes, drag-and-drop image, streaming **MD5/SHA-1/SHA-256** with progress and cancel, OS auto-detection |
| **Analysis** | ~100 curated plugins (Windows / Linux / macOS) by category, bilingual descriptions, search, one-click **presets** (quick look, full triage, malware hunt, network), PID filter, extra args, sequential **job queue** with live progress and cancel |
| **Results** | One tab per plugin, sortable columns, tree view for `pstree`, filter language (`pid:4 name:svchost`, `ip:`, `port:`, `cmd:`), global IOC search across all tables, copy cell/row, CSV / JSON export |
| **Findings** | Automated, MITRE ATT&CK-mapped leads: injected code (malfind), look-alike process names, duplicate `lsass`, wrong parents, Office→shell, encoded PowerShell, LOLBins, shadow-copy deletion, credential tools, suspicious connections, hidden processes, hooks, process hollowing/ghosting, ETW patching… each with a *how to verify* note. Flagged rows are highlighted in the result tables |
| **Reporting** | Self-contained HTML report (RTL aware, print to PDF) with case, hashes, findings, tables and audit trail |
| **Integrity** | Evidence is only read. Append-only **audit trail** (`audit.log`) of every action; results auto-saved in the case folder and reloadable |
| **Safety** | Credential-extraction plugins (`hashdump`, `lsadump`, `cachedump`) require explicit confirmation |

Findings are **heuristic leads, not verdicts** — every item must be verified by the examiner.

## Layout
```
forensic_gui/core    engine (no Qt): catalog, runner, results parser, findings, case, report, hashing
forensic_gui/ui      PySide6 interface
forensic_gui/tests   unit tests + offscreen end-to-end GUI test (fake vol.py)
legacy/              the original Tkinter prototypes
```
Tests: `pip install pytest && pytest forensic_gui/tests`

## Notes
Volatility 3 is licensed under the Volatility Software License (VSL); see `LICENSE.txt`.
