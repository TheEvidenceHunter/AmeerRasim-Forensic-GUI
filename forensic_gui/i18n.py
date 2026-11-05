"""Bilingual (English / Arabic) UI strings. Plain Python - no Qt dependency."""

from __future__ import annotations

from typing import Dict

LANGS = {"en": "English", "ar": "العربية"}
_lang = "en"


def set_language(code: str) -> None:
    global _lang
    _lang = code if code in LANGS else "en"


def language() -> str:
    return _lang


def is_rtl() -> bool:
    return _lang == "ar"


def tr(key: str, **kw) -> str:
    text = STRINGS.get(_lang, {}).get(key) or STRINGS["en"].get(key) or key
    if kw:
        try:
            return text.format(**kw)
        except (KeyError, IndexError):
            return text
    return text


EN: Dict[str, str] = {
    "app.title": "Forensic Studio",
    # navigation
    "nav.dashboard": "Dashboard", "nav.case": "Case & Evidence", "nav.plugins": "Analysis",
    "nav.results": "Results", "nav.findings": "Findings", "nav.log": "Activity Log", "nav.settings": "Settings",
    # menus / actions
    "menu.file": "&File", "menu.view": "&View", "menu.tools": "&Tools", "menu.help": "&Help",
    "act.new_case": "New case", "act.open_case": "Open case…", "act.save_case": "Save case",
    "act.open_image": "Open memory image…", "act.export_report": "Export HTML report…",
    "act.export_csv": "Export current table as CSV…", "act.export_json": "Export current table as JSON…",
    "act.quit": "Quit", "act.theme_dark": "Dark theme", "act.theme_light": "Light theme",
    "act.compute_hash": "Compute evidence hashes", "act.detect_os": "Detect operating system",
    "act.run_selected": "Run selected plugins", "act.about": "About", "act.docs": "Volatility 3 documentation",
    "act.stop": "Stop all",
    # buttons / common
    "btn.browse": "Browse…", "btn.cancel": "Cancel", "btn.close": "Close", "btn.clear": "Clear",
    "btn.save": "Save", "btn.copy": "Copy", "btn.run": "Run", "btn.ok": "OK", "btn.apply": "Apply",
    "common.none": "—", "common.unknown": "Unknown", "common.yes": "Yes", "common.no": "No",
    # case
    "case.title": "Case details", "case.id": "Case ID", "case.name": "Case name", "case.examiner": "Examiner",
    "case.notes": "Notes", "case.created": "Created", "case.folder": "Case folder",
    # evidence
    "evidence.title": "Memory evidence", "evidence.file": "Memory image", "evidence.size": "Size",
    "evidence.modified": "Modified", "evidence.os": "Operating system", "evidence.none": "No image selected",
    "evidence.drop": "Drop a memory image here or click Browse",
    "evidence.hash": "Integrity hashes", "evidence.hash_btn": "Compute hashes",
    "evidence.hash_running": "Hashing… {pct}%", "evidence.hash_done": "Hashes computed",
    "evidence.hash_cancelled": "Hashing cancelled", "evidence.detect": "Detect OS",
    "evidence.detecting": "Detecting operating system…", "evidence.detected": "Detected: {os}",
    "evidence.detect_failed": "Could not detect the OS automatically - choose it manually.",
    "evidence.not_found": "File not found: {path}",
    "evidence.readonly": "The image is only ever read - it is never modified.",
    "os.auto": "Auto", "os.windows": "Windows", "os.linux": "Linux", "os.mac": "macOS",
    # plugins page
    "plugins.title": "Analysis plugins", "plugins.search": "Search plugins…", "plugins.presets": "Investigation presets",
    "plugins.queue": "Job queue", "plugins.options": "Options", "plugins.pid": "Filter by PID(s)",
    "plugins.pid_hint": "e.g. 4 or 664,1520", "plugins.extra": "Extra arguments", "plugins.extra_hint": "e.g. --dump",
    "plugins.run_sel": "Run selected", "plugins.select_hint": "Tick the plugins to run, or pick a preset.",
    "plugins.slow": "Slow: scans the whole image", "plugins.sensitive": "Extracts credential material",
    "plugins.need_image": "Select a memory image first (Case & Evidence).",
    "plugins.nothing_selected": "No plugins selected.",
    "plugins.sensitive_confirm": "Selected plugins extract credential material (password hashes / secrets). "
                                 "Only continue if you are authorised to analyse this evidence.",
    "plugins.missing": "Not available in this Volatility version: {names}",
    "plugins.all": "All", "plugins.clear_sel": "Clear selection", "plugins.count": "{n} plugins",
    "queue.plugin": "Plugin", "queue.status": "Status", "queue.progress": "Progress", "queue.time": "Time",
    "queue.rows": "Rows", "queue.cancel_current": "Cancel current", "queue.cancel_all": "Cancel all",
    "queue.clear_done": "Clear finished",
    "status.queued": "Queued", "status.running": "Running", "status.parsing": "Parsing", "status.ok": "Done",
    "status.failed": "Failed", "status.cancelled": "Cancelled", "status.idle": "Ready",
    "status.busy": "Running {plugin}… {pct}%", "status.queue_left": "{n} queued",
    "preset.win_quick": "Windows - quick look", "preset.win_triage": "Windows - full triage",
    "preset.win_malware": "Windows - malware hunt", "preset.win_network": "Windows - network",
    "preset.linux_triage": "Linux - triage", "preset.mac_triage": "macOS - triage",
    "cat.info": "System information", "cat.processes": "Processes", "cat.malware": "Malware & injection",
    "cat.network": "Network", "cat.kernel": "Kernel & drivers", "cat.files": "Files & memory",
    "cat.registry": "Registry & execution evidence", "cat.persistence": "Persistence",
    "cat.credentials": "Credentials (sensitive)", "cat.general": "General", "cat.other": "Other plugins",
    # results
    "results.title": "Results", "results.filter": "Filter rows…", "results.rows": "rows",
    "results.shown": "{shown} of {total} rows", "results.columns": "Columns",
    "results.search_all": "Search all results", "results.search_prompt": "Search every table for an IOC "
    "(IP, PID, file name, hash, string):", "results.nomatch": "No matches.", "results.hits": "{n} matches",
    "results.copy_cell": "Copy cell", "results.copy_row": "Copy row", "results.filter_value": "Filter by this value",
    "results.empty": "No results yet. Run a plugin from the Analysis page.",
    "results.col_plugin": "Plugin", "results.col_row": "Row", "results.col_match": "Match",
    "results.flagged": "Flagged by findings",
    # findings
    "findings.title": "Findings", "findings.sev": "Severity", "findings.rule": "Detection", "findings.pid": "PID",
    "findings.process": "Process", "findings.evidence": "Evidence", "findings.plugin": "Source",
    "findings.mitre": "MITRE ATT&CK", "findings.none": "No findings yet. Run triage plugins to generate leads.",
    "findings.detail_hint": "Select a finding to see what it means and how to verify it.",
    "findings.goto": "Open in results", "findings.verify": "How to verify",
    "findings.disclaimer": "Findings are automated leads, not verdicts. Verify each one before drawing conclusions.",
    "sev.critical": "Critical", "sev.high": "High", "sev.medium": "Medium", "sev.low": "Low", "sev.info": "Info",
    # dashboard
    "dash.title": "Investigation overview", "dash.evidence": "Evidence", "dash.processes": "Processes",
    "dash.connections": "Network connections", "dash.plugins_done": "Plugins completed", "dash.findings": "Findings",
    "dash.quick": "Quick actions", "dash.no_evidence": "No evidence loaded", "dash.hashed": "Hashes verified & recorded",
    "dash.not_hashed": "Not hashed yet", "dash.start": "Start triage", "dash.top_findings": "Top findings",
    # log
    "log.title": "Activity log", "log.audit": "Audit trail (chain of custody)", "log.console": "Console",
    # settings
    "settings.title": "Settings", "settings.vol": "Volatility entry point (vol.py)", "settings.python": "Python interpreter",
    "settings.symbols": "Symbol directories (; separated)", "settings.cache": "Cache directory",
    "settings.offline": "Offline mode (never download symbols)", "settings.parallel": "Parallelism",
    "settings.output": "Output directory for dumped files", "settings.verbosity": "Verbosity",
    "settings.test": "Test Volatility", "settings.test_ok": "Volatility is working.",
    "settings.test_fail": "Volatility failed to start:\n{err}", "settings.language": "Language",
    "settings.theme": "Theme", "settings.cases_dir": "Cases directory", "settings.autosave": "Auto-save results to the case",
    "settings.vol_missing": "Volatility (vol.py) was not found. Set its location in Settings.",
    "settings.group_vol": "Volatility engine", "settings.group_ui": "Interface", "settings.group_case": "Cases",
    "settings.none": "None", "settings.threads": "Threads", "settings.processes": "Processes",
    # diagnostics
    "diag.symbols": "Symbol tables are missing or the image profile is unsupported. Disable offline mode so symbols "
                    "can be downloaded, or place the matching ISF files in the symbols directory.",
    "diag.deps": "A Python dependency is missing. Install them with:  pip install -e \".[full]\"",
    "diag.file": "A required file could not be found. Check the image path.",
    "diag.perm": "Permission denied. Check access rights to the image and output directory.",
    "diag.memory": "Not enough memory to process this image with this plugin.",
    "diag.yara": "This plugin needs YARA (pip install yara-python) and rules passed via extra arguments.",
    "diag.args": "Invalid plugin arguments. Check the 'Extra arguments' field.",
    "diag.generic": "The plugin exited with an error. See the Activity Log for the full output.",
    # report
    "report.title": "Memory Forensics Report", "report.case": "Case information", "report.evidence": "Evidence",
    "report.summary": "Executive summary", "report.findings": "Findings", "report.results": "Plugin results",
    "report.nofindings": "No automated findings were generated.",
    "report.truncated": "Showing the first {shown} of {total} rows. Export the full table as CSV/JSON.",
    "report.disclaimer": "Automated heuristics generate leads only. Every finding requires examiner verification.",
    "report.audit": "Audit trail",
    # messages
    "msg.error": "Error", "msg.info": "Information", "msg.confirm": "Please confirm",
    "msg.case_saved": "Case saved to {path}", "msg.case_loaded": "Case loaded: {name}",
    "msg.no_results": "There is nothing to export yet.", "msg.exported": "Exported to {path}",
    "msg.close_job": "Jobs are still running. Stop them and quit?",
    "msg.about": "Forensic Studio {version}\nA professional front-end for the Volatility 3 memory forensics "
                 "framework.\n\nAuthor: {author}\nPowered by Volatility 3 (Volatility Software License).",
    "msg.open_case_folder": "Select a case folder",
    "msg.select_image": "Select memory image", "msg.select_vol": "Locate vol.py",
    "msg.parse_failed": "{plugin}: output could not be parsed ({err})",
    "msg.job_failed": "{plugin} failed (exit code {code}).",
    "msg.job_done": "{plugin}: {rows} rows in {sec}s",
    "msg.started": "Started: {cmd}",
}

# ----------------------------------------------------------------- rules (title, how to verify)
RULES_EN = {
    "malfind_pe": ("PE image in private executable memory",
                   "A Windows executable (MZ header) sits in executable memory that no file backs - the classic sign of "
                   "reflective DLL / process injection. Dump the region and inspect it; check the owning process's "
                   "network and command line. Packers, .NET/JIT hosts and some security tools can be benign."),
    "malfind_rwx": ("Executable private memory",
                    "Memory that is readable, writable and executable and not backed by a file can hold injected "
                    "shellcode. Common false positives: browsers, JIT runtimes (.NET, Java), AV. Review the hexdump and "
                    "disassembly, then compare with other injection plugins."),
    "masq_name": ("Look-alike system process name",
                  "The process name is one character away from a core Windows process (e.g. svch0st.exe). Malware often "
                  "does this to blend in. Verify the full image path - legitimate ones run from System32."),
    "dup_single": ("Duplicate single-instance process",
                   "lsass.exe, services.exe and wininit.exe should run once. A second copy usually means impersonation. "
                   "Compare image paths and parent processes."),
    "bad_parent": ("Unexpected parent process",
                   "This core process has a parent different from the normal Windows process tree "
                   "(e.g. svchost.exe should be started by services.exe). Check the process tree and creation times."),
    "office_child": ("Shell spawned by Office / browser",
                     "A document reader or browser launched a command interpreter - typical of malicious documents or "
                     "drive-by exploitation. Review the command line and what the child did next."),
    "ps_encoded": ("Encoded PowerShell command",
                   "PowerShell was launched with a Base64 command to hide its content. Decode it "
                   "(UTF-16LE Base64) and review. Some management tools also do this legitimately."),
    "ps_download": ("PowerShell download / in-memory execution",
                    "The command line uses download or invoke-expression primitives, used to fetch and run payloads "
                    "without touching disk. Identify the URL and correlate with network results."),
    "ps_stealth": ("PowerShell stealth options",
                   "Hidden window, no-profile or execution-policy bypass flags are common in attacker tooling but "
                   "also in admin scripts. Review the full command."),
    "lolbin_download": ("Living-off-the-land download",
                        "certutil, bitsadmin or curl was used to fetch a file - a common way to bring tools onto a host. "
                        "Identify the source URL and destination file."),
    "lolbin_proxy": ("Signed-binary proxy execution",
                     "mshta, regsvr32, rundll32 or msiexec was used with a remote/script argument to run code through "
                     "a trusted binary. Review the argument and the child activity."),
    "shadow_delete": ("Backup / recovery destruction",
                      "Commands that delete shadow copies or disable recovery are a hallmark of ransomware. Treat as "
                      "urgent and look for encryption activity and ransom notes."),
    "wmic_exec": ("Remote/local process creation via WMI",
                  "WMIC process creation is used for lateral movement and execution. Check the target and the "
                  "account that issued it."),
    "cred_tool": ("Credential theft tooling",
                  "Command line references credential-dumping tools or LSASS dumping techniques. Confirm the process, "
                  "its parent, and look for dumped files."),
    "temp_path": ("Execution from user-writable path",
                  "A binary or script runs from a temp / public / ProgramData location - common for dropped malware, "
                  "though installers also use these paths. Verify the file and its signer."),
    "linux_pipe_sh": ("Download piped into a shell",
                      "curl/wget output is piped straight into a shell - runs remote code without saving it. "
                      "Identify the URL and run time."),
    "linux_revshell": ("Reverse shell pattern",
                       "The command matches known reverse-shell one-liners (nc -e, /dev/tcp, socat exec…). "
                       "Correlate with outbound connections from the same process."),
    "linux_tmp_exec": ("Execution from /tmp or /dev/shm",
                       "Executables in world-writable, often memory-backed directories are typical for droppers."),
    "linux_antiforensic": ("History / log tampering",
                           "Commands that clear shell history or logs indicate an attempt to hide activity."),
    "net_external": ("Scripting/LOLBin process talking to the internet",
                     "An interpreter or living-off-the-land binary holds an established connection to a public IP - "
                     "common for C2 and staging. Look up the address and review the process command line."),
    "net_badport": ("Connection on a suspicious port",
                    "The port is commonly used by backdoors, reverse shells or Tor. Many are also used legitimately - "
                    "check which process owns it."),
    "hidden_proc": ("Process hidden from the process list",
                    "The process exists in memory scans but is unlinked from the active list - a rootkit technique "
                    "(DKOM). Terminated processes are excluded; verify the exit time and thread count."),
    "hollow": ("Process hollowing indicators", "The process image in memory differs from the file on disk. Compare "
               "the module paths and dump the process for analysis."),
    "peb_masq": ("PEB spoofing", "Image path or command line in the PEB disagrees with kernel structures - the process "
                 "is lying about what it is."),
    "proc_spoof": ("Process name/command spoofing", "The visible name or command line does not match the real "
                   "executable, or the executable was deleted from disk after launch."),
    "ghosting": ("Process ghosting", "The process was created from a file that was deleted or marked for deletion, "
                 "so no file on disk matches it."),
    "etw_patch": ("Event Tracing for Windows tampered", "ETW functions were patched in memory to blind logging and EDR "
                  "telemetry. Strongly associated with advanced malware."),
    "susp_thread": ("Thread starts in unusual memory", "Threads begin execution in memory not backed by a module - "
                    "typical of injected code."),
    "syscall_evasion": ("Direct / indirect syscalls", "Code issues system calls itself to bypass user-mode API hooks "
                        "(EDR evasion). Some games and protectors do this legitimately."),
    "skeleton_key": ("Skeleton Key implant indicators", "Signs of the Skeleton Key authentication backdoor on a "
                     "domain controller."),
    "hidden_module": ("Hidden kernel module", "A module is present in memory but missing from the kernel's module "
                      "list - classic Linux rootkit behaviour."),
    "syscall_hook": ("Hooked kernel table entry", "A kernel dispatch table entry points outside the kernel or to an "
                     "unknown location, suggesting a hook installed by a rootkit."),
}

RULES_AR = {
    "malfind_pe": ("ملف PE في ذاكرة تنفيذية خاصة",
                   "ملف تنفيذي (ترويسة MZ) داخل ذاكرة تنفيذية لا يسندها ملف على القرص، وهي علامة كلاسيكية على حقن DLL أو "
                   "عملية. استخرج المنطقة وافحصها وراجع اتصالات العملية وسطر أوامرها. قد تظهر نتائج سليمة مع الحزم و"
                   "بيئات JIT وبعض أدوات الحماية."),
    "malfind_rwx": ("ذاكرة تنفيذية خاصة",
                    "ذاكرة قابلة للقراءة والكتابة والتنفيذ دون ملف يسندها قد تحوي shellcode محقونًا. الإنذارات الخاطئة "
                    "شائعة في المتصفحات وبيئات JIT ومضادات الفيروسات. راجع الـ hexdump والتفكيك وقارن مع إضافات الحقن الأخرى."),
    "masq_name": ("اسم عملية يشبه عملية نظام",
                  "اسم العملية يختلف بحرف واحد عن عملية أساسية في ويندوز (مثل svch0st.exe). تستعمل البرمجيات الخبيثة هذا "
                  "للتخفي. تحقق من المسار الكامل؛ العمليات الأصلية تعمل من System32."),
    "dup_single": ("نسخة مكررة من عملية يُفترض أن تكون وحيدة",
                   "يجب أن تعمل lsass.exe وservices.exe وwininit.exe مرة واحدة فقط. وجود نسخة ثانية يعني غالبًا انتحالًا. "
                   "قارن المسارات والعمليات الأب."),
    "bad_parent": ("عملية أب غير متوقعة",
                   "عملية النظام هذه لها أب يخالف شجرة ويندوز الطبيعية (مثلًا يجب أن تبدأ svchost.exe من services.exe). "
                   "راجع شجرة العمليات وأوقات الإنشاء."),
    "office_child": ("تشغيل سطر أوامر من Office أو المتصفح",
                     "برنامج مستندات أو متصفح شغّل مفسّر أوامر، وهذا نمط شائع في المستندات الخبيثة والاستغلال عبر المتصفح. "
                     "راجع سطر الأوامر وما فعلته العملية التالية."),
    "ps_encoded": ("أمر PowerShell مشفّر",
                   "شُغّل PowerShell بأمر Base64 لإخفاء محتواه. فُك التشفير (Base64 بترميز UTF-16LE) وراجعه. بعض أدوات "
                   "الإدارة تفعل ذلك بشكل مشروع."),
    "ps_download": ("تنزيل أو تنفيذ في الذاكرة عبر PowerShell",
                    "سطر الأوامر يستخدم دوال التنزيل أو invoke-expression لجلب وتشغيل حمولة دون لمس القرص. حدّد الرابط "
                    "وقارنه بنتائج الشبكة."),
    "ps_stealth": ("خيارات تخفٍّ في PowerShell",
                   "النافذة المخفية أو تجاوز سياسة التنفيذ شائعة في أدوات المهاجمين وأيضًا في سكربتات الإدارة. راجع الأمر كاملًا."),
    "lolbin_download": ("تنزيل باستخدام أدوات النظام",
                        "استُخدم certutil أو bitsadmin أو curl لجلب ملف، وهي طريقة شائعة لإدخال الأدوات إلى الجهاز. "
                        "حدّد الرابط والملف الوجهة."),
    "lolbin_proxy": ("تنفيذ عبر ملف موقّع موثوق",
                     "استُخدم mshta أو regsvr32 أو rundll32 أو msiexec مع معامل بعيد أو سكربت لتشغيل كود عبر ملف موثوق. "
                     "راجع المعامل والنشاط اللاحق."),
    "shadow_delete": ("تدمير النسخ الاحتياطية والاسترداد",
                      "حذف النسخ الاحتياطية أو تعطيل الاسترداد من علامات برامج الفدية. تعامل معها كحالة عاجلة وابحث عن "
                      "تشفير الملفات ورسائل الفدية."),
    "wmic_exec": ("إنشاء عملية عبر WMI",
                  "إنشاء العمليات عبر WMIC يُستخدم في التنقل الجانبي والتنفيذ. تحقق من الهدف والحساب الذي أصدر الأمر."),
    "cred_tool": ("أدوات سرقة بيانات الاعتماد",
                  "سطر الأوامر يشير إلى أدوات تفريغ بيانات الاعتماد أو تفريغ LSASS. أكّد العملية وأبيها وابحث عن الملفات المفرّغة."),
    "temp_path": ("تنفيذ من مسار قابل للكتابة للمستخدم",
                  "ملف تنفيذي أو سكربت يعمل من مجلد مؤقت أو عام أو ProgramData، وهذا شائع للبرمجيات المُسقطة رغم أن المثبّتات "
                  "تستخدمه أيضًا. تحقق من الملف وموقّعه."),
    "linux_pipe_sh": ("تنزيل يُمرَّر مباشرة إلى shell",
                      "مخرجات curl/wget تُمرَّر إلى shell فتُنفَّذ شيفرة بعيدة دون حفظها. حدّد الرابط ووقت التنفيذ."),
    "linux_revshell": ("نمط reverse shell",
                       "الأمر يطابق أسطر reverse shell المعروفة (nc -e، /dev/tcp، socat…). اربطه بالاتصالات الصادرة من العملية نفسها."),
    "linux_tmp_exec": ("تنفيذ من /tmp أو /dev/shm",
                       "ملفات تنفيذية في مجلدات قابلة للكتابة من الجميع وغالبًا في الذاكرة، وهذا شائع في أدوات الإسقاط."),
    "linux_antiforensic": ("العبث بالسجل أو التاريخ",
                           "أوامر مسح سجل shell أو السجلات تدل على محاولة إخفاء النشاط."),
    "net_external": ("عملية سكربت/نظام تتصل بالإنترنت",
                     "مفسّر أوامر أو أداة نظام لديها اتصال قائم بعنوان عام، وهذا شائع في قنوات التحكم (C2). ابحث عن العنوان "
                     "وراجع سطر أوامر العملية."),
    "net_badport": ("اتصال على منفذ مشبوه",
                    "المنفذ يُستخدم عادة في الأبواب الخلفية أو reverse shell أو Tor، وبعضها مشروع أيضًا. تحقق من العملية المالكة."),
    "hidden_proc": ("عملية مخفية من قائمة العمليات",
                    "العملية موجودة في مسح الذاكرة لكنها غير مرتبطة بالقائمة النشطة، وهي تقنية rootkit (DKOM). العمليات المنتهية "
                    "مستثناة؛ تحقق من وقت الانتهاء وعدد الخيوط."),
    "hollow": ("مؤشرات تفريغ العملية", "صورة العملية في الذاكرة تختلف عن الملف على القرص. قارن مسارات الوحدات واستخرج العملية للتحليل."),
    "peb_masq": ("تزوير بيانات PEB", "المسار أو سطر الأوامر في PEB يخالف هياكل النواة، أي أن العملية تكذب بشأن هويتها."),
    "proc_spoof": ("انتحال اسم أو أمر العملية", "الاسم أو سطر الأوامر الظاهر لا يطابق الملف الفعلي، أو حُذف الملف بعد التشغيل."),
    "ghosting": ("Process ghosting", "أُنشئت العملية من ملف حُذف أو وُسم للحذف، فلا يوجد ملف على القرص يطابقها."),
    "etw_patch": ("التلاعب بـ Event Tracing for Windows", "عُدّلت دوال ETW في الذاكرة لإعماء التسجيل وأدوات EDR. مرتبط بقوة بالبرمجيات "
                  "المتقدمة."),
    "susp_thread": ("خيط يبدأ من ذاكرة غير معتادة", "خيوط تبدأ التنفيذ من ذاكرة لا تتبع وحدة معروفة، وهذا نمط الكود المحقون."),
    "syscall_evasion": ("استدعاءات نظام مباشرة/غير مباشرة", "الكود ينفذ استدعاءات النظام بنفسه لتجاوز خطافات الـ API (التهرب من EDR). "
                        "بعض الألعاب والحمايات تفعل ذلك بشكل مشروع."),
    "skeleton_key": ("مؤشرات زرع Skeleton Key", "علامات على باب خلفي للمصادقة في متحكم النطاق."),
    "hidden_module": ("وحدة نواة مخفية", "وحدة موجودة في الذاكرة لكنها غائبة عن قائمة وحدات النواة، وهو سلوك rootkit كلاسيكي في لينكس."),
    "syscall_hook": ("مدخل مخطوف في جدول النواة", "مدخل في جدول النواة يشير إلى خارج النواة أو لموقع مجهول، مما يوحي بخطّاف زرعه rootkit."),
}

for _k, (_t, _d) in RULES_EN.items():
    EN[f"rule.{_k}.title"] = _t
    EN[f"rule.{_k}.desc"] = _d

AR: Dict[str, str] = {
    "app.title": "استوديو الأدلة الجنائية",
    "nav.dashboard": "لوحة التحكم", "nav.case": "القضية والدليل", "nav.plugins": "التحليل",
    "nav.results": "النتائج", "nav.findings": "الاكتشافات", "nav.log": "سجل النشاط", "nav.settings": "الإعدادات",
    "menu.file": "&ملف", "menu.view": "&عرض", "menu.tools": "&أدوات", "menu.help": "&مساعدة",
    "act.new_case": "قضية جديدة", "act.open_case": "فتح قضية…", "act.save_case": "حفظ القضية",
    "act.open_image": "فتح صورة ذاكرة…", "act.export_report": "تصدير تقرير HTML…",
    "act.export_csv": "تصدير الجدول الحالي CSV…", "act.export_json": "تصدير الجدول الحالي JSON…",
    "act.quit": "خروج", "act.theme_dark": "السمة الداكنة", "act.theme_light": "السمة الفاتحة",
    "act.compute_hash": "حساب بصمات الدليل", "act.detect_os": "اكتشاف نظام التشغيل",
    "act.run_selected": "تشغيل الإضافات المحددة", "act.about": "حول", "act.docs": "توثيق Volatility 3",
    "act.stop": "إيقاف الكل",
    "btn.browse": "استعراض…", "btn.cancel": "إلغاء", "btn.close": "إغلاق", "btn.clear": "مسح",
    "btn.save": "حفظ", "btn.copy": "نسخ", "btn.run": "تشغيل", "btn.ok": "موافق", "btn.apply": "تطبيق",
    "common.none": "—", "common.unknown": "غير معروف", "common.yes": "نعم", "common.no": "لا",
    "case.title": "بيانات القضية", "case.id": "رقم القضية", "case.name": "اسم القضية", "case.examiner": "الفاحص",
    "case.notes": "ملاحظات", "case.created": "تاريخ الإنشاء", "case.folder": "مجلد القضية",
    "evidence.title": "دليل الذاكرة", "evidence.file": "صورة الذاكرة", "evidence.size": "الحجم",
    "evidence.modified": "آخر تعديل", "evidence.os": "نظام التشغيل", "evidence.none": "لم يُحدَّد ملف",
    "evidence.drop": "اسحب صورة الذاكرة إلى هنا أو اضغط استعراض",
    "evidence.hash": "بصمات سلامة الدليل", "evidence.hash_btn": "حساب البصمات",
    "evidence.hash_running": "جارٍ الحساب… {pct}%", "evidence.hash_done": "تم حساب البصمات",
    "evidence.hash_cancelled": "أُلغي حساب البصمات", "evidence.detect": "اكتشاف النظام",
    "evidence.detecting": "جارٍ اكتشاف نظام التشغيل…", "evidence.detected": "تم الاكتشاف: {os}",
    "evidence.detect_failed": "تعذّر اكتشاف النظام تلقائيًا، اختره يدويًا.",
    "evidence.not_found": "الملف غير موجود: {path}",
    "evidence.readonly": "الصورة تُقرأ فقط ولا تُعدَّل أبدًا.",
    "os.auto": "تلقائي", "os.windows": "ويندوز", "os.linux": "لينكس", "os.mac": "ماك",
    "plugins.title": "إضافات التحليل", "plugins.search": "ابحث عن إضافة…", "plugins.presets": "سيناريوهات جاهزة للتحقيق",
    "plugins.queue": "قائمة المهام", "plugins.options": "الخيارات", "plugins.pid": "تصفية حسب PID",
    "plugins.pid_hint": "مثال: 4 أو 664,1520", "plugins.extra": "معاملات إضافية", "plugins.extra_hint": "مثال: --dump",
    "plugins.run_sel": "تشغيل المحدد", "plugins.select_hint": "حدّد الإضافات المطلوبة أو اختر سيناريو جاهزًا.",
    "plugins.slow": "بطيئة: تمسح الصورة كاملة", "plugins.sensitive": "تستخرج بيانات اعتماد",
    "plugins.need_image": "اختر صورة ذاكرة أولًا (القضية والدليل).",
    "plugins.nothing_selected": "لم تُحدَّد أي إضافة.",
    "plugins.sensitive_confirm": "بعض الإضافات المحددة تستخرج بيانات اعتماد (بصمات كلمات مرور/أسرار). "
                                 "تابع فقط إذا كنت مخوّلًا بتحليل هذا الدليل.",
    "plugins.missing": "غير متوفرة في إصدار Volatility هذا: {names}",
    "plugins.all": "الكل", "plugins.clear_sel": "إلغاء التحديد", "plugins.count": "{n} إضافة",
    "queue.plugin": "الإضافة", "queue.status": "الحالة", "queue.progress": "التقدم", "queue.time": "الزمن",
    "queue.rows": "الصفوف", "queue.cancel_current": "إلغاء الحالية", "queue.cancel_all": "إلغاء الكل",
    "queue.clear_done": "مسح المنتهية",
    "status.queued": "في الانتظار", "status.running": "قيد التشغيل", "status.parsing": "جارٍ التحليل", "status.ok": "اكتملت",
    "status.failed": "فشلت", "status.cancelled": "أُلغيت", "status.idle": "جاهز",
    "status.busy": "تشغيل {plugin}… {pct}%", "status.queue_left": "{n} في الانتظار",
    "preset.win_quick": "ويندوز - نظرة سريعة", "preset.win_triage": "ويندوز - فرز شامل",
    "preset.win_malware": "ويندوز - صيد البرمجيات الخبيثة", "preset.win_network": "ويندوز - الشبكة",
    "preset.linux_triage": "لينكس - فرز", "preset.mac_triage": "ماك - فرز",
    "cat.info": "معلومات النظام", "cat.processes": "العمليات", "cat.malware": "البرمجيات الخبيثة والحقن",
    "cat.network": "الشبكة", "cat.kernel": "النواة وبرامج التشغيل", "cat.files": "الملفات والذاكرة",
    "cat.registry": "السجل وأدلة التنفيذ", "cat.persistence": "الاستمرارية",
    "cat.credentials": "بيانات الاعتماد (حساسة)", "cat.general": "عام", "cat.other": "إضافات أخرى",
    "results.title": "النتائج", "results.filter": "تصفية الصفوف…", "results.rows": "صف",
    "results.shown": "{shown} من {total} صف", "results.columns": "الأعمدة",
    "results.search_all": "بحث في كل النتائج", "results.search_prompt": "ابحث في كل الجداول عن مؤشر (عنوان IP أو PID أو "
    "اسم ملف أو بصمة أو نص):", "results.nomatch": "لا توجد نتائج مطابقة.", "results.hits": "{n} نتيجة",
    "results.copy_cell": "نسخ الخلية", "results.copy_row": "نسخ الصف", "results.filter_value": "تصفية بهذه القيمة",
    "results.empty": "لا توجد نتائج بعد. شغّل إضافة من صفحة التحليل.",
    "results.col_plugin": "الإضافة", "results.col_row": "الصف", "results.col_match": "المطابقة",
    "results.flagged": "مُعلَّم من الاكتشافات",
    "findings.title": "الاكتشافات", "findings.sev": "الخطورة", "findings.rule": "نوع الاكتشاف", "findings.pid": "PID",
    "findings.process": "العملية", "findings.evidence": "الدليل", "findings.plugin": "المصدر",
    "findings.mitre": "MITRE ATT&CK", "findings.none": "لا توجد اكتشافات بعد. شغّل إضافات الفرز لاستخراج المؤشرات.",
    "findings.detail_hint": "اختر اكتشافًا لمعرفة معناه وكيفية التحقق منه.",
    "findings.goto": "فتح في النتائج", "findings.verify": "كيف تتحقق",
    "findings.disclaimer": "الاكتشافات مؤشرات آلية وليست أحكامًا. تحقق من كل واحد قبل استخلاص النتائج.",
    "sev.critical": "حرج", "sev.high": "عالٍ", "sev.medium": "متوسط", "sev.low": "منخفض", "sev.info": "معلومة",
    "dash.title": "نظرة عامة على التحقيق", "dash.evidence": "الدليل", "dash.processes": "العمليات",
    "dash.connections": "اتصالات الشبكة", "dash.plugins_done": "الإضافات المكتملة", "dash.findings": "الاكتشافات",
    "dash.quick": "إجراءات سريعة", "dash.no_evidence": "لا يوجد دليل محمَّل", "dash.hashed": "البصمات محسوبة ومسجّلة",
    "dash.not_hashed": "لم تُحسب البصمات بعد", "dash.start": "بدء الفرز", "dash.top_findings": "أهم الاكتشافات",
    "log.title": "سجل النشاط", "log.audit": "سجل التدقيق (سلسلة الحيازة)", "log.console": "وحدة التحكم",
    "settings.title": "الإعدادات", "settings.vol": "ملف تشغيل Volatility (vol.py)", "settings.python": "مفسّر Python",
    "settings.symbols": "مجلدات الرموز (تفصل بـ ;)", "settings.cache": "مجلد التخزين المؤقت",
    "settings.offline": "وضع عدم الاتصال (لا تنزّل الرموز)", "settings.parallel": "المعالجة المتوازية",
    "settings.output": "مجلد الملفات المستخرجة", "settings.verbosity": "مستوى التفصيل",
    "settings.test": "اختبار Volatility", "settings.test_ok": "Volatility يعمل بشكل سليم.",
    "settings.test_fail": "تعذّر تشغيل Volatility:\n{err}", "settings.language": "اللغة",
    "settings.theme": "السمة", "settings.cases_dir": "مجلد القضايا", "settings.autosave": "حفظ النتائج تلقائيًا في القضية",
    "settings.vol_missing": "لم يُعثر على Volatility (vol.py). حدّد موقعه من الإعدادات.",
    "settings.group_vol": "محرك Volatility", "settings.group_ui": "الواجهة", "settings.group_case": "القضايا",
    "settings.none": "بدون", "settings.threads": "خيوط", "settings.processes": "عمليات",
    "diag.symbols": "جداول الرموز مفقودة أو أن نوع الصورة غير مدعوم. عطّل وضع عدم الاتصال ليُسمح بتنزيل الرموز، أو ضع "
                    "ملفات ISF المناسبة في مجلد الرموز.",
    "diag.deps": "هناك مكتبة Python مفقودة. ثبّتها بالأمر:  pip install -e \".[full]\"",
    "diag.file": "تعذّر العثور على ملف مطلوب. تحقق من مسار الصورة.",
    "diag.perm": "تم رفض الوصول. تحقق من صلاحيات الصورة ومجلد المخرجات.",
    "diag.memory": "لا توجد ذاكرة كافية لمعالجة هذه الصورة بهذه الإضافة.",
    "diag.yara": "تحتاج هذه الإضافة إلى YARA (pip install yara-python) وقواعد تُمرَّر في المعاملات الإضافية.",
    "diag.args": "معاملات الإضافة غير صحيحة. راجع حقل «معاملات إضافية».",
    "diag.generic": "انتهت الإضافة بخطأ. راجع سجل النشاط للاطلاع على المخرجات الكاملة.",
    "report.title": "تقرير تحليل الذاكرة", "report.case": "بيانات القضية", "report.evidence": "الدليل",
    "report.summary": "الملخص التنفيذي", "report.findings": "الاكتشافات", "report.results": "نتائج الإضافات",
    "report.nofindings": "لم تُنتج الفحوص الآلية أي اكتشافات.",
    "report.truncated": "عُرض أول {shown} من {total} صف. صدّر الجدول كاملًا بصيغة CSV/JSON.",
    "report.disclaimer": "الفحوص الآلية تنتج مؤشرات فقط، وكل اكتشاف يحتاج إلى تحقق من الفاحص.",
    "report.audit": "سجل التدقيق",
    "msg.error": "خطأ", "msg.info": "معلومة", "msg.confirm": "يرجى التأكيد",
    "msg.case_saved": "حُفظت القضية في {path}", "msg.case_loaded": "تم فتح القضية: {name}",
    "msg.no_results": "لا يوجد ما يمكن تصديره بعد.", "msg.exported": "تم التصدير إلى {path}",
    "msg.close_job": "ما زالت هناك مهام قيد التشغيل. هل تريد إيقافها والخروج؟",
    "msg.about": "استوديو الأدلة الجنائية {version}\nواجهة احترافية لإطار تحليل الذاكرة Volatility 3.\n\n"
                 "المطوّر: {author}\nيعمل بمحرك Volatility 3 (رخصة Volatility Software License).",
    "msg.open_case_folder": "اختر مجلد القضية",
    "msg.select_image": "اختر صورة الذاكرة", "msg.select_vol": "حدّد ملف vol.py",
    "msg.parse_failed": "{plugin}: تعذّر تحليل المخرجات ({err})",
    "msg.job_failed": "فشلت {plugin} (رمز الخروج {code}).",
    "msg.job_done": "{plugin}: {rows} صف خلال {sec} ث",
    "msg.started": "بدأ: {cmd}",
}
for _k, (_t, _d) in RULES_AR.items():
    AR[f"rule.{_k}.title"] = _t
    AR[f"rule.{_k}.desc"] = _d

STRINGS: Dict[str, Dict[str, str]] = {"en": EN, "ar": AR}
