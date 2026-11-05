"""Curated Volatility 3 plugin catalog with bilingual descriptions and triage presets."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional

OS_WINDOWS = "windows"
OS_LINUX = "linux"
OS_MAC = "mac"
OS_ANY = "any"
OS_CHOICES = ["auto", OS_WINDOWS, OS_LINUX, OS_MAC]

CATEGORIES = [
    "info",
    "processes",
    "malware",
    "network",
    "kernel",
    "files",
    "registry",
    "persistence",
    "credentials",
    "general",
    "other",
]


@dataclass(frozen=True)
class PluginInfo:
    name: str
    os: str
    category: str
    title_en: str = ""
    title_ar: str = ""
    desc_en: str = ""
    desc_ar: str = ""
    pid: bool = False  # supports --pid
    slow: bool = False  # scans the whole image; can take minutes
    sensitive: bool = False  # extracts credential material

    def title(self, lang: str) -> str:
        return (self.title_ar if lang == "ar" and self.title_ar else self.title_en) or self.name

    def desc(self, lang: str) -> str:
        return (self.desc_ar if lang == "ar" and self.desc_ar else self.desc_en) or ""


def _p(name, os_, cat, en, ar, den, dar, pid=False, slow=False, sensitive=False):
    return PluginInfo(name, os_, cat, en, ar, den, dar, pid, slow, sensitive)


W, L, M, A = OS_WINDOWS, OS_LINUX, OS_MAC, OS_ANY

CATALOG: List[PluginInfo] = [
    # ------------------------------------------------------------ Windows
    _p("windows.info", W, "info", "System info", "معلومات النظام",
       "Kernel build, architecture and system time of the image.",
       "نسخة النواة والمعمارية ووقت النظام للصورة."),
    _p("windows.pslist", W, "processes", "Process list", "قائمة العمليات",
       "Active processes read from the kernel's process list.",
       "العمليات النشطة من قائمة النواة.", pid=True),
    _p("windows.psscan", W, "processes", "Process scan", "مسح العمليات",
       "Pool-scans memory; finds hidden and terminated processes.",
       "يمسح الذاكرة ويجد العمليات المخفية والمنتهية.", pid=True, slow=True),
    _p("windows.pstree", W, "processes", "Process tree", "شجرة العمليات",
       "Parent/child hierarchy with image path and command line.",
       "التسلسل الأبوي بين العمليات مع المسار وسطر الأوامر.", pid=True),
    _p("windows.cmdline", W, "processes", "Command lines", "أسطر الأوامر",
       "Arguments every process was launched with.",
       "المعاملات التي شُغّلت بها كل عملية.", pid=True),
    _p("windows.dlllist", W, "processes", "Loaded DLLs", "مكتبات DLL المحمّلة",
       "DLLs loaded into each process.", "مكتبات DLL المحمّلة داخل كل عملية.", pid=True),
    _p("windows.handles", W, "processes", "Handles", "المقابض (Handles)",
       "Open files, registry keys and mutexes per process.",
       "الملفات والمفاتيح والـ mutex المفتوحة لكل عملية.", pid=True, slow=True),
    _p("windows.envars", W, "processes", "Environment variables", "متغيرات البيئة",
       "Environment variables of each process.", "متغيرات البيئة لكل عملية.", pid=True),
    _p("windows.getsids", W, "processes", "Process SIDs", "معرّفات أمان العمليات",
       "Security identifiers (owner/groups) of each process.",
       "معرّفات الأمان (المالك والمجموعات) لكل عملية.", pid=True),
    _p("windows.privileges", W, "processes", "Process privileges", "صلاحيات العمليات",
       "Token privileges held by each process.", "صلاحيات التوكن لكل عملية.", pid=True),
    _p("windows.sessions", W, "processes", "Logon sessions", "جلسات الدخول",
       "Sessions and the processes inside them.", "الجلسات والعمليات داخلها.", pid=True),
    _p("windows.cmdscan", W, "processes", "Console history (cmdscan)", "سجل الأوامر (cmdscan)",
       "Commands typed into cmd.exe consoles.", "الأوامر المكتوبة في نوافذ cmd.exe."),
    _p("windows.consoles", W, "processes", "Console buffers", "مخازن الكونسول",
       "Console input and output buffers.", "مخازن إدخال وإخراج الكونسول."),
    _p("windows.thrdscan", W, "processes", "Thread scan", "مسح الخيوط",
       "Pool-scans for threads, including hidden ones.", "يبحث عن الخيوط بما فيها المخفية.", slow=True),
    # malware
    _p("windows.malware.malfind", W, "malware", "Injected code (malfind)", "الكود المحقون (malfind)",
       "Executable private memory regions that may hold injected code.",
       "مناطق ذاكرة تنفيذية خاصة قد تحوي كودًا محقونًا.", pid=True),
    _p("windows.malware.psxview", W, "malware", "Hidden process cross-view", "كشف العمليات المخفية",
       "Cross-checks several process sources to expose rootkit-hidden processes.",
       "يقارن عدة مصادر للعمليات لكشف ما أخفاه الـ rootkit.", slow=True),
    _p("windows.malware.hollowprocesses", W, "malware", "Hollowed processes", "العمليات المفرّغة",
       "Detects process hollowing (image replaced in memory).",
       "يكشف تفريغ العمليات (استبدال الصورة في الذاكرة).", pid=True),
    _p("windows.malware.ldrmodules", W, "malware", "Unlinked modules", "وحدات غير مرتبطة",
       "DLLs missing from the loader's lists (typical for injected DLLs).",
       "DLL غائبة عن قوائم المحمّل وهي علامة شائعة للحقن.", pid=True),
    _p("windows.malware.pebmasquerade", W, "malware", "PEB masquerading", "انتحال بيانات PEB",
       "Compares PEB image path/command line to kernel structures.",
       "يقارن مسار الصورة وسطر الأوامر في PEB بهياكل النواة.", pid=True),
    _p("windows.malware.processghosting", W, "malware", "Process ghosting", "Process ghosting",
       "Processes whose backing file was deleted/pending delete.",
       "عمليات حُذف ملفها الأصلي أو ينتظر الحذف."),
    _p("windows.malware.direct_system_calls", W, "malware", "Direct syscalls", "استدعاءات النظام المباشرة",
       "Code issuing raw syscalls to evade API hooks.", "كود ينفذ syscall مباشرة لتجاوز الـ hooks."),
    _p("windows.malware.indirect_system_calls", W, "malware", "Indirect syscalls", "استدعاءات النظام غير المباشرة",
       "Syscalls routed through ntdll gadgets to evade detection.", "syscalls عبر ntdll للتخفي."),
    _p("windows.etwpatch", W, "malware", "ETW patching", "تعديل ETW",
       "Detects tampering with Event Tracing for Windows.", "يكشف التلاعب بـ Event Tracing for Windows.", pid=True),
    _p("windows.suspicious_threads", W, "malware", "Suspicious threads", "خيوط مشبوهة",
       "Threads starting in unbacked or unusual memory.", "خيوط تبدأ من ذاكرة غير مدعومة بملف أو غير معتادة."),
    _p("windows.skeleton_key_check", W, "malware", "Skeleton Key check", "فحص Skeleton Key",
       "Looks for the Skeleton Key domain-controller implant.", "يبحث عن زرع Skeleton Key في متحكم النطاق."),
    # network
    _p("windows.netscan", W, "network", "Network scan", "مسح الشبكة",
       "Pool-scans for TCP/UDP sockets and connections.", "يمسح الذاكرة بحثًا عن اتصالات TCP/UDP.", slow=True),
    _p("windows.netstat", W, "network", "Network statistics", "إحصاءات الشبكة",
       "Active connections from kernel structures.", "الاتصالات النشطة من هياكل النواة."),
    # kernel
    _p("windows.modules", W, "kernel", "Kernel modules", "وحدات النواة",
       "Loaded kernel drivers.", "برامج التشغيل المحمّلة في النواة."),
    _p("windows.modscan", W, "kernel", "Module scan", "مسح الوحدات",
       "Pool-scans for kernel modules, including unlinked.", "يبحث عن وحدات النواة بما فيها غير المرتبطة.", slow=True),
    _p("windows.driverscan", W, "kernel", "Driver scan", "مسح برامج التشغيل",
       "Pool-scans for driver objects.", "يبحث عن كائنات برامج التشغيل.", slow=True),
    _p("windows.driverirp", W, "kernel", "Driver IRP hooks", "خطافات IRP",
       "IRP dispatch tables - detects hooked drivers.", "جداول IRP - لكشف الخطافات."),
    _p("windows.ssdt", W, "kernel", "SSDT", "جدول SSDT",
       "System service descriptor table entries (hook detection).", "مدخلات SSDT (لكشف الخطافات)."),
    _p("windows.callbacks", W, "kernel", "Kernel callbacks", "نداءات النواة",
       "Registered kernel callbacks.", "نداءات النواة المسجّلة."),
    _p("windows.devicetree", W, "kernel", "Device tree", "شجرة الأجهزة",
       "Driver -> device -> attached device relationships.", "علاقات برنامج التشغيل بالأجهزة."),
    _p("windows.unloadedmodules", W, "kernel", "Unloaded modules", "وحدات أُزيلت",
       "Recently unloaded kernel modules.", "وحدات نواة أُزيلت مؤخرًا."),
    # files
    _p("windows.filescan", W, "files", "File scan", "مسح الملفات",
       "Pool-scans for file objects in memory.", "يبحث عن كائنات الملفات في الذاكرة.", slow=True),
    _p("windows.mftscan", W, "files", "MFT scan", "مسح MFT",
       "MFT records found in memory.", "سجلات MFT الموجودة في الذاكرة.", slow=True),
    _p("windows.mutantscan", W, "files", "Mutex scan", "مسح الـ Mutex",
       "Named mutexes (malware markers).", "كائنات mutex المسمّاة (دلائل برمجيات خبيثة).", slow=True),
    _p("windows.vadinfo", W, "files", "VAD info", "معلومات VAD",
       "Virtual address descriptors per process.", "واصفات العناوين الافتراضية لكل عملية.", pid=True),
    _p("windows.memmap", W, "files", "Memory map", "خريطة الذاكرة",
       "Memory map of a process.", "خريطة ذاكرة العملية.", pid=True),
    # registry
    _p("windows.registry.hivelist", W, "registry", "Registry hives", "خلايا السجل",
       "Registry hives in memory.", "خلايا السجل في الذاكرة."),
    _p("windows.registry.userassist", W, "registry", "UserAssist", "UserAssist",
       "Programs launched by the user (GUI execution evidence).", "البرامج التي شغّلها المستخدم (دليل تنفيذ)."),
    _p("windows.registry.printkey", W, "registry", "Print registry key", "عرض مفتاح سجل",
       "Prints a registry key (use --key in extra arguments).", "يعرض مفتاح سجل (استخدم --key في المعاملات الإضافية)."),
    _p("windows.shimcachemem", W, "registry", "ShimCache (memory)", "ShimCache من الذاكرة",
       "Application compatibility cache - execution evidence.", "ذاكرة التوافق - دليل تنفيذ البرامج."),
    _p("windows.amcache", W, "registry", "Amcache", "Amcache",
       "Executed program inventory with hashes.", "سجل البرامج المنفذة مع البصمات."),
    # persistence
    _p("windows.svcscan", W, "persistence", "Services", "الخدمات",
       "Windows services and their binaries.", "خدمات ويندوز وملفاتها التنفيذية.", slow=True),
    _p("windows.svclist", W, "persistence", "Service list", "قائمة الخدمات",
       "Services read from the service control manager.", "الخدمات من مدير التحكم بالخدمات."),
    _p("windows.scheduled_tasks", W, "persistence", "Scheduled tasks", "المهام المجدولة",
       "Scheduled tasks found in the registry.", "المهام المجدولة من السجل."),
    # credentials
    _p("windows.hashdump", W, "credentials", "Password hashes", "بصمات كلمات المرور",
       "Extracts local account NTLM hashes (sensitive).", "يستخرج بصمات NTLM للحسابات المحلية (حساس).", sensitive=True),
    _p("windows.lsadump", W, "credentials", "LSA secrets", "أسرار LSA",
       "Dumps LSA secrets (sensitive).", "يستخرج أسرار LSA (حساس).", sensitive=True),
    _p("windows.cachedump", W, "credentials", "Cached domain creds", "بيانات النطاق المخزنة",
       "Cached domain logon hashes (sensitive).", "بصمات دخول النطاق المخزنة (حساس).", sensitive=True),
    # ------------------------------------------------------------ Linux
    _p("linux.pslist", L, "processes", "Process list", "قائمة العمليات",
       "Processes from the kernel task list.", "العمليات من قائمة مهام النواة.", pid=True),
    _p("linux.pstree", L, "processes", "Process tree", "شجرة العمليات",
       "Parent/child process hierarchy.", "التسلسل الأبوي للعمليات.", pid=True),
    _p("linux.psaux", L, "processes", "Process arguments", "معاملات العمليات",
       "Processes with full command-line arguments.", "العمليات مع سطر الأوامر كاملًا.", pid=True),
    _p("linux.psscan", L, "processes", "Process scan", "مسح العمليات",
       "Scans memory for processes (finds hidden ones).", "يمسح الذاكرة بحثًا عن العمليات المخفية.", slow=True),
    _p("linux.bash", L, "processes", "Bash history", "سجل bash",
       "Shell commands recovered from bash memory.", "أوامر shell المستعادة من ذاكرة bash.", pid=True),
    _p("linux.lsof", L, "processes", "Open files", "الملفات المفتوحة",
       "Open file descriptors per process.", "مقابض الملفات المفتوحة لكل عملية.", pid=True, slow=True),
    _p("linux.envars", L, "processes", "Environment variables", "متغيرات البيئة",
       "Environment variables per process.", "متغيرات البيئة لكل عملية.", pid=True),
    _p("linux.elfs", L, "processes", "Mapped ELF files", "ملفات ELF المحمّلة",
       "ELF binaries mapped into processes.", "ملفات ELF المحمّلة داخل العمليات.", pid=True),
    _p("linux.sockstat", L, "network", "Sockets", "المقابس (Sockets)",
       "All sockets with process attribution.", "كل المقابس مع العملية المالكة."),
    _p("linux.sockscan", L, "network", "Socket scan", "مسح المقابس",
       "Scans memory for socket structures.", "يمسح الذاكرة بحثًا عن هياكل المقابس.", slow=True),
    _p("linux.lsmod", L, "kernel", "Kernel modules", "وحدات النواة",
       "Loaded kernel modules.", "وحدات النواة المحمّلة."),
    _p("linux.malware.hidden_modules", L, "malware", "Hidden kernel modules", "وحدات نواة مخفية",
       "Kernel modules hidden from the module list (rootkit).", "وحدات نواة مخفية من القائمة (rootkit)."),
    _p("linux.malware.check_syscall", L, "malware", "Syscall table hooks", "خطافات syscall",
       "Checks the system call table for hooks.", "يفحص جدول syscall بحثًا عن خطافات."),
    _p("linux.malware.check_modules", L, "malware", "Module list check", "فحص قائمة الوحدات",
       "Compares kernel module sources.", "يقارن مصادر وحدات النواة."),
    _p("linux.malware.check_idt", L, "malware", "IDT hooks", "خطافات IDT",
       "Checks the interrupt descriptor table.", "يفحص جدول واصفات المقاطعات IDT."),
    _p("linux.malware.check_creds", L, "malware", "Shared credentials", "بيانات اعتماد مشتركة",
       "Processes sharing credential structures (privilege escalation).", "عمليات تشارك هياكل الصلاحيات (تصعيد صلاحيات)."),
    _p("linux.malware.process_spoofing", L, "malware", "Process spoofing", "انتحال العمليات",
       "Spoofed names/command lines and deleted executables.", "أسماء أو أوامر منتحلة وملفات منفذة محذوفة.", pid=True),
    _p("linux.malware.malfind", L, "malware", "Injected code (malfind)", "الكود المحقون (malfind)",
       "Executable anonymous memory regions.", "مناطق ذاكرة تنفيذية مجهولة المصدر.", pid=True),
    _p("linux.malware.tty_check", L, "malware", "TTY hooks", "خطافات TTY",
       "Checks TTY operations for hooks.", "يفحص عمليات TTY بحثًا عن خطافات."),
    _p("linux.malware.keyboard_notifiers", L, "malware", "Keyboard notifiers", "مراقبو لوحة المفاتيح",
       "Registered keyboard notifier callbacks (keyloggers).", "نداءات لوحة المفاتيح (keyloggers)."),
    _p("linux.malware.netfilter", L, "malware", "Netfilter hooks", "خطافات Netfilter",
       "Registered netfilter hooks.", "خطافات netfilter المسجلة."),
    _p("linux.malware.modxview", L, "malware", "Module cross-view", "مقارنة الوحدات",
       "Cross-view of kernel module sources.", "مقارنة مصادر وحدات النواة."),
    _p("linux.mountinfo", L, "files", "Mount points", "نقاط التركيب",
       "Mounted filesystems per namespace.", "أنظمة الملفات المركّبة."),
    _p("linux.kmsg", L, "info", "Kernel log", "سجل النواة",
       "Kernel ring buffer (dmesg).", "مخزن رسائل النواة (dmesg)."),
    _p("linux.boottime", L, "info", "Boot time", "وقت الإقلاع",
       "System boot time.", "وقت إقلاع النظام."),
    _p("linux.library_list", L, "processes", "Loaded libraries", "المكتبات المحمّلة",
       "Shared libraries loaded by processes.", "المكتبات المشتركة المحمّلة."),
    # ------------------------------------------------------------ macOS
    _p("mac.pslist", M, "processes", "Process list", "قائمة العمليات",
       "Processes from the kernel list.", "العمليات من قائمة النواة.", pid=True),
    _p("mac.pstree", M, "processes", "Process tree", "شجرة العمليات",
       "Parent/child hierarchy.", "التسلسل الأبوي للعمليات."),
    _p("mac.psaux", M, "processes", "Process arguments", "معاملات العمليات",
       "Processes with arguments.", "العمليات مع المعاملات.", pid=True),
    _p("mac.bash", M, "processes", "Bash history", "سجل bash",
       "Shell commands from memory.", "أوامر shell من الذاكرة.", pid=True),
    _p("mac.lsof", M, "files", "Open files", "الملفات المفتوحة",
       "Open files per process.", "الملفات المفتوحة لكل عملية.", pid=True, slow=True),
    _p("mac.netstat", M, "network", "Network connections", "اتصالات الشبكة",
       "Network connections.", "اتصالات الشبكة.", pid=True),
    _p("mac.ifconfig", M, "network", "Interfaces", "الواجهات",
       "Network interfaces.", "واجهات الشبكة."),
    _p("mac.mount", M, "files", "Mounts", "نقاط التركيب",
       "Mounted filesystems.", "أنظمة الملفات المركّبة."),
    _p("mac.malfind", M, "malware", "Injected code (malfind)", "الكود المحقون (malfind)",
       "Suspicious executable memory.", "ذاكرة تنفيذية مشبوهة.", pid=True),
    _p("mac.check_syscall", M, "malware", "Syscall hooks", "خطافات syscall",
       "Checks the syscall table.", "يفحص جدول syscall."),
    _p("mac.check_sysctl", M, "malware", "Sysctl hooks", "خطافات sysctl",
       "Checks sysctl handlers.", "يفحص معالجات sysctl."),
    _p("mac.check_trap_table", M, "malware", "Trap table hooks", "خطافات جدول trap",
       "Checks the trap table.", "يفحص جدول trap."),
    _p("mac.lsmod", M, "kernel", "Kernel extensions", "إضافات النواة",
       "Loaded kernel extensions.", "إضافات النواة المحمّلة."),
    _p("mac.dmesg", M, "info", "Kernel log", "سجل النواة",
       "Kernel message buffer.", "مخزن رسائل النواة."),
    # ------------------------------------------------------------ general
    _p("banners.Banners", A, "general", "OS banners", "ترويسات النظام",
       "Finds OS banners (used to detect Linux/macOS images).", "يبحث عن ترويسات النظام لتحديد نوعه."),
    _p("timeliner.Timeliner", A, "general", "Timeline", "الخط الزمني",
       "Merges timestamps from many plugins into a timeline.", "يدمج الطوابع الزمنية من عدة إضافات.", slow=True),
    _p("yarascan.YaraScan", A, "general", "YARA scan", "مسح YARA",
       "Scans memory with YARA rules (pass --yara-file in extra arguments).",
       "يمسح الذاكرة بقواعد YARA (مرّر --yara-file في المعاملات الإضافية).", slow=True),
    _p("regexscan.RegExScan", A, "general", "Regex scan", "مسح Regex",
       "Scans memory with a regular expression (--pattern).", "يمسح الذاكرة بتعبير نمطي (--pattern).", slow=True),
]

BY_NAME: Dict[str, PluginInfo] = {p.name: p for p in CATALOG}


def plugins_for_os(os_name: str) -> List[PluginInfo]:
    if os_name in ("auto", "", None):
        return list(CATALOG)
    return [p for p in CATALOG if p.os in (os_name, OS_ANY)]


def get(name: str) -> Optional[PluginInfo]:
    return BY_NAME.get(name)


# ------------------------------------------------------------------ presets
PRESETS: Dict[str, Dict[str, object]] = {
    "win_quick": {
        "os": OS_WINDOWS,
        "plugins": ["windows.info", "windows.pslist", "windows.pstree", "windows.cmdline", "windows.netscan"],
    },
    "win_triage": {
        "os": OS_WINDOWS,
        "plugins": [
            "windows.info", "windows.pslist", "windows.psscan", "windows.pstree", "windows.cmdline",
            "windows.malware.psxview", "windows.netscan", "windows.malware.malfind",
            "windows.malware.hollowprocesses", "windows.svcscan", "windows.registry.userassist",
        ],
    },
    "win_malware": {
        "os": OS_WINDOWS,
        "plugins": [
            "windows.pslist", "windows.pstree", "windows.cmdline", "windows.malware.malfind",
            "windows.malware.hollowprocesses", "windows.malware.ldrmodules",
            "windows.malware.pebmasquerade", "windows.malware.processghosting",
            "windows.malware.direct_system_calls", "windows.etwpatch", "windows.suspicious_threads",
            "windows.driverirp", "windows.ssdt",
        ],
    },
    "win_network": {
        "os": OS_WINDOWS,
        "plugins": ["windows.pslist", "windows.netscan", "windows.netstat", "windows.cmdline"],
    },
    "linux_triage": {
        "os": OS_LINUX,
        "plugins": [
            "linux.pslist", "linux.psaux", "linux.pstree", "linux.bash", "linux.sockstat", "linux.lsmod",
            "linux.malware.malfind", "linux.malware.hidden_modules", "linux.malware.check_syscall",
            "linux.malware.process_spoofing",
        ],
    },
    "mac_triage": {
        "os": OS_MAC,
        "plugins": [
            "mac.pslist", "mac.pstree", "mac.psaux", "mac.bash", "mac.netstat", "mac.ifconfig",
            "mac.lsof", "mac.mount", "mac.malfind",
        ],
    },
}


def presets_for_os(os_name: str) -> List[str]:
    return [k for k, v in PRESETS.items() if os_name in ("auto", "", None) or v["os"] == os_name]


# ------------------------------------------------------------------ discovery
def plugins_root(vol_root: str | Path) -> Path:
    return Path(vol_root) / "volatility3" / "framework" / "plugins"


def discover_modules(vol_root: str | Path) -> List[str]:
    """Return dotted module names of every plugin file below the plugins package."""
    root = plugins_root(vol_root)
    if not root.is_dir():
        return []
    mods = []
    for f in root.rglob("*.py"):
        if f.name == "__init__.py":
            continue
        rel = f.relative_to(root).with_suffix("")
        mods.append(".".join(rel.parts))
    return sorted(mods)


def _module_of(plugin_name: str) -> str:
    """windows.pslist -> windows.pslist ; banners.Banners -> banners"""
    parts = plugin_name.split(".")
    if parts[-1][:1].isupper():
        parts = parts[:-1]
    return ".".join(parts)


def missing_from_install(vol_root: str | Path, names: Iterable[str]) -> List[str]:
    """Catalog names that do not exist in the installed Volatility (version drift)."""
    mods = set(discover_modules(vol_root))
    if not mods:
        return []
    return [n for n in names if _module_of(n) not in mods]


def extra_plugins(vol_root: str | Path) -> List[PluginInfo]:
    """Plugins present in the install but not in the curated catalog -> category 'other'."""
    known = {_module_of(p.name) for p in CATALOG}
    out = []
    for mod in discover_modules(vol_root):
        if mod in known or mod.startswith(("renderers",)):
            continue
        head = mod.split(".")[0]
        os_ = head if head in (OS_WINDOWS, OS_LINUX, OS_MAC) else OS_ANY
        out.append(PluginInfo(mod, os_, "other", mod, mod))
    return out
