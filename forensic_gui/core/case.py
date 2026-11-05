"""Case folders: metadata, saved plugin output and an append-only audit trail."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

CASE_FILE = "case.json"
AUDIT_FILE = "audit.log"


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


def slugify(text: str) -> str:
    s = re.sub(r"[^\w\-.]+", "_", text.strip(), flags=re.UNICODE).strip("._")
    return s or "case"


_cases_dir_override: Optional[Path] = None


def set_cases_dir(path) -> None:
    """Where new cases are created (the user's 'Cases directory' setting). Empty -> built-in default."""
    global _cases_dir_override
    _cases_dir_override = Path(path) if path else None


def default_cases_dir() -> Path:
    return _cases_dir_override or Path.home() / "ForensicStudio" / "Cases"


@dataclass
class Case:
    case_id: str = ""
    name: str = ""
    examiner: str = ""
    notes: str = ""
    image_path: str = ""
    image_size: int = 0
    os_hint: str = "auto"
    hashes: Dict[str, str] = field(default_factory=dict)
    created: str = field(default_factory=now_iso)
    folder: str = ""
    runs: List[Dict] = field(default_factory=list)  # plugin run history

    # ------------------------------------------------------------ paths
    @property
    def results_dir(self) -> Path:
        return Path(self.folder) / "results"

    @property
    def exports_dir(self) -> Path:
        return Path(self.folder) / "exports"

    def result_path(self, plugin: str) -> Path:
        return self.results_dir / f"{slugify(plugin)}.json"

    # ------------------------------------------------------------ lifecycle
    def ensure_folder(self, base: Optional[Path] = None) -> Path:
        if not self.folder:
            base = Path(base) if base else default_cases_dir()
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            self.folder = str(base / f"{slugify(self.case_id or self.name or 'case')}_{stamp}")
        for d in (Path(self.folder), self.results_dir, self.exports_dir):
            d.mkdir(parents=True, exist_ok=True)
        return Path(self.folder)

    def save(self) -> None:
        self.ensure_folder()
        (Path(self.folder) / CASE_FILE).write_text(
            json.dumps(asdict(self), indent=2, ensure_ascii=False), encoding="utf-8"
        )

    @classmethod
    def load(cls, folder: str | Path) -> "Case":
        folder = Path(folder)
        data = json.loads((folder / CASE_FILE).read_text(encoding="utf-8"))
        known = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
        case = cls(**known)
        case.folder = str(folder)  # tolerate moved folders
        return case

    # ------------------------------------------------------------ results
    def save_result(self, plugin: str, raw_json: str) -> Path:
        self.ensure_folder()
        p = self.result_path(plugin)
        p.write_text(raw_json, encoding="utf-8")
        return p

    def saved_results(self) -> Dict[str, Path]:
        """plugin name -> file, using the run history for the original dotted names."""
        out = {}
        for run in self.runs:
            p = self.result_path(run.get("plugin", ""))
            if run.get("status") == "ok" and p.is_file():
                out[run["plugin"]] = p
        return out

    def record_run(self, plugin: str, status: str, rows: int, seconds: float, extra: str = "") -> None:
        self.runs = [r for r in self.runs if r.get("plugin") != plugin]
        self.runs.append({"plugin": plugin, "status": status, "rows": rows,
                          "seconds": round(seconds, 1), "finished": now_iso(), "note": extra})

    # ------------------------------------------------------------ audit trail
    def audit(self, action: str) -> None:
        """Append-only log. Never raises: auditing must not break an investigation."""
        try:
            self.ensure_folder()
            with open(Path(self.folder) / AUDIT_FILE, "a", encoding="utf-8") as f:
                f.write(f"{now_iso()}\t{self.examiner or '-'}\t{action}\n")
        except OSError:
            pass

    def audit_lines(self) -> List[str]:
        p = Path(self.folder) / AUDIT_FILE if self.folder else None
        if p and p.is_file():
            return p.read_text(encoding="utf-8").splitlines()
        return []
