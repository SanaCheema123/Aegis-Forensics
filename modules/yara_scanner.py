"""
YARA scanning for the forensics platform.

Rules live in <project root>/yara_rules/*.yar. Every rule can carry meta fields:
    description, severity (Critical/High/Medium/Low), mitre
Findings use IDs like Y-001 so they never collide with rule-engine IDs (F-001).
"""
from __future__ import annotations

from modules.csv_evidence import physical_line_number

import hashlib
import re
from pathlib import Path

try:
    import yara
    YARA_AVAILABLE = True
    IMPORT_ERROR = ""
except Exception as exc:  # yara-python not installed / failed to build
    yara = None
    YARA_AVAILABLE = False
    IMPORT_ERROR = str(exc)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_RULES_DIR = ROOT / "yara_rules"
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
MAX_IN_MEMORY = 100 * 1024 * 1024  # files above this are scanned from disk, without line numbers
CONTEXT_BYTES = 48

OFFICE_EXTENSIONS = {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".pptm"}
SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".py", ".sh"}
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".scr", ".com"}


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class YaraScanner:
    def __init__(self, rules_dir: str | Path | None = None):
        self.rules_dir = Path(rules_dir) if rules_dir else DEFAULT_RULES_DIR
        self.rules = None
        self.loaded_files: list[str] = []
        self.errors: list[str] = []
        self.rule_files: dict[str, str] = {}  # rule name -> .yar file it came from
        self._compile()

    # ------------------------------------------------------------------ setup
    @staticmethod
    def rules_signature(rules_dir: str | Path | None = None) -> str:
        """Changes whenever a rule file is added/edited, so caches can be invalidated."""
        d = Path(rules_dir) if rules_dir else DEFAULT_RULES_DIR
        parts = []
        for p in sorted(list(d.glob("**/*.yar")) + list(d.glob("**/*.yara"))):
            parts.append(f"{p.name}:{p.stat().st_mtime_ns}")
        return "|".join(parts)

    def _compile(self) -> None:
        if not YARA_AVAILABLE:
            self.errors.append(f"yara-python is not installed ({IMPORT_ERROR}). Run: pip install yara-python")
            return
        if not self.rules_dir.exists():
            self.errors.append(f"Rules folder not found: {self.rules_dir}")
            return

        files = sorted(list(self.rules_dir.glob("**/*.yar")) + list(self.rules_dir.glob("**/*.yara")))
        good: dict[str, str] = {}
        for p in files:
            try:
                single = yara.compile(filepath=str(p))  # test each file alone so one bad file cannot break the rest
                good[re.sub(r"\W", "_", p.stem)] = str(p)
                try:
                    for r in single:
                        self.rule_files[r.identifier] = p.name
                except TypeError:
                    pass
            except yara.Error as exc:
                self.errors.append(f"{p.name}: {exc}")
        if not good:
            if not files:
                self.errors.append(f"No .yar files in {self.rules_dir}")
            return
        try:
            self.rules = yara.compile(filepaths=good)
            self.loaded_files = [Path(p).name for p in good.values()]
        except yara.Error as exc:
            self.errors.append(f"Compile failed: {exc}")

    @property
    def ready(self) -> bool:
        return self.rules is not None

    def list_rules(self) -> list[dict]:
        """One row per loaded rule, for the rule-library page."""
        if not self.ready:
            return []
        rows = []
        try:
            for r in self.rules:
                meta = r.meta or {}
                rows.append({
                    "rule": r.identifier,
                    "file": self.rule_files.get(r.identifier, ""),
                    "severity": meta.get("severity", "Medium"),
                    "mitre": meta.get("mitre", ""),
                    "description": meta.get("description", ""),
                })
        except TypeError:
            pass
        rows.sort(key=lambda x: (SEVERITY_ORDER.get(x["severity"], 9), x["rule"]))
        return rows

    # --------------------------------------------------------------- scanning
    def scan_bytes(self, data: bytes, name: str, timeout: int = 10) -> list[dict]:
        """Scan bounded in-memory evidence such as a safely-read archive member."""
        if not self.ready:
            return []
        if len(data) > MAX_IN_MEMORY:
            raise ValueError("In-memory YARA scans are limited to 100 MB.")
        try:
            matches = self.rules.match(data=data, timeout=timeout)
        except yara.Error as exc:
            raise RuntimeError(f"YARA could not scan embedded content: {exc}") from exc
        digest = hashlib.sha256(data).hexdigest()
        is_text = b"\x00" not in data[:8192]
        return self._findings_from_matches(matches, name, digest, data, is_text)

    @staticmethod
    def _safe_text(value: bytes) -> str:
        text = value.decode("utf-8", errors="replace")
        safe = []
        for char in text:
            if char.isprintable():
                safe.append(char)
            elif ord(char) <= 0xFF:
                safe.append(f"\\x{ord(char):02x}")
            else:
                safe.append(f"\\u{ord(char):04x}")
        return "".join(safe)

    @staticmethod
    def _content_type(name: str, data: bytes | None) -> str:
        container, separator, member = name.partition("!")
        extension = Path(container).suffix.lower()
        member_path = Path(member.replace("\\", "/")) if separator else Path()
        member_name = member_path.as_posix().lower()

        if separator and re.search(r"(?:^|/)vbaProject\.bin$", member_name, re.IGNORECASE):
            return "macro"
        if separator and member_path.suffix.lower() in SCRIPT_EXTENSIONS:
            return "script"
        if separator and member_path.suffix.lower() in EXECUTABLE_EXTENSIONS:
            return "executable"
        if data:
            if len(data) >= 0x40 and data[:2] == b"MZ":
                pe_offset = int.from_bytes(data[0x3C:0x40], "little")
                if data[pe_offset:pe_offset + 4] == b"PE\0\0":
                    return "executable"
        if extension in SCRIPT_EXTENSIONS:
            return "script"
        if extension in EXECUTABLE_EXTENSIONS and data is None:
            return "executable"
        if (
            separator
            and extension in OFFICE_EXTENSIONS
            and member_name in {"word/document.xml", "xl/sharedstrings.xml", "ppt/slides/slide1.xml"}
            and data is not None
            and data.lstrip().startswith((b"<?xml", b"<"))
        ):
            return "document text"
        if (
            not separator
            and extension in OFFICE_EXTENSIONS
            and data is not None
            and data.startswith(b"PK\x03\x04")
        ):
            return "office archive"
        if data is not None and b"\0" not in data[:8192]:
            return "plain text"
        if data is not None:
            return "binary"
        return "unknown"

    @staticmethod
    def _extract(
        match,
        data: bytes | None,
        is_text: bool,
        limit: int = 20,
        *, name: str = "",
    ) -> tuple[list[dict], list[str], int]:
        hits = []
        identifiers = set()
        for s in match.strings:
            if hasattr(s, "instances"):  # yara-python >= 4.3
                ident = s.identifier
                found = [(i.offset, bytes(i.matched_data)) for i in s.instances]
            else:  # older versions return (offset, identifier, data)
                off, ident, val = s
                found = [(off, bytes(val))]
            if found:
                identifiers.add(ident)
            for off, val in found:
                line = None
                if data is not None and is_text:
                    line = physical_line_number(data, off) if Path(name).suffix.lower() == ".csv" else data.count(b"\n", 0, off) + 1
                context_start = max(0, off - CONTEXT_BYTES)
                context_end = min(len(data), off + len(val) + CONTEXT_BYTES) if data is not None else off + len(val)
                hits.append({
                    "string": ident,
                    "offset": off,
                    "line": line,
                    "snippet": YaraScanner._safe_text(val)[:120],
                    "context_start": context_start,
                    "context_end": context_end,
                    "context": (
                        YaraScanner._safe_text(data[context_start:context_end])
                        if data is not None else ""
                    ),
                })
        hits.sort(key=lambda h: h["offset"])
        return hits[:limit], sorted(identifiers), len(hits)

    def scan_file(self, path: str | Path, timeout: int = 60) -> list[dict]:
        if not self.ready:
            return []
        path = Path(path)
        size = path.stat().st_size
        data = path.read_bytes() if size <= MAX_IN_MEMORY else None
        is_text = data is not None and b"\x00" not in data[:8192]

        if data is not None:
            matches = self.rules.match(data=data, timeout=timeout)
        else:
            matches = self.rules.match(filepath=str(path), timeout=timeout)

        digest = _sha256(path)
        return self._findings_from_matches(matches, path.name, digest, data, is_text)

    def _findings_from_matches(self, matches, name, digest, data, is_text):
        findings = []
        for m in matches:
            meta = m.meta or {}
            extracted, matched_strings, match_count = self._extract(m, data, is_text, name=name)
            severity, confidence, content_type, reason = self._assess_severity(
                m.rule,
                meta.get("severity", "Medium"),
                name,
                data,
                matched_strings,
            )
            findings.append({
                "rule": m.rule,
                "severity": severity,
                "confidence": confidence,
                "content_type": content_type,
                "severity_reason": reason,
                "matched_strings": matched_strings,
                "match_count": match_count,
                "matches_truncated": match_count > len(extracted),
                "description": meta.get("description", ""),
                "mitre": meta.get("mitre", "n/a"),
                "tags": list(m.tags),
                "file": name,
                "sha256": digest,
                "matches": extracted,
            })
        return self._number(findings)

    @staticmethod
    def _assess_severity(rule, base_severity, name, data, matched_strings):
        content_type = YaraScanner._content_type(name, data)
        if rule != "Credential_Dumping_Tools":
            return base_severity, "rule match", content_type, "Severity follows the YARA rule metadata."

        identifiers = set(matched_strings)
        strong_indicators = {"$m1", "$m2"}
        strong_combinations = (
            {"$p1", "$p2"},
            {"$c1", "$c2"},
        )
        high_confidence = bool(identifiers & strong_indicators) or any(
            pair <= identifiers for pair in strong_combinations
        )
        confidence = "high" if high_confidence else "medium" if len(identifiers) > 1 else "low"
        behavioral_indicators = (
            rb"\b(?:Invoke-Expression|Start-Process|rundll32|regsvr32|Add-Type)\b",
            rb"\b(?:AutoOpen|Document_Open)\b",
            rb"\b(?:WScript\.Shell|CreateObject|Shell)\b",
        )
        has_behavior = data is not None and any(
            re.search(pattern, data, re.IGNORECASE)
            for pattern in behavioral_indicators
        )

        if content_type == "document text":
            return (
                "Medium",
                "low",
                content_type,
                "Matched indicators occur in ordinary Office document text, not executable content.",
            )
        if content_type == "plain text":
            return (
                "Medium",
                confidence,
                content_type,
                "Text-only indicator matches are not sufficient to establish credential theft.",
            )
        if content_type in {"script", "macro", "executable"}:
            if high_confidence and (
                content_type == "executable"
                or content_type == "script" and has_behavior
                or content_type == "macro" and has_behavior
            ):
                return (
                    "Critical",
                    confidence,
                    content_type,
                    "A high-confidence credential-dumping indicator is corroborated by executable or behavioral evidence.",
                )
            severity = "High" if confidence in {"medium", "high"} else "Medium"
            return (
                severity,
                confidence,
                content_type,
                "Credential-dumping indicators occur in active content but do not meet the high-confidence threshold.",
            )
        return (
            "Medium",
            confidence,
            content_type,
            "A rule string matched, but file context does not establish active credential-dumping content.",
        )

    def scan_folder(self, folder: str | Path) -> list[dict]:
        all_findings: list[dict] = []
        for p in sorted(Path(folder).glob("*")):
            if p.is_file():
                try:
                    all_findings.extend(self.scan_file(p))
                except Exception as exc:  # unreadable file: keep scanning the rest
                    self.errors.append(f"{p.name}: {exc}")
        return self._number(all_findings)

    @staticmethod
    def _number(findings: list[dict]) -> list[dict]:
        findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["file"], f["rule"]))
        for i, f in enumerate(findings, 1):
            f["id"] = f"Y-{i:03d}"
        return findings

    # ---------------------------------------------------------------- helpers
    @staticmethod
    def to_dataframe(findings: list[dict]):
        import pandas as pd
        return pd.DataFrame([{
            "ID": f["id"],
            "Severity": f["severity"],
            "Source": f.get("source", "YARA"),
            "Rule": f["rule"],
            "File": f["file"],
            "Hits": f.get("match_count", len(f["matches"])),
            "Matched strings": ", ".join(f.get("matched_strings", [])),
            "Confidence": f.get("confidence", ""),
            "Content type": f.get("content_type", ""),
            "Severity rationale": f.get("severity_reason", ""),
            "MITRE ATT&CK": f["mitre"],
            "Description": f["description"],
        } for f in findings])