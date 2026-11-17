"""Local-only checks for user-selected files, folders, and URL text."""
from __future__ import annotations

import hashlib
import io
import ipaddress
import re
import tempfile
import zipfile
import zlib
from pathlib import Path
from urllib.parse import urlsplit
from typing import Any

from pypdf import PdfReader
from pypdf.errors import PdfReadError

SCAN_EXTENSIONS = {
    ".7z", ".apk", ".bat", ".bin", ".bmp", ".cmd", ".com", ".csv", ".dll", ".dmp", ".doc",
    ".docm", ".docx", ".evtx", ".exe", ".gif", ".htm", ".html", ".hta", ".ico",
    ".iso", ".jar", ".jpeg", ".jpg", ".js", ".json", ".lnk", ".log",
    ".msi", ".msix", ".pdf", ".php", ".png", ".ppt", ".pptm", ".pptx", ".ps1", ".py",
    ".rar", ".rtf", ".scr", ".sh", ".svg", ".txt", ".vbs", ".webp",
    ".sys", ".wsf", ".xls", ".xlsm", ".xlsx", ".zip",
}
MAX_FOLDER_FILES = 500
MAX_FILE_SIZE = 100 * 1024 * 1024
MAX_EMBEDDED_ARCHIVE_SIZE = 50 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 100
MAX_ARCHIVE_MEMBER_SIZE = 5 * 1024 * 1024
MAX_ARCHIVE_UNCOMPRESSED_SIZE = 20 * 1024 * 1024
MAX_PDF_PAGES = 100
MAX_PDF_TEXT_CHARS = 1_000_000
SHORTENER_HOSTS = {"bit.ly", "t.co", "tinyurl.com", "is.gd", "cutt.ly"}
SCRIPT_EXTENSIONS = {".bat", ".cmd", ".hta", ".js", ".ps1", ".py", ".sh", ".vbs", ".wsf"}
SIGNAL_PATTERNS = (
    (
        re.compile(r"(?i)(?:-enc(?:odedcommand)?\b|frombase64string)"),
        "Encoded-command indicator in script content.",
        "Medium",
    ),
    (
        re.compile(r"(?i)\b(?:downloadstring|invoke-webrequest|start-bitstransfer|bitsadmin)\b"),
        "Script contains a network-download indicator.",
        "Medium",
    ),
    (
        re.compile(r"(?i)(?:add-mppreference|set-mppreference).{0,120}(?:exclusion|disablerealtimemonitoring)"),
        "Script contains a Microsoft Defender exclusion or protection-change indicator.",
        "High",
    ),
)
PDF_ACTION_PATTERNS = (
    (re.compile(rb"/(?:JavaScript|JS)\b", re.IGNORECASE), "PDF contains a JavaScript action marker."),
    (re.compile(rb"/(?:OpenAction|Launch)\b", re.IGNORECASE), "PDF contains an automatic or launch action marker."),
    (re.compile(rb"/(?:EmbeddedFiles|RichMedia)\b", re.IGNORECASE), "PDF contains an embedded-file or rich-media marker."),
)

def inspect_pdf_content(data: bytes) -> tuple[list[dict[str, Any]], list[str]]:
    """Inspect PDF structure markers and bounded extracted text without executing actions."""
    indicators = []
    warnings = []
    for pattern, description in PDF_ACTION_PATTERNS:
        match = pattern.search(data)
        if match:
            indicators.append({
                "severity": "Medium",
                "description": f"{description} This static marker is not proof of malicious activity.",
                "offset": match.start(),
            })

    try:
        reader = PdfReader(io.BytesIO(data), strict=False)
        page_count = len(reader.pages)
    except (OSError, PdfReadError, TypeError, ValueError) as exc:
        return indicators, [f"PDF text extraction could not parse the document: {exc}"]

    if page_count > MAX_PDF_PAGES:
        warnings.append(f"PDF text review is limited to the first {MAX_PDF_PAGES} pages.")
    text_characters = 0
    for page_number, page in enumerate(reader.pages[:MAX_PDF_PAGES], start=1):
        try:
            text = page.extract_text() or ""
        except (PdfReadError, TypeError, ValueError) as exc:
            warnings.append(f"Could not extract text from PDF page {page_number}: {exc}")
            continue
        remaining = MAX_PDF_TEXT_CHARS - text_characters
        if remaining <= 0:
            warnings.append(
                f"PDF text review reached the {MAX_PDF_TEXT_CHARS:,}-character limit."
            )
            break
        text = text[:remaining]
        text_characters += len(text)
        for pattern, description, severity in SIGNAL_PATTERNS:
            match = pattern.search(text)
            if match:
                indicator_text = (
                    description.lower()
                    .replace("script contains a ", "")
                    .replace(" in script content", "")
                    .rstrip(".")
                )
                indicators.append({
                    "severity": severity,
                    "description": (
                        f"Extracted PDF page {page_number} contains a {indicator_text}. "
                        "This is static text, not proof the content was executed."
                    ),
                    "page": page_number,
                })
        if text_characters >= MAX_PDF_TEXT_CHARS:
            warnings.append(
                f"PDF text review reached the {MAX_PDF_TEXT_CHARS:,}-character limit."
            )
            break
    return indicators, warnings


def inspect_url(value: str) -> dict:
    """Check URL formatting only; this function never makes a network request."""
    candidate = value.strip()
    signals = []
    if not candidate:
        return {
            "status": "invalid",
            "verdict": "Unknown",
            "host": "",
            "signals": ["Enter a URL to check."],
        }

    try:
        parsed = urlsplit(candidate)
        host = parsed.hostname or ""
        parsed.port
    except ValueError:
        return {
            "status": "invalid",
            "verdict": "Unknown",
            "host": "",
            "signals": ["The URL format is invalid."],
        }

    if parsed.scheme.lower() not in {"http", "https"} or not host:
        return {
            "status": "invalid",
            "verdict": "Unknown",
            "host": host,
            "signals": ["Only complete http:// or https:// URLs can be checked."],
        }
    if parsed.username is not None or parsed.password is not None:
        signals.append("The URL contains user-info before the host, which can disguise its destination.")
    safe_indicators = []
    if parsed.scheme.lower() != "https":
        signals.append("The link does not use HTTPS.")
    else:
        safe_indicators.append("The URL uses HTTPS transport encryption.")
    try:
        ipaddress.ip_address(host)
        signals.append("The link uses a raw IP address instead of a domain name.")
    except ValueError:
        if host.lower().startswith("xn--") or ".xn--" in host.lower():
            signals.append("The domain contains an internationalized (punycode) name; inspect it carefully.")
    if host.lower() in SHORTENER_HOSTS:
        signals.append("This is a shortened link, so its final destination is hidden.")
    if any(ord(char) < 32 for char in candidate):
        signals.append("The URL contains control characters.")
    if parsed.path.lower().endswith((
        ".exe", ".msi", ".msix", ".scr", ".bat", ".cmd", ".ps1", ".apk", ".jar", ".zip",
    )):
        signals.append("The link path appears to point to an executable or install package.")

    return {
        "status": "review" if signals else "no_obvious_flags",
        "verdict": (
            "Suspicious Indicators" if signals
            else "Safe Indicators" if safe_indicators
            else "Unknown"
        ),
        "host": host,
        "signals": signals,
        "safe_indicators": safe_indicators,
    }


def _file_type(data: bytes) -> str:
    if data.startswith(b"MZ"):
        return "Windows executable"
    if data.startswith(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"):
        return "OLE compound file"
    if data.startswith(b"\x7fELF"):
        return "ELF executable"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "PNG image"
    if data.startswith(b"BM"):
        return "BMP image"
    if data.startswith(b"\xff\xd8\xff"):
        return "JPEG image"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "GIF image"
    if data.startswith(b"%PDF-"):
        return "PDF document"
    if data.startswith(b"PK\x03\x04"):
        return "ZIP archive"
    if data.startswith(b"\x00\x00\x01\x00"):
        return "Icon image"
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "WebP image"
    if data.lstrip().lower().startswith((b"<svg", b"<?xml")) and b"<svg" in data[:1024].lower():
        return "SVG image"
    if data.lstrip().lower().startswith((b"<!doctype html", b"<html")):
        return "HTML document"
    return "Unknown or unsupported file signature"


def inspect_content(name: str, prefix: bytes) -> list[dict[str, Any]]:
    """Return bounded signature, extension, and script-content indicators."""
    path = Path(name)
    suffix = path.suffix.lower()
    detected_type = _file_type(prefix)
    indicators = []
    expected_images = {
        ".bmp": "BMP image",
        ".gif": "GIF image",
        ".ico": "Icon image",
        ".jpeg": "JPEG image",
        ".jpg": "JPEG image",
        ".png": "PNG image",
        ".svg": "SVG image",
        ".webp": "WebP image",
    }
    if suffix in expected_images and detected_type != expected_images[suffix]:
        indicators.append({
            "severity": "Medium",
            "description": f"The file extension says image, but its content looks like {detected_type}.",
            "offset": 0,
        })

    executable_extensions = {".dll", ".exe", ".scr", ".sys"}
    if suffix in executable_extensions and detected_type != "Windows executable":
        indicators.append({
            "severity": "High",
            "description": "The executable extension does not match a Windows executable signature.",
            "offset": 0,
        })
    expected_package_types = {".msi": "OLE compound file", ".msix": "ZIP archive"}
    if suffix in expected_package_types and detected_type != expected_package_types[suffix]:
        indicators.append({
            "severity": "High",
            "description": f"The {suffix} extension does not match its expected package signature.",
            "offset": 0,
        })
    if detected_type in {"Windows executable", "ELF executable"} and suffix not in executable_extensions:
        indicators.append({
            "severity": "High",
            "description": "Executable content uses a non-executable file extension.",
            "offset": 0,
        })
    if re.search(
        r"\.(?:pdf|docx?|xlsx?|pptx?|xlsm|docm|jpe?g|png)\.(?:exe|scr|bat|cmd|ps1)$",
        path.name,
        re.IGNORECASE,
    ):
        indicators.append({
            "severity": "Medium",
            "description": "Filename uses a document or image double-extension pattern.",
            "offset": 0,
        })

    if suffix in SCRIPT_EXTENSIONS:
        decoded = prefix.decode("utf-8", errors="replace")
        if b"\x00" in prefix:
            decoded = prefix.decode("utf-16-le", errors="replace")
        for pattern, description, severity in SIGNAL_PATTERNS:
            match = pattern.search(decoded)
            if match:
                indicators.append({
                    "severity": severity,
                    "description": description,
                    "line": decoded.count("\n", 0, match.start()) + 1,
                })
    return indicators


def _heuristic_findings(name: str, digest: str, indicators: list[dict[str, Any]]) -> list[dict]:
    findings = []
    for index, indicator in enumerate(indicators, start=1):
        line = indicator.get("line")
        evidence = (
            [{"file": name, "line": line}]
            if line
            else [{"file": name, "page": indicator["page"]}]
            if indicator.get("page")
            else []
        )
        matches = [{
            "string": "static_indicator",
            "offset": indicator.get("offset", 0),
            "line": line,
            "page": indicator.get("page"),
            "snippet": indicator["description"],
        }]
        findings.append({
            "id": f"F-{index:03d}",
            "severity": indicator["severity"],
            "source": "Static heuristic",
            "rule": indicator["description"],
            "description": indicator["description"],
            "mitre": "n/a",
            "file": name,
            "sha256": digest,
            "evidence": evidence,
            "matches": matches,
            "recommended_action": (
                "Preserve the file, avoid opening it, and validate the indicator with trusted security tooling."
                if indicator["severity"] in {"High", "Critical"}
                else "Review the referenced file content and verify its origin before opening."
            ),
        })
    return findings


def scan_embedded_content(name: str, data: bytes, scanner) -> tuple[list[dict], list[str]]:
    """Inspect ZIP-based formats in memory with strict member and expansion limits."""
    if not data.startswith(b"PK\x03\x04"):
        return [], []
    if len(data) > MAX_EMBEDDED_ARCHIVE_SIZE:
        return [], ["Embedded-content review skipped: archive exceeds 50 MB."]
    if not scanner.ready or not callable(getattr(scanner, "scan_bytes", None)):
        return [], ["Embedded-content review unavailable: YARA byte scanning is not ready."]

    findings = []
    warnings = []
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile, EOFError) as exc:
        return [], [f"Embedded-content review could not read the archive: {exc}"]

    total_uncompressed = 0
    with archive:
        for member_number, info in enumerate(archive.infolist(), start=1):
            if info.is_dir():
                continue
            if member_number > MAX_ARCHIVE_MEMBERS:
                warnings.append(f"Embedded-content review is limited to {MAX_ARCHIVE_MEMBERS} archive members.")
                break
            if info.file_size > MAX_ARCHIVE_MEMBER_SIZE:
                warnings.append(f"Skipped oversized archive member: {info.filename}")
                continue
            if total_uncompressed + info.file_size > MAX_ARCHIVE_UNCOMPRESSED_SIZE:
                warnings.append("Embedded-content review reached the 20 MB expanded-data limit.")
                break
            try:
                content = archive.read(info)
                matches = scanner.scan_bytes(
                    content,
                    f"{name}!{info.filename}",
                    timeout=5,
                )
            except (
                OSError,
                EOFError,
                RuntimeError,
                ValueError,
                zipfile.BadZipFile,
                zlib.error,
            ) as exc:
                warnings.append(f"Could not inspect archive member {info.filename}: {exc}")
                continue
            total_uncompressed += len(content)
            for finding in matches:
                finding["container"] = name
                finding["member"] = info.filename
                findings.append(finding)
    return findings, warnings


def check_uploaded_file(name: str, data: bytes, scanner) -> dict:
    """Hash and YARA-scan uploaded bytes using a temporary local file."""
    digest = hashlib.sha256(data).hexdigest()
    detected_type = _file_type(data)
    extension = Path(name).suffix.lower()
    content_indicators = inspect_content(name, data[:256 * 1024])
    pdf_warnings = []
    if extension == ".pdf":
        pdf_indicators, pdf_warnings = inspect_pdf_content(data)
        content_indicators.extend(pdf_indicators)
    signals = [item["description"] for item in content_indicators]
    heuristic_findings = _heuristic_findings(name, digest, content_indicators)

    if not scanner.ready:
        return {
            "sha256": digest,
            "size": len(data),
            "detected_type": detected_type,
            "signals": signals,
            "heuristic_findings": heuristic_findings,
            "scan_warnings": pdf_warnings,
            "verdict": "Suspicious Indicators" if signals else "Unknown",
            "findings": [],
            "scanner_ready": False,
        }

    temp_path = None
    embedded_warnings = []
    try:
        with tempfile.NamedTemporaryFile(prefix="aegis-check-", suffix=extension, delete=False) as temp:
            temp.write(data)
            temp_path = Path(temp.name)
        findings = scanner.scan_file(temp_path)
    finally:
        if temp_path is not None:
            temp_path.unlink(missing_ok=True)
    for finding in findings:
        finding["file"] = Path(name).name
    embedded_findings, embedded_warnings = scan_embedded_content(name, data, scanner)
    findings.extend(embedded_findings)
    for index, finding in enumerate(findings, start=1):
        finding["id"] = f"Y-{index:03d}"

    return {
        "sha256": digest,
        "size": len(data),
        "detected_type": detected_type,
        "signals": signals,
        "heuristic_findings": heuristic_findings,
        "scan_warnings": pdf_warnings + embedded_warnings,
        "verdict": (
            "Suspicious Indicators" if signals or findings
            else "Safe Indicators" if (
                _extension_matches(extension, detected_type)
                and not pdf_warnings
                and not embedded_warnings
            )
            else "Unknown"
        ),
        "findings": findings,
        "scanner_ready": True,
    }


def _extension_matches(extension: str, detected_type: str) -> bool:
    expected = {
        ".apk": "ZIP archive",
        ".bmp": "BMP image",
        ".dll": "Windows executable",
        ".exe": "Windows executable",
        ".gif": "GIF image",
        ".ico": "Icon image",
        ".jar": "ZIP archive",
        ".jpeg": "JPEG image",
        ".jpg": "JPEG image",
        ".msi": "OLE compound file",
        ".msix": "ZIP archive",
        ".pdf": "PDF document",
        ".png": "PNG image",
        ".scr": "Windows executable",
        ".sys": "Windows executable",
        ".webp": "WebP image",
        ".zip": "ZIP archive",
    }
    return expected.get(extension.lower()) == detected_type


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan_local_folder(folder: str | Path, scanner) -> dict:
    """Recursively scan supported regular files without following symlinks."""
    root = Path(folder).expanduser()
    if not root.exists() or not root.is_dir():
        raise ValueError("Choose an existing folder on this computer.")
    findings = []
    errors = []
    warnings = []
    checked = 0
    skipped = 0
    limit_reached = False
    for path in root.rglob("*"):
        if path.is_symlink() or not path.is_file() or path.suffix.lower() not in SCAN_EXTENSIONS:
            continue
        if checked + skipped >= MAX_FOLDER_FILES:
            skipped += 1
            limit_reached = True
            break
        try:
            if path.stat().st_size > MAX_FILE_SIZE:
                skipped += 1
                continue
            file_findings = scanner.scan_file(path, timeout=10)
            for finding in file_findings:
                finding["source"] = "YARA"
            with path.open("rb") as source:
                prefix = source.read(256 * 1024)
            indicators = inspect_content(path.name, prefix)
            pdf_warnings = []
            if path.suffix.lower() == ".pdf":
                pdf_indicators, pdf_warnings = inspect_pdf_content(path.read_bytes())
                indicators.extend(pdf_indicators)
            if indicators:
                file_findings.extend(_heuristic_findings(str(path), _sha256_file(path), indicators))
            warnings.extend(f"{path}: {warning}" for warning in pdf_warnings)
            with path.open("rb") as source:
                is_archive = source.read(4) == b"PK\x03\x04"
            if is_archive:
                if path.stat().st_size > MAX_EMBEDDED_ARCHIVE_SIZE:
                    warnings.append(f"{path}: embedded-content review skipped above 50 MB.")
                else:
                    embedded, embedded_warnings = scan_embedded_content(path.name, path.read_bytes(), scanner)
                    for finding in embedded:
                        finding["source"] = "YARA"
                    file_findings.extend(embedded)
                    warnings.extend(f"{path}: {warning}" for warning in embedded_warnings)
            findings.extend(file_findings)
            checked += 1
        except OSError as exc:
            errors.append(f"{path}: {exc}")
            skipped += 1
        except Exception as exc:
            errors.append(f"{path}: {exc}")
            skipped += 1

    yara_number = 0
    heuristic_number = 0
    for finding in findings:
        if finding.get("source") == "Static heuristic":
            heuristic_number += 1
            finding["id"] = f"F-{heuristic_number:03d}"
        else:
            yara_number += 1
            finding["id"] = f"Y-{yara_number:03d}"

    return {
        "findings": findings,
        "errors": errors,
        "warnings": warnings,
        "checked": checked,
        "skipped": skipped,
        "limit_reached": limit_reached,
    }
