"""Local, read-only Windows security review and explicit Defender scan controls."""
from __future__ import annotations

from modules.event_timestamps import parse_timestamp, resolve_event_timestamp

import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any


class WindowsSecurityError(RuntimeError):
    """Raised when a local Windows security query cannot be completed."""


SECURITY_EVENT_LOGS = {
    "Security": (4624, 4625, 1102, 4672, 4720, 4722, 4723, 4724, 4725, 4726, 4728, 4732, 4733, 4735, 4756, 4757),
    "System": (7045,),
    "Microsoft-Windows-PowerShell/Operational": (4104,),
    "Microsoft-Windows-Windows Defender/Operational": (1116, 1117),
}


def _powershell_executable() -> str:
    if os.name != "nt":
        raise WindowsSecurityError("Windows security checks are only available on Windows.")
    executable = shutil.which("powershell.exe") or shutil.which("pwsh.exe")
    if not executable:
        raise WindowsSecurityError("PowerShell could not be found on this computer.")
    return executable


def _powershell_args(script: str) -> list[str]:
    return [
        _powershell_executable(),
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        script,
    ]


def _run_powershell_json(script: str, timeout: int = 30) -> Any:
    try:
        result = subprocess.run(
            _powershell_args(script),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired as exc:
        raise WindowsSecurityError("The Windows query took too long and was stopped.") from exc
    except OSError as exc:
        raise WindowsSecurityError(f"PowerShell could not be started: {exc}") from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip()
        raise WindowsSecurityError(detail or "The Windows security query failed.")
    try:
        return json.loads(result.stdout.lstrip("\ufeff"))
    except json.JSONDecodeError as exc:
        raise WindowsSecurityError("PowerShell returned an unreadable result.") from exc


def get_defender_status() -> dict[str, Any]:
    """Read Defender status and recent detections without changing settings."""
    script = r"""
$ErrorActionPreference = 'Stop'
$status = Get-MpComputerStatus
$detectionErrors = @()
$detections = @()
try {
    $detections = @(Get-MpThreatDetection -ErrorAction Stop |
        Sort-Object InitialDetectionTime -Descending |
        Select-Object -First 20 InitialDetectionTime, DetectionID, ThreatID, ActionSuccess, Resources)
} catch {
    $detectionErrors += [pscustomobject]@{ Source = 'Defender detections'; Error = $_.Exception.Message }
}
$result = [ordered]@{
    status = $status | Select-Object AMServiceEnabled, AntivirusEnabled,
        RealTimeProtectionEnabled, AntivirusSignatureLastUpdated,
        QuickScanStartTime, QuickScanEndTime, FullScanStartTime, FullScanEndTime
    detections = $detections
    errors = $detectionErrors
    detection_limit = 20
}
ConvertTo-Json -InputObject $result -Depth 5 -Compress
"""
    result = _run_powershell_json(script)
    if not isinstance(result, dict) or not isinstance(result.get("status"), dict):
        raise WindowsSecurityError("Defender returned an incomplete status result.")
    return result


def start_defender_scan(scan_type: str) -> subprocess.Popen:
    """Start a user-requested Defender scan; never changes Defender policy."""
    scan_types = {"quick": "QuickScan", "full": "FullScan"}
    if scan_type not in scan_types:
        raise ValueError("Scan type must be 'quick' or 'full'.")
    script = (
        "$ErrorActionPreference = 'Stop'; "
        f"try {{ Start-MpScan -ScanType {scan_types[scan_type]} -ErrorAction Stop; "
        f"Write-Output 'Defender accepted the {scan_type} scan request.' }} "
        "catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }"
    )
    try:
        return subprocess.Popen(
            _powershell_args(script),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except OSError as exc:
        raise WindowsSecurityError(f"Defender scan could not be started: {exc}") from exc


def read_security_events(days: int = 7) -> dict[str, Any]:
    """Read a bounded set of relevant local Windows events; does not edit logs."""
    if days not in {1, 7, 30}:
        raise ValueError("Choose an event-log period of 1, 7, or 30 days.")
    return _read_security_event_logs(
        days=days,
        log_names=tuple(SECURITY_EVENT_LOGS),
        max_events_per_log=50,
    )


def read_latest_windows_security_events(limit: int = 50) -> dict[str, Any]:
    """Read the latest bounded set of existing Security and System events."""
    if limit != 50:
        raise ValueError("The read-only event preview is limited to the latest 50 events.")
    result = _read_security_event_logs(
        days=None,
        log_names=("Security", "System"),
        max_events_per_log=limit,
    )
    result["events"].sort(key=_event_time_sort_key, reverse=True)
    result["events"] = result["events"][:limit]
    return result


def _read_security_event_logs(
    days: int | None,
    log_names: tuple[str, ...],
    max_events_per_log: int,
) -> dict[str, Any]:
    source_entries = ",\n".join(
        f"    @{{ Log = '{name}'; Ids = @({', '.join(map(str, SECURITY_EVENT_LOGS[name]))}) }}"
        for name in log_names
    )
    since_assignment = f"$since = (Get-Date).AddDays(-{days})" if days is not None else ""
    start_time_filter = "; StartTime = $since" if days is not None else ""
    result_days = "$null" if days is None else str(days)
    script = rf"""
$ErrorActionPreference = 'Stop'
{since_assignment}
$sources = @(
{source_entries}
)
$events = @()
$errors = @()
foreach ($source in $sources) {{
    try {{
        $found = @(Get-WinEvent -FilterHashtable @{{ LogName = $source.Log; Id = $source.Ids{start_time_filter} }} -MaxEvents {max_events_per_log} -ErrorAction Stop)
        foreach ($event in $found) {{
            $message = [string]$event.Message
            if ($message.Length -gt 4000) {{ $message = $message.Substring(0, 4000) }}
            $eventData = [ordered]@{{}}
            $xml = [xml]$event.ToXml()
            foreach ($item in @($xml.Event.EventData.Data)) {{
                if ($item -and $item.Name) {{
                    $eventData[[string]$item.Name] = [string]$item.InnerText
                }}
            }}
            $events += [pscustomobject]@{{
                Log = $source.Log
                Time = $event.TimeCreated.ToUniversalTime().ToString('o')
                EventId = $event.Id
                RecordId = $event.RecordId
                Computer = $event.MachineName
                Level = $event.LevelDisplayName
                Provider = $event.ProviderName
                Message = $message
                EventData = $eventData
            }}
        }}
    }} catch {{
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') {{
            $errors += [pscustomobject]@{{ Log = $source.Log; Error = $_.Exception.Message }}
        }}
    }}
}}
$result = [ordered]@{{ events = $events; errors = $errors; days = {result_days} }}
ConvertTo-Json -InputObject $result -Depth 5 -Compress
"""
    result = _run_powershell_json(script, timeout=60)
    if not isinstance(result, dict):
        raise WindowsSecurityError("Windows event logs returned an incomplete result.")
    return {
        "events": sorted([normalize_security_event(event) for event in _as_rows(result.get("events"))],
                         key=_event_time_sort_key, reverse=True),
        "errors": _as_rows(result.get("errors")),
        "days": days,
        "logs": list(log_names),
    }


def read_security_event_page(log_name: str, after_record_id: int = 0,
                             limit: int = 200, timeout: int = 10) -> dict[str, Any]:
    """Read the oldest next matching events, with an all-event high-water mark.

    The exact cursor record's XML fingerprint detects Record ID reuse after a
    clear/restore, even if the new log has already grown past the old cursor.
    On-demand history/preview APIs deliberately retain their existing behavior.
    """
    if log_name not in SECURITY_EVENT_LOGS:
        raise ValueError("Unsupported Windows event log.")
    if type(after_record_id) is not int or not 0 <= after_record_id < 2**63:
        raise ValueError("Invalid Windows event cursor.")
    if type(limit) is not int or type(timeout) is not int or not 1 <= limit <= 500 or not 1 <= timeout <= 10:
        raise ValueError("Event page size or query timeout is out of range.")
    event_filter = " or ".join(f"EventID={event_id}" for event_id in SECURITY_EVENT_LOGS[log_name])
    script = rf"""
$ErrorActionPreference = 'Stop'
$name = '{log_name}'
function Read-Optional([string]$xpath, [int]$count, [bool]$oldest) {{
    try {{
        if ($oldest) {{ return @(Get-WinEvent -LogName $name -FilterXPath $xpath -Oldest -MaxEvents $count -ErrorAction Stop) }}
        return @(Get-WinEvent -LogName $name -FilterXPath $xpath -MaxEvents $count -ErrorAction Stop)
    }} catch {{
        if ($_.FullyQualifiedErrorId -like 'NoMatchingEventsFound*') {{ return @() }}
        throw
    }}
}}
function Fingerprint($event) {{
    if ($null -eq $event) {{ return '' }}
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {{ return [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($event.ToXml()))).Replace('-', '').ToLowerInvariant() }}
    finally {{ $sha.Dispose() }}
}}
$configuration = Get-WinEvent -ListLog $name -ErrorAction Stop
if (-not $configuration.IsEnabled) {{ throw 'Event log is disabled; coverage is unavailable.' }}
$first = @(Read-Optional '*' 1 $true)
$last = @(Read-Optional '*' 1 $false)
$oldest = if ($first.Count) {{ [long]$first[0].RecordId }} else {{ 0 }}
$newest = if ($last.Count) {{ [long]$last[0].RecordId }} else {{ 0 }}
$latestFingerprint = if ($last.Count) {{ Fingerprint $last[0] }} else {{ '' }}
$anchor = @(Read-Optional '*[System[EventRecordID={after_record_id}]]' 1 $false)
$anchorFingerprint = if ($anchor.Count) {{ Fingerprint $anchor[0] }} else {{ '' }}
$xpath = '*[System[(EventRecordID > {after_record_id}) and (EventRecordID <= ' + $newest + ') and ({event_filter})]]'
$found = @(Read-Optional $xpath {limit + 1} $true)
$more = $found.Count -gt {limit}
$events = @()
foreach ($event in @($found | Select-Object -First {limit})) {{
    $xml = [xml]$event.ToXml()
    $eventData = [ordered]@{{}}
    foreach ($item in @($xml.Event.EventData.Data)) {{
        if ($item -and $item.Name) {{ $eventData[[string]$item.Name] = [string]$item.InnerText }}
    }}
    $events += [pscustomobject]@{{
        Log = $name; EventId = $event.Id; RecordId = $event.RecordId
        Computer = $event.MachineName
        Time = $event.TimeCreated.ToUniversalTime().ToString('o')
        Provider = $event.ProviderName; Level = $event.LevelDisplayName
        Message = ([string]$event.Message).Substring(0, [Math]::Min(4000, ([string]$event.Message).Length))
        EventData = $eventData; Fingerprint = (Fingerprint $event)
    }}
}}
# Ensure the queried generation/high-water record still exists unchanged.
if ($newest -gt 0) {{
    $endAnchor = @(Read-Optional ('*[System[EventRecordID=' + $newest + ']]') 1 $false)
    if (-not $endAnchor.Count -or (Fingerprint $endAnchor[0]) -ne $latestFingerprint) {{
        throw 'Event log changed during page retrieval; batch was not checkpointed. Retry is required.'
    }}
    $endFirst = @(Read-Optional '*' 1 $true)
    if (-not $endFirst.Count -or [long]$endFirst[0].RecordId -gt [Math]::Max([long]({after_record_id} + 1), $oldest)) {{
        throw 'Event log retention advanced over unread records during retrieval; coverage may be incomplete. Batch was not checkpointed.'
    }}
}} else {{
    $endLast = @(Read-Optional '*' 1 $false)
    if ($endLast.Count) {{ throw 'Event log changed during empty-log retrieval; retry required.' }}
}}
$nextId = if ($more) {{ [long]$events[-1].RecordId }} else {{ $newest }}
$nextFingerprint = if ($more) {{ $events[-1].Fingerprint }} else {{ $latestFingerprint }}
ConvertTo-Json -InputObject ([ordered]@{{
    log = $name; oldest = $oldest; newest = $newest
    anchor_fingerprint = $anchorFingerprint; next_record_id = $nextId
    next_fingerprint = $nextFingerprint; more = $more; events = $events
}}) -Depth 7 -Compress
"""
    result = _run_powershell_json(script, timeout=timeout)
    if not isinstance(result, dict) or result.get("log") != log_name:
        raise WindowsSecurityError("Windows event page returned an incomplete result.")
    try:
        oldest, newest, next_id = (result[key] for key in ("oldest", "newest", "next_record_id"))
        if any(type(value) is not int or value < 0 for value in (oldest, newest, next_id)):
            raise ValueError("Invalid record boundaries")
        if oldest > newest or (oldest == 0) != (newest == 0) or next_id > newest or type(result["more"]) is not bool:
            raise ValueError("Invalid page boundaries")
        if not isinstance(result.get("events"), list):
            raise ValueError("Missing or invalid event batch")
        events = result["events"]
        if len(events) > limit:
            raise ValueError("Oversized event page")
        previous = after_record_id
        for event in events:
            if not isinstance(event, dict):
                raise ValueError("Invalid event object")
            record_id = event.get("RecordId")
            if (event.get("Log") != log_name or type(record_id) is not int
                    or not previous < record_id <= newest or record_id > next_id
                    or type(event.get("EventId")) is not int or not event.get("Time")
                    or not re.fullmatch(r"[0-9a-f]{64}", str(event.get("Fingerprint", "")))):
                raise ValueError("Invalid or unordered event record")
            previous = record_id
        if next_id and not re.fullmatch(r"[0-9a-f]{64}", str(result.get("next_fingerprint", ""))):
            raise ValueError("Missing checkpoint fingerprint")
        if result["more"] and (not events or next_id != events[-1]["RecordId"]):
            raise ValueError("Non-progressing event page")
        if not result["more"] and next_id != newest:
            raise ValueError("Incomplete high-water checkpoint")
        if not isinstance(result.get("anchor_fingerprint"), str) or (
            result["anchor_fingerprint"] and not re.fullmatch(r"[0-9a-f]{64}", result["anchor_fingerprint"])
        ):
            raise ValueError("Invalid cursor anchor fingerprint")
    except (KeyError, TypeError, ValueError) as exc:
        raise WindowsSecurityError(f"Invalid Windows event page: {exc}") from exc
    return {**result, "events": [normalize_security_event(event) for event in events]}


def inspect_startup_items() -> dict[str, Any]:
    """List startup apps and scheduled tasks for review; never disable or edit them."""
    script = r"""
$ErrorActionPreference = 'Stop'
$errors = @()
$startup = @()
$tasks = @()
$taskCount = 0
try {
    $startup = @(Get-CimInstance Win32_StartupCommand -ErrorAction Stop |
        Select-Object -First 200 Name, Command, Location, User)
} catch {
    $errors += [pscustomobject]@{ Source = 'Startup apps'; Error = $_.Exception.Message }
}
try {
    $allTasks = @(Get-ScheduledTask -ErrorAction Stop)
    $taskCount = $allTasks.Count
    foreach ($task in ($allTasks | Select-Object -First 300)) {
        foreach ($action in $task.Actions) {
            $tasks += [pscustomobject]@{
                Name = $task.TaskName
                Path = $task.TaskPath
                State = [string]$task.State
                Execute = [string]$action.Execute
                Arguments = [string]$action.Arguments
                User = [string]$task.Principal.UserId
            }
        }
    }
} catch {
    $errors += [pscustomobject]@{ Source = 'Scheduled tasks'; Error = $_.Exception.Message }
}
$result = [ordered]@{
    startup = $startup
    tasks = $tasks
    totalTasks = $taskCount
    errors = $errors
}
ConvertTo-Json -InputObject $result -Depth 5 -Compress
"""
    result = _run_powershell_json(script, timeout=60)
    if not isinstance(result, dict):
        raise WindowsSecurityError("Startup inventory returned an incomplete result.")
    startup = _as_rows(result.get("startup"))
    tasks = _as_rows(result.get("tasks"))
    for item in startup:
        item["review_reasons"] = _review_reasons(
            f"{item.get('Command', '')} {item.get('Location', '')}"
        )
    for item in tasks:
        item["review_reasons"] = _review_reasons(
            f"{item.get('Execute', '')} {item.get('Arguments', '')}"
        )
    return {
        "startup": startup,
        "tasks": tasks,
        "total_tasks": int(result.get("totalTasks") or 0),
        "truncated": int(result.get("totalTasks") or 0) > 300,
        "errors": _as_rows(result.get("errors")),
    }


def inspect_running_processes() -> dict[str, Any]:
    """Read a bounded process inventory and flag command-line review signals."""
    script = r"""
$ErrorActionPreference = 'Stop'
$processes = @(Get-CimInstance Win32_Process -ErrorAction Stop |
    Select-Object -First 500 ProcessId, ParentProcessId, Name, ExecutablePath, CommandLine)
$result = [ordered]@{ processes = $processes; total = $processes.Count }
ConvertTo-Json -InputObject $result -Depth 4 -Compress
"""
    result = _run_powershell_json(script, timeout=60)
    if not isinstance(result, dict):
        raise WindowsSecurityError("Process inventory returned an incomplete result.")
    processes = _as_rows(result.get("processes"))
    for process in processes:
        process["review_reasons"] = _review_reasons(
            f"{process.get('ExecutablePath', '')} {process.get('CommandLine', '')}"
        )
    total = int(result.get("total") or 0)
    return {
        "processes": processes,
        "total": total,
        "truncated": total > 500,
    }


def _as_rows(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [row for row in value if isinstance(row, dict)]
    return []


def normalize_security_event(event: dict[str, Any]) -> dict[str, Any]:
    """Add consistent account and network fields while retaining raw event data."""
    data = event.get("EventData")
    fields = {
        str(key).casefold(): str(value).strip()
        for key, value in data.items()
        if value is not None
    } if isinstance(data, dict) else {}
    event_fields = {
        str(key).casefold(): str(value).strip()
        for key, value in event.items()
        if value is not None
    }

    def field(*names: str) -> str:
        for name in names:
            value = fields.get(name.casefold(), "") or event_fields.get(name.casefold(), "")
            if value and value not in {"-", "N/A", "NULL"}:
                return value
        return ""

    try:
        event_id = int(event.get("EventId", event.get("Id", 0)))
    except (TypeError, ValueError):
        event_id = 0

    account_fields = {
        4624: ("TargetUserName", "SubjectUserName"),
        4625: ("TargetUserName", "SubjectUserName"),
        4672: ("SubjectUserName", "TargetUserName"),
        4720: ("TargetUserName", "SubjectUserName"),
        4732: ("MemberName", "SubjectUserName", "TargetUserName"),
        1102: ("SubjectUserName", "TargetUserName"),
        7045: ("AccountName", "TargetUserName"),
    }
    account = field(*(account_fields.get(
        event_id,
        ("TargetUserName", "SubjectUserName", "MemberName", "AccountName", "UserName"),
    )), "account")
    domain = field("TargetDomainName", "SubjectDomainName", "MemberDomain")
    if account and domain and "\\" not in account and domain not in {".", "-"}:
        account = f"{domain}\\{account}"
    descriptions = {
        4624: "Successful Windows logon",
        4625: "Failed Windows logon",
        4672: "Special privileges assigned to a logon",
        4720: "Windows user account created",
        4732: "Member added to a local security group",
        1102: "Windows Security audit log cleared",
        7045: "Windows service installed",
    }
    timestamp_source = {key: value for key, value in event.items()
        if not (key == 'TimeUtc' and event.get('Time') is not None)}
    timestamp_selection, timestamp_value = resolve_event_timestamp(timestamp_source)
    timestamp_utc, timestamp_local = _event_timestamp_values(timestamp_value.utc)
    return {
        **event,
        "TimeUtc": timestamp_utc,
        "TimeLocal": timestamp_local,
        "TimestampOriginal": event.get("TimestampOriginal", timestamp_value.original),
        "TimestampStatus": timestamp_value.status,
        "TimestampSource": timestamp_selection['column'],
        "account": account,
        "logon_type": field("LogonType", "logon_type"),
        "source_ip": field("IpAddress", "SourceNetworkAddress", "SourceIp", "source_ip"),
        "description": str(
            event.get("Message")
            or event.get("description")
            or descriptions.get(event_id, "Windows event")
        ),
    }


_WINDOWS_DATE_PATTERN = re.compile(r"^/Date\((-?\d+)([+-]\d{4})?\)/$")


def _event_timestamp_values(
    value: Any,
    local_timezone: tzinfo | None = None,
) -> tuple[str | None, str]:
    """Return canonical UTC and local-display timestamps without changing source data."""
    resolved = parse_timestamp(value)
    if resolved.utc is None:
        return None, "Unknown"
    utc_timestamp = resolved.utc
    # Ask the host for the offset at this instant, not its current seasonal offset.
    try:
        display_zone = local_timezone or utc_timestamp.to_pydatetime(warn=False).astimezone().tzinfo
        local_timestamp = utc_timestamp.tz_convert(display_zone)
    except (OSError, OverflowError, ValueError):
        # Some Windows hosts cannot render local dates before the Unix epoch.
        # The independently resolved UTC instant remains available.
        local_timestamp = None
    precision = 'milliseconds' if utc_timestamp.value % 1_000_000 == 0 else 'auto'
    return (
        utc_timestamp.isoformat(timespec=precision).replace("+00:00", "Z"),
        local_timestamp.isoformat(sep=" ", timespec=precision) if local_timestamp is not None else "Unknown",
    )


def _event_time_sort_key(event):
    _, resolved = resolve_event_timestamp(event)
    # Unresolved rows form a separate trailing group even for pre-1970 events.
    native = str(event.get('RecordId', '')).zfill(24)
    return (resolved.utc is not None, resolved.utc.value if resolved.utc is not None else 0, str(event.get('Log', '')), native)


def summarize_security_events(events: list[dict[str, Any]]) -> dict[str, int]:
    """Count selected event IDs to make the read-only log review easier to triage."""
    counts = {
        "failed_logins": 0,
        "successful_logins": 0,
        "security_log_cleared": 0,
        "new_services": 0,
        "privilege_changes": 0,
        "account_changes": 0,
        "powershell_script_events": 0,
        "defender_detections": 0,
        "defender_actions": 0,
    }
    event_counts = {
        4625: "failed_logins",
        4624: "successful_logins",
        1102: "security_log_cleared",
        7045: "new_services",
        4672: "privilege_changes",
        4720: "account_changes",
        4722: "account_changes",
        4723: "account_changes",
        4724: "account_changes",
        4725: "account_changes",
        4726: "account_changes",
        4728: "account_changes",
        4732: "account_changes",
        4733: "account_changes",
        4735: "account_changes",
        4756: "account_changes",
        4757: "account_changes",
        4104: "powershell_script_events",
        1116: "defender_detections",
        1117: "defender_actions",
    }
    for event in events:
        try:
            key = event_counts.get(int(event.get("EventId", event.get("Id"))))
        except (TypeError, ValueError):
            continue
        if key:
            counts[key] += 1
    return counts


def _review_reasons(command: str) -> list[str]:
    lowered = command.lower().replace("/", "\\")
    reasons = []
    if re.search(r"\\appdata\\(?:local\\temp|roaming)\\|\\downloads\\|%temp%", lowered):
        reasons.append("Runs from a user-writable or temporary folder.")
    if re.search(r"(?:-enc(?:odedcommand)?\b|\bfrombase64string\b)", lowered):
        reasons.append("Contains an encoded-command indicator.")
    if re.search(r"\b(?:downloadstring|invoke-webrequest|bitsadmin)\b|https?://", lowered):
        reasons.append("Contains a network-download indicator.")
    if re.search(r"\b(?:mshta|wscript|cscript|regsvr32)\b", lowered) and re.search(
        r"https?://|\.js\b|\.vbs\b|\.hta\b", lowered
    ):
        reasons.append("Uses a script host or system utility with a script or URL.")
    return reasons


def build_review_report(
    defender: dict[str, Any] | None,
    events: dict[str, Any] | None,
    startup: dict[str, Any] | None,
    defender_scan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a local downloadable snapshot from the results currently collected."""
    return {
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "Local Windows review; collected results only; no changes made.",
        "defender": defender,
        "defender_scan": defender_scan,
        "security_events": events,
        "startup_inventory": startup,
        "limitations": [
            "A read-only event review and startup inventory are not a full forensic examination.",
            "Startup review flags are heuristics for human review, not proof of malware.",
            "Defender manages its own scan status and remediation; this dashboard does not remove files.",
        ],
    }
