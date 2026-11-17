import os

# Windows fix: PATH ki duplicate entries hata do, warna XGBoost import par
# "environment variable is longer than 32767 characters" error aa sakta hai
_seen, _clean = set(), []
for _p in os.environ.get("PATH", "").split(os.pathsep):
    if _p and _p.lower() not in _seen:
        _seen.add(_p.lower())
        _clean.append(_p)
os.environ["PATH"] = os.pathsep.join(_clean)

# XGBoost ko sab se pehle import karo (jab PATH chhota ho), taake baad mein
# koi doosri library PATH bara kar bhi isay load karte waqt error na de
import xgboost  # noqa: F401

import hashlib
import html
import importlib
import re
import streamlit as st
import pandas as pd
import sys
import json
import uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

# Root directory ko path mein add karna taake modules easily import ho sakein
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.integrity import EvidenceIntegrity
from modules.evidence_storage import save_evidence_copy
from modules.scanned_evidence import (
    add_scanned_evidence,
    select_saved_scan, scan_record_id, invalidate_scan_session,
    evidence_matches_search,
    evidence_search_display_name,
    load_scanned_evidence_aliases,
    load_scanned_evidence_records,
)
from modules.evidence_storage import evidence_id_for_file
from modules.alert_investigation import (
    alert_file_details,
    alert_identity,
    promote_alert_to_evidence,
)
from modules.parser import LogParser
from modules.ml_detector import MLAnomalyDetector
from modules.model_store import ModelReliabilityError
from modules.timeline import TimelineConstructor
from modules.event_timestamps import select_timestamp_column, identifier_field, CHRONOLOGY_VERSION
from modules.semantic_search import prepare_evidence_search, search_evidence
from modules.ai_reporter import (
    LocalLLMReporter,
    ml_to_report_findings,
    yara_to_report_findings,
)
from modules.rules import RuleEngine, load_log_csv
from modules.yara_scanner import YaraScanner, YARA_AVAILABLE
from modules.safety_checks import SCAN_EXTENSIONS, check_uploaded_file, inspect_url
from modules.laptop_scanner import (
    MAX_LAPTOP_FILES,
    MAX_LAPTOP_FILE_SIZE,
    MAX_SCAN_SECONDS,
    scan_laptop,
)
from modules.realtime_monitor import RealtimeMonitor, classify_security_event
from modules.realtime_monitor import SYNTHETIC_EVENT_TEMPLATES, make_synthetic_security_event
import modules.background_monitor as background_monitor_module
background_monitor_module = importlib.reload(background_monitor_module)
from modules.background_monitor import (
    BackgroundMonitorError,
    MONITOR_LOG_PATH,
    STATE_DIR,
    get_background_status,
    install_startup_task,
    load_background_alerts,
    remove_startup_task,
    start_background_monitor,
    stop_background_monitor,
)
from modules.pdf_report import render_forensic_pdf
from modules.laptop_findings import collect_laptop_findings, laptop_source_coverage
from modules.report_validation import (
    bind_report_context, validate_report_export, render_forensic_text, DRAFT_WARNING,
)
from modules.evidence_reports import (
    build_saved_evidence_report, build_laptop_scan_report,
    merge_investigation_findings,
    saved_evidence_findings,
)
from modules.report_history import load_forensic_reports, save_forensic_report
from modules.security_history import load_scan_history, save_scan_report
from modules.windows_security import (
    WindowsSecurityError,
    build_review_report,
    get_defender_status,
    inspect_running_processes,
    inspect_startup_items,
    normalize_security_event,
    read_latest_windows_security_events,
    read_security_events,
    start_defender_scan,
    summarize_security_events,
)
import forensic_ui as ui

try:
    import plotly.express as px
    PLOTLY = True
except Exception:
    PLOTLY = False

ROOT = Path(__file__).resolve().parent.parent
REPORT_DIR = ROOT / "reports"
RAW_DIR = ROOT / "data" / "raw_evidence"
CASES_DIR = ROOT / "data" / "cases"
DEFAULT_CASE_ID = "CASE-2026-001"

LOG_EXT = (".csv", ".json", ".log", ".txt")
BINARY_EXT = (".exe", ".dll", ".ps1", ".bat", ".vbs", ".js", ".php", ".jsp", ".sh", ".py", ".bin", ".dmp", ".zip")
IMAGE_EXTENSIONS = {".bmp", ".gif", ".ico", ".jpeg", ".jpg", ".png", ".svg", ".webp"}

SEV_COLORS = ui.SEV_COLORS
HASH_RE = re.compile(r"File uploaded: (.+?) \| SHA256: ([0-9a-fA-F]{64})")

# Page configuration
st.set_page_config(
    page_title="Aegis Forensics",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

ui.inject_css()
sev_badge = ui.sev_badge


# ----------------------------------------------------------------------------
# Cached heavy work, so moving a widget does not re-run ML / YARA every time
# ----------------------------------------------------------------------------
@st.cache_data(show_spinner="Running ML detection...")
def cached_ml(_df, sha, model, threshold, split, checkpoint_signature):
    det = MLAnomalyDetector(_df, model=model, threshold=threshold, split=split, evidence_sha256=sha)
    out = det.detect_anomalies()
    return out, det.last_mode


@st.cache_data(show_spinner="Scanning with YARA...")
def cached_yara(path, sha, rules_sig):
    return YaraScanner().scan_file(path)


SEVERITY_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
ALERT_PAGE_SIZE = 5
ML_DETAIL_PAGE_SIZE = 10
SEMANTIC_SEARCH_MAX_RECORDS = 10_000
RULE_FRIENDLY_TEXT = {
    "Brute force login attempts": (
        "Several failed sign-in attempts were recorded close together.",
        "Confirm the attempts with the account owner and review the source before blocking access.",
    ),
    "Successful login after brute force": (
        "A successful sign-in followed a series of failed attempts.",
        "Verify the sign-in with the account owner and secure the account if it was not expected.",
    ),
    "Login at unusual hour": (
        "A sign-in was recorded during the configured unusual-hours period.",
        "Ask the account owner whether the sign-in was expected.",
    ),
    "Audit log cleared": (
        "A security log was cleared. This can remove useful investigation records.",
        "Preserve remaining logs and confirm who cleared the log and why.",
    ),
    "New user account created": (
        "A new user account was created.",
        "Confirm the account was approved; disable it only through your normal authorized process.",
    ),
    "Account added to administrators": (
        "An account was added to an administrator group.",
        "Confirm the change was approved and review the account's access.",
    ),
    "New service installed": (
        "A new Windows service was installed.",
        "Confirm the service and its publisher are expected before taking action.",
    ),
}


def _finding_priority(finding):
    severity = finding.get("severity", "Low")
    evidence = finding.get("evidence", [])
    return (
        SEVERITY_RANK.get(severity, len(SEVERITY_RANK)),
        0 if evidence else 1,
        str(finding.get("source", "")),
        str(finding.get("id", "")),
    )


def _alert_summary(findings):
    counts = Counter(item.get("severity", "Low") for item in findings)
    highest = min(
        (item.get("severity", "Low") for item in findings),
        key=lambda severity: SEVERITY_RANK.get(severity, len(SEVERITY_RANK)),
        default="None",
    )
    representatives = {}
    for item in findings:
        source = str(item.get("source", "rule")).lower()
        identity = (
            source,
            item.get("model_name")
            if source == "ml"
            else item.get("rule") or item.get("title") or item.get("id"),
        )
        if identity not in representatives or _finding_priority(item) < _finding_priority(representatives[identity]):
            representatives[identity] = item
    top = sorted(representatives.values(), key=_finding_priority)[:3]
    next_action = (
        _finding_presentation(top[0])["recommendation"]
        if top
        else "No follow-up is needed for this scan. Review coverage limitations before relying on a clean result."
    )
    return {
        "total": len(findings),
        "severity_counts": counts,
        "highest_severity": highest,
        "top_findings": top,
        "next_action": next_action,
    }


def _reset_pagination_if_needed(widget_key, page_count):
    current_page = st.session_state.get(widget_key, 1)
    if not isinstance(current_page, int) or current_page < 1 or current_page > page_count:
        st.session_state[widget_key] = 1


def _finding_presentation(finding):
    source = str(finding.get("source", "rule")).lower()
    severity = finding.get("severity", "Medium")
    evidence = finding.get("evidence", [])
    if not isinstance(evidence, list):
        evidence = []
    location = next((item for item in evidence if isinstance(item, dict)), {})
    file_name = finding.get("file") or finding.get("path") or location.get("file") or "Evidence item"
    line = finding.get("original_csv_line") or location.get("line")
    affected = str(file_name)
    if location.get("record_number") is not None:
        affected += f" · logical CSV record {location['record_number']}"
    if line:
        end = location.get("line_end") or finding.get("original_csv_line_end") or line
        affected += f" · CSV line {line}" if end == line else f" · CSV lines {line}–{end}"

    if source == "ml":
        model = finding.get("model_name", "ML model")
        return {
            "title": "Unusual record flagged for review",
            "severity": severity,
            "affected": affected,
            "explanation": (
                f"{model} flagged this record for review. This is a model prediction, "
                "not confirmation of malicious activity."
            ),
            "recommendation": (
                "Review this source row and compare related network activity before taking action."
            ),
            "certainty": "Model prediction · unconfirmed",
            "icon": "eye",
        }
    if source == "ml_aggregate":
        return {
            "title": f"{finding.get('count', 0):,} unusual records flagged",
            "severity": severity,
            "affected": affected,
            "explanation": (
                f"{finding.get('model_name', 'The model')} flagged these records for review. "
                "Predictions are not confirmation of malicious activity."
            ),
            "recommendation": (
                "Search the individual records and compare them with expected network activity."
            ),
            "certainty": "Aggregated model predictions",
            "icon": "eye",
        }
    if source == "yara":
        return {
            "title": "File content matched a detection rule",
            "severity": severity,
            "affected": affected,
            "explanation": (
                "Some file content matched a saved detection rule. A match needs review and "
                "does not by itself confirm malicious activity."
            ),
            "recommendation": (
                "Keep the original file unchanged and ask a reviewer to verify the match."
            ),
            "certainty": "Rule match · review required",
            "icon": "file",
        }
    if source in {"static heuristic", "heuristic"}:
        indicator = str(finding.get("rule", "A basic content indicator was found.")).rstrip(".")
        return {
            "title": "File indicator needs review",
            "severity": severity,
            "affected": affected,
            "explanation": (
                f"{indicator[:140]}. This does not confirm "
                "that the file is harmful."
            ),
            "recommendation": (
                "Keep the original unchanged and verify the file's source before opening or removing it."
            ),
            "certainty": "Static indicator · unconfirmed",
            "icon": "file",
        }
    if source in {"windows event", "windows event log"}:
        event_id = finding.get("event_id")
        event_titles = {
            4625: "Repeated or failed Windows sign-in",
            4672: "Special access granted to a sign-in",
            4720: "Windows account created",
            4732: "Account added to a local group",
            1102: "Windows security log cleared",
            7045: "Windows service installed",
        }
        return {
            "title": event_titles.get(event_id, "Windows security activity needs review"),
            "severity": severity,
            "affected": finding.get("affected", f"Windows event log · Event {event_id or 'unknown'}"),
            "explanation": (
                "Windows recorded a security-related change. Confirm it was expected before treating "
                "it as a threat."
            ),
            "recommendation": (
                "Review the account, device, and change with the system owner."
            ),
            "certainty": "System event · review required",
            "icon": "alert",
        }
    if source == "defender":
        return {
            "title": finding.get("title", "Microsoft Defender detection"),
            "severity": severity,
            "affected": finding.get("affected", "Windows Defender"),
            "explanation": (
                "Microsoft Defender reported a detection. Review Defender's status and action details "
                "before deciding what to do."
            ),
            "recommendation": (
                "Open Windows Security to confirm the detection and any action already taken."
            ),
            "certainty": "Reported by Microsoft Defender",
            "icon": "shield",
        }
    if source == "url":
        indicator = str(finding.get("description", "A URL-format indicator was found.")).rstrip(".")
        indicator = indicator.split("; ", 1)[0]
        return {
            "title": "URL has indicators that need review",
            "severity": severity,
            "affected": finding.get("affected", "URL host"),
            "explanation": (
                f"{indicator[:180]} This local check did not visit the site or confirm that it is harmful."
            ),
            "recommendation": (
                "Do not open the link unless you can verify the destination through a trusted source."
            ),
            "certainty": "URL heuristic · unconfirmed",
            "icon": "eye",
        }
    if source in {"monitor capacity", "file monitor", "windows event monitor"}:
        return {
            "title": finding.get("title", "Monitoring check needs attention"),
            "severity": severity,
            "affected": affected,
            "explanation": (
                "A monitoring check could not fully review this activity. This is a coverage "
                "notice, not a confirmed threat."
            ),
            "recommendation": (
                "Check the monitor status and review the affected item manually."
            ),
            "certainty": "Monitoring coverage notice",
            "icon": "eye",
        }
    if source == "synthetic event":
        return {
            "title": finding.get("title", "Synthetic security-event demonstration"),
            "severity": severity,
            "affected": finding.get("affected", "Generated demonstration data"),
            "explanation": (
                "This example was generated by Aegis for demonstration. It is not a real Windows "
                "event and is not evidence of activity on this computer."
            ),
            "recommendation": (
                "Use this example only to demonstrate alert review and dashboard behavior."
            ),
            "certainty": "Synthetic · not a Windows event",
            "icon": "alert",
        }

    rule_name = str(finding.get("rule", "Security activity needs review"))
    friendly_text = RULE_FRIENDLY_TEXT.get(rule_name)
    if friendly_text:
        explanation, recommendation = friendly_text
    else:
        explanation = (
            "A security rule found activity that needs review. This is an alert, not proof "
            "that the activity was harmful."
        )
        recommendation = "Review the referenced evidence and confirm whether the activity was expected."
    return {
        "title": rule_name,
        "severity": severity,
        "affected": affected,
        "explanation": explanation,
        "recommendation": recommendation,
        "certainty": "Needs review",
        "icon": "alert",
    }


def _windows_event_findings(events, classification_required=False):
    severity_by_event = {
        1102: "High",
        4726: "High",
        4728: "High",
        4732: "High",
        4735: "High",
        4756: "High",
        4625: "Medium",
        4672: "Medium",
        4720: "Medium",
        4722: "Medium",
        4723: "Medium",
        4724: "Medium",
        4725: "Medium",
        4733: "Medium",
        7045: "Medium",
        4104: "Medium",
        1116: "High",
    }
    findings = []
    for event in events:
        normalized = normalize_security_event(event)
        event_id = normalized.get("EventId")
        try:
            event_id = int(event_id)
        except (TypeError, ValueError):
            continue
        classification, reasons = classify_security_event(normalized)
        if classification_required and classification == "Normal":
            continue
        event_identity = hashlib.sha256(
            json.dumps(normalized, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:12]
        findings.append({
            "id": f"EV-{event_identity}",
            "source": "windows event",
            "severity": severity_by_event.get(event_id, "Low"),
            "event_id": event_id,
            "affected": f"{normalized.get('Log', 'Windows')} · Event {event_id}",
            "description": normalized.get("description", normalized.get("Message", "")),
            "classification": classification,
            "classification_reasons": reasons,
            "evidence": [{
                "file": normalized.get("Log", "Windows event log"),
                "record_id": normalized.get("RecordId", "not recorded"),
            }],
            "technical_record": normalized,
        })
    return findings


def _defender_alert_findings(detections):
    findings = []
    for detection in detections:
        if not isinstance(detection, dict):
            continue
        detection_identity = hashlib.sha256(
            json.dumps(detection, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:12]
        title = str(
            detection.get("ThreatName")
            or detection.get("Name")
            or detection.get("DetectionName")
            or "Microsoft Defender detection"
        )
        findings.append({
            "id": f"DEF-{detection_identity}",
            "source": "defender",
            "severity": "High",
            "title": title,
            "affected": str(
                detection.get("Resources")
                or detection.get("Path")
                or detection.get("ProcessName")
                or "Windows Defender"
            ),
            "description": "Reported by Microsoft Defender.",
            "technical_record": detection,
            "evidence": [{"file": "Microsoft Defender detection history"}],
        })
    return findings


def _monitor_alert_findings(alerts):
    findings = []
    for alert in alerts:
        evidence = alert.get("evidence")
        evidence = evidence if isinstance(evidence, dict) else {}
        source = str(alert.get("source", "monitor"))
        if evidence.get("detection_id"):
            normalized_source = "behavioral"
            event_id = None
        elif source.casefold().startswith("windows event"):
            normalized_source = "windows event"
            event_id = evidence.get("event_id")
        elif source.casefold() == "yara":
            normalized_source = "yara"
            event_id = None
        elif source.casefold() in {"monitor capacity", "file monitor", "windows event monitor"}:
            normalized_source = source.casefold()
            event_id = None
        else:
            normalized_source = "static heuristic"
            event_id = None
        path = evidence.get("path") or evidence.get("file") or source
        alert_identity = hashlib.sha256(
            json.dumps(alert, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()[:12]
        findings.append({
            **(evidence if evidence.get("detection_id") else {}),
            "id": f"MON-{alert_identity}",
            "source": normalized_source,
            "detection_type": source,
            "severity": alert.get("severity", "Low"),
            "title": str(alert.get("message", "Monitoring alert")),
            "description": str(alert.get("message", "Monitoring alert")),
            "created_at_utc": alert.get("created_at_utc"),
            "rule": evidence.get("rule"),
            "file": str(path),
            "affected": str(path),
            "event_id": event_id,
            "technical_record": alert,
            "evidence": evidence.get("evidence", []) if evidence.get("detection_id") else [{"file": str(path)}],
        })
    return findings


def _mark_false_positive_for_review(finding, context, case_id):
    from modules.finding_reviews import mark_for_review, review_identity
    review_key = review_identity(finding, case_id)
    reviewed = st.session_state.setdefault("false_positive_reviews", {})
    source = finding.get("file") or finding.get("path") or context
    audit = mark_for_review(finding, case_id)
    reviewed[review_key] = {
        "context": context,
        "source": source,
        "marked_at_utc": datetime.now(timezone.utc).isoformat(),
        "audit_entry": audit,
    }


def _render_technical_finding(finding, source_rows=None):
    evidence = finding.get("evidence", [])
    line_numbers = {
        int(item["line"])
        for item in evidence
        if isinstance(item, dict) and item.get("line") is not None
    }
    record_numbers = {item["record_number"] for item in evidence
        if isinstance(item, dict) and item.get("record_number") is not None}
    original_line = finding.get("original_csv_line")
    if original_line is not None:
        line_numbers.add(int(original_line))
    with st.expander("Technical Details", expanded=False):
        st.caption(
            f"Finding {finding.get('id', 'not recorded')} · "
            f"SHA-256: {finding.get('sha256', 'not recorded')}"
        )
        if finding.get("source") == "ml":
            if finding.get("count") is not None:
                st.caption(
                    f"Model: {finding.get('model_name', 'not recorded')} · "
                    f"Checkpoint: {finding.get('checkpoint_split', 'not recorded')} · "
                    f"Records in this group: {finding['count']:,}"
                )
            else:
                st.caption(
                    f"Model: {finding.get('model_name', 'not recorded')} · "
                    f"Checkpoint: {finding.get('checkpoint_split', 'not recorded')} · "
                    f"Model score: {finding.get('ml_score', 'not recorded')} · "
                    f"anomaly score: {finding.get('anomaly_score', 'not recorded')}"
                )
        if finding.get("technical_record"):
            st.json(finding["technical_record"], expanded=False)
        if finding.get("rule"):
            st.caption(f"Detection rule: {finding['rule']}")
        if (line_numbers or record_numbers) and source_rows is not None:
            from modules.csv_evidence import source_locator
            mask = [source_locator(source_rows, index).get("record_number") in record_numbers
                    or source_locator(source_rows, index).get("line") in line_numbers
                    for index in source_rows.index]
            matched_rows = source_rows.loc[mask]
            if not matched_rows.empty:
                st.dataframe(matched_rows.head(10), use_container_width=True, hide_index=True)
            else:
                st.caption("The referenced CSV row is not available in the current view.")
        if finding.get("matches"):
            st.json(finding["matches"][:10], expanded=False)


def _alert_widget_identity(context, finding, occurrence_index=0):
    context_key = re.sub(r"[^a-zA-Z0-9_-]", "_", str(context))
    finding_key = re.sub(
        r"[^a-zA-Z0-9_-]",
        "_",
        str(finding.get("id") or "finding"),
    )
    return f"{context_key}_{finding_key}_{occurrence_index}"


def _render_threat_alert(
    finding,
    context,
    source_rows=None,
    show_actions=True,
    case_id=None,
    evidence_context=None,
    occurrence_index=0,
):
    presentation = _finding_presentation(finding)
    detection_type = str(
        finding.get("detection_type") or finding.get("source") or "Detection"
    ).replace("_", " ").title()
    rule = finding.get("rule")
    if rule and str(rule) not in detection_type:
        detection_type = f"{detection_type} · {rule}"
    timestamp = (
        finding.get("created_at_utc")
        or finding.get("scanned_at_utc")
        or finding.get("first_seen")
    )
    presentation["detection_type"] = detection_type
    presentation["timestamp"] = (
        _protection_alert_time({"created_at_utc": timestamp}) if timestamp else ""
    )
    card_fields = {
        key: value
        for key, value in presentation.items()
        if key not in {"detection_type", "timestamp"}
    }
    card_markup = ui.threat_alert_card(**card_fields)
    metadata = " · ".join(
        value
        for value in (presentation["detection_type"], presentation["timestamp"])
        if value
    )
    if metadata:
        metadata_markup = (
            '<div class="threat-meta" style="color:#94A3B8;font-size:.73rem;margin-top:3px">'
            f'{html.escape(metadata)}</div>'
        )
        card_markup = card_markup.replace(
            '<p class="threat-explanation">',
            f'{metadata_markup}<p class="threat-explanation">',
            1,
        )
    st.markdown(
        card_markup,
        unsafe_allow_html=True,
    )
    if show_actions:
        key_suffix = _alert_widget_identity(context, finding, occurrence_index)
        action_cols = st.columns(3 if case_id else 2)
        review_col = action_cols[0]
        investigate_col = action_cols[2] if case_id else action_cols[1]
        if review_col.button(
            "Review Evidence",
            key=f"review_{key_suffix}",
            use_container_width=True,
        ):
            st.session_state[f"review_evidence_{key_suffix}"] = not st.session_state.get(
                f"review_evidence_{key_suffix}", False
            )
        if case_id:
            false_positive_col = action_cols[1]
            if false_positive_col.button(
                "Flag for review",
                key=f"false_positive_{key_suffix}",
                use_container_width=True,
            ):
                try:
                    _mark_false_positive_for_review(finding, context, case_id)
                except (OSError, ValueError) as exc:
                    st.error(f"The review note could not be added to the case audit trail: {exc}")
                else:
                    st.rerun()
        if investigate_col.button(
            "Investigate",
            key=f"investigate_{key_suffix}",
            use_container_width=True,
        ):
            if evidence_context is not None:
                st.session_state["pending_scanned_evidence"] = {
                    **evidence_context,
                    "selected_finding_id": finding.get("id"),
                    "selected_finding": dict(finding),
                }
                navigate_to("Evidence")
            else:
                st.session_state["investigation_focus"] = finding.get("id")
                st.session_state["investigation_selected_finding"] = dict(finding)
                navigate_to("Investigation")
            st.rerun()
        from modules.finding_reviews import review_status
        try:
            pending_review = review_status(finding, case_id) if case_id else None
        except (OSError, ValueError) as exc:
            pending_review = None
            st.error(f"Review status could not be verified: {exc}")
        if pending_review:
            st.caption("Flagged for false-positive review. Detection results remain unchanged.")
        if st.session_state.get(f"review_evidence_{key_suffix}"):
            _render_technical_finding(finding, source_rows)


def _render_alert_collection(
    findings,
    key,
    *,
    source_rows=None,
    case_id=None,
    empty_message="No threats detected in this scan.",
    coverage_note=None,
    max_default=ALERT_PAGE_SIZE,
    show_recommendation=False,
    evidence_context=None,
):
    summary = _alert_summary(findings)
    if not findings:
        st.success(empty_message)
        if coverage_note:
            st.caption(coverage_note)
        return summary

    metric_cols = st.columns(3)
    metric_cols[0].metric("Suspicious items", summary["total"])
    metric_cols[1].metric("Highest severity", summary["highest_severity"])
    metric_cols[2].metric("High / critical", summary["severity_counts"].get("High", 0)
                          + summary["severity_counts"].get("Critical", 0))
    if show_recommendation:
        st.info("Recommended next action: " + summary["next_action"])
    if coverage_note:
        st.caption(coverage_note)

    ml_findings = []
    other_findings = []
    for finding in findings:
        if finding.get("source") == "ml":
            ml_findings.append(finding)
        else:
            other_findings.append(finding)
    other_findings.sort(key=_finding_priority)
    display_findings = list(other_findings)
    if ml_findings:
        model_name = ml_findings[0].get("model_name", "ML model")
        source_file = ml_findings[0].get("file", "uploaded CSV")
        lines = [
            item.get("original_csv_line")
            for item in ml_findings
            if item.get("original_csv_line") is not None
        ]
        display_findings.append({
            "id": f"{key}_ml_aggregate",
            "source": "ml_aggregate",
            "severity": max(
                (item.get("severity", "Medium") for item in ml_findings),
                key=lambda value: -SEVERITY_RANK.get(value, len(SEVERITY_RANK)),
            ),
            "file": source_file,
            "model_name": model_name,
            "checkpoint_split": ml_findings[0].get("checkpoint_split", "not recorded"),
            "count": len(ml_findings),
            "row_range": (min(lines), max(item.get("original_csv_line_end") or item["original_csv_line"]
                for item in ml_findings if item.get("original_csv_line") is not None)) if lines else None,
            "record_range": (min(item["original_csv_record"] for item in ml_findings if item.get("original_csv_record") is not None),
                max(item["original_csv_record"] for item in ml_findings if item.get("original_csv_record") is not None))
                if any(item.get("original_csv_record") is not None for item in ml_findings) else None,
        })
    display_findings.sort(key=_finding_priority)
    page_size = min(max_default, ALERT_PAGE_SIZE)
    max_pages = max(1, (len(display_findings) + page_size - 1) // page_size)
    page_key = f"alert_page_{key}"
    _reset_pagination_if_needed(page_key, max_pages)
    page = 1
    if max_pages > 1:
        page = st.number_input(
            "Alert page",
            min_value=1,
            max_value=max_pages,
            value=1,
            step=1,
            key=page_key,
        )
    start = (page - 1) * page_size
    selected = display_findings[start:start + page_size]
    for selected_index, item in enumerate(selected, start=start):
        if item.get("source") == "ml_aggregate":
            line_range = item.get("row_range")
            affected = item["file"]
            if item.get("record_range"):
                first, last = item["record_range"]
                affected += f" · logical CSV records {first}–{last}"
            if line_range:
                affected += f" · {item['count']} records, spanning CSV lines {line_range[0]}–{line_range[1]}"
            aggregate = {
                "id": item["id"],
                "source": "ml",
                "severity": item["severity"],
                "file": item["file"],
                "model_name": item["model_name"],
                "checkpoint_split": item["checkpoint_split"],
                "count": item["count"],
            }
            st.markdown(ui.threat_alert_card(
                title=f"{item['count']:,} unusual records flagged",
                severity=item["severity"],
                affected=affected,
                explanation=(
                    f"{item['model_name']} identified records for review. These are model predictions, "
                    "not confirmation of malicious activity."
                ),
                recommendation=(
                    "Search the individual records below and compare them with expected network activity."
                ),
                icon="eye",
                certainty="Aggregated model predictions",
            ), unsafe_allow_html=True)
            review_col, investigate_col = st.columns(2)
            if review_col.button(
                "Review Evidence",
                key=f"review_{key}_{item['id']}",
            ):
                st.session_state[f"review_evidence_{item['id']}"] = not st.session_state.get(
                    f"review_evidence_{item['id']}", False
                )
            if investigate_col.button(
                "Investigate",
                key=f"investigate_{key}_{item['id']}",
            ):
                st.session_state["investigation_focus"] = item["id"]
                navigate_to("Investigation")
                st.rerun()
            if st.session_state.get(f"review_evidence_{item['id']}"):
                _render_technical_finding(aggregate)
        else:
            _render_threat_alert(
                item,
                key,
                source_rows,
                case_id=case_id,
                evidence_context=evidence_context,
                occurrence_index=selected_index,
            )

    if ml_findings and st.checkbox(
        f"Search individual ML records ({len(ml_findings):,})",
        value=False,
        key=f"ml_details_toggle_{key}",
    ):
        query = st.text_input(
                "Search model findings by CSV record, line, file, model, or finding ID",
                key=f"ml_search_{key}",
        ).strip().casefold()
        filtered_ml = [
            item for item in ml_findings
            if not query or query in " ".join(
                str(item.get(part, ""))
                for part in ("id", "file", "model_name", "original_csv_line")
            ).casefold()
        ]
        if not filtered_ml:
            st.info("No model findings match that search.")
        else:
            detail_pages = max(1, (len(filtered_ml) + ML_DETAIL_PAGE_SIZE - 1) // ML_DETAIL_PAGE_SIZE)
            detail_page = 1
            page_key = f"ml_page_{key}"
            _reset_pagination_if_needed(page_key, detail_pages)
            if detail_pages > 1:
                detail_page = st.number_input(
                    "ML detail page",
                    min_value=1,
                    max_value=detail_pages,
                    value=1,
                    step=1,
                    key=page_key,
                )
            offset = (detail_page - 1) * ML_DETAIL_PAGE_SIZE
            st.caption(
                f"Showing {offset + 1}–{min(offset + ML_DETAIL_PAGE_SIZE, len(filtered_ml))} "
                f"of {len(filtered_ml):,} matching records."
            )
            for item_index, item in enumerate(
                filtered_ml[offset:offset + ML_DETAIL_PAGE_SIZE],
                start=offset,
            ):
                _render_threat_alert(
                    item,
                    f"{key}_ml",
                    source_rows,
                    case_id=case_id,
                    evidence_context=evidence_context,
                    occurrence_index=item_index,
                )
    return summary


def _render_scan_summary(findings, key):
    """Show concise scan results; keep matches and hashes inside per-finding details."""
    if not findings:
        st.info("No detections were returned by the available checks.")
        return

    summary = _alert_summary(findings)
    metrics = st.columns(3)
    metrics[0].metric("Findings", summary["total"])
    metrics[1].metric("Highest severity", summary["highest_severity"])
    metrics[2].metric(
        "High / critical",
        summary["severity_counts"].get("High", 0)
        + summary["severity_counts"].get("Critical", 0),
    )
    for index, finding in enumerate(findings):
        source = str(finding.get("source", "detection")).casefold()
        if source == "yara":
            method = "YARA rule match"
        elif source in {"static heuristic", "heuristic"}:
            method = "Static content indicator"
        elif source in {"ml", "ml_aggregate"}:
            method = f"Network-flow model prediction · {finding.get('model_name', 'trained model')}"
        elif source in {"rule", "rules", "rule engine"}:
            method = "Explainable CSV rule"
        else:
            method = str(finding.get("detection_type") or finding.get("source") or "Detection")
        title = (
            finding.get("rule")
            if source == "yara"
            else finding.get("description")
            or _finding_presentation(finding)["title"]
        )
        columns = st.columns([0.85, 4, 2])
        columns[0].markdown(
            ui.sev_badge(str(finding.get("severity", "Unknown"))),
            unsafe_allow_html=True,
        )
        columns[1].markdown(f"**{html.escape(str(title))}**")
        columns[2].caption(method)
        finding_id = str(finding.get("id") or f"{key}-{index + 1}")
        with st.expander(f"Technical Details · {finding_id}", expanded=False):
            st.caption(
                f"Detection method: {method} · "
                f"SHA-256: {finding.get('sha256', 'not recorded')}"
            )
            if finding.get("rule"):
                st.caption(f"Rule: {finding['rule']}")
            if source in {"ml", "ml_aggregate"}:
                st.caption(
                    f"Model: {finding.get('model_name', 'not recorded')} · "
                    f"Checkpoint: {finding.get('checkpoint_split', 'not recorded')}"
                )
            if finding.get("matches"):
                st.json(finding["matches"][:10], expanded=False)
            if finding.get("technical_record"):
                st.json(finding["technical_record"], expanded=False)


def _render_investigation_finding_summary(findings):
    if not findings:
        st.info("No findings are linked to this evidence.")
        return
    summary = _alert_summary(findings)
    metrics = st.columns(3)
    metrics[0].metric("Linked findings", summary["total"])
    metrics[1].metric("Highest severity", summary["highest_severity"])
    metrics[2].metric(
        "High / critical",
        summary["severity_counts"].get("High", 0)
        + summary["severity_counts"].get("Critical", 0),
    )
    st.caption(
        "Review each finding once in its source tab: Anomaly review, Explainable findings, "
        "or Threat-rule review."
    )


def _render_technical_table(records, key, page_size=10):
    if records is None or records.empty:
        st.caption("No technical records are available.")
        return
    query = st.text_input("Filter records", key=f"record_search_{key}").strip()
    filtered = records
    if query:
        matching = pd.Series(False, index=records.index)
        for column_name in records.columns:
            matching |= records[column_name].astype(str).str.contains(
                re.escape(query),
                case=False,
                na=False,
            )
        filtered = records.loc[matching]
    if filtered.empty:
        st.info("No records match that filter.")
        return
    page_count = max(1, (len(filtered) + page_size - 1) // page_size)
    page_key = f"record_page_{key}"
    _reset_pagination_if_needed(page_key, page_count)
    page = 1
    if page_count > 1:
        page = st.number_input(
            "Detail page",
            min_value=1,
            max_value=page_count,
            value=1,
            step=1,
            key=page_key,
        )
    start = (page - 1) * page_size
    st.caption(
        f"Showing {start + 1}–{min(start + page_size, len(filtered))} "
        f"of {len(filtered):,} matching record(s)."
    )
    st.dataframe(filtered.iloc[start:start + page_size], use_container_width=True, hide_index=True)


def events_over_time(df, timestamp_column=None):
    selection = select_timestamp_column(df, timestamp_column)
    ts = pd.Series([v.utc for v in selection['values'] if v.utc is not None], dtype='datetime64[ns, UTC]')
    if len(ts) < 2:
        return None, None
    span = ts.max() - ts.min()
    freq = "min" if span < pd.Timedelta(hours=6) else "h" if span < pd.Timedelta(days=3) else "D"
    counts = ts.dt.floor(freq).value_counts().sort_index()
    return pd.DataFrame({"time": counts.index, "events": counts.values}), selection['column']


def _render_investigation_analytics(df, raw_df, findings, yara_findings, anomalies, ml_findings, timestamp_column=None):
    combined_findings = findings + yara_findings
    severity_counts = Counter(item["severity"] for item in combined_findings)
    risk = ui.risk_score(severity_counts)
    risk_label, risk_color = ui.risk_label(risk)

    metrics = st.columns(4)
    metrics[0].metric("Parsed records", len(df))
    metrics[1].metric("Rule findings", len(findings))
    metrics[2].metric("YARA matches", len(yara_findings))
    metrics[3].metric("ML predictions", len(ml_findings))

    series, timestamp_column = events_over_time(df, timestamp_column)
    if series is not None:
        st.markdown(f"**Events over time · {timestamp_column}**")
        if PLOTLY:
            figure = px.area(series, x="time", y="events")
            figure.update_traces(line_color="#37D7E8", fillcolor="rgba(55,215,232,0.16)")
            ui.style_fig(figure, height=260)
            st.plotly_chart(figure, use_container_width=True)
        else:
            st.line_chart(series.set_index("time"))

    visual_columns = st.columns(3)
    with visual_columns[0]:
        st.markdown(f"**Rule/YARA risk score: {risk}/100 · {risk_label}**")
        st.markdown(f'<span style="color:{risk_color}">{risk_label}</span>', unsafe_allow_html=True)
        st.markdown(ui.risk_breakdown_html(severity_counts), unsafe_allow_html=True)
    with visual_columns[1]:
        st.markdown("**Mapped ATT&CK techniques**")
        st.markdown(ui.mitre_html(combined_findings), unsafe_allow_html=True)
    with visual_columns[2]:
        st.markdown("**Rule-finding timeline**")
        st.markdown(ui.timeline_html(findings), unsafe_allow_html=True)

    if raw_df is not None:
        topology = ui.topology(raw_df, findings)
        if topology is not None:
            st.markdown("**Network topology**")
            st.plotly_chart(topology, use_container_width=True)
        st.markdown("**Source records**")
        _render_technical_table(raw_df, "investigation_source_records")
    elif not anomalies.empty:
        st.caption("Source CSV rows are unavailable; model detections are not linked to report evidence.")


def render_yara(yara_findings, scanner_ok, key, case_id=None):
    """Shared by the investigation tab and the binary-file view."""
    if not YARA_AVAILABLE and not yara_findings:
        st.warning("Threat-rule review is currently unavailable for this evidence.")
        return
    if not scanner_ok and not yara_findings:
        st.warning("No active threat rules are available for this evidence.")
        return
    if not yara_findings:
        st.success("No threats detected by the available file rules.")
        return

    findings = []
    for finding in yara_findings:
        normalized = dict(finding)
        normalized["source"] = "yara"
        normalized.setdefault("file", normalized.get("path", "Evidence file"))
        findings.append(normalized)
    _render_alert_collection(
        findings,
        f"yara_{key}",
        case_id=case_id,
        empty_message="No threats detected by the available file rules.",
    )
    with st.expander("Technical Details · YARA matches", expanded=False):
        st.download_button(
            "Export YARA details (.json)",
            json.dumps(yara_findings, indent=2, default=str),
            file_name="yara_findings.json",
            key=f"dl_{key}",
        )
        if findings:
            selected = st.selectbox(
                "Choose a detection",
                range(min(len(findings), 10)),
                format_func=lambda index: (
                    f"{findings[index]['id']} · {findings[index].get('rule', 'Detection rule')}"
                ),
                key=f"yara_details_{key}",
            )
            finding = findings[selected]
            st.caption(
                f"SHA-256: {finding.get('sha256', 'not recorded')} · "
                f"MITRE: {finding.get('mitre', 'not recorded')}"
            )
            if finding.get("matched_strings"):
                st.caption(
                    "Matched content identifiers: "
                    + ", ".join(finding["matched_strings"][:10])
                )
            st.json(finding.get("matches", [])[:10], expanded=False)
            if len(findings) > 10:
                st.caption(f"Showing technical details for up to 10 of {len(findings):,} matches.")


def show_yara_library():
    ui.page_header("Threat rules", "Review the detection coverage available to your investigations.")
    scanner = YaraScanner()
    if not YARA_AVAILABLE:
        st.warning("Threat-rule scanning is currently unavailable. Other investigation tools remain available.")
        return

    a, b = st.columns(2)
    rules = scanner.list_rules()
    a.metric("Active detection rules", len(rules))
    b.metric("Rule groups", len(scanner.loaded_files))

    if scanner.errors:
        st.warning(f"{len(scanner.errors)} detection rule(s) could not be loaded.")

    if rules:
        with st.expander("Technical Details · active detection rules", expanded=False):
            _render_technical_table(pd.DataFrame(rules), "yara_rule_library")

    st.subheader("Review stored evidence")
    st.caption("Run threat-rule checks across evidence previously added to this workspace.")
    if st.button("Scan evidence", disabled=not scanner.ready):
        with st.spinner("Scanning..."):
            found = scanner.scan_folder(RAW_DIR) if RAW_DIR.exists() else []
        st.session_state["yara_library_findings"] = found
        st.session_state["yara_library_scan_errors"] = list(scanner.errors)
    found = st.session_state.get("yara_library_findings")
    if found is not None:
        render_yara(found, scanner.ready, "library")
    if st.session_state.get("yara_library_scan_errors"):
        errors = st.session_state["yara_library_scan_errors"]
        st.warning(f"{len(errors)} item(s) could not be checked.")
        with st.expander("Technical Details · scan errors", expanded=False):
            st.write(errors)


# ----------------------------------------------------------------------------
# Evidence vault: every file in raw_evidence, checked against the hash recorded at upload
# ----------------------------------------------------------------------------
def recorded_hashes():
    """file name -> [(sha256, case_id), ...] read from every audit log in data/cases."""
    rec = {}
    if CASES_DIR.exists():
        for lf in sorted(CASES_DIR.glob("*.log")):
            case = lf.stem.replace("_audit", "")
            try:
                entries = EvidenceIntegrity.read_verified_audit(case, lf)
            except (OSError, ValueError) as exc:
                st.warning(f"Case audit verification failed; its evidence records are unverified: {exc}")
                continue
            for entry in entries:
                if entry.get("action") != "EVIDENCE_UPLOAD":
                    continue
                match = HASH_RE.fullmatch(str(entry.get("details", "")))
                if match:
                    rec.setdefault(match.group(1).strip(), []).append((match.group(2).lower(), case))
    return rec


def verify_file(path, recs, key, record_audit=True):
    current = EvidenceIntegrity.calculate_sha256(str(path))
    trusted = []
    for digest, case in recs:
        try:
            EvidenceIntegrity.require_evidence(
                case, path, audit_path=CASES_DIR / f"{case}_audit.log", expected_hash=digest,
            )
            trusted.append((digest, case))
        except (OSError, ValueError) as exc:
            st.warning(f"Evidence verification failed: {exc}")
    if not recs:
        status = "norecord"
    elif trusted:
        status = "verified"
    else:
        status = "modified"
    st.session_state[key] = {"status": status, "hash": current}
    if trusted and record_audit:
        try:
            EvidenceIntegrity.log_audit_trail(trusted[-1][1], "EVIDENCE_VERIFIED", f"{path.name} | result={status}")
        except (OSError, ValueError) as exc:
            st.session_state[key]["status"] = "norecord"
            st.warning(f"Audit verification or recording failed; evidence is unverified: {exc}")


def _saved_scan_for_case(sha256_hash, case_id=None):
    return select_saved_scan(CASES_DIR, sha256_hash,
        case_ids=[case_id] if case_id else None)


def _choose_investigation_case(default_case, key):
    case_ids = sorted(path.name.removesuffix("_audit.log")
                      for path in CASES_DIR.glob("*_audit.log"))
    return st.selectbox("Investigation case", list(dict.fromkeys([default_case, *case_ids])), key=key,
        help="Choose explicitly. An invalid audit chain remains blocked; it is never repaired or bypassed.")


def _selected_saved_evidence_path(selection):
    """Resolve a recorded source, never the first same-hash directory entry."""
    filename = selection.get("stored_filename") or (selection.get("scan_record") or {}).get("stored_filename")
    if filename:
        if Path(filename).name != filename:
            raise ValueError("The selected evidence filename leaves the evidence store.")
        candidate = RAW_DIR / filename
        return candidate if candidate.is_file() and EvidenceIntegrity.calculate_sha256(candidate) == selection["sha256"] else None
    # Older browser sessions did not retain the stored filename. Only a unique
    # case-linked, hash-verified source can be recovered without another choice.
    matches = []
    case = selection.get("case_id")
    if not case:
        raise ValueError("Reopen this evidence from the Evidence Vault to establish its source identity.")
    for candidate in RAW_DIR.iterdir() if RAW_DIR.exists() else []:
        if not candidate.is_file() or EvidenceIntegrity.calculate_sha256(candidate) != selection["sha256"]:
            continue
        try:
            EvidenceIntegrity.require_evidence(case, candidate,
                audit_path=CASES_DIR / f"{case}_audit.log", expected_hash=selection["sha256"],
                scanned_record=selection.get("scan_record"))
        except ValueError:
            continue
        matches.append(candidate)
    if len(matches) > 1:
        raise ValueError("Multiple case-linked copies have identical bytes. Reopen the intended source from the Evidence Vault.")
    return matches[0] if matches else None


def _open_saved_evidence(path, cases, evidence_id, scan_id=None):
    sha256_hash = EvidenceIntegrity.calculate_sha256(str(path))
    if not cases:
        raise ValueError("No verified case audit record is linked to this evidence.")
    linked_record = select_saved_scan(CASES_DIR, sha256_hash, case_ids=cases, scan_id=scan_id, source_path=path)
    invalidate_scan_session(st.session_state, linked_record)
    case_id = (
        linked_record.get("case_id")
        if linked_record
        else (cases[0] if cases else DEFAULT_CASE_ID)
    )
    EvidenceIntegrity.require_evidence(
        case_id, path, audit_path=CASES_DIR / f"{case_id}_audit.log",
        expected_hash=sha256_hash, scanned_record=linked_record,
    )
    st.session_state["selected_saved_evidence"] = {
        "sha256": sha256_hash,
        "stored_filename": path.name,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "scan_record": linked_record,
        "historical_scan_id": scan_id,
        "history_case_id": case_id if scan_id else None,
    }
    scope = case_id if scan_id else None
    st.session_state["saved_case_scope_v2_" + sha256_hash] = scope or "__all_cases__"
    st.session_state[f"saved_scan_version_v2_{sha256_hash}_{scope or 'all'}"] = scan_id or "__latest_scan__"
    st.session_state["investigation_focus"] = (
        linked_record.get("findings", [{}])[0].get("id")
        if linked_record and linked_record.get("findings")
        else None
    )
    st.session_state.pop("pending_monitor_alert_investigation", None)
    navigate_to("Investigation")


def _generate_saved_evidence_report(path, evidence_id, cases):
    sha256_hash = EvidenceIntegrity.calculate_sha256(str(path))
    selection = st.session_state.get("selected_saved_evidence") or {}
    historical_id = selection.get("historical_scan_id") if selection.get("sha256") == sha256_hash else None
    scope = selection.get("history_case_id") if selection.get("sha256") == sha256_hash else None
    report_cases = [scope] if scope else (None if selection.get("sha256") == sha256_hash else (cases or None))
    linked_record = select_saved_scan(CASES_DIR, sha256_hash, case_ids=report_cases,
        scan_id=historical_id, source_path=path)
    invalidate_scan_session(st.session_state, linked_record)
    if linked_record is None:
        raise ValueError("No saved scan findings are linked to this evidence. Open it in Investigation first.")
    if not any(
        digest == sha256_hash and case == linked_record.get("case_id")
        for digest, case in recorded_hashes().get(path.name, [])
    ):
        raise ValueError("The saved evidence does not match its case integrity record.")

    report_record = build_saved_evidence_report(
        linked_record,
        evidence_id,
        path,
        audit_path=CASES_DIR / f"{linked_record['case_id']}_audit.log",
    )
    save_forensic_report(report_record)
    st.session_state["ai_report"] = {
        "key": (linked_record["case_id"], sha256_hash),
        "text": report_record["text"],
        "mode": report_record["mode"],
        "note": report_record["note"],
        "validation": report_record["validation"],
        "report_record": report_record,
    }
    return report_record


def _evidence_vault_id(path):
    return evidence_id_for_file(RAW_DIR, path)


def _save_pending_monitor_alert(alert, data, filename, case_id):
    record = promote_alert_to_evidence(
        alert,
        data,
        filename=filename,
        case_id=case_id,
        evidence_directory=RAW_DIR,
        audit_log_path=CASES_DIR / f"{case_id}_audit.log",
    )
    evidence_path = RAW_DIR / record["stored_filename"]
    evidence_id = _evidence_vault_id(evidence_path)
    selected_finding = record["findings"][0]
    st.session_state["selected_saved_evidence"] = {
        "sha256": record["sha256"],
        "stored_filename": evidence_path.name,
        "case_id": case_id,
        "evidence_id": evidence_id,
        "scan_record": record,
    }
    st.session_state["evidence_focus_sha256"] = record["sha256"]
    st.session_state["evidence_focus_finding_id"] = selected_finding["id"]
    st.session_state["evidence_saved_notice"] = (
        f"Evidence ID #{evidence_id} · Case {case_id} · {record['original_filename']}"
        + (" (existing evidence reused)." if record.get("duplicate") else "")
    )
    st.session_state["evidence_page"] = 1
    st.session_state.pop("pending_monitor_alert_investigation", None)
    st.rerun()


def _render_pending_monitor_alert_investigation(alert):
    try:
        filename, full_path, expected_hash = alert_file_details(alert)
    except ValueError as exc:
        st.error(f"The selected alert's file metadata is invalid: {exc}")
        return

    evidence = alert.get("evidence")
    evidence = evidence if isinstance(evidence, dict) else {}
    st.subheader("Selected Live Protection Alert")
    st.markdown(f"**Filename:** {html.escape(filename)}")
    st.markdown(f"**Full path:** `{html.escape(full_path or 'Not recorded')}`")
    st.markdown(
        f"**YARA rule / detection:** {html.escape(str(evidence.get('rule') or alert.get('source') or 'Not recorded'))}"
    )
    st.markdown(f"**Severity:** {html.escape(str(alert.get('severity') or 'Unknown'))}")
    st.markdown(
        f"**Detection time (UTC):** {html.escape(str(alert.get('created_at_utc') or 'Not recorded'))}"
    )
    st.markdown(f"**Alert details:** {html.escape(str(alert.get('message') or 'Not recorded'))}")
    with st.expander("Alert evidence details", expanded=False):
        st.json(alert, expanded=False)

    if full_path:
        source_path = Path(full_path)
        try:
            source_available = source_path.is_file()
        except (OSError, ValueError) as exc:
            source_available = False
            st.error(f"The original file path could not be checked: {exc}")
    else:
        source_path = None
        source_available = False
        st.error("This alert has no recorded original file path. Use the manual upload option.")

    if source_available and source_path is not None:
        st.caption(
            "The original will be read without modification. Its SHA-256 will be checked against "
            "the alert before evidence is linked."
        )
    else:
        st.error("The original file is missing or inaccessible. No evidence has been created.")

    case_ids = (
        [path.name.removesuffix("_audit.log") for path in CASES_DIR.glob("*_audit.log")]
        if CASES_DIR.exists()
        else []
    )
    case_options = list(dict.fromkeys([DEFAULT_CASE_ID, *sorted(case_ids)]))
    case_key = f"monitor_alert_case_{alert_identity(alert)}"
    case_id = st.selectbox("Investigation case", case_options, key=case_key)

    action_cols = st.columns(2)
    if action_cols[0].button(
        "Add to Investigation",
        type="primary",
        key=f"add_monitor_alert_original_{alert_identity(alert)}",
        disabled=not source_available,
        use_container_width=True,
    ):
        try:
            original_bytes = source_path.read_bytes()
            _save_pending_monitor_alert(alert, original_bytes, filename, case_id)
        except (OSError, ValueError, RuntimeError) as exc:
            st.error(f"The original file could not be added as evidence: {exc}")

    with st.expander(
        "Upload the original manually if it is unavailable",
        expanded=not source_available,
    ):
        if expected_hash:
            st.caption("The upload must match the SHA-256 recorded at detection time.")
        else:
            st.warning(
                "This alert has no detection-time SHA-256. The uploaded file's real SHA-256 "
                "will be recorded, but it cannot be verified against the original alert bytes."
            )
        uploaded_file = st.file_uploader(
            "Select the original file",
            type=[extension.lstrip(".") for extension in LOG_EXT + BINARY_EXT],
            key=f"monitor_alert_upload_{alert_identity(alert)}",
        )
        if st.button(
            "Add uploaded file to Investigation",
            key=f"add_monitor_alert_upload_{alert_identity(alert)}",
            disabled=uploaded_file is None,
            use_container_width=True,
        ):
            try:
                _save_pending_monitor_alert(
                    alert,
                    uploaded_file.getvalue(),
                    filename,
                    case_id,
                )
            except (OSError, ValueError, RuntimeError) as exc:
                st.error(f"The uploaded file could not be added as evidence: {exc}")


def _render_pending_scanned_evidence():
    pending = st.session_state.get("pending_scanned_evidence")
    if not pending:
        return

    pending["case_id"] = _choose_investigation_case(pending["case_id"], "pending_scan_case")

    selected_id = pending.get("selected_finding_id")
    selected_finding = pending.get("selected_finding")
    findings = pending.get("findings", [])
    if selected_finding:
        selected_findings = [item for item in findings if item == selected_finding]
    elif selected_id:
        selected_findings = [
            item for item in findings
            if item.get("id") == selected_id
        ]
    else:
        selected_findings = findings[:1]

    if not selected_findings:
        selected_findings = findings[:1]

    st.warning(
        f"Confirm adding '{pending['filename']}' and the selected scan finding to this case. "
        "An identical file already in Evidence will be reused."
    )
    for finding in selected_findings:
        _render_threat_alert(
            finding,
            "pending_scanned_evidence",
            show_actions=False,
            case_id=pending["case_id"],
        )

    confirm_col, cancel_col = st.columns(2)
    if confirm_col.button(
        "Confirm Add to Investigation",
        type="primary",
        key="confirm_add_scanned_evidence",
    ):
        try:
            record = add_scanned_evidence(
                RAW_DIR,
                pending["filename"],
                pending["data"],
                findings,
                case_id=pending["case_id"],
                scanned_at_utc=pending["scanned_at_utc"],
                audit_log_path=CASES_DIR / f"{pending['case_id']}_audit.log",
            )
        except (OSError, ValueError, RuntimeError) as exc:
            st.error(f"The scanned file could not be added to the investigation: {exc}")
        else:
            st.session_state["evidence_focus_sha256"] = record["sha256"]
            st.session_state["evidence_focus_finding_id"] = (
                selected_findings[0].get("id") if selected_findings else selected_id
            )
            evidence_id = record["evidence_id"]
            status = "Evidence reused" if record.get("duplicate") else "Evidence newly saved"
            confirmation_notice = (
                f"{status}: Evidence ID #{evidence_id} · Case {pending['case_id']} · "
                f"{pending['filename']}"
                + (
                    f" (stored as {record['stored_filename']})."
                    if record.get("duplicate")
                    else "."
                )
            )
            st.session_state["evidence_saved_notice"] = confirmation_notice
            st.session_state["evidence_page"] = 1
            st.session_state.pop("pending_scanned_evidence", None)
            st.rerun()
    if cancel_col.button("Cancel", key="cancel_add_scanned_evidence"):
        st.session_state.pop("pending_scanned_evidence", None)
        st.rerun()


def show_evidence_vault():
    ui.page_header("Evidence", "Review your uploaded files and verify their integrity.")
    if st.session_state.get("pending_scanned_evidence"):
        _render_pending_scanned_evidence()
        return
    saved_notice = st.session_state.pop("evidence_saved_notice", None)
    if saved_notice:
        st.success(saved_notice)

    s1, s2, s3 = st.columns([5, 1.2, 1.4])
    query = s1.text_input("Search", placeholder="Search evidence by filename or case ID...",
                          label_visibility="collapsed").strip().lower()
    if s2.button("Refresh", use_container_width=True):
        st.rerun()
    verify_all = s3.button("Verify all", type="primary", use_container_width=True)

    files = sorted([p for p in RAW_DIR.glob("*") if p.is_file()], key=lambda p: p.stat().st_mtime) if RAW_DIR.exists() else []
    try:
        audit_warnings = []
        filename_aliases = load_scanned_evidence_aliases(CASES_DIR, verification_warnings=audit_warnings)
        for warning in audit_warnings:
            st.warning(f"Case audit verification failed: {warning}")
    except (OSError, ValueError) as exc:
        st.error(f"Scanner evidence filenames could not be read from the case audit logs: {exc}")
        filename_aliases = {}
    focus_hash = st.session_state.get("evidence_focus_sha256")
    focused_file = None
    if focus_hash:
        for candidate in files:
            if EvidenceIntegrity.calculate_sha256(str(candidate)) == focus_hash:
                focused_file = candidate
                break
        if focused_file is None:
            st.error("The selected evidence record is no longer present in the evidence store.")
            st.session_state.pop("evidence_focus_sha256", None)
            st.session_state.pop("evidence_focus_finding_id", None)
        else:
            st.subheader(f"Selected evidence · {focused_file.name}")
            try:
                audit_warnings = []
                linked_scans = load_scanned_evidence_records(
                    CASES_DIR, focus_hash, verification_warnings=audit_warnings,
                )
                for warning in audit_warnings:
                    st.warning(f"Case audit verification failed: {warning}")
            except (OSError, ValueError) as exc:
                st.error(f"Linked scanner findings could not be read from the case audit logs: {exc}")
                linked_scans = []
            if linked_scans:
                for scan_record in linked_scans:
                    st.caption(
                        f"Case {scan_record['case_id']} · scanned "
                        f"{scan_record['scanned_at_utc']} · original name "
                        f"{scan_record['original_filename']}"
                    )
                    if st.button("Open historical scan", key="open_history_" + scan_record_id(scan_record)):
                        try:
                            _open_saved_evidence(focused_file, [scan_record["case_id"]],
                                _evidence_vault_id(focused_file), scan_id=scan_record_id(scan_record))
                        except (OSError, ValueError) as exc:
                            st.error(f"Historical scan verification failed: {exc}")
                    linked_findings = scan_record.get("findings", [])
                    selected_id = st.session_state.get("evidence_focus_finding_id")
                    linked_findings = sorted(
                        linked_findings,
                        key=lambda item: item.get("id") != selected_id,
                    )
                    for finding in linked_findings:
                        _render_threat_alert(
                            finding,
                            "evidence_vault",
                            show_actions=False,
                            case_id=scan_record["case_id"],
                        )
                        _render_technical_finding(finding)
            else:
                st.caption("No scanner findings are linked to this evidence record.")
            with st.expander("Technical Details · selected evidence", expanded=False):
                st.caption(f"Stored filename: {focused_file.name}")
                st.caption(f"SHA-256: {focus_hash}")

    if not files:
        st.info("No evidence has been added yet. Start an investigation to add your first file.")
        return

    records = recorded_hashes()
    rows = []
    for idx, p in enumerate(files, 1):
        recs = records.get(p.name, [])
        cases = ", ".join(sorted({c for _, c in recs}))
        aliases = filename_aliases.get(p.name, ())
        if (
            query
            and not evidence_matches_search(p.name, aliases, cases, query)
            and p != focused_file
        ):
            continue
        rows.append((idx, p, recs, cases))
    rows.reverse()  # newest first
    if focused_file is not None:
        rows.sort(key=lambda row: row[1] != focused_file)
    if not rows:
        st.info("No evidence matches your search.")
        return

    page_size = 10
    page_count = max(1, (len(rows) + page_size - 1) // page_size)
    page_number = 1
    st.caption(f"{len(rows):,} evidence file(s) match your search.")
    if page_count > 1:
        _reset_pagination_if_needed("evidence_page", page_count)
        page_number = st.number_input(
            "Evidence page",
            min_value=1,
            max_value=page_count,
            value=1,
            step=1,
            key="evidence_page",
        )
    page_start = (page_number - 1) * page_size
    rows = rows[page_start:page_start + page_size]
    st.markdown(ui.vault_head(), unsafe_allow_html=True)
    spec = [0.7, 3.2, 2.8, 1.3, 1.8]
    for idx, p, recs, cases in rows:
        key = f"ver::{p.name}"
        if not recs:
            st.session_state.pop(key, None)
        if verify_all or st.session_state.get(key, {}).get("status") == "verified":
            verify_file(p, recs, key, record_audit=verify_all)
        try:
            c = st.columns(spec, vertical_alignment="center")
        except TypeError:
            c = st.columns(spec)
        stat = p.stat()
        aliases = filename_aliases.get(p.name, ())
        display_filename = evidence_search_display_name(p.name, aliases, query)
        searched_alias = display_filename if display_filename != p.name else None
        c[0].markdown(f'<span class="v-id">#{idx}</span>', unsafe_allow_html=True)
        c[1].markdown(ui.vault_file(display_filename, datetime.fromtimestamp(stat.st_mtime).strftime("%b %d, %Y, %I:%M %p")),
                      unsafe_allow_html=True)
        if searched_alias:
            c[1].caption(f"Evidence ID #{idx} · Stored file: {p.name}")
        elif aliases:
            c[1].caption("Also scanned as: " + ", ".join(aliases))
        c[2].markdown(ui.vault_record(cases), unsafe_allow_html=True)
        c[3].markdown(ui.vault_status(st.session_state.get(key, {}).get("status")), unsafe_allow_html=True)
        if c[4].button("Verify", key=f"ck_{idx}", type="primary", use_container_width=True):
            verify_file(p, recs, key)
            st.rerun()
        case_ids = list(dict.fromkeys(case for _, case in recs))
        if c[4].button(
            "Open Investigation",
            key=f"open_investigation_{idx}",
            use_container_width=True,
        ):
            try:
                _open_saved_evidence(p, case_ids, idx)
            except (OSError, ValueError) as exc:
                st.error(f"Saved evidence could not be opened in the investigation: {exc}")
            else:
                st.rerun()
        if c[4].button(
            "Generate Forensic Report",
            key=f"generate_evidence_report_{idx}",
            use_container_width=True,
        ):
            try:
                _generate_saved_evidence_report(p, idx, case_ids)
            except (OSError, ValueError, RuntimeError) as exc:
                st.error(f"A report could not be generated for this evidence: {exc}")
            else:
                navigate_to("AI Forensic Reports")
                st.rerun()
        with st.expander(f"Technical Details · {p.name}", expanded=False):
            cur = st.session_state.get(key, {}).get("hash") or EvidenceIntegrity.calculate_sha256(str(p))
            lines = [f"Size: {stat.st_size:,} bytes", f"Current SHA-256:  {cur}"]
            lines += [f"Recorded ({case}): {h}" for h, case in recs] or ["Recorded: none"]
            st.markdown(
                '<div class="hashline">' + "<br>".join(html.escape(x) for x in lines) + "</div>",
                unsafe_allow_html=True,
            )
        st.markdown('<div class="v-sep"></div>', unsafe_allow_html=True)
    st.caption("Integrity checks compare file hashes against internally consistent case records. An unanchored chain does not independently prove authenticity.")


# ----------------------------------------------------------------------------
# Website pages and navigation
# ----------------------------------------------------------------------------
def _section_page_key(section):
    normalized = re.sub(r"[^a-z0-9]+", "_", section.casefold()).strip("_")
    return f"site_subpage_{normalized}"


def _select_mobile_section():
    navigate_to(st.session_state["site_section_mobile"])


def navigate_to(page_name):
    destination = ui.NAVIGATION_DESTINATIONS.get(page_name)
    if destination is None:
        raise ValueError(f"Unknown Aegis navigation destination: {page_name}")
    target_section, target_page = destination
    st.session_state["active_section"] = target_section
    st.session_state["_pending_navigation"] = (target_section, target_page)
    if target_section == "Live Protection":
        st.session_state["live_protection_tab"] = {
            "Live Security Alerts": "Alert History",
            "Windows Review": "Windows Events",
        }.get(page_name, "Overview")
    if target_section == "Security Scanner":
        st.session_state["scanner_mode"] = target_page


def _apply_pending_navigation():
    pending = st.session_state.pop("_pending_navigation", None)
    if pending is None:
        return
    target_section, target_page = pending
    if (
        target_section not in ui.SECTION_PAGES
        or target_page not in ui.SECTION_PAGES[target_section]
    ):
        raise ValueError(f"Invalid pending Aegis navigation destination: {pending}")
    st.session_state["active_section"] = target_section
    st.session_state[_section_page_key(target_section)] = target_page


def show_home():
    monitor = st.session_state.get("security_monitor")
    monitor_snapshot = monitor.snapshot() if monitor is not None else {}
    try:
        background_status = get_background_status()
    except BackgroundMonitorError as exc:
        background_status = {"state": "unknown", "running": False}
        st.warning(f"Background monitoring health could not be checked: {exc}")

    try:
        monitor_alerts = list(monitor_snapshot.get("alerts", []))
        monitor_alerts.extend(load_background_alerts())
    except (BackgroundMonitorError, OSError, ValueError) as exc:
        monitor_alerts = list(monitor_snapshot.get("alerts", []))
        st.error(f"Recent monitor alerts could not be loaded: {exc}")
    monitor_alerts.sort(
        key=lambda alert: alert.get("created_at_utc", ""),
        reverse=True,
    )
    monitor_findings = _monitor_alert_findings(monitor_alerts)
    alert_summary = _alert_summary(monitor_findings)

    try:
        scan_history = load_scan_history(limit=100)
    except (OSError, ValueError) as exc:
        scan_history = []
        st.error(f"Saved scan coverage could not be loaded: {exc}")
    last_scan = scan_history[0] if scan_history else None
    if last_scan:
        try:
            EvidenceIntegrity.require_scan_report(last_scan)
        except (OSError, ValueError) as exc:
            st.warning(f"Unverified saved scan summary: {exc}")
        files_scanned = f"{last_scan.get('files_checked', 0):,}"
        files_note = "Files checked in the latest scan"
        scan_note = "Latest scan complete" if last_scan.get("scan_complete") else "Latest scan incomplete"
        if last_scan.get("files_skipped") or last_scan.get("error_count"):
            scan_note = (
                f"{last_scan.get('files_skipped', 0):,} skipped; "
                f"{last_scan.get('error_count', 0):,} errors"
            )
    else:
        files_scanned = "0"
        files_note = "No saved scan yet"
        scan_note = "No saved scans"

    if background_status.get("state") == "stale":
        monitor_health = "Attention needed"
        monitor_note = "Background monitor status is stale"
    elif background_status.get("running"):
        monitor_health = "Background active"
        monitor_note = "User-enabled background monitoring is running"
    elif monitor_snapshot.get("running"):
        monitor_health = "Session active"
        monitor_note = "Monitoring is active in this app session"
    elif background_status.get("state") == "unknown":
        monitor_health = "Unavailable"
        monitor_note = background_status.get("error", "Could not verify monitor health")
    else:
        monitor_health = "Not running"
        monitor_note = "Enable monitoring from Live Protection when needed"

    title_col, action_col = st.columns([4, 1.15])
    with title_col:
        st.markdown(
            '<div class="dashboard-topbar"><h1 class="dashboard-title">Security overview</h1>'
            '<div class="dashboard-subtitle">Threat signals, protection health, and recent scan activity.</div></div>',
            unsafe_allow_html=True,
        )
    action_col.button(
        "Scan Now",
        type="primary",
        on_click=navigate_to,
        args=("File Scan",),
        use_container_width=True,
    )

    summary_cards = st.columns(4)
    summary_cards[0].markdown(
        ui.dashboard_stat(
            "alert",
            f"{alert_summary['total']:,}",
            "Saved alerts",
            "Historical records; not active threats",
            "red" if alert_summary["total"] else "blue",
        ),
        unsafe_allow_html=True,
    )
    summary_cards[1].markdown(
        ui.dashboard_stat(
            "file",
            files_scanned,
            "Files scanned",
            scan_note,
            "blue",
        ),
        unsafe_allow_html=True,
    )
    summary_cards[2].markdown(
        ui.dashboard_stat("shield", monitor_health, "Protection status", monitor_note, "teal"),
        unsafe_allow_html=True,
    )
    summary_cards[3].markdown(
        ui.dashboard_stat(
            "target",
            f"{len(scan_history):,}",
            "Recent scans",
            "Saved reports (latest 100)" if len(scan_history) == 100 else "Saved scan reports",
            "violet",
        ),
        unsafe_allow_html=True,
    )

    st.markdown(
        '<div class="section-heading"><div><div class="section-heading-title">Quick scan actions</div>'
        '<div class="section-heading-subtitle">Choose a scan type.</div></div></div>',
        unsafe_allow_html=True,
    )
    quick_actions = st.columns(3)
    for column, (label, destination) in zip(
        quick_actions,
        (
            ("Scan a file", "File Scan"),
            ("Scan a folder", "Folder Scan"),
            ("Check a URL", "URL Scan"),
        ),
    ):
        column.button(
            label,
            on_click=navigate_to,
            args=(destination,),
            use_container_width=True,
        )

    st.markdown(
        '<div class="section-heading"><div><div class="section-heading-title">Recent monitor alerts</div>'
        '<div class="section-heading-subtitle">Saved historical records for review.</div></div></div>',
        unsafe_allow_html=True,
    )
    _render_alert_collection(
        monitor_findings,
        "dashboard_recent_detections",
        empty_message=(
            "No recent monitor detections. This does not confirm that a scan is clean; "
            "review scan coverage or run a scan."
        ),
        show_recommendation=False,
    )

    activity_col = st.container()
    with activity_col:
        with st.container(border=True):
            st.markdown("#### Monitoring activity")
            if monitor_snapshot.get("running"):
                monitored = ", ".join(monitor_snapshot.get("directories", [])) or "No folders listed"
                st.caption(
                    f"Session monitor active · {monitor_snapshot.get('files_checked', 0):,} files checked"
                )
                st.text(monitored)
            elif background_status.get("running"):
                monitored = ", ".join(background_status.get("directories", [])) or "No folders listed"
                st.caption("Background monitor active")
                st.text(monitored)
            else:
                st.caption("No active monitor process.")
            if last_scan and last_scan.get("completed_at_utc"):
                st.caption(f"Last scan completed: {last_scan['completed_at_utc']}")
def show_about():
    ui.page_header(
        "Settings",
        "Configure scans and monitoring from their respective sections.",
    )
    st.info("There are no additional application preferences to change here.")
    st.markdown("#### Safety and privacy")
    st.caption(
        "Scans run only when requested. Findings are indicators for review, not confirmation of an incident."
    )
    st.caption(
        "Evidence and reports stay in configured project folders. URL checks do not visit or submit "
        "destinations; Defender manages its own remediation."
    )


def render_defender_scan_controls(key_prefix):
    st.subheader("Scan this Windows computer with Microsoft Defender")
    st.caption(
        "Quick scan or confirmed full scan. Defender handles any quarantine/removal; "
        "this app does not delete files."
    )
    if st.button("Refresh Defender status", key=f"{key_prefix}_refresh_defender"):
        try:
            st.session_state["windows_defender"] = get_defender_status()
            st.session_state["windows_defender_error"] = None
        except WindowsSecurityError as exc:
            st.session_state.pop("windows_defender", None)
            st.session_state["windows_defender_error"] = str(exc)

    if st.session_state.get("windows_defender_error"):
        st.error(st.session_state["windows_defender_error"])
    defender = st.session_state.get("windows_defender")
    if defender:
        status = defender["status"]
        if status.get("AntivirusEnabled") is False or status.get("RealTimeProtectionEnabled") is False:
            st.warning("Microsoft Defender reports that antivirus or real-time protection is disabled.")
        elif status.get("AntivirusEnabled") is True and status.get("RealTimeProtectionEnabled") is True:
            st.success("Microsoft Defender reports antivirus and real-time protection enabled.")
        else:
            st.info("Microsoft Defender status is available; some protection details are unknown.")
        with st.expander("Technical Details · Defender status", expanded=False):
            st.json(status, expanded=False)

    process = st.session_state.get("windows_scan_process")
    scan_active = process is not None and process.poll() is None
    if scan_active:
        st.info(f"Defender is processing the requested {st.session_state.get('windows_scan_type', '')} scan.")
    elif process is not None:
        output, _ = process.communicate()
        if process.returncode == 0:
            st.session_state["windows_scan_result"] = output.strip() or (
                "Defender accepted the scan request. Check Windows Security for scan progress and results."
            )
            st.session_state["windows_scan_error"] = None
        else:
            st.session_state["windows_scan_error"] = output.strip() or (
                "Defender could not start the scan. Check PowerShell permissions and Windows Security."
            )
        st.session_state["windows_scan_process"] = None
    if st.session_state.get("windows_scan_error"):
        st.error(st.session_state["windows_scan_error"])
    if st.session_state.get("windows_scan_result"):
        st.success(st.session_state["windows_scan_result"])
        st.caption("The request being accepted does not mean the scan has finished.")

    quick, full = st.columns(2)
    if quick.button(
        "Start Defender quick scan",
        type="primary",
        disabled=scan_active,
        key=f"{key_prefix}_defender_quick",
    ):
        try:
            st.session_state["windows_scan_process"] = start_defender_scan("quick")
            st.session_state["windows_scan_type"] = "quick"
            st.session_state["windows_scan_error"] = None
            st.session_state["windows_scan_result"] = None
            st.rerun()
        except (WindowsSecurityError, ValueError) as exc:
            st.error(f"Quick scan could not be started: {exc}")

    full_confirm = full.checkbox(
        "I understand a full scan may take a long time and use system resources.",
        key=f"{key_prefix}_confirm_full_scan",
    )
    if full.button(
        "Start Defender full scan",
        disabled=scan_active or not full_confirm,
        key=f"{key_prefix}_defender_full",
    ):
        try:
            st.session_state["windows_scan_process"] = start_defender_scan("full")
            st.session_state["windows_scan_type"] = "full"
            st.session_state["windows_scan_error"] = None
            st.session_state["windows_scan_result"] = None
            st.rerun()
        except (WindowsSecurityError, ValueError) as exc:
            st.error(f"Full scan could not be started: {exc}")


def show_safety_scan():
    image_mode = st.session_state.get("scanner_mode") == "Image Scan"
    title = "Image scan" if image_mode else "File scan"
    allowed_extensions = (
        IMAGE_EXTENSIONS
        if image_mode
        else SCAN_EXTENSIONS - IMAGE_EXTENSIONS
    )
    ui.page_header(
        title,
        "Check one saved image locally without opening it."
        if image_mode
        else "Check one saved file locally without opening it.",
    )
    st.caption(
        "On-demand local checks only. YARA matches and static indicators are review signals, "
        "not confirmation of malware."
    )
    uploaded = st.file_uploader(
        "Upload an image" if image_mode else "Upload a file",
        type=sorted(extension.lstrip(".") for extension in allowed_extensions),
        key="safety_image_upload" if image_mode else "safety_file_upload",
    )
    if uploaded is not None:
        if uploaded.size > 100 * 1024 * 1024:
            st.error("This local check accepts files up to 100 MB.")
        else:
            uploaded_bytes = uploaded.getvalue()
            upload_identity = (
                uploaded.name,
                hashlib.sha256(uploaded_bytes).hexdigest(),
            )
            if st.button(
                "Scan image" if image_mode else "Scan file",
                type="primary",
                key="scan_upload",
            ):
                scanner = YaraScanner()
                with st.spinner("Checking the uploaded copy locally..."):
                    try:
                        result = check_uploaded_file(
                            Path(uploaded.name).name,
                            uploaded_bytes,
                            scanner,
                        )
                    except (OSError, ValueError, RuntimeError) as exc:
                        st.error(f"The file could not be checked: {exc}")
                        result = None
                if result:
                    st.session_state["uploaded_file_scan"] = {
                        "identity": upload_identity,
                        "result": result,
                        "scanned_at_utc": datetime.now(timezone.utc).isoformat(),
                    }
            saved_scan = st.session_state.get("uploaded_file_scan")
            if saved_scan and saved_scan["identity"] == upload_identity:
                result = saved_scan["result"]
                st.success("File review completed.")
                if not result["scanner_ready"]:
                    st.warning("YARA is unavailable, so threat-rule scanning did not run.")
                combined_findings = [
                    {
                        **finding,
                        "source": "Static heuristic",
                        "path": uploaded.name,
                        "sha256": result["sha256"],
                    }
                    for finding in result.get("heuristic_findings", [])
                ] + [
                    {**finding, "source": "yara", "sha256": result["sha256"]}
                    for finding in result.get("findings", [])
                ]
                evidence_context = {
                    "filename": Path(uploaded.name).name,
                    "data": uploaded_bytes,
                    "findings": combined_findings,
                    "scanned_at_utc": saved_scan.get(
                        "scanned_at_utc",
                        datetime.now(timezone.utc).isoformat(),
                    ),
                    "case_id": DEFAULT_CASE_ID,
                }
                methods = []
                if result["scanner_ready"]:
                    methods.append("YARA rule matching")
                if result.get("heuristic_findings"):
                    methods.append("static content indicators")
                st.caption(
                    "Detection methods: " + (", ".join(methods) if methods else "available local checks")
                )
                _render_scan_summary(combined_findings, "uploaded_file")
                if st.button(
                    "Add to Investigation",
                    key="add_scanned_file_to_investigation",
                    help="Open a confirmation before saving this file and its scan findings as case evidence.",
                ):
                    st.session_state["pending_scanned_evidence"] = evidence_context
                    navigate_to("Evidence")
                    st.rerun()
                with st.expander("Technical Details", expanded=False):
                    st.caption(f"Detected content type: {result['detected_type']}")
                    st.caption(f"SHA-256: {result['sha256']}")
                    for signal in result["signals"]:
                        st.caption(f"Static indicator: {signal}")
                    for warning in result.get("scan_warnings", []):
                        st.warning(warning)


def show_windows_review():
    ui.page_header(
        "Windows security review",
        "Request a Defender scan and review selected Windows security records locally.",
    )
    st.warning(
        "This page only runs on Windows. Defender scans start only when you press a button. "
        "Microsoft Defender controls its own quarantine/remediation; this app will not delete, "
        "disable, or change system settings. Some log details may require administrator access."
    )
    if os.name != "nt":
        st.info("Windows Defender and Windows event-log checks are unavailable on this computer.")
        return

    render_defender_scan_controls("windows_review")
    st.subheader("Recent Defender detections")
    st.caption("These may be from before the scan started; they are not a result for the current scan.")
    defender = st.session_state.get("windows_defender")
    detections = defender.get("detections") or [] if defender else []
    if detections:
        _render_alert_collection(
            _defender_alert_findings(detections),
            "windows_defender",
            empty_message="No recent Microsoft Defender detections were returned.",
        )
        st.caption("These are Defender-reported detections; review current Windows Security status.")
    else:
        st.info("Refresh Defender status to check for recent detections.")

    st.divider()
    st.subheader("Read-only security event review")
    days = st.selectbox("Look back", [1, 7, 30], index=1, format_func=lambda value: f"Last {value} days")
    if st.button("Review Windows event logs", key="read_windows_events"):
        try:
            st.session_state["windows_events"] = read_security_events(days)
            st.session_state["windows_events_error"] = None
        except WindowsSecurityError as exc:
            st.session_state.pop("windows_events", None)
            st.session_state["windows_events_error"] = str(exc)
    if st.session_state.get("windows_events_error"):
        st.error(st.session_state["windows_events_error"])
    events = st.session_state.get("windows_events")
    if events:
        st.metric("Windows events reviewed", len(events["events"]))
        event_summary = summarize_security_events(events["events"])
        event_findings = _windows_event_findings(
            events["events"],
            classification_required=True,
        )
        _render_alert_collection(
            event_findings,
            "windows_review_events",
            empty_message="No suspicious activity was identified in the reviewed event sample.",
        )
        if events["errors"]:
            st.warning("Some event logs could not be read; event coverage is incomplete.")
        with st.expander("Technical Details · Windows event records", expanded=False):
            st.json({"summary": event_summary, **events}, expanded=False)

    st.divider()
    st.subheader("Startup applications and scheduled tasks")
    st.caption(
        "Read-only inventory. Review flags are simple heuristics, not proof of malware. "
        "Nothing is disabled or removed."
    )
    if st.button("Review startup items and scheduled tasks", key="review_startup"):
        try:
            st.session_state["windows_startup"] = inspect_startup_items()
            st.session_state["windows_startup_error"] = None
        except WindowsSecurityError as exc:
            st.session_state.pop("windows_startup", None)
            st.session_state["windows_startup_error"] = str(exc)
    if st.session_state.get("windows_startup_error"):
        st.error(st.session_state["windows_startup_error"])
    startup = st.session_state.get("windows_startup")
    if startup:
        flagged = [
            item
            for item in startup["startup"] + startup["tasks"]
            if item.get("review_reasons")
        ]
        inventory_findings = [
            {
                "id": f"STARTUP-{index:03d}",
                "source": "static heuristic",
                "severity": "Medium",
                "file": item.get("Path") or item.get("Name") or "Startup item",
                "description": "; ".join(item.get("review_reasons", [])),
                "technical_record": item,
                "evidence": [{"file": item.get("Path") or item.get("Name", "Startup inventory")}],
            }
            for index, item in enumerate(flagged, start=1)
        ]
        _render_alert_collection(
            inventory_findings,
            "windows_startup",
            empty_message="No startup items were flagged by the review checks.",
        )
        if startup["truncated"]:
            st.info("The displayed scheduled-task list is limited to the first 300 tasks.")
        if startup["errors"]:
            st.warning("Some startup information could not be read.")
        with st.expander("Technical Details · startup inventory", expanded=False):
            st.json(startup, expanded=False)

    st.divider()
    st.subheader("Download current review")
    st.caption("Exports only results you have collected in this browser session.")
    process = st.session_state.get("windows_scan_process")
    scan_report = None
    if process is not None or st.session_state.get("windows_scan_result") or st.session_state.get("windows_scan_error"):
        if process is not None and process.poll() is None:
            scan_status = "running"
        elif st.session_state.get("windows_scan_error"):
            scan_status = "failed"
        else:
            scan_status = "request_accepted"
        scan_report = {
            "type": st.session_state.get("windows_scan_type"),
            "status": scan_status,
            "message": st.session_state.get("windows_scan_result")
            or st.session_state.get("windows_scan_error"),
        }
    report = build_review_report(defender, events, startup, scan_report)
    st.download_button(
        "Download review (.json)",
        data=json.dumps(report, indent=2, default=str),
        file_name="aegis_windows_review.json",
        mime="application/json",
        key="download_windows_review",
    )


def _scan_findings_for_report(scan_report):
    return collect_laptop_findings(scan_report)


def _uploaded_event_references(raw_df, findings, timestamp_column=None):
    if raw_df is None or "event_id" not in raw_df.columns:
        return []
    from modules.csv_evidence import CSV_METADATA, source_locator
    from modules.event_timestamps import select_timestamp_column
    parsed_times = select_timestamp_column(raw_df, timestamp_column)['values']
    times_by_index = dict(zip(raw_df.index, parsed_times))
    wanted_records = {e["record_number"] for f in findings for e in f.get("evidence", [])
        if isinstance(e, dict) and e.get("record_number") is not None}
    metadata = raw_df.attrs.get(CSV_METADATA, {})
    if metadata:
        by_record = {number: index for index, (number, _, _) in metadata.get("locations", {}).items()
            if number in wanted_records and index in raw_df.index}
    else:
        by_record = {position + 1: index for position, index in enumerate(raw_df.index)
            if position + 1 in wanted_records}
    references = []
    seen = set()
    for finding in findings:
        if finding.get("source") == "yara":
            continue
        for evidence in finding.get("evidence", []):
            if not isinstance(evidence, dict):
                continue
            from modules.csv_evidence import source_locator
            if evidence.get("record_number") is not None:
                index = by_record.get(evidence["record_number"])
                rows = raw_df.loc[[index]] if index is not None else raw_df.iloc[0:0]
            elif evidence.get("line") is not None and "line_no" in raw_df:
                rows = raw_df.loc[raw_df["line_no"] == evidence["line"]]
            else:
                continue
            for source_index, row in rows.iterrows():
                source_time = times_by_index.get(source_index)
                event_id = row.get("event_id")
                if pd.isna(event_id):
                    continue
                identity = (str(evidence.get("file", "")), evidence.get("record_number"), evidence.get("line"), str(event_id))
                if identity in seen:
                    continue
                seen.add(identity)
                references.append({
                    "log": evidence.get("file", ""),
                    "event_id": event_id,
                    "time_utc": source_time.text if source_time else None,
                    "timestamp_original": source_time.original if source_time else None,
                    "timestamp_status": source_time.status if source_time else 'unresolved',
                    "finding_id": finding.get("id", "Not linked"),
                    **{key: evidence[key] for key in ("file", "sha256", "record_number", "csv_record_id", "line", "line_end")
                       if key in evidence},
                })
    return references


def _windows_event_references(events):
    references = []
    for event in events or []:
        normalized = normalize_security_event(event)
        references.append({
            "log": normalized.get("Log", "Unknown"),
            "event_id": normalized.get("EventId", "Unknown"),
            "record_id": normalized.get("RecordId", "Unknown"),
            "time_utc": normalized.get("TimeUtc", "Unknown"),
            "finding_id": "Not linked",
        })
    return references


def _forensic_limitations(scan_report=None):
    limitations = [
        "Automated findings are investigative indicators and do not establish compromise.",
        "Only evidence and Windows records collected for this report are represented.",
        "A clean result does not prove that the system or evidence is safe.",
    ]
    if scan_report is not None and not scan_report.get("scan_complete", False):
        limitations.append(
            "The selected filesystem scan was incomplete; skipped items, errors, or limits may have left evidence unchecked."
        )
    if scan_report is not None and scan_report.get("warnings"):
        limitations.append(
            "Some embedded archive content could not be inspected within the configured safety limits."
        )
    return limitations


def show_laptop_scan():
    folder_mode = st.session_state.get("scanner_mode") == "Folder Scan"
    ui.page_header(
        "Folder scan" if folder_mode else "Laptop scan",
        "Run a bounded, read-only review of accessible files and Windows security evidence.",
    )
    st.warning(
        "Read-only scan. Files are never executed, deleted, or quarantined."
    )
    with st.expander("Scan scope and safety"):
        st.caption(
            "The scan is bounded by the selected file, size, and time limits. Unsupported or "
            "unreadable files are reported as skipped. Model and rule findings are indicators, "
            "not proof of infection. Defender status is read-only here."
        )
    scan_root = st.text_input(
        "Folder to scan" if folder_mode else "Directory to scan",
        value=str(Path.home()),
    )
    limit_col1, limit_col2, limit_col3 = st.columns(3)
    max_files = limit_col1.selectbox(
        "Maximum supported files",
        [100, 500, 1000, MAX_LAPTOP_FILES],
        index=3,
    )
    max_file_size_mb = limit_col2.selectbox(
        "Maximum file size",
        [10, 25, MAX_LAPTOP_FILE_SIZE // (1024 * 1024)],
        index=2,
        format_func=lambda value: f"{value} MB",
    )
    max_duration_minutes = limit_col3.selectbox(
        "Maximum duration",
        [1, 5, MAX_SCAN_SECONDS // 60],
        index=2,
        format_func=lambda value: f"{value} minute(s)",
    )
    confirm_scan = st.checkbox(
        "I understand this scans the selected directory and may use disk and CPU resources.",
        key="confirm_laptop_scan",
    )
    if st.button(
        "Scan folder" if folder_mode else "Scan laptop",
        type="primary",
        disabled=not confirm_scan,
    ):
        progress = st.progress(0, text="Preparing local file review...")
        progress_note = st.empty()
        scanner = YaraScanner()
        defender_status = None
        defender_status_error = None
        if os.name == "nt":
            try:
                defender_status = get_defender_status()
                defender_collected_at = datetime.now(timezone.utc).isoformat()
            except WindowsSecurityError as exc:
                defender_status_error = str(exc)

        def update_scan_progress(checked: int, maximum: int, path: str) -> None:
            progress.progress(
                min(checked / maximum, 1.0),
                text=f"Files checked: {checked:,} / {maximum:,} maximum",
            )
            progress_note.caption(path)

        try:
            report = scan_laptop(
                scan_root,
                scanner,
                max_files=max_files,
                max_file_size=max_file_size_mb * 1024 * 1024,
                max_seconds=max_duration_minutes * 60,
                progress_callback=update_scan_progress,
            )
        except (ValueError, OSError, RuntimeError) as exc:
            st.error(f"The local scan could not be completed: {exc}")
            report = None

        if report is not None:
            report["case_id"] = f"LAPTOP-{uuid.uuid4().hex[:8].upper()}"
            report["system_collection_times"] = {}
            report["defender_status"] = defender_status
            if defender_status is not None:
                report["system_collection_times"]["defender"] = defender_collected_at
            if defender_status_error:
                report["defender_status_error"] = defender_status_error

            if os.name == "nt":
                try:
                    process_result = inspect_running_processes()
                    report["system_collection_times"]["process"] = datetime.now(timezone.utc).isoformat()
                    report["running_processes"] = [
                        dict(item) for item in process_result["processes"] if item.get("review_reasons")
                    ]
                    report["process_inventory_truncated"] = process_result.get("truncated", False) or process_result.get("total", 0) >= 500
                    report["processes_reviewed"] = process_result["total"]
                except WindowsSecurityError as exc:
                    report["process_inventory_error"] = str(exc)
                try:
                    startup_result = inspect_startup_items()
                    report["system_collection_times"]["startup"] = datetime.now(timezone.utc).isoformat()
                    report["system_collection_times"]["scheduled task"] = report["system_collection_times"]["startup"]
                    report["startup_inventory"] = {
                        "startup_count": len(startup_result["startup"]),
                        "scheduled_task_count": startup_result["total_tasks"],
                        "flagged_startup_items": [
                            item for item in startup_result["startup"]
                            if item.get("review_reasons")
                        ],
                        "flagged_scheduled_tasks": [
                            item for item in startup_result["tasks"]
                            if item.get("review_reasons")
                        ],
                        "errors": startup_result["errors"],
                        "truncated": startup_result.get("truncated", False),
                    }
                except WindowsSecurityError as exc:
                    report["startup_inventory_error"] = str(exc)
                try:
                    report["security_events"] = read_security_events(days=7)
                    report["system_collection_times"]["windows event"] = datetime.now(timezone.utc).isoformat()
                    report["security_event_summary"] = summarize_security_events(
                        report["security_events"]["events"]
                    )
                except WindowsSecurityError as exc:
                    report["security_event_error"] = str(exc)

            st.session_state["laptop_scan_report"] = report
            st.session_state.pop("laptop_forensic_report", None)
            st.session_state.pop("laptop_forensic_report_record", None)
            audit_entry = EvidenceIntegrity.log_audit_trail(
                report["case_id"],
                "LAPTOP_SCAN_COMPLETED",
                f"checked={report['files_checked']}; skipped={report['files_skipped']}; "
                f"errors={report['error_count']}; complete={report['scan_complete']}; root={report['root']}"
                f"; snapshot_sha256={EvidenceIntegrity.scan_snapshot_hash(report)}",
            )
            report["audit_trail"] = [audit_entry]
            try:
                save_scan_report(report)
            except OSError as exc:
                st.error(f"Scan completed, but local history could not be saved: {exc}")
            progress.progress(1.0, text="Scan complete")
            st.rerun()

    report = st.session_state.get("laptop_scan_report")
    if not report:
        return

    all_scan_findings = collect_laptop_findings(report)
    findings = [item for item in all_scan_findings if item["source_type"] in {"filesystem", "yara"}]
    process_findings = [item for item in all_scan_findings if item["source_type"] == "process"]
    startup_findings = [item for item in all_scan_findings if item["source_type"] in {"startup", "scheduled task"}]

    coverage_note = (
        f"Checked {report['files_checked']:,} supported files; skipped {report['files_skipped']:,}. "
        "Coverage is incomplete because traversal stopped before the selected scope was fully counted."
        if report["coverage_percent"] is None
        else (
            f"Checked {report['files_checked']:,} supported files with "
            f"{report['coverage_percent']:.1f}% supported-file coverage; "
            f"{report['files_skipped']:,} files were skipped. "
            + (
                "This scan was incomplete; review skipped items and limits."
                if not report["scan_complete"]
                else "Coverage applies only to accessible supported file types in the selected folder."
            )
        )
    )
    _render_alert_collection(
        all_scan_findings,
        "laptop_scan",
        case_id=report.get("case_id"),
        empty_message="No threats detected in this scan.",
        coverage_note=coverage_note,
    )

    for source in laptop_source_coverage(report):
        if source["source"] not in {"filesystem", "yara"} and source["status"] != "recorded":
            st.caption(f"{source['source']}: {source['status']}. {source['detail']}")
    if not report["yara_available"]:
        st.warning("YARA is unavailable; file results use static checks only.")
    if report.get("defender_status"):
        defender_info = report["defender_status"]["status"]
        st.caption(
            "Microsoft Defender: "
            f"antivirus enabled={defender_info.get('AntivirusEnabled', 'Unknown')}; "
            f"real-time protection={defender_info.get('RealTimeProtectionEnabled', 'Unknown')}."
        )
    if report.get("defender_status_error"):
        st.warning(f"Microsoft Defender status was unavailable: {report['defender_status_error']}")
    if report["coverage_percent"] is None:
        st.warning(
            "Coverage is incomplete: traversal stopped before the selected scope was fully counted. "
            "The number of remaining files is unknown."
        )
    if not report["scan_complete"]:
        st.warning(
            "This was not a complete scan. Review skipped files, errors, unsupported file types, "
            "and any reached limits before drawing conclusions."
        )
    if report["limit_reached"]:
        st.info("A configured time, file, or findings limit was reached; some files may remain unchecked.")
    if report["errors"]:
        st.warning(f"{report['error_count']} file or directory error(s) occurred.")
        with st.expander("File scan errors"):
            st.write(report["errors"])
            if report["error_count"] > len(report["errors"]):
                st.caption("Only the first 200 errors are shown.")
    if report["unsupported_files"]:
        st.caption(
            f"{report['unsupported_files']} unsupported file(s) were skipped and are not included "
            "in supported-file coverage."
        )
    if report["directories_skipped"]:
        st.caption(
            f"{report['directories_skipped']} symbolic-link or reparse-point directory(ies) "
            "were not followed."
        )
    if report.get("warnings"):
        st.warning(f"{len(report['warnings'])} embedded-content check(s) were limited.")
        with st.expander("Embedded-content review notes"):
            st.write(report["warnings"])
    if findings:
        with st.expander("Technical Details · complete scan findings", expanded=False):
            st.caption("Hashes, full evidence locations, and rule matches remain available here.")
            detail_page_size = 10
            detail_page_count = max(1, (len(findings) + detail_page_size - 1) // detail_page_size)
            detail_page = 1
            if detail_page_count > 1:
                _reset_pagination_if_needed(
                    "laptop_finding_details_page",
                    detail_page_count,
                )
                detail_page = st.number_input(
                    "Finding details page",
                    min_value=1,
                    max_value=detail_page_count,
                    value=1,
                    step=1,
                    key="laptop_finding_details_page",
                )
            detail_offset = (detail_page - 1) * detail_page_size
            detail_findings = findings[detail_offset:detail_offset + detail_page_size]
            selected_finding = st.selectbox(
                "Choose a finding",
                range(len(detail_findings)),
                format_func=lambda index: (
                    f"{detail_findings[index]['severity']} · "
                    f"{Path(detail_findings[index]['path']).name} · "
                    f"{detail_findings[index]['source']}"
                ),
                key="laptop_finding_details",
            )
            item = detail_findings[selected_finding]
            st.write(item["description"])
            st.caption(f"Evidence path: {item['path']}")
            if item.get("sha256"):
                st.code(item["sha256"], language=None)
            else:
                st.caption("Evidence hash not recorded.")
            if item.get("container_sha256"):
                st.caption(f"Container SHA-256: {item['container_sha256']}")
            st.write(f"Recommended action: {item.get('recommended_action') or item.get('recommendation', 'Review the referenced file.')}")
            st.json({
                "line_evidence": item.get("evidence", []),
                "matched_content": item.get("matches", []),
            }, expanded=False)
            st.caption(f"{len(findings):,} complete findings are retained in the downloadable report.")

    if "process_inventory_error" in report:
        st.warning(f"Running process inventory was unavailable: {report['process_inventory_error']}")
    elif report.get("running_processes"):
        st.caption(
            f"Process review: {report.get('processes_reviewed', 0):,} process(es) checked; "
            f"{len(process_findings):,} item(s) flagged for review."
        )
    if "startup_inventory_error" in report:
        st.warning(f"Startup inventory was unavailable: {report['startup_inventory_error']}")
    elif report.get("startup_inventory"):
        startup = report["startup_inventory"]
        st.caption(
            f"Reviewed {startup['startup_count']} startup item(s) and "
            f"{startup['scheduled_task_count']} scheduled task(s); "
            f"{len(startup_findings):,} item(s) flagged for review."
        )
        if startup["errors"]:
            st.warning("Some startup information could not be read.")
    if "security_event_error" in report:
        st.warning(f"Windows event review was unavailable: {report['security_event_error']}")
    elif report.get("security_event_summary"):
        st.caption(
            f"Windows event review: {len(report.get('security_events', {}).get('events', [])):,} "
            "event(s) checked; suspicious events are included in the alert summary above."
        )
        if report.get("security_events", {}).get("events"):
            with st.expander("Technical Details · Windows event review", expanded=False):
                st.json({
                    "summary": report["security_event_summary"],
                    "events": report["security_events"]["events"],
                }, expanded=False)
        if report.get("security_events", {}).get("errors"):
            st.warning("Some Windows event logs could not be read.")

    st.download_button(
        "Download scan report (.json)",
        data=json.dumps(report, indent=2, default=str),
        file_name="aegis_laptop_scan.json",
        mime="application/json",
        key="download_laptop_scan",
    )


@st.fragment(run_every=3)
def _render_live_alerts():
    monitor = st.session_state.get("security_monitor")
    snapshot = monitor.snapshot() if monitor is not None else {}
    if monitor is not None:
        st.subheader("Current Streamlit-session file alerts")
        st.caption(
            f"Monitoring {len(snapshot['directories'])} directory(ies); "
            f"{snapshot['files_checked']} file(s) checked."
        )
        if not snapshot["yara_available"]:
            st.warning("YARA is unavailable; changed files receive static checks only.")
        if snapshot["queue_dropped"]:
            st.warning(
                f"{snapshot['queue_dropped']} file event(s) exceeded the bounded queue and were not checked."
            )
        if snapshot.get("persistence_error"):
            st.error(f"Monitor alerts could not be persisted: {snapshot['persistence_error']}")
        session_alerts = list(snapshot.get("alerts", []))
        if session_alerts:
            _render_alert_collection(
                _monitor_alert_findings(session_alerts),
                "session_file_monitor_alerts",
                empty_message="No file-monitor alerts have been recorded in this session.",
            )
        else:
            st.info("No file-monitor alerts have been recorded in this session.")
    else:
        st.info("Session file monitoring is stopped; no current-session file alerts are being collected.")

    try:
        persisted_alerts = load_background_alerts()
    except (BackgroundMonitorError, OSError, ValueError) as exc:
        st.error(f"Persistent monitor alerts could not be loaded: {exc}")
        persisted_alerts = []
    st.subheader("Persisted security-alert history")
    st.caption(
        "These records can include earlier monitoring sessions; their presence alone does not mean "
        "a monitor is currently running."
    )
    if persisted_alerts:
        st.caption("Latest persisted records, newest first:")
        for alert in persisted_alerts[:5]:
            finding = _monitor_alert_findings([alert])[0]
            st.markdown(
                ui.threat_alert_card(**_finding_presentation(finding)),
                unsafe_allow_html=True,
            )
            st.caption(
                f"{alert.get('created_at_utc', 'Timestamp not recorded')} · "
                f"{alert.get('source', 'Unknown source')}"
            )
            evidence = alert.get("evidence")
            if isinstance(evidence, dict):
                if evidence.get("rule"):
                    st.caption(f"Matched rule: {evidence['rule']}")
                if evidence.get("path"):
                    st.caption(f"Evidence path: {evidence['path']}")
        if len(persisted_alerts) > 5:
            with st.expander("Browse full persisted alert history", expanded=False):
                _render_alert_collection(
                    _monitor_alert_findings(persisted_alerts),
                    "persisted_monitor_alerts",
                    empty_message="No persisted monitor alerts have been recorded.",
                )
    else:
        st.info("No persisted monitor alerts have been recorded.")


def _render_synthetic_event_demo():
    with st.expander("Demo Tools · Synthetic events", expanded=False):
        st.caption(
            "Synthetic examples only. They are generated locally and never counted as Windows events."
        )
        selected_id = st.selectbox(
            "Synthetic event type",
            list(SYNTHETIC_EVENT_TEMPLATES),
            format_func=lambda value: f"{value} — {SYNTHETIC_EVENT_TEMPLATES[value]}",
            key="synthetic_event_id",
        )
        if st.button("Generate synthetic demo event", key="generate_synthetic_event"):
            event = make_synthetic_security_event(selected_id)
            events = list(st.session_state.get("synthetic_security_events", []))
            events.insert(0, event)
            st.session_state["synthetic_security_events"] = events[:20]
        events = st.session_state.get("synthetic_security_events", [])
        if events:
            _render_alert_collection(
                [
                    {
                        "id": f"SYN-{event['RecordId']}",
                        "source": "synthetic event",
                        "title": event["description"],
                        "severity": event["severity"],
                        "affected": f"Generated example · Event {event['EventId']}",
                        "description": event["description"],
                        "technical_record": event,
                        "evidence": [{"file": "Aegis synthetic demo generator"}],
                    }
                    for event in events
                ],
                "synthetic_events",
                empty_message="No synthetic events have been generated.",
            )


def _protection_alert_detection(alert):
    evidence = alert.get("evidence")
    evidence = evidence if isinstance(evidence, dict) else {}
    source = str(alert.get("source", "monitor"))
    if evidence.get("rule"):
        return str(evidence["rule"])
    if source.casefold() == "yara":
        return "YARA Rule Match"
    if source.casefold().startswith("windows event"):
        return "Windows Security Event"
    if source.casefold() in {"file monitor", "monitor capacity"}:
        return source.title()
    return "Static Heuristic"


def _protection_alert_filename(alert):
    evidence = alert.get("evidence")
    evidence = evidence if isinstance(evidence, dict) else {}
    path = evidence.get("path") or evidence.get("file") or alert.get("source")
    return Path(str(path or "Unknown file")).name


def _protection_alert_time(alert):
    from modules.event_timestamps import parse_timestamp
    value = parse_timestamp(alert.get("created_at_utc"))
    if value.status == 'missing':
        return "Not recorded"
    if value.utc is None:
        return "Unresolved timestamp"
    return value.text.replace('T', ' ').replace('+00:00', ' UTC')


def _render_protection_alerts(alerts, context, limit=None):
    displayed_alerts = alerts if limit is None else alerts[:limit]
    if not displayed_alerts:
        st.info("No saved monitor alerts match these filters.")
        return

    for index, alert in enumerate(displayed_alerts):
        finding = _monitor_alert_findings([alert])[0]
        alert_key = f"{re.sub(r'[^a-zA-Z0-9_-]', '_', finding['id'])}_{index}"
        with st.container(key=f"protection_alert_{context}_{alert_key}"):
            file_col, detection_col, severity_col, time_col, status_col = st.columns(
                [2.2, 1.65, 0.8, 1.5, 0.7]
            )
            file_col.markdown(f"**{html.escape(_protection_alert_filename(alert))}**")
            detection_col.caption(_protection_alert_detection(alert))
            severity_col.markdown(
                ui.sev_badge(str(alert.get("severity", "Low"))),
                unsafe_allow_html=True,
            )
            time_col.caption(_protection_alert_time(alert))
            status_col.caption("Saved")
            st.caption(str(alert.get("message", "Saved monitor alert for review.")))
            st.caption("Next: " + _finding_presentation(finding)["recommendation"])

            action_cols = st.columns(3)
            detail_key = f"protection_alert_details_{context}_{alert_key}"
            evidence_key = f"protection_alert_evidence_{context}_{alert_key}"
            if action_cols[0].button(
                "View Details",
                key=f"protection_view_{context}_{alert_key}",
                use_container_width=True,
            ):
                st.session_state[detail_key] = not st.session_state.get(detail_key, False)
            if action_cols[1].button(
                "Investigate",
                key=f"protection_investigate_{context}_{alert_key}",
                use_container_width=True,
            ):
                st.session_state["pending_monitor_alert_investigation"] = dict(alert)
                st.session_state["investigation_focus"] = finding["id"]
                st.session_state.pop("selected_saved_evidence", None)
                navigate_to("Investigation")
                st.rerun()
            if action_cols[2].button(
                "Review Evidence",
                key=f"protection_evidence_{context}_{alert_key}",
                use_container_width=True,
            ):
                st.session_state[evidence_key] = not st.session_state.get(evidence_key, False)

            if st.session_state.get(detail_key):
                st.json(alert, expanded=False)
            if st.session_state.get(evidence_key):
                evidence = alert.get("evidence")
                st.caption("Evidence recorded with this alert")
                if evidence:
                    st.json(evidence, expanded=False)
                else:
                    st.caption("This alert has no saved evidence details.")


def _load_protection_alerts():
    try:
        alerts = load_background_alerts()
    except (BackgroundMonitorError, OSError, ValueError) as exc:
        st.error(f"Saved protection alerts could not be loaded: {exc}")
        return []
    alerts.sort(
        key=lambda alert: str(alert.get("created_at_utc", "")),
        reverse=True,
    )
    return alerts


def _render_windows_event_tables(events, label):
    findings = _windows_event_findings(events, classification_required=True)
    _render_alert_collection(
        findings,
        f"windows_events_{re.sub(r'[^a-zA-Z0-9_-]', '_', label)}",
        empty_message=f"No suspicious activity was identified in {label.lower()}.",
    )
    with st.expander(f"Technical Details · {label}", expanded=False):
        st.caption(
            f"{len(events):,} event(s) returned. Raw event fields and normal activity are retained here."
        )
        st.json(events, expanded=False)


@st.fragment(run_every=3)
def _render_windows_security_events():
    st.subheader("Windows Security Events")
    _render_synthetic_event_demo()
    monitor = st.session_state.get("security_monitor")
    snapshot = monitor.snapshot() if monitor is not None else {}
    session_running = monitor is not None and monitor.running
    status = snapshot.get("event_monitoring_status", "stopped").title()
    if os.name == "nt":
        start_col, stop_col = st.columns([1, 1])
        if start_col.button(
            "Start Session Monitoring",
            type="primary",
            disabled=session_running,
            key="start_session_event_monitoring",
        ):
            directories = st.session_state.get(
                "monitor_directories",
                str(Path.home() / "Downloads"),
            )
            selected = list(dict.fromkeys(
                Path(line.strip()) for line in directories.splitlines() if line.strip()
            ))
            try:
                session_monitor = RealtimeMonitor(
                    selected,
                    YaraScanner(),
                    alert_log_path=STATE_DIR / "alerts.jsonl",
                )
                session_monitor.start()
                st.session_state["security_monitor"] = session_monitor
                st.rerun()
            except (OSError, RuntimeError, ValueError) as exc:
                st.error(f"Session monitoring could not start: {exc}")
        if stop_col.button(
            "Stop Session Monitoring",
            disabled=not session_running,
            key="stop_session_event_monitoring",
        ):
            monitor.stop()
            st.session_state.pop("security_monitor", None)
            st.rerun()

    normal_count = snapshot.get("normal_event_count", 0)
    alert_count = snapshot.get("security_alert_count", 0)
    status_columns = st.columns(4)
    status_columns[0].metric("Session monitoring", "Running" if session_running else status)
    status_columns[1].metric("New events observed", snapshot.get("security_event_count", 0))
    status_columns[2].metric("Normal events", normal_count)
    status_columns[3].metric("Security alerts", alert_count)
    last_read = snapshot.get("last_successful_event_read_utc")
    st.caption(f"Last successful event-log read (UTC): {last_read or 'Not yet successful'}")

    if os.name != "nt":
        st.info("Windows Security and System event logs are available only on Windows.")
        return
    st.caption(
        "Session monitoring runs inside this app session and is independent of background file protection."
    )
    for error in snapshot.get("event_log_errors", []):
        st.error(
            f"{error.get('Log', 'Windows event logs')}: "
            f"{error.get('Error', 'Unable to read the event log. Check permissions.')}"
        )

    if st.button("Load latest 50 existing Windows security events (read-only)", key="load_latest_windows_events"):
        try:
            st.session_state["windows_existing_events"] = read_latest_windows_security_events()
            st.session_state.pop("windows_existing_events_error", None)
        except WindowsSecurityError as exc:
            st.session_state.pop("windows_existing_events", None)
            st.session_state["windows_existing_events_error"] = str(exc)
    if st.session_state.get("windows_existing_events_error"):
        st.error(st.session_state["windows_existing_events_error"])

    existing = st.session_state.get("windows_existing_events")
    if existing is not None:
        st.caption(
            f"{len(existing['events'])} existing event(s) returned; loading the preview is read-only."
        )
        for error in existing.get("errors", []):
            st.error(
                f"{error.get('Log', 'Windows event logs')}: "
                f"{error.get('Error', 'Unable to read the event log. Check permissions.')}"
            )
        if existing["events"]:
            _render_windows_event_tables(existing["events"], "Existing events")
        else:
            st.info("No matching existing Security or System events were returned.")

    live_events = snapshot.get("security_events", [])
    st.caption(
        "New events are deduplicated by log, event ID, timestamp, provider, and record ID. "
        "Security-relevant event types are indicators for review, not proof of malicious activity."
    )
    if live_events:
        _render_windows_event_tables(live_events, "Newly monitored events")
    elif snapshot.get("event_monitoring_status") == "running":
        st.info("Waiting for new Windows Security or System events.")
    else:
        st.info("Start monitoring to receive new Windows Security and System events.")


@st.fragment(run_every=3)
def _render_background_monitor_controls(directories=None):
    st.subheader("Background directory monitoring")
    try:
        background_status = get_background_status()
    except BackgroundMonitorError as exc:
        background_status = {"state": "unknown", "running": False, "error": str(exc)}
        st.error(f"Background monitor status could not be verified: {exc}")

    heartbeat = background_status.get("heartbeat_utc")
    state = background_status.get("state", "unknown")
    if directories is None:
        directories = st.session_state.get(
            "monitor_directories",
            str(Path.home() / "Downloads"),
        )

    status_name = "Monitoring Stopped"
    status_note = "No verified background monitor is running."
    status_tone = "neutral"
    if background_status.get("running"):
        status_name = "Monitoring Active"
        status_note = f"Configured file monitor verified · PID {background_status.get('pid')}"
        status_tone = "teal"
    elif state == "starting":
        status_name = "Starting"
        status_note = "Waiting for a healthy process and heartbeat."
        status_tone = "amber"
    elif state == "stopping":
        status_name = "Stopping"
        status_note = f"Stopping · PID {background_status.get('pid', 'not reported')}"
        status_tone = "amber"
    elif state in {"failed", "stale", "unknown"}:
        status_name = "Monitoring Error"
        status_note = str(background_status.get("error", "Monitor health could not be verified."))
        status_tone = "red"

    status_col, action_col = st.columns([3, 1])
    status_col.markdown(
        f'<div class="protection-status protection-status-{status_tone}">'
        f'<span class="protection-status-dot"></span><span>{html.escape(status_name)}</span>'
        f'<small>{html.escape(status_note)}</small></div>',
        unsafe_allow_html=True,
    )
    if background_status.get("running"):
        if action_col.button(
            "Stop Monitoring",
            type="primary",
            key="stop_background_monitor",
            use_container_width=True,
        ):
            try:
                stopped = stop_background_monitor()
            except (BackgroundMonitorError, OSError, ValueError) as exc:
                st.error(f"Background monitor could not be stopped cleanly: {exc}")
            else:
                st.success(
                    f"Monitoring stopped · PID {stopped.get('pid')} · "
                    f"{stopped.get('files_checked', 0):,} file(s) checked."
                )
                st.rerun()
    elif state in {"starting", "stopping"}:
        action_col.button(
            "Monitoring Starting" if state == "starting" else "Monitoring Stopping",
            disabled=True,
            use_container_width=True,
        )
    elif os.name != "nt":
        action_col.button(
            "Start Monitoring",
            type="primary",
            disabled=True,
            help="Background directory monitoring is available only on Windows.",
            use_container_width=True,
        )
    elif action_col.button(
        "Start Monitoring",
        type="primary",
        key="start_background_monitor",
        use_container_width=True,
    ):
        selected = list(dict.fromkeys(
            Path(line.strip()) for line in directories.splitlines() if line.strip()
        ))
        try:
            status = start_background_monitor(selected)
        except (BackgroundMonitorError, OSError, ValueError) as exc:
            st.error(f"Background monitor could not start: {exc}")
            st.caption(f"Monitor log: {MONITOR_LOG_PATH}")
        else:
            st.success(
                f"Monitoring is healthy · PID {status.get('pid')} · "
                f"{status.get('files_checked', 0):,} file(s) checked."
            )
            st.rerun()

    scan_count = background_status.get("files_checked")
    scan_value = f"{scan_count:,}" if isinstance(scan_count, int) else "—"
    activity_time = heartbeat
    activity_note = "Last monitor heartbeat (UTC)" if activity_time else "No activity recorded"
    status_cards = st.columns(4)
    status_cards[0].markdown(
        ui.dashboard_stat("shield", status_name, "Monitor Status", status_note, status_tone),
        unsafe_allow_html=True,
    )
    status_cards[1].markdown(
        ui.dashboard_stat("file", scan_value, "Files Scanned", "Last reported monitor count"),
        unsafe_allow_html=True,
    )
    monitored_directories = background_status.get("directories", [])
    status_cards[2].markdown(
        ui.dashboard_stat(
            "file",
            f"{len(monitored_directories):,}",
            "Monitored Directories",
            "Configured file-watch paths",
        ),
        unsafe_allow_html=True,
    )
    status_cards[3].markdown(
        ui.dashboard_stat(
            "bolt",
            _protection_alert_time({"created_at_utc": activity_time}) if activity_time else "—",
            "Last Activity",
            activity_note,
            "violet",
        ),
        unsafe_allow_html=True,
    )

    if os.name != "nt":
        st.info("Background directory monitoring is available only on Windows.")
    default_watch = str(Path.home() / "Downloads")
    configured_directories = "\n".join(background_status.get("directories", [])) or default_watch
    directories = st.text_area(
        "Directories to monitor (one path per line)",
        value=configured_directories,
        help="Only selected directories are observed. This is not system-wide antivirus protection.",
        height=76,
        key="monitor_directories",
    )
    st.caption(
        "Monitoring is limited to the configured directories and supported Windows event sources; "
        "it is not full antivirus or system-wide protection."
    )

    with st.expander("Advanced Details · Monitoring", expanded=False):
        pid_label = "Actual process PID" if background_status.get("running") else "Last reported PID"
        pid_value = background_status.get("pid", "Not reported")
        st.caption(f"{pid_label}: {pid_value}")
        st.caption(f"Last heartbeat (UTC): {heartbeat or 'Not reported'}")
        monitored_directories = background_status.get("directories", [])
        directory_label = (
            "Monitored directories" if background_status.get("running")
            else "Last configured directories (inactive)"
        )
        st.caption(
            directory_label + ": "
            + (", ".join(monitored_directories) if monitored_directories else "Not active")
        )
        health = background_status.get("health")
        health = health if isinstance(health, dict) else {}
        if background_status.get("running") or state == "stopped":
            worker_statuses = (
                health.get("file_observer_status", "unknown"),
                health.get("file_worker_status", "unknown"),
                health.get("event_monitoring_status", "unknown"),
            )
        else:
            worker_statuses = (state.title(),) * 3 if state in {"starting", "stopping"} else ("Unverified",) * 3
        detail_columns = st.columns(3)
        detail_columns[0].metric("File observer", str(worker_statuses[0]).title())
        detail_columns[1].metric("File worker", str(worker_statuses[1]).title())
        detail_columns[2].metric("Windows event worker", str(worker_statuses[2]).title())
        errors = []
        if background_status.get("error"):
            errors.append(str(background_status["error"]))
        for error in health.get("event_log_errors", []):
            errors.append(
                f"{error.get('Log', 'Windows event logs')}: "
                f"{error.get('Error', 'Unable to read the event log.')}"
            )
        if health.get("persistence_error"):
            errors.append(f"Alert persistence: {health['persistence_error']}")
        if health.get("queue_dropped"):
            errors.append(
                f"{health['queue_dropped']} file event(s) exceeded the bounded queue and were not checked."
            )
        if health.get("yara_available") is False:
            errors.append("YARA is unavailable; changed files receive static checks only.")
        if errors:
            for error in errors:
                st.error(error)
        else:
            st.caption("No monitoring errors reported.")
        st.markdown("**Windows sign-in startup**")
        st.caption("Optional standard-user Task Scheduler integration for the selected directories.")
        startup_approved = st.checkbox(
            "Approve adding the Aegis background monitor at sign-in",
            key="approve_monitor_startup",
        )
        if st.button(
            "Add approved startup task",
            disabled=not startup_approved,
            key="install_monitor_startup",
        ):
            selected = list(dict.fromkeys(
                Path(line.strip()) for line in directories.splitlines() if line.strip()
            ))
            try:
                install_startup_task(selected, user_approved=startup_approved)
            except (BackgroundMonitorError, OSError, ValueError, PermissionError) as exc:
                st.error(f"Startup task could not be added: {exc}")
            else:
                st.success("Aegis sign-in startup task created.")
        remove_approved = st.checkbox(
            "Approve removing only the Aegis monitor task",
            key="approve_monitor_startup_removal",
        )
        if st.button(
            "Remove Aegis startup task",
            disabled=not remove_approved,
            key="remove_monitor_startup",
        ):
            try:
                remove_startup_task()
            except BackgroundMonitorError as exc:
                st.error(f"Startup task could not be removed: {exc}")
            else:
                st.success("Aegis sign-in startup task removed.")


def _render_alert_history():
    st.subheader("Alert History")
    st.caption("Saved monitor alerts are historical records, not an indication of active threats.")
    alerts = _load_protection_alerts()
    search = st.text_input(
        "Search by filename",
        placeholder="Search saved alert filenames",
        key="protection_alert_search",
    ).strip().casefold()
    severities = sorted(
        {str(alert.get("severity", "Low")) for alert in alerts},
        key=lambda severity: (SEVERITY_RANK.get(severity, len(SEVERITY_RANK)), severity),
    )
    detection_types = sorted({_protection_alert_detection(alert) for alert in alerts})
    filter_cols = st.columns(2)
    severity_filter = filter_cols[0].selectbox(
        "Severity",
        ["All", *severities],
        key="protection_alert_severity_filter",
    )
    detection_filter = filter_cols[1].selectbox(
        "Detection type",
        ["All", *detection_types],
        key="protection_alert_detection_filter",
    )
    filtered_alerts = [
        alert for alert in alerts
        if (not search or search in _protection_alert_filename(alert).casefold())
        and (severity_filter == "All" or str(alert.get("severity", "Low")) == severity_filter)
        and (
            detection_filter == "All"
            or _protection_alert_detection(alert) == detection_filter
        )
    ]
    st.caption(f"{len(filtered_alerts):,} saved alert(s)")
    _render_protection_alerts(filtered_alerts, "history")


def show_realtime_protection():
    st.markdown(
        '<div class="live-protection-heading"><h1>Live Protection</h1>'
        '<p>Monitor configured directories and supported Windows events; coverage is limited to those sources.</p></div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        """
        <style>
        .live-protection-heading { margin:.1rem 0 1.1rem; }
        .live-protection-heading h1 { margin:0; color:#F1F5F9; font-size:1.72rem; font-weight:650; }
        .live-protection-heading p { margin:.35rem 0 0; color:#94A3B8; font-size:.94rem; }
        .protection-status { display:flex; align-items:center; gap:.6rem; padding:.78rem .9rem;
          min-height:46px; border:1px solid #27344A; border-radius:10px; background:#101827;
          color:#F1F5F9; font-size:.92rem; font-weight:700; }
        .protection-status small { margin-left:auto; color:#94A3B8; font-size:.76rem; font-weight:500; text-align:right; }
        .protection-status-dot { width:.62rem; height:.62rem; border-radius:50%; background:#94A3B8; flex:0 0 auto; }
        .protection-status-teal .protection-status-dot { background:#22C55E; box-shadow:0 0 12px #22C55566; }
        .protection-status-amber .protection-status-dot { background:#F59E0B; }
        .protection-status-red .protection-status-dot { background:#EF4444; }
        [class*="st-key-protection_alert_"] { padding:.65rem; border:1px solid #27344A;
          border-radius:10px; background:#101827; margin:.35rem 0; }
        .st-key-live_protection_tab div[role="radiogroup"] { display:flex; gap:.35rem; padding-bottom:.55rem;
          border-bottom:1px solid #27344A; }
        .st-key-live_protection_tab div[role="radiogroup"] label { padding:.42rem .8rem; border:1px solid transparent;
          border-radius:8px; background:transparent; }
        .st-key-live_protection_tab div[role="radiogroup"] label:has(input:checked) {
          border-color:#4C3A78; background:#201A37; }
        .st-key-live_protection_tab div[role="radiogroup"] label:has(input:checked) p { color:#F1F5F9; }
        @media(max-width:850px) {
          .protection-status { align-items:flex-start; flex-wrap:wrap; }
          .protection-status small { width:100%; margin-left:1.22rem; text-align:left; }
        }
        @media(max-width:650px) {
          .st-key-live_protection_tab div[role="radiogroup"] { flex-wrap:wrap; }
          .st-key-live_protection_tab div[role="radiogroup"] label { padding:.35rem .55rem; }
        }
        </style>
        """,
        unsafe_allow_html=True,
    )
    selected_view = st.radio(
        "Live Protection views",
        ["Overview", "Windows Events", "Alert History"],
        horizontal=True,
        label_visibility="collapsed",
        key="live_protection_tab",
    )
    if selected_view == "Overview":
        _render_background_monitor_controls()
    elif selected_view == "Windows Events":
        _render_windows_security_events()
    else:
        _render_alert_history()


def show_live_alerts():
    ui.page_header("Live security alerts", "Recent file and Windows event signals from this local session.")
    _render_live_alerts()


def show_url_security_checker():
    ui.page_header(
        "URL security checker",
        "Inspect URL formatting and visible indicators without visiting the destination.",
    )
    st.warning(
        "URLs are not opened or submitted externally. An unknown result is not a safe verdict."
    )
    st.caption(
        "No reputation database is configured; HTTPS alone does not verify who controls a destination."
    )
    url = st.text_input("URL Input", placeholder="https://example.com/file", key="url_security_input")
    if st.button("Check URL", type="primary", key="url_security_check"):
        result = inspect_url(url)
        st.session_state["url_security_result"] = {
            "input": url.strip(),
            "result": result,
        }
    saved_result = st.session_state.get("url_security_result")
    if saved_result and saved_result["input"] == url.strip():
        result = saved_result["result"]
        if result["status"] == "invalid":
            st.error(result["signals"][0])
        elif result["signals"]:
            _render_alert_collection(
                [{
                    "id": "URL-001",
                    "source": "url",
                    "severity": "Medium",
                    "title": "URL has indicators that need review",
                    "affected": result["host"],
                    "description": "; ".join(result["signals"]),
                    "technical_record": {
                        "url": url,
                        "signals": result["signals"],
                        "safe_indicators": result.get("safe_indicators", []),
                    },
                    "evidence": [{"file": result["host"]}],
                }],
                "url_review",
                empty_message="No URL-format indicators were found.",
            )
        else:
            st.success("No obvious URL-format indicators found.")
            st.caption(
                "No reputation lookup was performed, so this is not a safety verdict. "
                "The destination was not visited."
            )
        st.caption("The destination is never opened or submitted to a third party.")


def show_scan_history():
    ui.page_header("Security scan history", "Review scan summaries saved on this computer.")
    try:
        history = load_scan_history()
    except (OSError, ValueError) as exc:
        st.error(f"Stored scan history could not be read: {exc}")
        return
    if not history:
        st.info("No laptop scan reports have been saved yet.")
        return
    query = st.text_input("Search saved scans", key="scan_history_search").strip().casefold()
    filtered_history = [
        item
        for item in history
        if not query
        or query in " ".join(
            str(item.get(field, ""))
            for field in ("completed_at_utc", "root", "case_id")
        ).casefold()
    ]
    if not filtered_history:
        st.info("No saved scans match that search.")
        return
    choices = [
        f"{item.get('completed_at_utc', 'Unknown time')} · "
        f"{Path(item.get('root', 'Unknown directory')).name} · "
        f"{len(item.get('findings', [])):,} finding(s)"
        for item in filtered_history
    ]
    page_size = 10
    page_count = max(1, (len(filtered_history) + page_size - 1) // page_size)
    page_number = 1
    if page_count > 1:
        _reset_pagination_if_needed("scan_history_page", page_count)
        page_number = st.number_input(
            "Saved scan page",
            min_value=1,
            max_value=page_count,
            value=1,
            step=1,
            key="scan_history_page",
        )
    offset = (page_number - 1) * page_size
    page_choices = choices[offset:offset + page_size]
    selected_index = st.selectbox(
        "Choose a saved scan",
        range(len(page_choices)),
        format_func=lambda index: page_choices[index],
    )
    report = filtered_history[offset + selected_index]
    try:
        EvidenceIntegrity.require_scan_report(report)
    except (OSError, ValueError) as exc:
        st.warning(f"Unverified historical scan findings (displayed for review only): {exc}")
    _render_alert_collection(
        _scan_findings_for_report(report),
        "scan_history",
        case_id=report.get("case_id"),
        empty_message="No threats detected in this saved scan.",
        coverage_note=(
            f"{report.get('files_checked', 0):,} files checked; "
            f"{report.get('files_skipped', 0):,} skipped. "
            + (
                "The saved scan did not complete."
                if not report.get("scan_complete", False)
                else "Coverage is limited to accessible supported files in the selected folder."
            )
        ),
    )
    with st.expander("Technical Details · saved scan record", expanded=False):
        st.json(report, expanded=False)
    st.download_button(
        "Download selected report (.json)",
        data=json.dumps(report, indent=2, default=str),
        file_name="aegis_saved_scan.json",
        mime="application/json",
    )


def _report_export_payloads(record, *, cached_text=None, expected_case_id=None, expected_sha256=None, expected_scan_snapshot_sha256=None):
    """Every forensic download uses freshly checked payloads, never session flags."""
    from reportlab.platypus.doctemplate import LayoutError
    if not record or (cached_text is not None and cached_text != record.get("text")):
        st.warning(DRAFT_WARNING + " Cached report content does not match its evidence record.")
        return None
    context = dict(expected_case_id=expected_case_id, expected_sha256=expected_sha256,
                   expected_scan_snapshot_sha256=expected_scan_snapshot_sha256)
    check = validate_report_export(record, **context)
    if not check["passed"]:
        st.warning(DRAFT_WARNING + " " + "; ".join(check["errors"]))
        return None
    try:
        return (render_forensic_text(record, **context), render_forensic_pdf(record, **context))
    except (OSError, ValueError, LayoutError) as exc:
        st.warning(DRAFT_WARNING + " " + str(exc))
        return None


def _render_report_mode(saved):
    labels = {"template": "Deterministic template", "llm": "Local language model",
              "hybrid": "Local language-model summary with deterministic findings"}
    st.caption("Report mode: " + labels.get(saved.get("mode"), "Not recorded"))
    if saved.get("note"):
        st.info(saved["note"])


def show_ai_reports():
    ui.page_header("AI forensic reports", "Evidence-grounded reporting from the existing investigation workflow.")
    saved = st.session_state.get("ai_report")
    if saved:
        valid, message = EvidenceIntegrity.verify_audit_trail(saved.get("report_record", {}).get("case_id", DEFAULT_CASE_ID))
        if not valid:
            st.warning(f"Unverified historical report: current case audit verification failed. {message}")
        st.caption(
            "This report was generated by the existing investigation reporter. Review its evidence "
            "references and validation notes before relying on it."
        )
        _render_report_mode(saved)
        payloads = _report_export_payloads(saved.get("report_record"), cached_text=saved["text"])
        st.markdown(saved["text"])
        st.download_button("Download investigation report (.md)", payloads[0] if payloads else "", disabled=not payloads, file_name="aegis_forensic_report.md")
        if saved.get("report_record"):
            st.download_button(
                "Download investigation report (.pdf)",
                data=payloads[1] if payloads else b"",
                disabled=not payloads,
                file_name=f"{saved['report_record']['case_id']}_forensic_report.pdf",
                mime="application/pdf",
                key="download_current_forensic_pdf",
            )
    else:
        st.info("No AI report has been generated in this browser session.")
        st.button(
            "Open Investigation workspace",
            on_click=navigate_to,
            args=("Investigation",),
            use_container_width=True,
        )

    try:
        archived_reports = load_forensic_reports()
    except (OSError, ValueError) as exc:
        st.error(f"Saved forensic reports could not be read: {exc}")
        archived_reports = []
    if archived_reports:
        st.divider()
        st.subheader("Saved forensic reports")
        report_query = st.text_input("Search saved reports", key="saved_report_search").strip().casefold()
        filtered_reports = [
            item
            for item in archived_reports
            if not report_query
            or report_query in " ".join(
                str(item.get(field, ""))
                for field in (
                    "generated_at_utc",
                    "case_id",
                    "mode",
                    "filename",
                    "evidence_id",
                    "sha256",
                )
            ).casefold()
        ]
        if not filtered_reports:
            st.info("No saved reports match that search.")
        else:
            report_choices = [
                f"{item.get('generated_at_utc', 'Unknown time')} · "
                f"{item.get('case_id', 'Unknown case')} · {item.get('mode', 'unknown mode')} · "
                f"{item.get('filename', 'Unknown evidence')} · "
                f"Evidence #{item.get('evidence_id', 'not recorded')}"
                for item in filtered_reports
            ]
            report_page_size = 10
            report_page_count = max(1, (len(filtered_reports) + report_page_size - 1) // report_page_size)
            report_page = 1
            if report_page_count > 1:
                _reset_pagination_if_needed("saved_report_page", report_page_count)
                report_page = st.number_input(
                    "Saved report page",
                    min_value=1,
                    max_value=report_page_count,
                    value=1,
                    step=1,
                    key="saved_report_page",
                )
            report_offset = (report_page - 1) * report_page_size
            choices_on_page = report_choices[report_offset:report_offset + report_page_size]
            selected_report = st.selectbox(
                "Choose a saved report",
                range(len(choices_on_page)),
                format_func=lambda index: choices_on_page[index],
            )
            archived = filtered_reports[report_offset + selected_report]
            valid, message = EvidenceIntegrity.verify_audit_trail(archived.get("case_id", DEFAULT_CASE_ID))
            if not valid:
                st.warning(f"Unverified historical report: current case audit verification failed. {message}")
            st.caption("Stored report text is not independently authenticated by the case hash chain.")
            with st.expander("Technical Details · report evidence hash", expanded=False):
                st.caption(f"Evidence SHA-256: {archived.get('sha256', 'not recorded')}")
            payloads = _report_export_payloads(archived)
            st.markdown(archived.get("text", ""))
            st.download_button(
                "Download saved report (.md)",
                payloads[0] if payloads else "",
                disabled=not payloads,
                file_name=f"{archived.get('case_id', 'aegis')}_forensic_report.md",
                key="download_saved_forensic_report",
            )
            st.download_button(
                "Download saved report (.pdf)",
                data=payloads[1] if payloads else b"",
                disabled=not payloads,
                file_name=f"{archived.get('case_id', 'aegis')}_forensic_report.pdf",
                mime="application/pdf",
                key="download_saved_forensic_pdf",
            )

    scan_report = st.session_state.get("laptop_scan_report")
    if scan_report:
        st.divider()
        st.subheader("Evidence-grounded laptop scan report")
        st.caption(
            "The trained XGBoost and Isolation Forest models are not applied to arbitrary files. "
            "This report uses the existing deterministic reporter and scan evidence only."
        )
        if st.button("Build local report from scan evidence", key="build_laptop_forensic_report"):
            try:
                record = build_laptop_scan_report(scan_report)
            except (OSError, ValueError) as exc:
                st.warning(f"Case or scan verification failed. Report generation blocked: {exc}")
                st.stop()
            report_text = record["text"]
            st.session_state["laptop_forensic_report"] = report_text
            st.session_state["laptop_forensic_report_record"] = record
            try:
                save_forensic_report(record)
            except OSError as exc:
                st.error(f"The report was generated but could not be saved to local history: {exc}")
        report_text = st.session_state.get("laptop_forensic_report")
        if report_text:
            report_record = st.session_state.get("laptop_forensic_report_record")
            payloads = _report_export_payloads(report_record, cached_text=report_text,
                expected_case_id=scan_report.get("case_id"),
                expected_scan_snapshot_sha256=EvidenceIntegrity.scan_snapshot_hash(scan_report))
            st.markdown(report_text)
            st.download_button(
                "Download laptop forensic report (.md)",
                payloads[0] if payloads else "",
                disabled=not payloads,
                file_name="aegis_laptop_forensic_report.md",
                key="download_laptop_forensic_report",
            )
            report_record = st.session_state.get("laptop_forensic_report_record")
            if report_record:
                st.download_button(
                    "Download laptop forensic report (.pdf)",
                    data=payloads[1] if payloads else b"",
                    disabled=not payloads,
                    file_name=f"{report_record['case_id']}_forensic_report.pdf",
                    mime="application/pdf",
                    key="download_laptop_forensic_report_pdf",
                )


_apply_pending_navigation()
section = st.session_state.get(
    "active_section",
    "Dashboard",
)
if section not in ui.SECTION_PAGES:
    section = "Dashboard"
st.session_state["active_section"] = section
if st.session_state.get("site_section_mobile") != section:
    st.session_state["site_section_mobile"] = section

with st.container(key="aegis_top_nav"):
    brand_col, nav_col, actions_col = st.columns([1.9, 7.8, 2.3])
    with brand_col:
        ui.top_brand()
    with nav_col:
        with st.container(key="aegis_desktop_nav"):
            nav_columns = st.columns(len(ui.NAV), gap="small")
            for nav_item, nav_column in zip(ui.NAV, nav_columns):
                with nav_column:
                    st.button(
                        nav_item,
                        type="primary" if section == nav_item else "secondary",
                        on_click=navigate_to,
                        args=(nav_item,),
                        use_container_width=True,
                        key=f"nav_{_section_page_key(nav_item)}",
                    )
        with st.container(key="aegis_mobile_nav"):
            st.selectbox(
                "Navigate",
                ui.MOBILE_NAV,
                label_visibility="collapsed",
                key="site_section_mobile",
                on_change=_select_mobile_section,
            )
    with actions_col:
        with st.container(key="aegis_nav_actions"):
            alert_action, settings_action = st.columns(2)
            alert_action.button(
                "Alerts",
                icon=":material/notifications:",
                help="Open recent security alerts",
                on_click=navigate_to,
                args=("Live Security Alerts",),
                use_container_width=True,
                key="nav_alerts",
            )
            settings_action.button(
                "Settings",
                icon=":material/settings:",
                help="Open settings and safety information",
                type="primary" if section == "Settings" else "secondary",
                on_click=navigate_to,
                args=("Settings",),
                use_container_width=True,
                key="nav_settings",
            )

section = st.session_state.get("active_section", "Dashboard")
if section not in ui.SECTION_PAGES:
    section = "Dashboard"
    st.session_state["active_section"] = section

section_pages = ui.SECTION_PAGES[section]
page_key = _section_page_key(section)
if st.session_state.get(page_key) not in section_pages:
    st.session_state[page_key] = section_pages[0]

if len(section_pages) > 1 and section != "Live Protection":
    with st.container(key="aegis_page_nav"):
        selected_page = st.radio(
            "Section pages",
            section_pages,
            horizontal=True,
            label_visibility="collapsed",
            key=page_key,
        )
elif section == "Live Protection":
    selected_page = "Real-Time Protection"
else:
    selected_page = section_pages[0]
page = ui.SECTION_PAGE_TARGETS.get(selected_page, selected_page)
if section == "Security Scanner":
    st.session_state["scanner_mode"] = selected_page

if page == "Home":
    show_home()
    st.stop()

if page == "About":
    show_about()
    st.stop()

if page == "Scan My Laptop":
    show_laptop_scan()
    st.stop()

if page == "Real-Time Protection":
    show_realtime_protection()
    st.stop()

if page == "Malware Scanner":
    show_safety_scan()
    st.stop()

if page == "URL Security Checker":
    show_url_security_checker()
    st.stop()

if page == "Live Security Alerts":
    show_live_alerts()
    st.stop()

if page == "Security Scan History":
    show_scan_history()
    st.stop()

if page == "AI Forensic Reports":
    show_ai_reports()
    st.stop()

if page == "Windows Review":
    show_windows_review()
    st.stop()

if page == "YARA Rules":
    show_yara_library()
    st.stop()

if page == "Evidence":
    show_evidence_vault()
    st.stop()

# Keep analysis defaults internal; the workspace stays simple while the existing
# detection pipeline continues to use its established configuration.
case_id = DEFAULT_CASE_ID
threshold = 0.5

# ----------------------------------------------------------------------------
# Dashboard (investigation) page
# ----------------------------------------------------------------------------
network_csv_mode = (
    st.session_state.get("active_section") == "Security Scanner"
    and st.session_state.get("scanner_mode") == "Network CSV"
)
ui.page_header(
    "Network CSV scan" if network_csv_mode else "Investigation workspace",
    "Run the existing network-flow models and rules on supported CSV data."
    if network_csv_mode
    else "Review saved evidence and its findings.",
)
pending_monitor_alert = st.session_state.get("pending_monitor_alert_investigation")
if pending_monitor_alert:
    _render_pending_monitor_alert_investigation(pending_monitor_alert)
    st.stop()

selected_alert_finding = st.session_state.get("investigation_selected_finding")
if selected_alert_finding:
    with st.expander("Selected alert finding", expanded=True):
        _render_threat_alert(
            selected_alert_finding,
            "investigation_selection",
            show_actions=False,
        )
        if st.button("Clear selected finding", key="clear_selected_investigation_finding"):
            st.session_state.pop("investigation_selected_finding", None)
            st.session_state.pop("investigation_focus", None)
            st.rerun()

with st.expander("Case audit verification", expanded=False):
    if st.button("Verify case audit chains", key="verify_workspace_case_audits"):
        audit_results = []
        for audit_path in sorted(CASES_DIR.glob("*_audit.log")):
            audit_case = audit_path.name.removesuffix("_audit.log")
            valid, message = EvidenceIntegrity.verify_audit_trail(audit_case, audit_path)
            audit_results.append({"Case": audit_case, "Verified": valid, "Result": message})
        st.dataframe(pd.DataFrame(audit_results), hide_index=True, use_container_width=True)

selected_saved_evidence = (
    None
    if network_csv_mode
    else st.session_state.get("selected_saved_evidence")
)
selected_saved_path = None
if selected_saved_evidence:
    try:
        selected_saved_path = _selected_saved_evidence_path(selected_saved_evidence)
    except (OSError, ValueError) as exc:
        st.error(f"The selected evidence source cannot be resolved safely: {exc}")
        st.stop()
    if selected_saved_path is None:
        st.error("The selected saved evidence is no longer present in the evidence store.")
        st.session_state.pop("selected_saved_evidence", None)
        st.stop()
    case_id = selected_saved_evidence.get("case_id") or DEFAULT_CASE_ID
    # Keep the global default fail-closed, but let the investigator explicitly
    # limit review to a case. An unrelated invalid chain must not prevent this
    # choice from being rendered. Never label a scoped result globally current.
    scope_options = ["__all_cases__"] + sorted(path.name.removesuffix("_audit.log")
                                   for path in CASES_DIR.glob("*_audit.log"))
    scope_value = st.selectbox("Case history scope", scope_options,
        format_func=lambda value: "All case histories (all chains must verify)" if value == "__all_cases__" else value,
        key="saved_case_scope_v2_" + selected_saved_evidence["sha256"])
    scope = None if scope_value == "__all_cases__" else scope_value
    selected_saved_evidence["history_case_id"] = scope
    scoped_cases = [scope] if scope else None
    try:
        available_scans = load_scanned_evidence_records(CASES_DIR, selected_saved_evidence["sha256"], case_ids=scoped_cases)
        options = ["__latest_scan__"] + sorted({scan_record_id(r) for r in available_scans})
        chosen_value = st.selectbox("Saved scan version", options,
            format_func=lambda value: ("Latest verified scan in selected case" if scope else "Latest verified scan") if value == "__latest_scan__" else next(
                f"Historical ? {r.get('scanned_at_utc') or 'time unavailable'} ? {r['case_id']} ? {value}"
                for r in available_scans if scan_record_id(r) == value),
            index=options.index(selected_saved_evidence.get("historical_scan_id")) if selected_saved_evidence.get("historical_scan_id") in options else 0,
            key=f"saved_scan_version_v2_{selected_saved_evidence['sha256']}_{scope or 'all'}")
        chosen_scan = None if chosen_value == "__latest_scan__" else chosen_value
        resolved_scan = select_saved_scan(CASES_DIR, selected_saved_evidence["sha256"],
            case_ids=scoped_cases, scan_id=chosen_scan, source_path=selected_saved_path)
        invalidate_scan_session(st.session_state, resolved_scan)
        selected_saved_evidence["scan_record"] = resolved_scan
        selected_saved_evidence["historical_scan_id"] = chosen_scan
        if resolved_scan:
            case_id = resolved_scan["case_id"]
            selected_saved_evidence["case_id"] = case_id
        elif scope:
            case_id = scope
        EvidenceIntegrity.require_evidence(
            case_id, selected_saved_path, audit_path=CASES_DIR / f"{case_id}_audit.log",
            expected_hash=selected_saved_evidence["sha256"],
            scanned_record=selected_saved_evidence.get("scan_record"),
        )
    except (OSError, ValueError) as exc:
        invalidate_scan_session(st.session_state, None)
        st.session_state.pop("ai_report", None)
        st.warning(f"Case or evidence verification failed. Saved findings cannot be trusted: {exc}")
        st.stop()
    if resolved_scan is None:
        st.info("No saved scan version is linked to this evidence in the selected history. Analysis below is derived from the verified source file.")
    else:
        st.caption(f"Saved historical snapshot: {scan_record_id(resolved_scan)}. Anomaly review below runs the currently selected model separately.")
    st.info(
        f"Selected saved evidence: {(selected_saved_evidence.get('scan_record') or {}).get('original_filename', selected_saved_path.name)} "
        f"· Evidence ID #{selected_saved_evidence.get('evidence_id', 'not recorded')} "
        f"· Case {case_id}"
    )
    if st.button("Choose a different evidence file", key="clear_saved_investigation_evidence"):
        st.session_state.pop("selected_saved_evidence", None)
        st.rerun()
    uploaded_file = None
else:
    case_id = _choose_investigation_case(DEFAULT_CASE_ID, "investigation_upload_case")
    uploaded_file = st.file_uploader(
        "Upload a network CSV" if network_csv_mode else "Add an evidence file",
        type=["csv"] if network_csv_mode else [x.lstrip(".") for x in LOG_EXT + BINARY_EXT],
    )

if network_csv_mode and selected_saved_path is None and uploaded_file is not None:
    network_csv_identity = (
        Path(uploaded_file.name).name,
        hashlib.sha256(uploaded_file.getvalue()).hexdigest(),
    )
    if st.session_state.get("network_csv_scan_identity") != network_csv_identity:
        if st.button("Analyze network CSV", type="primary", key="analyze_network_csv"):
            st.session_state["network_csv_scan_identity"] = network_csv_identity
        else:
            st.caption(
                "The existing network-flow models are intended for supported network CSV data, "
                "not arbitrary files."
            )
            st.stop()

if selected_saved_path is not None:
    saved_scan_record = selected_saved_evidence.get("scan_record")
    upload_bytes = selected_saved_path.read_bytes()
    safe_name = (
        saved_scan_record.get("original_filename")
        if saved_scan_record
        else selected_saved_path.name
    )
    file_path = str(selected_saved_path)
    saved_upload = {
        "uploaded_at_utc": (
            saved_scan_record.get("scanned_at_utc")
            if saved_scan_record
            else "Unknown"
        ),
    }
elif uploaded_file is not None:
    if (CASES_DIR / f"{case_id}_audit.log").exists():
        valid, message = EvidenceIntegrity.verify_audit_trail(case_id, CASES_DIR / f"{case_id}_audit.log")
        if not valid:
            st.warning(f"Case audit verification failed. No evidence was added: {message}")
            st.stop()
    saved_scan_record = None
    # Preserve prior evidence on filename collisions; reuse this session's saved copy on reruns.
    upload_bytes = uploaded_file.getbuffer()
    safe_name = Path(uploaded_file.name).name
    upload_identity = (case_id, safe_name, hashlib.sha256(upload_bytes).hexdigest())
    saved_upload = st.session_state.get("investigation_upload")
    if (
        saved_upload
        and saved_upload["identity"] == upload_identity
        and Path(saved_upload["path"]).is_file()
    ):
        safe_name = saved_upload["name"]
        file_path = saved_upload["path"]
    else:
        saved_path = save_evidence_copy(RAW_DIR, safe_name, upload_bytes)
        safe_name = saved_path.name
        file_path = str(saved_path)
        saved_upload = {
            "identity": upload_identity,
            "name": safe_name,
            "path": file_path,
            "uploaded_at_utc": datetime.now(timezone.utc).isoformat(),
        }
        st.session_state["investigation_upload"] = saved_upload
else:
    if st.session_state.get("investigation_focus"):
        st.info(
            "An alert was selected for investigation. Open its saved evidence from the Evidence Vault "
            "or upload the source file to review the original records."
        )
    if not network_csv_mode:
        st.caption("Open saved evidence from the Evidence Vault or upload evidence to begin.")
    st.stop()

if selected_saved_path is not None and st.button(
    "Generate Forensic Report",
    key="generate_selected_saved_evidence_report",
):
    try:
        _generate_saved_evidence_report(
            selected_saved_path,
            selected_saved_evidence.get("evidence_id", "not recorded"),
            [case_id],
        )
    except (OSError, ValueError, RuntimeError) as exc:
        st.error(f"A report could not be generated for this evidence: {exc}")
    else:
        navigate_to("AI Forensic Reports")
        st.rerun()

ext = Path(safe_name).suffix.lower()
is_log = ext in LOG_EXT

# 1. SHA-256 Hash & Integrity Audit
sha256_hash = EvidenceIntegrity.calculate_sha256(file_path)
if selected_saved_path is None and sha256_hash != hashlib.sha256(upload_bytes).hexdigest():
    st.warning("Evidence verification failed: the stored upload no longer matches the uploaded bytes. No new integrity record was written.")
    st.stop()
if selected_saved_path is None and st.session_state.get("logged_upload") != (case_id, sha256_hash):
    EvidenceIntegrity.log_audit_trail(case_id, "EVIDENCE_UPLOAD", f"File uploaded: {safe_name} | SHA256: {sha256_hash}")
    st.session_state["logged_upload"] = (case_id, sha256_hash)

if selected_saved_path is None:
    st.caption(f"File: {safe_name} · Case: {case_id}")

# 2. YARA scan (runs for every file type)
scanner = YaraScanner()
yara_findings = []
saved_findings = saved_evidence_findings(saved_scan_record) if saved_scan_record else []
if saved_scan_record:
    yara_findings = [item for item in saved_findings if item.get("source") == "yara"]
elif scanner.ready:
    try:
        yara_findings = cached_yara(file_path, sha256_hash, YaraScanner.rules_signature())
    except Exception as e:
        st.error("Threat-rule review could not be completed for this evidence.")
    if st.session_state.get("logged_yara") != (case_id, sha256_hash):
        EvidenceIntegrity.log_audit_trail(
            case_id, "YARA_SCAN",
            f"{len(yara_findings)} rule match(es) on {safe_name} using {len(scanner.loaded_files)} rule file(s)")
        st.session_state["logged_yara"] = (case_id, sha256_hash)

st.success(
    "Saved evidence opened in this investigation."
    if selected_saved_path is not None
    else "Evidence added to your investigation."
)
with st.expander("Evidence integrity details"):
    st.markdown(f'<div class="hashline">{sha256_hash}</div>', unsafe_allow_html=True)
    st.caption("This file's integrity record is available in the Evidence section.")

# Non-log files retain saved scanner findings alongside the YARA review.
if not is_log:
    st.info("This file type is reviewed for integrity and available threat-rule matches.")
    st.subheader("Threat-rule review")
    render_yara(yara_findings, scanner.ready, "bin", case_id=case_id)
    saved_static_findings = [item for item in saved_findings if item.get("source") != "yara"]
    if saved_static_findings:
        _render_alert_collection(
            saved_static_findings,
            "saved_file_static_findings",
            case_id=case_id,
            empty_message="No saved static findings are linked to this evidence.",
        )
    st.stop()

# 3. Parse logs
parser = LogParser(file_path)
try:
    df = parser.parse_logs()
    from modules.csv_evidence import refresh_csv_session
    refresh_csv_session(st.session_state, df)
except (OSError, ValueError, UnicodeError) as exc:
    st.error(f"Evidence parsing failed; CSV source locations cannot be established: {exc}")
    st.stop()
with st.expander("Advanced Settings", expanded=False):
    model_column, split_column = st.columns(2)
    model_name = model_column.selectbox(
        "ML inference model",
        ["xgboost", "iforest", "generic_iforest"],
        format_func=lambda value: {"xgboost": "XGBoost (supervised classification)",
            "iforest": "Isolation Forest (unsupervised checkpoint)",
            "generic_iforest": "Generic Isolation Forest (fit to this evidence)"}[value],
        help="Network-flow checkpoints require their exact trained schema. Generic evidence fitting runs only when explicitly selected.",
    )
    model_split = split_column.selectbox(
        "Training checkpoint",
        ["random", "official"],
        disabled=model_name == 'generic_iforest',
        format_func=lambda value: (
            "Deduplicated random 70/30 split" if value == "random" else "Official UNSW-NB15 split"
        ),
    )

    selected_timestamp_column = st.selectbox(
        "Event timestamp column",
        [None] + [column for column in df.columns if not identifier_field(column)],
        format_func=lambda column: "Automatic (recognized timestamp fields)" if column is None else str(column),
        key="event_timestamp_column_" + sha256_hash,
        help="Choose the event-time field if automatic detection is ambiguous. Values still require an explicit timezone.",
    )
    timestamp_selection = select_timestamp_column(df, selected_timestamp_column)
    st.caption(timestamp_selection['message'])
chronology_context = (CHRONOLOGY_VERSION, sha256_hash, selected_timestamp_column)
if st.session_state.get('chronology_context') != chronology_context:
    st.session_state.pop('ai_report', None)
    st.session_state['chronology_context'] = chronology_context

# Rule-based findings are computed once, so the AI report can use them
findings = []
raw_df = None
rules_note = ""
if file_path.lower().endswith(".csv"):
    raw_df = load_log_csv(file_path)
    can_run, _ = RuleEngine.can_run(raw_df, selected_timestamp_column)
    if can_run:
        rule_engine = RuleEngine(raw_df, source_file=safe_name, timestamp_column=selected_timestamp_column)
        findings = rule_engine.run()
        rules_note = "; ".join(rule_engine.behavioral_diagnostics)
    else:
        rules_note = "This log is missing information required for explainable rule findings."
else:
    rules_note = "Explainable rule findings are available for supported CSV logs."

# ML + timeline are computed before the tabs so the Overview can summarise them
ml_inference_error = None
ml_checkpoint_signature = None
try:
    ml_checkpoint_signature = MLAnomalyDetector.cache_identity(model_name, model_split)
    anomalies, ml_mode = cached_ml(df, sha256_hash, model_name, threshold, model_split, ml_checkpoint_signature)
except ModelReliabilityError as exc:
    ml_inference_error = str(exc)
    anomalies, ml_mode = df.iloc[0:0].copy(), 'blocked'
    st.warning(f"ML inference was not run: {ml_inference_error}")
ml_provenance = anomalies.attrs.get('ml_provenance', {})
ml_context = (sha256_hash, model_name, model_split, threshold, ml_checkpoint_signature, ml_mode)
if st.session_state.get('ml_inference_context') != ml_context:
    st.session_state.pop('ai_report', None)
    st.session_state['ml_inference_context'] = ml_context
ml_findings = []
ml_report_link_error = None
if raw_df is not None and not anomalies.empty:
    try:
        ml_findings = ml_to_report_findings(
            anomalies,
            raw_df,
            ml_mode,
            model_split,
            safe_name,
            sha256_hash,
        )
    except ValueError as exc:
        ml_report_link_error = str(exc)
        st.error(f"ML detections could not be linked to original CSV evidence rows: {exc}")

derived_analysis_id = hashlib.sha256(json.dumps(
    [ml_context, scan_record_id(saved_scan_record) if saved_scan_record else saved_upload.get("uploaded_at_utc")],
    sort_keys=True, default=str).encode("utf-8")).hexdigest()
ml_findings = [{**finding, "analysis_origin": "derived_from_verified_source",
                "analysis_identity": derived_analysis_id} for finding in ml_findings]

# Keep findings from each source distinct; the reporter bounds its prompt context.
report_findings = merge_investigation_findings(
    saved_findings,
    findings + ([] if saved_scan_record else yara_to_report_findings(yara_findings)) + ml_findings,
)
# Keep displayed findings and report citations on the same collision-free IDs.
findings = [item for item in report_findings if item.get("source", "rule") == "rule"]
ml_findings = [item for item in report_findings if item.get("source") == "ml"]
investigation_focus = st.session_state.get("investigation_focus")
if investigation_focus:
    focused_finding = next(
        (item for item in report_findings if item.get("id") == investigation_focus),
        None,
    )
    if focused_finding:
        source = str(focused_finding.get("source", "")).casefold()
        focus_tab = (
            "Anomaly review" if source == "ml"
            else "Threat-rule review" if source == "yara"
            else "Explainable findings"
        )
        st.success(f"The selected finding is linked to this evidence. Review it in {focus_tab}.")
        st.session_state.pop("investigation_focus", None)
    else:
        st.info(
            "The selected alert is not linked to this evidence file. Confirm the source file before "
            "using these findings."
        )

if network_csv_mode:
    network_scan_findings = list(findings) + list(yara_findings)
    if ml_findings:
        ml_lines = [
            item.get("original_csv_line")
            for item in ml_findings
            if item.get("original_csv_line") is not None
        ]
        network_scan_findings.append({
            "id": f"network_csv_ml_{sha256_hash[:12]}",
            "source": "ml_aggregate",
            "severity": max(
                (item.get("severity", "Medium") for item in ml_findings),
                key=lambda value: -SEVERITY_RANK.get(value, len(SEVERITY_RANK)),
            ),
            "file": safe_name,
            "model_name": model_name,
            "checkpoint_split": model_split,
            "count": len(ml_findings),
            "row_range": (min(ml_lines), max(item.get("original_csv_line_end") or item["original_csv_line"]
                for item in ml_findings if item.get("original_csv_line") is not None)) if ml_lines else None,
            "sha256": sha256_hash,
        })
    st.caption(
        "Only supported network-flow CSV rows are evaluated by the trained ML models. "
        "Predictions and rule matches are review signals, not confirmed malicious activity."
    )
    if not scanner.ready:
        st.caption("YARA is unavailable; the configured CSV rules and network-flow checks remain separate.")
    if ml_report_link_error:
        st.warning(
            "Some model detections could not be linked to original CSV rows and are excluded from reportable findings."
        )
    _render_scan_summary(network_scan_findings, "network_csv")
    if st.button("Open in Investigations", type="primary", key="open_network_csv_investigation"):
        try:
            scan_record = add_scanned_evidence(
                RAW_DIR, safe_name, upload_bytes,
                findings + yara_to_report_findings(yara_findings) + ml_findings,
                case_id=case_id, scanned_at_utc=datetime.now(timezone.utc).isoformat(),
                audit_log_path=CASES_DIR / f"{case_id}_audit.log",
            )
        except (OSError, ValueError) as exc:
            st.error(f"The network scan could not be saved to the case: {exc}")
            st.stop()
        st.session_state["selected_saved_evidence"] = {
            "sha256": sha256_hash,
            "stored_filename": scan_record["stored_filename"],
            "case_id": case_id,
            "evidence_id": scan_record.get("evidence_id", _evidence_vault_id(Path(file_path))),
            "scan_record": scan_record,
            "historical_scan_id": scan_record_id(scan_record),
            "history_case_id": case_id,
        }
        st.session_state[f"saved_case_scope_v2_{sha256_hash}"] = case_id
        st.session_state[f"saved_scan_version_v2_{sha256_hash}_{case_id}"] = scan_record_id(scan_record)
        navigate_to("Investigation")
        st.rerun()
    st.stop()

timeline_df = pd.DataFrame()
timeline_error = None
try:
    time_builder = TimelineConstructor(df)
    timeline_df = time_builder.build_timeline(timestamp_column=selected_timestamp_column)
except Exception as e:
    timeline_error = str(e)

tab0, tab1, tab2, tab3, tab5, tab6, tab4 = st.tabs([
    "Overview", "Anomaly review", "Timeline", "Search",
    "Rule findings", "Threat rules", "Investigation report"],
    key="investigation_workspace_tab", on_change="rerun")

# ---------------------------------------------------------------- Overview
with tab0:
    _render_investigation_finding_summary(report_findings)
    if ml_report_link_error:
        st.warning(
            "Some model detections are excluded from reportable findings because they could not "
            "be linked to an original CSV evidence row."
        )

    with st.expander("Technical Details · investigation analytics", expanded=False):
        st.caption(
            f"Parsed records: {len(df):,} · Rule findings: {len(findings):,} · "
            f"YARA matches: {len(yara_findings):,} · ML predictions: {len(ml_findings):,}"
        )
        _render_investigation_analytics(
            df,
            raw_df,
            findings,
            yara_findings,
            anomalies,
            ml_findings,
            timestamp_column=selected_timestamp_column,
        )

# ---------------------------------------------------------------- ML
with tab1:
    st.subheader("Anomaly review")
    st.caption("Current derived analysis of the verified source file. These predictions are separate from any saved historical scan.")
    if saved_scan_record:
        historical_ml = [finding for finding in saved_findings if finding.get("source") == "ml"]
        with st.expander("Saved historical ML findings", expanded=False):
            st.caption(f"Scan {scan_record_id(saved_scan_record)}; recorded {saved_scan_record.get('scanned_at_utc', 'time unavailable')}.")
            _render_alert_collection(historical_ml, "historical_ml", source_rows=raw_df,
                case_id=case_id, empty_message="No individual ML findings were recorded in this snapshot.")
    if ml_mode == 'blocked':
        st.error(f"Selected model unavailable: {ml_inference_error}")
    elif ml_mode and ml_mode.startswith("trained"):
        task = 'supervised classification' if ml_mode == 'trained_xgboost' else 'unsupervised anomaly detection'
        st.success(f"The selected {model_name} checkpoint ({model_split} split) ran {task}.")
        st.caption(f"Checkpoint: {ml_provenance.get('checkpoint_path')} | SHA-256: {ml_provenance.get('checkpoint_sha256')}")
        st.caption(ml_provenance.get('score_meaning', 'Score interpretation unavailable.'))
    elif ml_mode == "insufficient_data":
        st.info("There are too few source rows for this analysis; no model was fitted and no alternate model was run.")
    elif ml_mode == 'unsupervised_isolation_forest':
        st.info("Generic Isolation Forest was explicitly selected and fitted only to this evidence. It is unsupervised anomaly detection, not supervised classification or a trained network-flow checkpoint.")
        st.caption(ml_provenance.get('score_meaning', ''))

    _render_alert_collection(
        ml_findings,
        "investigation_ml",
        source_rows=raw_df,
        case_id=case_id,
        empty_message=(
            ("Selected ML inference was not run." if ml_mode == 'blocked' else "No unusual records were flagged by the selected model.")
            if anomalies.empty
            else "No model detections could be linked to original CSV evidence rows."
        ),
    )
    if not anomalies.empty and not ml_findings:
        st.warning(
            "The model returned unusual records, but they are not shown as evidence alerts because "
            "their original CSV row references could not be verified."
        )

    with st.expander("Technical Details · model output and evaluation", expanded=False):
        if ml_provenance:
            st.json(ml_provenance, expanded=False)
        training_metrics = MLAnomalyDetector.load_metrics(model_split) if ml_mode and ml_mode.startswith('trained_') else {}
        if training_metrics:
            metric_rows = []
            for metric_model in ("XGBoost", "IsolationForest"):
                result = training_metrics.get(metric_model)
                if result:
                    metric_rows.append({
                        "Model": metric_model,
                        "Accuracy": result.get("accuracy"),
                        "Precision": result.get("precision"),
                        "Recall": result.get("recall"),
                        "F1": result.get("f1"),
                        "AUC": result.get("auc"),
                        "Confusion matrix [TN, FP; FN, TP]": result.get("confusion_matrix"),
                    })
            if metric_rows:
                st.markdown("Stored training evaluation (not this upload's performance)")
                st.dataframe(pd.DataFrame(metric_rows), use_container_width=True, hide_index=True)
                st.caption(
                    "UNSW-NB15 holdout evaluation recorded in "
                    f"reports{'/official_split' if model_split == 'official' else ''}/metrics.json."
                )
        if not anomalies.empty:
            _render_technical_table(anomalies, "investigation_anomalies")
        if ("label" in df.columns and ml_mode and ml_mode.startswith("trained")
                and st.checkbox("Evaluate this explicitly labeled dataset", key="evaluate_labeled_" + sha256_hash)):
            from modules.ml_evaluation import evaluate_labeled_csv
            try:
                evaluation = evaluate_labeled_csv(df, anomalies)
            except ValueError as exc:
                st.warning(f"Upload evaluation is unavailable: {exc}")
            else:
                st.markdown("Evaluation on this labeled file only")
                e1, e2, e3, e4 = st.columns(4)
                e1.metric("Accuracy", f"{evaluation['accuracy']:.4f}")
                e2.metric("Precision", f"{evaluation['precision']:.4f}")
                e3.metric("Recall", f"{evaluation['recall']:.4f}")
                e4.metric("F1", f"{evaluation['f1']:.4f}")
                st.write({key: evaluation[key] for key in ("tp", "tn", "fp", "fn", "confusion_matrix")})
                st.caption("Confusion matrix: [TN, FP; FN, TP]. A demonstration sample does not establish full-dataset performance.")

# ---------------------------------------------------------------- Timeline
with tab2:
    st.subheader("Incident timeline")
    if not timeline_error and time_builder.selection['status'] != 'resolved':
        st.warning(time_builder.selection['message'])
    if not timeline_error and not time_builder.unresolved_events.empty:
        st.caption(f"{len(time_builder.unresolved_events):,} records have unresolved event times and are excluded from chronological ordering.")
        with st.expander("Technical Details - unresolved event times", expanded=False):
            _render_technical_table(time_builder.unresolved_events, "investigation_unresolved_times")
    if timeline_error:
        st.info("A timeline is not available because this evidence does not contain a usable date or time field.")
    else:
        if timeline_df.empty:
            st.info("No timeline records are available.")
        else:
            st.caption(
                f"{len(timeline_df):,} records in chronological order. "
                "Only resolved UTC event times are ordered here. The timeline is context, not a threat verdict."
            )
            with st.expander("Technical Details · timeline records", expanded=False):
                _render_technical_table(timeline_df, "investigation_timeline")

# ---------------------------------------------------------------- Semantic
with tab3:
    st.subheader("Search related activity")
    query = st.text_input("Describe the activity or indicator you want to find:", "unauthorized access")
    prepared_search = prepare_evidence_search(
        df, sha256=sha256_hash, case_id=case_id, query=query, filename=safe_name,
        max_records=SEMANTIC_SEARCH_MAX_RECORDS, source_rows=raw_df,
    )
    search_result = st.session_state.get("investigation_search_result")
    if search_result and search_result.get("key") != prepared_search["key"]:
        st.session_state.pop("investigation_search_result", None)
        search_result = None
    if st.button("Search evidence"):
        if prepared_search["records"] and prepared_search["query"]:
            if search_result is None:
                try:
                    search_result = search_evidence(prepared_search)
                    st.session_state["investigation_search_result"] = search_result
                except Exception as exc:
                    st.error(f"Evidence search failed: {type(exc).__name__}: {exc}")
        else:
            st.warning(
                "No searchable text was found in this evidence."
                if not prepared_search["records"] else "Enter an activity or indicator to search."
            )
            st.session_state.pop("investigation_search_result", None)
    search_result = st.session_state.get("investigation_search_result")
    if search_result and search_result.get("key") == prepared_search["key"]:
        matches = search_result["matches"]
        if search_result["searched_records"] < search_result["total_records"]:
            st.warning(
                f"Search covered the first {search_result['searched_records']:,} of "
                f"{search_result['total_records']:,} records to limit memory use."
            )
        if matches:
            st.caption(
                f"{len(matches):,} related records found. Similarity is a search aid, not a threat verdict."
            )
            for match in matches[:5]:
                location_text = f"Logical CSV record {match['record_number']}" if safe_name.lower().endswith(".csv") else f"Record {match['record_number']}"
                if match.get("source_line") is not None:
                    start, end = match["source_line"], match.get("source_line_end", match["source_line"])
                    location_text += f" · line {start}" if start == end else f" · lines {start}–{end}"
                st.markdown(f"**{location_text} · {safe_name}**")
                st.write(str(match["event"])[:240])
            if len(matches) > 5:
                st.caption(f"{len(matches) - 5:,} additional records are available in Technical Details.")
            with st.expander("Technical Details · search results", expanded=False):
                st.caption(
                    "Similarity scores and the complete searchable result set are shown here. "
                    "They do not represent malware probabilities."
                )
                st.write(
                    f"Search method: {search_result['mode']}"
                    + (
                        f" · {search_result['model_name']}"
                        if search_result["mode"] == "sentence_transformers"
                        else " · lexical heuristic"
                    )
                )
                if search_result.get("score_meaning"):
                    st.caption(search_result["score_meaning"])
                if search_result["error"]:
                    st.caption(f"Search model note: {search_result['error']}")
                _render_technical_table(
                    pd.DataFrame(matches),
                    "investigation_search",
                )
        else:
            st.info("No related records were found for that search.")

# ---------------------------------------------------------------- AI report
with tab4:
    st.subheader("Investigation report")
    st.caption("Generate a readable summary grounded in the findings and evidence from this investigation.")
    if ml_report_link_error:
        st.warning(
            "ML detections are excluded because they could not be linked to original CSV rows: "
            f"{ml_report_link_error}"
        )
    elif raw_df is None and not anomalies.empty:
        st.info(
            "ML anomaly rows are not included in this report because this evidence has no "
            "original CSV record references."
        )
    if len(report_findings) > LocalLLMReporter.MAX_PROMPT_FINDINGS:
        st.caption(
            f"{len(report_findings):,} findings are available. Report generation uses "
            f"at most {LocalLLMReporter.MAX_PROMPT_FINDINGS} representative findings in its "
            "language-model context and preserves aggregate totals."
        )
    model_choice = "llama3.2"
    use_llm = True
    if not report_findings:
        st.info("There are no reportable findings in this evidence yet.")

    if st.button("Generate report", disabled=not report_findings):
        try:
            EvidenceIntegrity.require_evidence(
                case_id, file_path, audit_path=CASES_DIR / f"{case_id}_audit.log",
                expected_hash=sha256_hash, scanned_record=saved_scan_record,
            )
        except (OSError, ValueError) as exc:
            st.warning(f"Case or evidence verification failed. Report generation blocked: {exc}")
            st.stop()
        with st.spinner("Preparing your evidence-grounded report..."):
            from modules.csv_evidence import locator_label
            representative_lines = [locator_label(item.get("source_locator", {}))
                for item in ml_findings[:10]]
            anomalies_summary = (
                f"{len(anomalies):,} model-predicted unusual record(s); "
                f"{len(ml_findings):,} linked to original CSV evidence. "
                "Predictions are not confirmed malicious activity. "
                f"Representative source locators: {', '.join(representative_lines) or 'none'}."
            )
            timeline_summary = (
                f"Chronological view derived from {len(timeline_df):,} parsed source record(s). "
                "Individual raw records are cited only through validated finding evidence."
            )

            reporter = LocalLLMReporter(model_name=model_choice)
            report = reporter.generate_grounded_report(timeline_summary, anomalies_summary, findings=report_findings, use_llm=use_llm)
            generated_at = datetime.now(timezone.utc).isoformat()
            if selected_saved_path is not None:
                report = (
                    "## Saved Evidence Record\n"
                    f"- Evidence ID: {selected_saved_evidence.get('evidence_id', 'not recorded')}\n"
                    f"- Filename: {safe_name}\n"
                    f"- SHA-256: {sha256_hash}\n"
                    f"- Scan timestamp (UTC): "
                    f"{(saved_scan_record or {}).get('scanned_at_utc', 'not recorded')}\n\n"
                    f"{report}"
                )
            try:
                EvidenceIntegrity.require_evidence(
                    case_id, file_path, audit_path=CASES_DIR / f"{case_id}_audit.log",
                    expected_hash=sha256_hash, scanned_record=saved_scan_record,
                )
            except (OSError, ValueError) as exc:
                st.warning(f"Case or evidence verification failed. Report generation blocked: {exc}")
                st.stop()
            audit_entry = EvidenceIntegrity.log_audit_trail(
                case_id,
                "AI_REPORT_GENERATED",
                f"mode={reporter.last_mode}; model={model_choice}; findings={len(report_findings)}; "
                f"validation_passed={reporter.last_validation.get('passed')}",
            )
            report_record = {
                "generated_at_utc": generated_at,
                "case_id": case_id,
                "evidence_id": (
                    selected_saved_evidence.get("evidence_id")
                    if selected_saved_path is not None
                    else None
                ),
                "filename": safe_name,
                "scanned_at_utc": (saved_scan_record or {}).get("scanned_at_utc"),
                "chronology_version": CHRONOLOGY_VERSION,
                "timestamp_interpretation": {"column": timestamp_selection['column'],
                    "status": timestamp_selection['status'], "resolved": timestamp_selection.get('resolved', 0),
                    "unresolved": len(df) - timestamp_selection.get('resolved', 0)},
                "scan_id": scan_record_id(saved_scan_record) if saved_scan_record else None,
                "investigation_started_at_utc": saved_upload.get("uploaded_at_utc", "Unknown"),
                "investigation_completed_at_utc": generated_at,
                "source_paths": [str(file_path)],
                "sha256": sha256_hash,
                "findings": reporter.last_report_findings,
                "finding_summary": reporter.last_finding_summary,
                "windows_event_references": _uploaded_event_references(raw_df, findings, selected_timestamp_column),
                "limitations": _forensic_limitations(),
                "audit_trail": [audit_entry],
                "mode": reporter.last_mode,
                "llm_generation": reporter.last_llm_diagnostics,
                "note": reporter.last_note,
                "validation": reporter.last_validation,
                "text": report,
            }
            bind_report_context(report_record, report_findings,
                audit_path=CASES_DIR / f"{case_id}_audit.log", scanned_record=saved_scan_record)
            st.session_state["ai_report"] = {
                "key": (case_id, sha256_hash),
                "text": report,
                "mode": reporter.last_mode,
                "note": reporter.last_note,
                "validation": reporter.last_validation,
                "report_record": report_record,
            }
            try:
                save_forensic_report(report_record)
            except OSError as exc:
                st.error(f"The report was generated but could not be saved to local history: {exc}")

    saved = st.session_state.get("ai_report")
    if saved and saved["key"] == (case_id, sha256_hash):
        st.markdown("---")
        payloads = _report_export_payloads(saved.get("report_record"), cached_text=saved["text"],
            expected_case_id=case_id, expected_sha256=sha256_hash)
        if payloads:
            st.success("Your report is ready. Review its cited findings before sharing.")
        _render_report_mode(saved)
        v = saved["validation"]
        if v and v.get("speculative_lines", 0) > 0:
            st.warning("Some report statements may need additional review before you rely on them.")
        st.markdown(saved["text"])
        st.download_button("Download report (.md)", payloads[0] if payloads else "", disabled=not payloads, file_name=f"{case_id}_report.md")
        if saved.get("report_record"):
            st.download_button(
                "Download report (.pdf)",
                data=payloads[1] if payloads else b"",
                disabled=not payloads,
                file_name=f"{case_id}_report.pdf",
                mime="application/pdf",
                key="download_investigation_pdf",
            )

# ---------------------------------------------------------------- Rules
with tab5:
    st.subheader("Explainable findings")
    if rules_note:
        st.info(rules_note)

    saved_static_findings = [
        item for item in saved_findings if item.get("source") not in {"yara", "rule", "ml"}
    ]
    if saved_static_findings:
        _render_alert_collection(
            saved_static_findings,
            "saved_log_static_findings",
            case_id=case_id,
            empty_message="No saved static findings are linked to this evidence.",
        )

    if findings:
        if st.session_state.get("logged_rules") != (case_id, sha256_hash):
            EvidenceIntegrity.log_audit_trail(case_id, "RULES_RUN", f"{len(findings)} findings on {safe_name}")
            st.session_state["logged_rules"] = (case_id, sha256_hash)
        _render_alert_collection(
            findings,
            "investigation_rule_findings",
            source_rows=raw_df,
            case_id=case_id,
            empty_message="No suspicious activity was identified by the configured rules.",
        )
        with st.expander("Technical Details · rule findings", expanded=False):
            st.caption(
                f"{len(findings):,} explainable rule finding(s) are linked to the original CSV rows."
            )
            _render_technical_table(
                RuleEngine.to_dataframe(findings),
                "investigation_rule_table",
            )
    elif raw_df is not None and RuleEngine.can_run(raw_df)[0]:
        st.success("No threats detected by the configured rules.")

# ---------------------------------------------------------------- YARA
with tab6:
    st.subheader("Threat-rule review")
    st.caption("Potential matches are shown separately from other investigation findings.")
    render_yara(yara_findings, scanner.ready, "log", case_id=case_id)
