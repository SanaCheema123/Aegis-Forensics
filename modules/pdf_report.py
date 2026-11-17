"""Generate local, evidence-structured PDF exports for forensic reports."""
from __future__ import annotations

from modules.ai_reporter import _evidence_text
from modules.csv_evidence import locator_label
from modules.report_validation import DRAFT_WARNING, require_report_export
from html import escape
from io import BytesIO
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


def _paragraph(value: Any, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(str(value)).replace("\n", "<br/>"), style)


def _evidence_summary(finding: dict[str, Any]) -> str:
    text = _evidence_text(finding) or str(finding.get("file") or finding.get("path") or "No evidence locator recorded")
    if finding.get("sha256"):
        text += f"; SHA-256 {finding['sha256']}"
    if finding.get('evidence_status'):
        text += '; ' + finding['evidence_status']
    return text


def _draw_footer(canvas, document) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#5B6472"))
    canvas.drawString(18 * mm, 12 * mm, "Aegis Forensics | Local evidence report")
    canvas.drawRightString(192 * mm, 12 * mm, f"Page {document.page}")
    canvas.restoreState()


def render_forensic_pdf(report: dict[str, Any], *, draft=False, **context) -> bytes:
    """Render a report record without executing or interpreting report content."""
    if not draft:
        require_report_export(report, **context)
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=18 * mm,
        leftMargin=18 * mm,
        topMargin=18 * mm,
        bottomMargin=20 * mm,
        title=f"Aegis Forensics - {report.get('case_id', 'Evidence report')}",
        author="Aegis Forensics",
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="AegisTitle",
        parent=styles["Title"],
        alignment=TA_CENTER,
        textColor=colors.HexColor("#34204F"),
        spaceAfter=12,
    ))
    styles.add(ParagraphStyle(
        name="AegisSection",
        parent=styles["Heading2"],
        textColor=colors.HexColor("#34204F"),
        spaceBefore=10,
        spaceAfter=6,
    ))
    styles.add(ParagraphStyle(
        name="AegisSmall",
        parent=styles["BodyText"],
        fontSize=8,
        leading=10,
        wordWrap="CJK",
    ))
    story = [
        _paragraph("Aegis Forensics - Evidence Report", styles["AegisTitle"]),
        _paragraph("Case and investigation details", styles["AegisSection"]),
    ]

    if draft:
        story.insert(0, _paragraph(DRAFT_WARNING, styles["AegisSection"]))

    metadata_rows = [
        ["Case ID", report.get("case_id", "Not recorded")],
        ["Evidence ID", report.get("evidence_id", "Not recorded")],
        ["Evidence filename", report.get("filename", "Not recorded")],
        ["Evidence scanned (UTC)", report.get("scanned_at_utc", "Not recorded")],
        ["Investigation started (UTC)", report.get("investigation_started_at_utc", "Not recorded")],
        ["Investigation completed (UTC)", report.get("investigation_completed_at_utc", "Not recorded")],
        ["Report generated (UTC)", report.get("generated_at_utc", "Not recorded")],
        ["Evidence SHA-256", report.get("sha256", "See findings/evidence list")],
    ]
    for label, value in metadata_rows:
        story.append(Table(
            [[_paragraph(label, styles["AegisSmall"]), _paragraph(value, styles["AegisSmall"])]],
            colWidths=[48 * mm, 124 * mm],
            style=TableStyle([
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F0EDF5")),
                ("BOX", (0, 0), (-1, -1), 0.3, colors.HexColor("#D7D1E2")),
                ("INNERGRID", (0, 0), (-1, -1), 0.2, colors.HexColor("#E3DFEA")),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]),
        ))

    finding_summary = report.get("finding_summary", {})
    if finding_summary:
        severity_counts = finding_summary.get("severity_counts", {})
        source_counts = finding_summary.get("source_counts", {})
        story.extend([
            Spacer(1, 5),
            _paragraph("Finding totals", styles["Heading3"]),
            _paragraph(
                f"Total findings: {finding_summary.get('total_findings', 'Not recorded')}; "
                f"severity totals: {severity_counts}; source totals: {source_counts}; "
                f"representative findings included: {finding_summary.get('representative_count', 'Not recorded')}; "
                f"omitted from bounded report: {finding_summary.get('omitted_count', 'Not recorded')}.",
                styles["AegisSmall"],
            ),
        ])

    source_paths = report.get("source_paths", [])
    if source_paths:
        story.extend([
            Spacer(1, 5),
            _paragraph("Evidence source paths", styles["Heading3"]),
            _paragraph("; ".join(str(path) for path in source_paths), styles["AegisSmall"]),
        ])

    narrative = str(report.get("text", "")).splitlines()
    if narrative:
        story.extend([Spacer(1, 8), _paragraph("Evidence-based findings narrative", styles["AegisSection"])])
        for line in narrative:
            content = line.strip()
            if not content:
                story.append(Spacer(1, 3))
            elif content.startswith("### "):
                story.append(_paragraph(content[4:], styles["Heading3"]))
            elif content.startswith("## "):
                story.append(_paragraph(content[3:], styles["Heading2"]))
            else:
                story.append(_paragraph(content.removeprefix("- "), styles["BodyText"]))

    findings = report.get("findings", [])
    story.append(_paragraph("Structured findings and evidence", styles["AegisSection"]))
    if findings:
        table_data = [[
            _paragraph("ID", styles["AegisSmall"]),
            _paragraph("Severity / source", styles["AegisSmall"]),
            _paragraph("Rule and explanation", styles["AegisSmall"]),
            _paragraph("Evidence path / SHA-256", styles["AegisSmall"]),
        ]]
        for finding in findings:
            table_data.append([
                _paragraph(finding.get("id", "Not recorded"), styles["AegisSmall"]),
                _paragraph(
                    f"{finding.get('severity', 'Unknown')} / {finding.get('source', 'Unknown')}",
                    styles["AegisSmall"],
                ),
                _paragraph(
                    f"{finding.get('rule', 'Finding')}: {finding.get('description', '')}",
                    styles["AegisSmall"],
                ),
                _paragraph(_evidence_summary(finding), styles["AegisSmall"]),
            ])
        findings_table = Table(
            table_data,
            colWidths=[15 * mm, 28 * mm, 67 * mm, 62 * mm],
            repeatRows=1,
            # A single Windows event message can exceed a page. Preserve it
            # across pages instead of raising LayoutError for an oversized row.
            splitInRow=1,
        )
        findings_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E9E3F1")),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#D7D1E2")),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
            ("RIGHTPADDING", (0, 0), (-1, -1), 4),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(findings_table)
    else:
        story.append(_paragraph("No reportable findings were recorded.", styles["BodyText"]))

    event_references = report.get("windows_event_references", [])
    story.append(_paragraph("Windows event references", styles["AegisSection"]))
    if event_references:
        for event in event_references:
            story.append(_paragraph(
                f"Log {event.get('log', 'Unknown')}; Event ID {event.get('event_id', 'Unknown')}; "
                f"Record ID {event.get('record_id', 'Unknown')}; Time {event.get('time_utc', 'Unknown')}; "
                f"Finding {event.get('finding_id', 'Not linked')}"
                + (f"; {locator_label(event)}" if locator_label(event) else ""),
                styles["AegisSmall"],
            ))
    else:
        story.append(_paragraph(
            "No Windows event references were supplied with this report.",
            styles["BodyText"],
        ))

    limitations = report.get("limitations", [])
    story.append(_paragraph("Limitations and uncertainty", styles["AegisSection"]))
    if limitations:
        for limitation in limitations:
            story.append(_paragraph(f"- {limitation}", styles["BodyText"]))
    else:
        story.append(_paragraph(
            "Automated findings are indicators for human review and do not establish compromise.",
            styles["BodyText"],
        ))

    audit_trail = report.get("audit_trail", [])
    story.append(_paragraph("Audit trail", styles["AegisSection"]))
    if audit_trail:
        for entry in audit_trail:
            story.append(_paragraph(
                f"{entry.get('timestamp', 'Unknown time')} | {entry.get('action', 'Unknown action')} | "
                f"Entry hash: {entry.get('entry_hash', 'Not recorded')} | "
                f"Previous hash: {entry.get('prev_hash', 'Not recorded')}",
                styles["AegisSmall"],
            ))
    else:
        story.append(_paragraph("No audit-chain entry was attached to this report.", styles["BodyText"]))

    document.build(story, onFirstPage=_draw_footer, onLaterPages=_draw_footer)
    return buffer.getvalue()
