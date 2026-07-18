"""Generates the audit-ready PDF report from a completed ScanResult."""

import io
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from app.models import ScanResult, Severity

SEVERITY_COLORS = {
    Severity.CRITICAL: colors.HexColor("#7f1d1d"),
    Severity.HIGH: colors.HexColor("#b91c1c"),
    Severity.MEDIUM: colors.HexColor("#d97706"),
    Severity.LOW: colors.HexColor("#2563eb"),
    Severity.INFO: colors.HexColor("#64748b"),
}

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


def _build_styles():
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="ReportTitle", fontSize=24, leading=28, spaceAfter=6, textColor=colors.HexColor("#0f172a")))
    styles.add(ParagraphStyle(name="ReportSubtitle", fontSize=12, textColor=colors.HexColor("#475569"), spaceAfter=20))
    styles.add(ParagraphStyle(name="SectionHeading", fontSize=16, spaceBefore=18, spaceAfter=8, textColor=colors.HexColor("#0f172a")))
    styles.add(ParagraphStyle(name="Body", fontSize=10, leading=14))
    styles.add(ParagraphStyle(name="FindingTitle", fontSize=11, leading=14, spaceBefore=10, textColor=colors.HexColor("#0f172a")))
    return styles


def generate_pdf_report(scan: ScanResult) -> bytes:
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        topMargin=0.75 * inch,
        bottomMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
    )
    styles = _build_styles()
    story = []

    # --- Title page ---
    story.append(Paragraph("SecureOps AI — Azure Security Audit Report", styles["ReportTitle"]))
    story.append(
        Paragraph(
            f"Subscription: {scan.subscription_id}<br/>"
            f"Scan ID: {scan.id}<br/>"
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
            styles["ReportSubtitle"],
        )
    )

    # --- AI executive summary ---
    if scan.ai_analysis:
        story.append(Paragraph("Executive Summary", styles["SectionHeading"]))
        story.append(Paragraph(scan.ai_analysis.executive_summary, styles["Body"]))

        story.append(Paragraph("Top Risks", styles["SectionHeading"]))
        for risk in scan.ai_analysis.top_risks:
            story.append(Paragraph(f"• {risk}", styles["Body"]))

        story.append(Paragraph("Prioritized Remediation Plan", styles["SectionHeading"]))
        for i, step in enumerate(scan.ai_analysis.remediation_plan, start=1):
            story.append(Paragraph(f"{i}. {step}", styles["Body"]))

        story.append(Paragraph("Business Impact", styles["SectionHeading"]))
        story.append(Paragraph(scan.ai_analysis.business_impact, styles["Body"]))

    # --- Severity summary table ---
    story.append(Paragraph("Findings Summary", styles["SectionHeading"]))
    table_data = [["Severity", "Count"]]
    for sev in SEVERITY_ORDER:
        table_data.append([sev.value.upper(), str(scan.severity_counts.get(sev.value, 0))])
    summary_table = Table(table_data, colWidths=[3 * inch, 1.5 * inch])
    summary_table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#0f172a")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#cbd5e1")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f1f5f9")]),
            ]
        )
    )
    story.append(summary_table)
    story.append(PageBreak())

    # --- Detailed findings, sorted by severity ---
    story.append(Paragraph("Detailed Findings", styles["SectionHeading"]))
    sorted_findings = sorted(scan.findings, key=lambda f: SEVERITY_ORDER.index(f.severity))

    if not sorted_findings:
        story.append(Paragraph("No findings were detected in this scan.", styles["Body"]))

    for finding in sorted_findings:
        badge_color = SEVERITY_COLORS[finding.severity]
        story.append(
            Paragraph(
                f'<font color="{badge_color.hexval()}"><b>[{finding.severity.value.upper()}]</b></font> '
                f"{finding.title}",
                styles["FindingTitle"],
            )
        )
        detail_rows = [
            ["Resource", f"{finding.resource_name} ({finding.resource_type})"],
            ["CVSS Score", str(finding.cvss_score)],
            ["MITRE ATT&CK", f"{finding.mitre.tactic_name} ({finding.mitre.tactic_id}) — {finding.mitre.technique_name} ({finding.mitre.technique_id})"],
            ["Description", finding.description],
            ["Recommendation", finding.recommendation],
        ]
        detail_table = Table(
            [[Paragraph(f"<b>{k}</b>", styles["Body"]), Paragraph(v, styles["Body"])] for k, v in detail_rows],
            colWidths=[1.4 * inch, 5.1 * inch],
        )
        detail_table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#e2e8f0")),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f8fafc")),
                ]
            )
        )
        story.append(detail_table)
        story.append(Spacer(1, 6))

    # --- Coverage notes: any scanner errors, so gaps are visible, not hidden ---
    all_errors = [e for summary in scan.scanner_summaries for e in summary.errors]
    story.append(Paragraph("Scan Coverage Notes", styles["SectionHeading"]))
    if all_errors:
        for err in all_errors:
            story.append(Paragraph(f"• [{err.scanner}] {err.message}", styles["Body"]))
    else:
        story.append(Paragraph("All scanners completed without errors. Full coverage across networking, secrets, storage, and identity.", styles["Body"]))

    doc.build(story)
    return buffer.getvalue()
