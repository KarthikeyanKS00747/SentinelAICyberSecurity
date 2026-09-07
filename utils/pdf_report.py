"""Deterministic PDF rendering for SentinelAI security reports."""

import re
from dataclasses import dataclass
from datetime import datetime
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import (
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

# Palette mirrored from templates/base.html so the report matches the dashboard.
INK = colors.HexColor("#0a1628")
PANEL = colors.HexColor("#0f2040")
ACCENT = colors.HexColor("#3b82f6")
MUTED = colors.HexColor("#64748b")
HAIRLINE = colors.HexColor("#cbd5e1")
SEVERITY_COLORS = {
    "critical": colors.HexColor("#ef4444"),
    "high": colors.HexColor("#f97316"),
    "medium": colors.HexColor("#f59e0b"),
    "low": colors.HexColor("#64748b"),
}
SEVERITY_ORDER = ("critical", "high", "medium", "low")

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
DESCRIPTION_LIMIT = 600
FILENAME_LIMIT = 120


@dataclass(frozen=True)
class ReportAlert:
    severity: str
    threat_name: str
    source_ip: str | None
    risk_score: float
    status: str
    detected_at: datetime | None
    description: str


@dataclass(frozen=True)
class ReportData:
    log_file_id: int
    filename: str
    uploaded_at: datetime | None
    log_status: str
    entries_parsed: int
    alerts_generated: int
    generated_at: datetime
    alerts: list[ReportAlert]


def sanitize_for_pdf(value: object, limit: int | None = None) -> str:
    """Reduce user-influenced text to printable ASCII that reportlab can render."""
    text = "" if value is None else str(value)
    text = text.encode("ascii", "ignore").decode("ascii")
    text = _CONTROL_CHARS.sub("", text)
    text = " ".join(text.split())
    if limit is not None and len(text) > limit:
        text = text[:limit].rstrip() + "..."
    return text


def _format_timestamp(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M:%S UTC") if value else "-"


def report_filename(log_file_id: int, generated_at: datetime) -> str:
    """Build the suggested download name; ASCII-safe by construction."""
    return f"SentinelAI_Report_{log_file_id}_{generated_at.strftime('%Y%m%d_%H%M%S')}.pdf"


class _NumberedCanvas(Canvas):
    """Two-pass canvas so the footer can print 'Page N of M'."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_pages: list[dict] = []

    def showPage(self) -> None:
        self._saved_pages.append(dict(self.__dict__))
        self._startPage()

    def save(self) -> None:
        total = len(self._saved_pages)
        for state in self._saved_pages:
            self.__dict__.update(state)
            self._draw_footer(total)
            super().showPage()
        super().save()

    def _draw_footer(self, total: int) -> None:
        width, _ = self._pagesize
        self.saveState()
        self.setStrokeColor(HAIRLINE)
        self.setLineWidth(0.5)
        self.line(15 * mm, 12 * mm, width - 15 * mm, 12 * mm)
        self.setFont("Helvetica", 7.5)
        self.setFillColor(MUTED)
        self.drawString(15 * mm, 8 * mm, "SentinelAI - Lightweight SIEM - Academic Prototype")
        self.drawRightString(width - 15 * mm, 8 * mm, f"Page {self._pageNumber} of {total}")
        self.restoreState()


def _styles() -> dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    return {
        "title": ParagraphStyle(
            "SentinelTitle", parent=base["Title"], fontName="Helvetica-Bold",
            fontSize=20, leading=24, textColor=INK, alignment=TA_LEFT, spaceAfter=2,
        ),
        "subtitle": ParagraphStyle(
            "SentinelSubtitle", parent=base["Normal"], fontName="Helvetica",
            fontSize=9, leading=12, textColor=MUTED, spaceAfter=10,
        ),
        "heading": ParagraphStyle(
            "SentinelHeading", parent=base["Heading2"], fontName="Helvetica-Bold",
            fontSize=11.5, leading=14, textColor=PANEL, spaceBefore=10, spaceAfter=6,
        ),
        "body": ParagraphStyle(
            "SentinelBody", parent=base["Normal"], fontName="Helvetica",
            fontSize=8.5, leading=11, textColor=INK,
        ),
        "cell": ParagraphStyle(
            "SentinelCell", parent=base["Normal"], fontName="Helvetica",
            fontSize=7.5, leading=9.5, textColor=INK,
        ),
        "cellHeader": ParagraphStyle(
            "SentinelCellHeader", parent=base["Normal"], fontName="Helvetica-Bold",
            fontSize=7.5, leading=9.5, textColor=colors.white,
        ),
        "empty": ParagraphStyle(
            "SentinelEmpty", parent=base["Normal"], fontName="Helvetica-Oblique",
            fontSize=10, leading=14, textColor=MUTED, spaceBefore=6,
        ),
    }


def _paragraph(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(text) or "-", style)


def _severity_style(level: str, base: ParagraphStyle) -> ParagraphStyle:
    """Bold, severity-coloured variant of the table cell style."""
    return ParagraphStyle(
        f"SentinelSeverity_{level or 'unknown'}",
        parent=base,
        fontName="Helvetica-Bold",
        textColor=SEVERITY_COLORS.get(level, MUTED),
    )


def _header_flowables(data: ReportData, styles: dict[str, ParagraphStyle]) -> list:
    filename = sanitize_for_pdf(data.filename, FILENAME_LIMIT) or "(unnamed)"
    meta = [
        ["Log file", filename],
        ["Log file ID", str(data.log_file_id)],
        ["Uploaded", _format_timestamp(data.uploaded_at)],
        ["Analysis status", sanitize_for_pdf(data.log_status).upper() or "-"],
        ["Report generated", _format_timestamp(data.generated_at)],
    ]
    table = Table(meta, colWidths=[32 * mm, 120 * mm], hAlign="LEFT")
    table.setStyle(
        TableStyle(
            [
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("TEXTCOLOR", (0, 0), (0, -1), MUTED),
                ("TEXTCOLOR", (1, 0), (1, -1), INK),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ]
        )
    )
    return [
        Paragraph("SentinelAI Security Report", styles["title"]),
        Paragraph("Automated log analysis and rule-based threat detection", styles["subtitle"]),
        table,
    ]


def _summary_flowables(data: ReportData, styles: dict[str, ParagraphStyle]) -> list:
    counts = {level: 0 for level in SEVERITY_ORDER}
    for alert in data.alerts:
        level = sanitize_for_pdf(alert.severity).lower()
        if level in counts:
            counts[level] += 1

    header = ["Total alerts", "Critical", "High", "Medium", "Low", "Entries parsed", "Alerts generated"]
    row = [
        str(len(data.alerts)),
        str(counts["critical"]),
        str(counts["high"]),
        str(counts["medium"]),
        str(counts["low"]),
        str(data.entries_parsed),
        str(data.alerts_generated),
    ]
    table = Table([header, row], colWidths=[38 * mm] + [24 * mm] * 4 + [30 * mm, 32 * mm], hAlign="LEFT")
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), PANEL),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTNAME", (0, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 7.5),
        ("FONTSIZE", (0, 1), (-1, 1), 13),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 1), (-1, 1), 7),
        ("BOTTOMPADDING", (0, 1), (-1, 1), 7),
        ("GRID", (0, 0), (-1, -1), 0.4, HAIRLINE),
        ("ROWBACKGROUNDS", (0, 1), (-1, 1), [colors.HexColor("#f8fafc")]),
    ]
    for index, level in enumerate(SEVERITY_ORDER, start=1):
        style.append(("TEXTCOLOR", (index, 1), (index, 1), SEVERITY_COLORS[level]))
    table.setStyle(TableStyle(style))
    return [Paragraph("Summary", styles["heading"]), table]


def _alerts_flowables(data: ReportData, styles: dict[str, ParagraphStyle]) -> list:
    heading = Paragraph("Detected Alerts", styles["heading"])
    if not data.alerts:
        return [
            heading,
            Paragraph(
                "No alerts detected. Every parsed entry in this log file passed the "
                "active detection rules.",
                styles["empty"],
            ),
        ]

    header = ["Severity", "Threat", "Source IP", "Risk", "Status", "Detected At", "Description"]
    rows: list[list] = [[_paragraph(column, styles["cellHeader"]) for column in header]]
    for alert in data.alerts:
        level = sanitize_for_pdf(alert.severity).lower()
        rows.append(
            [
                _paragraph(level.upper(), _severity_style(level, styles["cell"])),
                _paragraph(sanitize_for_pdf(alert.threat_name, 80), styles["cell"]),
                _paragraph(sanitize_for_pdf(alert.source_ip, 45), styles["cell"]),
                _paragraph(f"{alert.risk_score:.0f}", styles["cell"]),
                _paragraph(sanitize_for_pdf(alert.status).upper(), styles["cell"]),
                _paragraph(_format_timestamp(alert.detected_at), styles["cell"]),
                _paragraph(sanitize_for_pdf(alert.description, DESCRIPTION_LIMIT), styles["cell"]),
            ]
        )

    table = Table(
        rows,
        colWidths=[18 * mm, 34 * mm, 30 * mm, 12 * mm, 22 * mm, 34 * mm, 111 * mm],
        repeatRows=1,
        hAlign="LEFT",
    )
    style = [
        ("BACKGROUND", (0, 0), (-1, 0), PANEL),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.4, HAIRLINE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    table.setStyle(TableStyle(style))
    return [heading, table]


def build_report_pdf(data: ReportData) -> bytes:
    """Render one security report and return the finished PDF bytes."""
    styles = _styles()
    buffer = BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        leftMargin=15 * mm,
        rightMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=18 * mm,
        title=f"SentinelAI Security Report - Log file {data.log_file_id}",
        author="SentinelAI",
        subject="Automated log analysis report",
    )
    story: list = []
    story.extend(_header_flowables(data, styles))
    story.append(Spacer(1, 6))
    story.extend(_summary_flowables(data, styles))
    story.append(Spacer(1, 6))
    story.extend(_alerts_flowables(data, styles))
    document.build(story, canvasmaker=_NumberedCanvas)
    return buffer.getvalue()
