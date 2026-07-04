from __future__ import annotations

import csv
import html
import io
import json
import zipfile
from pathlib import Path
from typing import Any

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


EVIDENCE_CSV_FIELDS = [
    "fact_id",
    "source_title",
    "source_year",
    "locator",
    "span_start",
    "span_end",
    "predicate",
    "subject",
    "object",
    "property",
    "comparator",
    "numeric_value",
    "min_value",
    "max_value",
    "unit",
    "value_text",
    "confidence",
    "extraction_confidence",
    "validation_status",
    "evidence",
]

FONT_CANDIDATES = [
    "/System/Library/Fonts/Supplemental/Arial.ttf",
    "/System/Library/Fonts/Supplemental/Arial Unicode.ttf",
    "/Library/Fonts/Arial.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "/usr/share/fonts/truetype/liberation/LiberationSans-Regular.ttf",
]


def _span_bounds(span: Any) -> tuple[Any, Any]:
    if isinstance(span, list | tuple) and len(span) == 2:
        return span[0], span[1]
    return None, None


def evidence_pack_to_csv(payload: dict[str, Any]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=EVIDENCE_CSV_FIELDS)
    writer.writeheader()
    for fact in payload.get("evidence_pack", {}).get("facts", []):
        value = fact.get("value") if isinstance(fact.get("value"), dict) else {}
        span_start, span_end = _span_bounds(fact.get("span"))
        writer.writerow(
            {
                "fact_id": fact.get("fact_id"),
                "source_title": fact.get("source_title"),
                "source_year": fact.get("source_year"),
                "locator": fact.get("locator"),
                "span_start": span_start,
                "span_end": span_end,
                "predicate": fact.get("predicate"),
                "subject": fact.get("subject"),
                "object": fact.get("object"),
                "property": value.get("property"),
                "comparator": value.get("comparator"),
                "numeric_value": value.get("numeric_value"),
                "min_value": value.get("min_value"),
                "max_value": value.get("max_value"),
                "unit": value.get("unit"),
                "value_text": value.get("value_text"),
                "confidence": fact.get("confidence"),
                "extraction_confidence": fact.get("extraction_confidence"),
                "validation_status": fact.get("validation_status"),
                "evidence": fact.get("evidence"),
            }
        )
    return output.getvalue()


def _pdf_font_name() -> str:
    font_name = "RDReport"
    if font_name in pdfmetrics.getRegisteredFontNames():
        return font_name
    for candidate in FONT_CANDIDATES:
        if Path(candidate).exists():
            pdfmetrics.registerFont(TTFont(font_name, candidate))
            return font_name
    return "Helvetica"


def _clean_markdown_line(line: str) -> str:
    stripped = line.strip()
    if not stripped:
        return ""
    stripped = stripped.lstrip("#").strip()
    if stripped.startswith("- "):
        stripped = "* " + stripped[2:].strip()
    stripped = stripped.replace("**", "")
    return stripped


def _fact_rows(payload: dict[str, Any], limit: int = 18) -> list[list[str]]:
    rows = [["Fact", "Predicate", "Value", "Source", "Locator"]]
    for fact in payload.get("evidence_pack", {}).get("facts", [])[:limit]:
        value = fact.get("value") if isinstance(fact.get("value"), dict) else {}
        numeric = value.get("numeric_value")
        if numeric is None and (value.get("min_value") is not None or value.get("max_value") is not None):
            numeric = f"{value.get('min_value') or ''}-{value.get('max_value') or ''}"
        value_text = " ".join(str(part) for part in [value.get("comparator"), numeric, value.get("unit")] if part is not None)
        rows.append(
            [
                str(fact.get("fact_id") or ""),
                str(fact.get("predicate") or ""),
                value_text or str(value.get("value_text") or ""),
                str(fact.get("source_title") or ""),
                str(fact.get("locator") or ""),
            ]
        )
    return rows


def answer_payload_to_pdf(payload: dict[str, Any]) -> bytes:
    buffer = io.BytesIO()
    font_name = _pdf_font_name()
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "RDTitle",
        parent=styles["Title"],
        fontName=font_name,
        fontSize=16,
        leading=20,
        spaceAfter=8,
    )
    body_style = ParagraphStyle(
        "RDBody",
        parent=styles["BodyText"],
        fontName=font_name,
        fontSize=9,
        leading=12,
        spaceAfter=4,
    )
    small_style = ParagraphStyle(
        "RDSmall",
        parent=body_style,
        fontSize=7,
        leading=9,
    )
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=16 * mm,
        rightMargin=16 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
        title="R&D evidence report",
    )
    story: list[Any] = [
        Paragraph("R&D Evidence Report", title_style),
        Paragraph(f"Query: {html.escape(str(payload.get('query') or ''))}", body_style),
        Paragraph(f"Confidence: {payload.get('confidence', '')}", body_style),
        Spacer(1, 4 * mm),
    ]
    for raw_line in str(payload.get("answer_markdown") or "").splitlines()[:120]:
        line = _clean_markdown_line(raw_line)
        if not line:
            story.append(Spacer(1, 2 * mm))
            continue
        story.append(Paragraph(html.escape(line), body_style))
    rows = _fact_rows(payload)
    if len(rows) > 1:
        story.append(PageBreak())
        story.append(Paragraph("Evidence Table", title_style))
        table_rows = [[Paragraph(html.escape(str(cell)), small_style) for cell in row] for row in rows]
        table = Table(table_rows, colWidths=[18 * mm, 34 * mm, 32 * mm, 70 * mm, 28 * mm], repeatRows=1)
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8EEF7")),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#B8C0CC")),
                    ("FONTNAME", (0, 0), (-1, -1), font_name),
                    ("FONTSIZE", (0, 0), (-1, -1), 6.5),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F7F9FC")]),
                ]
            )
        )
        story.append(table)
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph("Generated from role-aware evidence pack; sensitive fields may be redacted by DLP policy.", small_style))
    doc.build(story)
    return buffer.getvalue()


def report_package_to_zip(payload: dict[str, Any]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as package:
        package.writestr("answer.md", str(payload.get("answer_markdown") or ""))
        package.writestr("evidence.csv", evidence_pack_to_csv(payload))
        package.writestr("payload.json", json.dumps(payload, ensure_ascii=False, indent=2))
        package.writestr("report.pdf", answer_payload_to_pdf(payload))
    return buffer.getvalue()
