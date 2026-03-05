from __future__ import annotations

import html
import re
from typing import Any


def render_response_html(*, questionnaire: dict[str, Any], version: dict[str, Any], session: dict[str, Any], answers_by_question_id: dict[str, Any]) -> str:
    schema = (version or {}).get("schema_json") or {}
    sections = schema.get("sections") or []

    parts: list[str] = [
        "<html><head><meta charset='utf-8'><title>Questionnaire Response</title></head><body>",
        f"<h1>{html.escape(str(questionnaire.get('title') or schema.get('questionnaire_id') or 'Questionnaire'))}</h1>",
        f"<p><strong>Questionnaire ID:</strong> {html.escape(str(schema.get('questionnaire_id') or questionnaire.get('questionnaire_id') or ''))}</p>",
        f"<p><strong>Session ID:</strong> {html.escape(str(session.get('response_session_id') or ''))}</p>",
        f"<p><strong>Version ID:</strong> {html.escape(str(version.get('version_id') or ''))}</p>",
        f"<p><strong>Submitted At:</strong> {html.escape(str(session.get('submitted_at') or ''))}</p>",
    ]

    for i, section in enumerate(sections, start=1):
        section_title = str(section.get("title") or f"Section {i}")
        parts.append(f"<h2>{html.escape(section_title)}</h2><ul>")
        for question in section.get("questions") or []:
            qid = str(question.get("question_id") or "")
            label = str(question.get("label") or qid or "Question")
            value = answers_by_question_id.get(qid)
            if value is None:
                rendered = "—"
            elif isinstance(value, list):
                rendered = ", ".join(str(v) for v in value) if value else "—"
            elif isinstance(value, dict):
                rendered = str(value)
            else:
                rendered = str(value)
            if not rendered.strip():
                rendered = "—"
            parts.append(f"<li><strong>{html.escape(label)}</strong>: {html.escape(rendered)}</li>")
        parts.append("</ul>")

    parts.append("</body></html>")
    return "".join(parts)


def _pdf_escape(text: str) -> str:
    return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def html_to_pdf_bytes(rendered_html: str) -> bytes:
    plain_text = re.sub(r"<[^>]+>", "", rendered_html)
    lines = [line.strip() for line in plain_text.splitlines() if line.strip()]
    content_lines = ["BT", "/F1 11 Tf", "72 760 Td", "14 TL"]
    for line in lines[:400]:
        content_lines.append(f"({_pdf_escape(line[:2000])}) Tj")
        content_lines.append("T*")
    content_lines.append("ET")
    stream = "\n".join(content_lines).encode("utf-8")

    objects = [
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>\nendobj\n",
        b"4 0 obj\n<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>\nendobj\n",
        f"5 0 obj\n<< /Length {len(stream)} >>\nstream\n".encode("utf-8") + stream + b"\nendstream\nendobj\n",
    ]

    pdf = bytearray(b"%PDF-1.4\n")
    offsets = []
    for obj in objects:
        offsets.append(len(pdf))
        pdf.extend(obj)
    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("utf-8"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("utf-8"))
    pdf.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref_offset}\n%%EOF\n".encode("utf-8")
    )
    return bytes(pdf)
