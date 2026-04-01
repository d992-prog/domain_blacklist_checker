from __future__ import annotations

import csv
import io


def build_csv_report(bundle: dict) -> str:
    stream = io.StringIO()
    writer = csv.writer(stream)
    writer.writerow(
        [
            "domain",
            "overall_status",
            "risk_score",
            "listed_blacklists",
            "safe_browsing_status",
            "lumen_notices",
            "spf",
            "dkim",
            "dmarc",
            "checked_at",
        ]
    )
    for report in bundle["reports"]:
        listed_count = sum(1 for item in report["blacklists"] if item["listed"])
        writer.writerow(
            [
                report["domain"],
                report["overall_status"],
                report["risk_score"],
                listed_count,
                report["safe_browsing"]["status"],
                report["lumen"]["total_notices"],
                report["email_auth"]["spf"],
                report["email_auth"]["dkim"],
                report["email_auth"]["dmarc"],
                report["checked_at"],
            ]
        )
    return stream.getvalue()


def _escape_pdf_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def build_pdf_report(bundle: dict) -> bytes:
    lines = [
        "Domain Blacklist Checker report",
        f"Job ID: {bundle['job_id']}",
        f"Status: {bundle['status']}",
        f"Domains: {bundle['summary'].get('total_domains', 0)}",
        f"Listed: {bundle['summary'].get('listed_domains', 0)}",
        f"Warnings: {bundle['summary'].get('warning_domains', 0)}",
        "",
    ]
    for report in bundle["reports"][:18]:
        listed_count = sum(1 for item in report["blacklists"] if item["listed"])
        lines.append(
            f"{report['domain']} | status={report['overall_status']} | risk={report['risk_score']} | blacklists={listed_count}"
        )
    content = ["BT", "/F1 11 Tf", "50 790 Td", "14 TL"]
    for index, line in enumerate(lines):
        if index:
            content.append("T*")
        content.append(f"({_escape_pdf_text(line)}) Tj")
    content.append("ET")
    content_bytes = "\n".join(content).encode("utf-8")

    objects = [
        b"1 0 obj << /Type /Catalog /Pages 2 0 R >> endobj",
        b"2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj",
        b"3 0 obj << /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >> endobj",
        f"4 0 obj << /Length {len(content_bytes)} >> stream\n".encode("utf-8") + content_bytes + b"\nendstream endobj",
        b"5 0 obj << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> endobj",
    ]
    pdf = io.BytesIO()
    pdf.write(b"%PDF-1.4\n")
    offsets = [0]
    for obj in objects:
        offsets.append(pdf.tell())
        pdf.write(obj)
        pdf.write(b"\n")
    xref_offset = pdf.tell()
    pdf.write(f"xref\n0 {len(offsets)}\n".encode("utf-8"))
    pdf.write(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.write(f"{offset:010} 00000 n \n".encode("utf-8"))
    pdf.write(
        (
            f"trailer << /Size {len(offsets)} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF"
        ).encode("utf-8")
    )
    return pdf.getvalue()
