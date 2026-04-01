from app.services.exports import build_csv_report, build_pdf_report


def sample_bundle():
    return {
        "job_id": "job-1",
        "status": "completed",
        "summary": {
            "total_domains": 1,
            "listed_domains": 0,
            "warning_domains": 1,
            "clean_domains": 0,
            "average_risk_score": 15,
        },
        "reports": [
            {
                "domain": "example.com",
                "overall_status": "warning",
                "risk_score": 15,
                "blacklists": [{"source": "Spamhaus ZEN", "listed": False}],
                "lumen": {"total_notices": 0},
                "safe_browsing": {"status": "unknown"},
                "email_auth": {"spf": "pass", "dkim": "none", "dmarc": "pass"},
                "checked_at": "2026-04-01T12:00:00+00:00",
            }
        ],
    }


def test_csv_report_contains_domain_row():
    csv_report = build_csv_report(sample_bundle())
    assert "example.com" in csv_report
    assert "warning" in csv_report


def test_pdf_report_has_pdf_header():
    pdf_report = build_pdf_report(sample_bundle())
    assert pdf_report.startswith(b"%PDF-1.4")
