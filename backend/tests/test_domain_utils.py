from app.services.domain_utils import dedupe_domains, normalize_domain


def test_normalize_domain_strips_scheme_and_path():
    assert normalize_domain("https://Example.com/path?q=1") == "example.com"


def test_normalize_domain_rejects_ip_and_garbage():
    assert normalize_domain("127.0.0.1") is None
    assert normalize_domain("not a domain") is None


def test_dedupe_domains_keeps_unique_valid_domains():
    result = dedupe_domains(["example.com", "Example.com", "https://openai.com/docs", "bad input"])
    assert result == ["example.com", "openai.com"]
