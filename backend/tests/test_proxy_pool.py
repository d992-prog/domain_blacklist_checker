import pytest

from app.services.proxy_pool import build_proxy_url, parse_proxy_url


def test_parse_proxy_url_supports_socks_and_http():
    socks = parse_proxy_url("socks5://user:pass@127.0.0.1:1080")
    http = parse_proxy_url("http://10.0.0.1:8080")
    assert socks["scheme"] == "socks5"
    assert socks["username"] == "user"
    assert http["scheme"] == "http"


def test_parse_proxy_url_rejects_invalid_scheme():
    with pytest.raises(ValueError):
        parse_proxy_url("ftp://127.0.0.1:21")


def test_build_proxy_url_round_trip():
    class ProxyStub:
        scheme = "http"
        host = "127.0.0.1"
        port = 8080
        username = "user"
        password = "pass"

    assert build_proxy_url(ProxyStub()) == "http://user:pass@127.0.0.1:8080"
