from app.target_utils import normalize_target
from tools.nmap_adapter import NmapAdapter


def test_normalize_localhost_url_and_port():
    assert normalize_target("http://127.0.0.1:3000") == ("127.0.0.1", 3000, "http://127.0.0.1:3000")
    assert normalize_target("localhost", 5000) == ("localhost", 5000, "http://localhost:5000")


def test_normalize_rejects_non_localhost():
    try:
        normalize_target("https://example.com")
    except ValueError as exc:
        assert "Only localhost" in str(exc)
    else:
        raise AssertionError("Non-localhost target was accepted")


def test_nmap_missing_uses_safe_builtin_fallback(monkeypatch):
    monkeypatch.setattr(NmapAdapter, "resolve_path", staticmethod(lambda: None))
    result = NmapAdapter().scan("127.0.0.1", [1])
    assert result.return_code == 0
    assert result.engine == "builtin_tcp"
    assert result.warning and "Nmap executable" in result.warning
