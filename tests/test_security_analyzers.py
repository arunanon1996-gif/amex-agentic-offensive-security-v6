from tools.security_header_analyzer import SecurityHeaderAnalyzer
from tools.technology_analyzer import TechnologyAnalyzer
from tools.cors_analyzer import CorsAnalyzer


def test_security_analyzers_use_http_evidence_fixture():
    target = "localhost"
    headers = {
        "Content-Security-Policy": "default-src 'self'",
        "X-Frame-Options": "SAMEORIGIN",
        "Access-Control-Allow-Origin": "*",
        "Server": "Express",
        "Content-Type": "text/html; charset=utf-8",
    }
    body = '<html><script src="/main.js"></script><title>Juice Shop</title></html>'

    header_analysis = SecurityHeaderAnalyzer().analyze(target, headers)
    technology_analysis = TechnologyAnalyzer().analyze(target, headers, body)
    cors_analysis = CorsAnalyzer().analyze(target, headers)

    assert any(signal.name == "CSP" for signal in header_analysis.signals)
    assert any(signal.name == "JavaScript" for signal in technology_analysis.signals)
    assert any(
        signal.name == "Access-Control-Allow-Origin"
        and signal.value == "*"
        for signal in cors_analysis.signals
    )
