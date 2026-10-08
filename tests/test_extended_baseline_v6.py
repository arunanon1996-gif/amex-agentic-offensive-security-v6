import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from tools.initial_web_scanner import InitialWebScanner
from tools.sqli_login_validator import SqliLoginValidator
from tools.dom_xss_validator import DomXssValidator
from agent.finding_engine import FindingEngine


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/":
            body = b'<html><script src="/main.js"></script></html>'
            self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers(); self.wfile.write(body); return
        if self.path == "/main.js":
            body = b'const q=location.hash; const x=bypassSecurityTrustHtml(q);'
            self.send_response(200); self.send_header("Content-Type", "application/javascript"); self.end_headers(); self.wfile.write(body); return
        self.send_response(404); self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0")); body = json.loads(self.rfile.read(length) or b"{}")
        self.send_response(200); self.send_header("Content-Type", "application/json"); self.end_headers()
        if "email" in body and "or 1=1" in body["email"].lower():
            self.wfile.write(b'{"authentication":{"token":"demo-token"}}')
        else:
            self.wfile.write(b'{"error":"Invalid email or password"}')

    def log_message(self, *args):
        pass


def server():
    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True); t.start()
    return httpd


def test_baseline_discovers_dom_xss_and_login_surface():
    s = server()
    try:
        r = InitialWebScanner().scan("127.0.0.1", s.server_port)
        assert r.login_candidates
        assert r.dom_xss_candidates
    finally:
        s.shutdown()


def test_login_sqli_validator_and_finding_provenance():
    s = server()
    try:
        result = SqliLoginValidator().validate("127.0.0.1", s.server_port, "/login")
        data = result.__dict__
        assert data["confirmed"] is True
        findings = FindingEngine().from_observation("sqli_login_validate", data)
        assert findings[0]["finding_id"] == "F-SQLI-LOGIN-001"
        assert "baseline" in findings[0]["discovery_method"].lower()
    finally:
        s.shutdown()


def test_dom_xss_validator_confirms_runtime_bundle_source_sink():
    s = server()
    try:
        result = DomXssValidator().validate("127.0.0.1", s.server_port, "/", "/main.js")
        assert result.confirmed is True
        assert result.source_signal
        assert result.sink_signal
    finally:
        s.shutdown()
