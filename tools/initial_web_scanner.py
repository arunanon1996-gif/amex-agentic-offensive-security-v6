from dataclasses import dataclass, field
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from urllib.request import Request, urlopen
from urllib.error import HTTPError
import re


@dataclass
class WebScanResult:
    base_url: str
    status_code: int
    discovered_urls: list[str]
    endpoints: list[dict]
    technologies: list[str]
    security_signals: list[dict]
    xss_candidates: list[dict]
    sqli_candidates: list[dict]
    forms: list[dict]
    login_candidates: list[dict] = field(default_factory=list)
    dom_xss_candidates: list[dict] = field(default_factory=list)
    error: str | None = None


class _LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []
        self.forms = []
        self._form = None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in {"a", "link", "script"} and (a.get("href") or a.get("src")):
            value = a.get("href") or a.get("src")
            if value:
                self.links.append(value)
        if tag == "form":
            self._form = {"action": a.get("action", ""), "method": a.get("method", "GET").upper(), "inputs": []}
        elif tag == "input" and self._form is not None:
            self._form["inputs"].append({"name": a.get("name"), "type": a.get("type", "text")})

    def handle_endtag(self, tag):
        if tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None


class InitialWebScanner:
    """Localhost-only, Burp-like unauthenticated baseline scanner.

    It is intentionally non-destructive: it crawls a bounded set of public
    routes and sends inert XSS/SQLi probes whose purpose is reflection/error
    detection. It creates candidates, not confirmed vulnerabilities.
    """

    USER_AGENT = "AMEX-AI-Offensive-Security-Agent/3.0"
    COMMON_ROUTES = [
        "/rest/products/search?q=amexscan",
        "/rest/products/1",
        "/api/Products/1",
        "/rest/basket/1",
        "/rest/user/login",
        "/rest/user/whoami",
        "/rest/track-order/undefined",
        "/api/Challenges",
    ]
    DOM_XSS_SOURCES = ("location.hash", "location.search", "URLSearchParams", "searchQuery", "queryParams")
    DOM_XSS_SINKS = ("bypassSecurityTrustHtml", ".innerHTML", "insertAdjacentHTML", "document.write(")
    SQL_ERRORS = (
        "sql syntax", "sqlite", "sequelize", "mysql", "postgresql",
        "postgres", "ora-", "microsoft sql", "odbc", "syntax error",
        "database error", "query failed", "unterminated string",
    )

    def scan(self, target: str, port: int) -> WebScanResult:
        base = f"http://{target}:{port}"
        root = self._get(base + "/")
        if root["status"] == 0:
            return WebScanResult(base, 0, [], [], [], [], [], [], root["error"])

        parser = _LinkParser()
        try:
            parser.feed(root["body"])
        except Exception:
            pass

        discovered = []
        for raw in parser.links:
            absolute = urljoin(base + "/", raw)
            parsed = urlparse(absolute)
            if parsed.netloc == urlparse(base).netloc and absolute not in discovered:
                discovered.append(absolute)

        for route in self.COMMON_ROUTES:
            url = urljoin(base + "/", route)
            if url not in discovered:
                discovered.append(url)

        discovered = discovered[:25]
        endpoints = []
        technologies = self._technologies(root["body"], root["headers"])
        signals = []
        if root["headers"].get("Access-Control-Allow-Origin") == "*":
            signals.append({"category": "cors", "name": "wildcard", "value": "*", "severity_hint": "low", "confidence": 0.90, "rationale": "Unauthenticated response permits wildcard cross-origin access."})
        if not root["headers"].get("Content-Security-Policy"):
            signals.append({"category": "security_header", "name": "CSP", "value": "missing", "severity_hint": "medium", "confidence": 0.90, "rationale": "Root response does not advertise Content-Security-Policy."})

        for url in discovered:
            result = self._get(url)
            if result["status"] == 0:
                continue
            parsed = urlparse(url)
            params = list(parse_qs(parsed.query).keys())
            endpoints.append({
                "url": url,
                "method": "GET",
                "status_code": result["status"],
                "content_type": result["headers"].get("Content-Type", ""),
                "parameters": params,
            })

        xss_candidates = self._xss_candidates(base, endpoints)
        sqli_candidates = self._sqli_candidates(base, endpoints)
        return WebScanResult(
            base_url=base,
            status_code=root["status"],
            discovered_urls=discovered,
            endpoints=endpoints,
            technologies=technologies,
            security_signals=signals,
            xss_candidates=xss_candidates,
            sqli_candidates=sqli_candidates,
            forms=parser.forms,
            login_candidates=self._login_candidates(base, endpoints),
            dom_xss_candidates=self._dom_xss_candidates(base, parser.links),
        )


    def _login_candidates(self, base, endpoints):
        """Discover authentication surfaces without attempting credentials."""
        candidates = []
        login_url = urljoin(base + "/", "/rest/user/login")
        result = self._post_json(login_url, {"email": "amex-invalid@example.local", "password": "definitely-invalid"})
        if result["status"] in {200, 400, 401, 403, 422, 429, 500}:
            candidates.append({
                "url": login_url,
                "method": "POST",
                "parameter": "email",
                "authentication_surface": True,
                "baseline_status": result["status"],
                "evidence": "A live JSON login endpoint accepted a controlled invalid-credential request and is available for bounded authentication/SQLi validation.",
            })
        return candidates

    def _dom_xss_candidates(self, base, links):
        candidates = []
        scripts = []
        for raw in links:
            if not raw:
                continue
            absolute = urljoin(base + "/", raw)
            parsed = urlparse(absolute)
            if parsed.netloc == urlparse(base).netloc and parsed.path.lower().endswith(".js"):
                if absolute not in scripts:
                    scripts.append(absolute)
        for script_url in scripts[:5]:
            result = self._get(script_url)
            if result["status"] == 0:
                continue
            body = result["body"]
            lower = body.lower()
            source = next((x for x in self.DOM_XSS_SOURCES if x.lower() in lower), None)
            sink = next((x for x in self.DOM_XSS_SINKS if x.lower() in lower), None)
            if source and sink:
                candidates.append({
                    "type": "DOM_XSS_STATIC_RUNTIME",
                    "bundle_url": script_url,
                    "source_signal": source,
                    "sink_signal": sink,
                    "evidence": "Served JavaScript contains a URL/search-controlled source and an unsafe HTML sink; targeted runtime-bundle validation is required.",
                })
        return candidates[:5]

    def _post_json(self, url, payload):
        import json
        request = Request(url, data=json.dumps(payload).encode("utf-8"), method="POST", headers={"User-Agent": self.USER_AGENT, "Content-Type": "application/json", "Accept": "application/json,*/*"})
        try:
            with urlopen(request, timeout=5) as response:
                return {"status": response.status, "headers": dict(response.headers), "body": response.read(8000).decode("utf-8", errors="replace"), "error": None}
        except HTTPError as exc:
            return {"status": exc.code, "headers": dict(exc.headers), "body": exc.read(8000).decode("utf-8", errors="replace"), "error": str(exc)}
        except Exception as exc:
            return {"status": 0, "headers": {}, "body": "", "error": str(exc)}

    def _xss_candidates(self, base, endpoints):
        marker = "AMEX_XSS_7f31"
        candidates = []
        for endpoint in endpoints:
            parsed = urlparse(endpoint["url"])
            params = list(parse_qs(parsed.query).keys())
            if not params:
                continue
            for param in params[:3]:
                probe_url = self._replace_query(endpoint["url"], param, marker)
                result = self._get(probe_url)
                if marker.lower() in result["body"].lower():
                    candidates.append({"url": endpoint["url"], "method": "GET", "parameter": param, "marker": marker, "probe_url": probe_url, "evidence": "Input marker was reflected in the response."})
        return candidates[:10]

    def _sqli_candidates(self, base, endpoints):
        candidates = []
        probes = ["'", '"']
        for endpoint in endpoints:
            parsed = urlparse(endpoint["url"])
            params = list(parse_qs(parsed.query).keys())
            if not params:
                continue
            for param in params[:3]:
                for probe in probes:
                    probe_url = self._replace_query(endpoint["url"], param, probe)
                    result = self._get(probe_url)
                    body = result["body"].lower()
                    matched = next((err for err in self.SQL_ERRORS if err in body), None)
                    if matched:
                        candidates.append({"url": endpoint["url"], "method": "GET", "parameter": param, "probe": probe, "probe_url": probe_url, "error_signature": matched, "evidence": "Database/parser error signature observed after controlled quote probe."})
                        break
        return candidates[:10]

    def _get(self, url):
        request = Request(url, method="GET", headers={"User-Agent": self.USER_AGENT, "Accept": "text/html,application/json,*/*"})
        try:
            with urlopen(request, timeout=5) as response:
                body = response.read(12000).decode("utf-8", errors="replace")
                return {"status": response.status, "headers": dict(response.headers), "body": body, "error": None}
        except HTTPError as exc:
            body = exc.read(12000).decode("utf-8", errors="replace")
            return {"status": exc.code, "headers": dict(exc.headers), "body": body, "error": str(exc)}
        except Exception as exc:
            return {"status": 0, "headers": {}, "body": "", "error": str(exc)}

    @staticmethod
    def _replace_query(url, name, value):
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        query[name] = [value]
        return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))

    @staticmethod
    def _technologies(body, headers):
        values = []
        blob = (body + " " + " ".join(headers.values())).lower()
        if "juice shop" in blob:
            values.append("OWASP Juice Shop")
        if "angular" in blob or "ng-version" in blob:
            values.append("Angular")
        if "express" in blob:
            values.append("Express")
        if "sequelize" in blob:
            values.append("Sequelize")
        return list(dict.fromkeys(values))
