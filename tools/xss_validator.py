from dataclasses import dataclass, asdict
from urllib.request import Request, urlopen
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from urllib.error import HTTPError
from validation.validator import ValidatorMetadata

@dataclass
class XssValidationResult:
    url: str
    method: str
    parameter: str
    payload: str
    status_code: int
    reflected: bool
    executable_context: bool
    confirmed: bool
    conclusion: str
    error: str | None = None

class XssValidator:
    metadata = ValidatorMetadata(name="xss_validate", description="Validate a suspected reflected XSS input using a controlled inert marker/payload.", category="XSS")

    def validate(self, target, port, url_path="/", parameter="q", payload="<svg/onload=alert(1)>"):
        url = f"http://{target}:{port}{url_path}"
        parsed = urlparse(url)
        query = parse_qs(parsed.query, keep_blank_values=True)
        query[parameter] = [payload]
        probe = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
        request = Request(probe, method="GET", headers={"User-Agent": "AMEX-AI-Offensive-Security-Agent/3.0"})
        try:
            with urlopen(request, timeout=8) as response:
                body = response.read(12000).decode("utf-8", errors="replace")
                reflected = payload in body
                executable = reflected and ("<img" in body.lower() or "<script" in body.lower() or "<svg" in body.lower() or "onerror=" in body.lower() or "onload=" in body.lower())
                confirmed = executable
                conclusion = "Controlled payload was reflected in an executable HTML context." if confirmed else ("Input was reflected, but executable context was not established." if reflected else "Controlled XSS payload was not reflected.")
                return XssValidationResult(probe, "GET", parameter, payload, response.status, reflected, executable, confirmed, conclusion)
        except HTTPError as exc:
            return XssValidationResult(probe, "GET", parameter, payload, exc.code, False, False, False, "Validation request returned an HTTP error.", str(exc))
        except Exception as exc:
            return XssValidationResult(probe, "GET", parameter, payload, 0, False, False, False, "XSS validation could not be completed.", str(exc))
