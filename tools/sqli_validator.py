from dataclasses import dataclass
from urllib.request import Request, urlopen
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from urllib.error import HTTPError
from validation.validator import ValidatorMetadata

@dataclass
class SqliValidationResult:
    url: str
    method: str
    parameter: str
    baseline_status: int
    probe_status: int
    error_signature: str | None
    confirmed: bool
    conclusion: str
    error: str | None = None

class SqliValidator:
    metadata = ValidatorMetadata(name="sqli_validate", description="Validate a suspected SQL injection using controlled error-based and response-differential probes.", category="SQL Injection")
    ERRORS = ("sql syntax", "sqlite", "sequelize", "mysql", "postgresql", "postgres", "ora-", "microsoft sql", "odbc", "syntax error", "database error", "query failed", "unterminated string")

    def validate(self, target, port, url_path="/", parameter="q"):
        base = f"http://{target}:{port}{url_path}"
        baseline = self._request(base, parameter, "amex-baseline")
        probe = self._request(base, parameter, "'")
        blob = probe["body"].lower()
        signature = next((x for x in self.ERRORS if x in blob), None)
        confirmed = signature is not None
        conclusion = f"Controlled quote probe produced a database error signature: {signature}." if confirmed else "Controlled SQL injection probe did not produce a database error signature."
        return SqliValidationResult(probe["url"], "GET", parameter, baseline["status"], probe["status"], signature, confirmed, conclusion, probe["error"])

    @staticmethod
    def _request(base, parameter, value):
        parsed = urlparse(base)
        query = parse_qs(parsed.query, keep_blank_values=True)
        query[parameter] = [value]
        url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))
        try:
            with urlopen(Request(url, method="GET", headers={"User-Agent":"AMEX-AI-Offensive-Security-Agent/3.0"}), timeout=8) as response:
                return {"url": url, "status": response.status, "body": response.read(12000).decode("utf-8", errors="replace"), "error": None}
        except HTTPError as exc:
            return {"url": url, "status": exc.code, "body": exc.read(12000).decode("utf-8", errors="replace"), "error": str(exc)}
        except Exception as exc:
            return {"url": url, "status": 0, "body": "", "error": str(exc)}
