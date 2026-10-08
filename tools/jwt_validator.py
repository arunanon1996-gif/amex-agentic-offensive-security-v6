from dataclasses import dataclass
import base64
import json
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from validation.validator import ValidatorMetadata
from tools.session_store import SESSION_STORE


@dataclass
class JwtValidationResult:
    session_id: str
    token_present: bool
    algorithm: str | None
    token_type: str | None
    claims: dict
    has_exp: bool
    expired: bool | None
    has_issuer: bool
    has_audience: bool
    sensitive_claims: list[str]
    protected_resource_status: int | None
    invalid_token_status: int | None
    authentication_bypass_observed: bool
    confirmed: bool
    conclusion: str
    error: str | None = None


class JwtValidator:
    metadata = ValidatorMetadata(
        name="jwt_validate",
        description="Inspect the approved JWT and test protected-resource rejection of a controlled invalid bearer token.",
        category="Authentication",
    )

    def validate(self, target: str, session_id: str, port: int = 3000, protected_path: str = "/") -> JwtValidationResult:
        session = SESSION_STORE.get(session_id)
        if not session:
            return JwtValidationResult(session_id, False, None, None, {}, False, None, False, False, [], None, None, False, False, "No approved authenticated session is available.", "Unknown session.")
        token = session.token
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return JwtValidationResult(session_id, True, None, None, {}, False, None, False, False, [], None, None, False, False, "Authenticated token is not a three-part JWT.")
            header = json.loads(self._decode(parts[0]))
            claims = json.loads(self._decode(parts[1]))
            alg = header.get("alg")
            sensitive = [k for k in claims if k.lower() in {"password", "passwd", "secret", "token", "apikey", "api_key"}]
            exp = claims.get("exp")
            import time
            expired = bool(exp is not None and float(exp) < time.time()) if exp is not None else None

            protected_status = None
            invalid_status = None
            bypass = False
            protected_url = f"http://{target}:{port}{protected_path}"
            valid_req = Request(protected_url, method="GET", headers={"User-Agent":"AMEX-AI-Offensive-Security-Agent/3.0","Authorization":f"Bearer {token}","Accept":"application/json"})
            try:
                with urlopen(valid_req, timeout=5) as response:
                    response.read(1000); protected_status = response.status
            except HTTPError as exc:
                protected_status = exc.code
            except Exception:
                protected_status = None

            invalid_req = Request(protected_url, method="GET", headers={"User-Agent":"AMEX-AI-Offensive-Security-Agent/3.0","Authorization":"Bearer AMEX_INVALID_TOKEN","Accept":"application/json"})
            try:
                with urlopen(invalid_req, timeout=5) as response:
                    response.read(1000); invalid_status = response.status
            except HTTPError as exc:
                invalid_status = exc.code
            except Exception:
                invalid_status = None
            bypass = invalid_status is not None and 200 <= invalid_status < 300

            reasons=[]
            if alg in {None, "none"}: reasons.append("unsafe or missing signing algorithm")
            if exp is None: reasons.append("no expiration claim")
            if sensitive: reasons.append("sensitive data present in claims")
            if bypass: reasons.append("protected resource accepted an invalid bearer token")
            weak = bool(reasons)
            conclusion = "JWT/authentication review identified: " + ", ".join(reasons) if reasons else "JWT structure and invalid-token enforcement appear reasonable for this bounded POC check."
            return JwtValidationResult(session_id, True, alg, header.get("typ"), claims, exp is not None, expired, "iss" in claims, "aud" in claims, sensitive, protected_status, invalid_status, bypass, weak, conclusion)
        except Exception as exc:
            return JwtValidationResult(session_id, True, None, None, {}, False, None, False, False, [], None, None, False, False, "JWT/authentication validation could not be safely completed.", str(exc))

    @staticmethod
    def _decode(value):
        value += "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(value.encode()).decode("utf-8", errors="replace")
