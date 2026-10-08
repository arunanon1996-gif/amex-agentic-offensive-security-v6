from dataclasses import dataclass
import json
import time
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from validation.validator import ValidatorMetadata


@dataclass
class AuthBruteForceResult:
    login_url: str
    attempts: int
    interval_seconds: float
    status_codes: list[int]
    response_lengths: list[int]
    rate_limited: bool
    account_lockout_observed: bool
    response_consistency: bool
    credential_enumeration_signal: bool
    confirmed: bool
    conclusion: str
    error: str | None = None


class AuthBruteForceValidator:
    """Bounded authentication-resilience check; never performs unrestricted brute force."""

    metadata = ValidatorMetadata(
        name="auth_bruteforce_validate",
        description="Run a small, policy-bounded set of invalid login attempts and inspect throttling/lockout behavior.",
        category="Authentication",
    )

    def validate(self, target: str, port: int, login_path: str, username: str, attempts: int = 4, interval_seconds: float = 0.15) -> AuthBruteForceResult:
        attempts = max(1, min(int(attempts), 5))
        interval_seconds = max(0.05, min(float(interval_seconds), 1.0))
        login_url = f"http://{target}:{port}{login_path}"
        status_codes, lengths = [], []
        rate_limited = False
        lockout = False
        try:
            for i in range(attempts):
                payload = json.dumps({"email": username, "password": f"AMEX-invalid-{i}-not-a-password"}).encode()
                req = Request(login_url, data=payload, method="POST", headers={"User-Agent":"AMEX-AI-Offensive-Security-Agent/3.0","Content-Type":"application/json","Accept":"application/json"})
                try:
                    with urlopen(req, timeout=5) as response:
                        body = response.read(4000)
                        status_codes.append(response.status); lengths.append(len(body))
                except HTTPError as exc:
                    body = exc.read(4000)
                    status_codes.append(exc.code); lengths.append(len(body))
                    if exc.code in {429, 403}:
                        rate_limited = True
                if status_codes and status_codes[-1] in {429, 423}:
                    rate_limited = True
                    if status_codes[-1] == 423:
                        lockout = True
                if i < attempts - 1:
                    time.sleep(interval_seconds)
            # A stable unauthorized response is not itself a weakness; the signal is
            # the absence of throttling/lockout after repeated controlled failures.
            consistent = len(set(status_codes)) <= 1 and len(set(lengths)) <= 1
            enumeration = len(set(status_codes)) > 1 and not rate_limited
            confirmed = not rate_limited and not lockout and len(status_codes) >= 3
            conclusion = (
                "No rate limiting or lockout signal was observed during the bounded invalid-login test."
                if confirmed else
                "Authentication resilience controls were observed during the bounded test."
            )
            return AuthBruteForceResult(login_url, attempts, interval_seconds, status_codes, lengths, rate_limited, lockout, consistent, enumeration, confirmed, conclusion)
        except Exception as exc:
            return AuthBruteForceResult(login_url, attempts, interval_seconds, status_codes, lengths, rate_limited, lockout, False, False, False, "Authentication resilience test could not be completed.", str(exc))
