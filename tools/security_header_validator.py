from dataclasses import dataclass, asdict
from urllib.request import Request, urlopen
from validation.validator import ValidatorMetadata

@dataclass
class SecurityHeaderValidationResult:
    url: str
    status_code: int
    headers: dict
    missing_headers: list[str]
    present_headers: list[str]
    csp_present: bool
    confirmed: bool
    conclusion: str
    error: str | None = None

class SecurityHeaderValidator:
    metadata = ValidatorMetadata(
        name='security_header_validate',
        description='Validate security response headers including CSP.',
        category='Security Headers',
    )
    REQUIRED = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Content-Type-Options', 'Referrer-Policy', 'Permissions-Policy']

    def validate(self, target: str, port: int):
        url = f'http://{target}:{port}/'
        try:
            req = Request(url, method='GET', headers={'User-Agent': 'AMEX-AI-Offensive-Security-Agent/2.0'})
            with urlopen(req, timeout=10) as response:
                headers = dict(response.headers)
                normalized = {k.lower(): v for k, v in headers.items()}
                missing = [h for h in self.REQUIRED if h.lower() not in normalized]
                present = [h for h in self.REQUIRED if h.lower() in normalized]
                csp = 'content-security-policy' in normalized
                return SecurityHeaderValidationResult(url, response.status, headers, missing, present, csp, bool(missing),
                    'One or more recommended security headers are absent.' if missing else 'Required security headers are present.')
        except Exception as exc:
            return SecurityHeaderValidationResult(url, 0, {}, [], [], False, False, 'Security-header validation could not be completed.', str(exc))

    @staticmethod
    def to_dict(result):
        return asdict(result)
