from tools.nmap_adapter import NmapAdapter
from tools.http_adapter import HttpAdapter
from tools.cors_validator import CorsValidator
from tools.csrf_validator import CsrfValidator
from tools.authenticated_resource_probe import AuthenticatedResourceProbe
from tools.idor_validator import IdorValidator
from tools.security_header_validator import SecurityHeaderValidator
from tools.initial_web_scanner import InitialWebScanner
from tools.xss_validator import XssValidator
from tools.sqli_validator import SqliValidator
from tools.auth_bruteforce_validator import AuthBruteForceValidator
from tools.jwt_validator import JwtValidator
from tools.tls_validator import TLSValidator
from tools.sqli_login_validator import SqliLoginValidator
from tools.dom_xss_validator import DomXssValidator
from tools.tool_registry import ToolRegistry


def build_tool_registry() -> ToolRegistry:
    registry = ToolRegistry()

    nmap = NmapAdapter()
    http = HttpAdapter()
    cors = CorsValidator()
    csrf = CsrfValidator()
    authenticated_resource = AuthenticatedResourceProbe()
    idor = IdorValidator()
    headers = SecurityHeaderValidator()
    baseline = InitialWebScanner()
    xss = XssValidator()
    sqli = SqliValidator()
    brute = AuthBruteForceValidator()
    jwt = JwtValidator()
    tls = TLSValidator()
    sqli_login = SqliLoginValidator()
    dom_xss = DomXssValidator()

    registry.register(
        name="nmap",
        description=(
            "Perform approved TCP port discovery against an "
            "authorized target."
        ),
        execute=nmap.scan,
    )

    registry.register(
        name="http_probe",
        description=(
            "Perform an HTTP GET probe against an approved HTTP service."
        ),
        execute=http.probe,
    )

    registry.register(
        name="cors_validate",
        description=(
            "Validate CORS behavior using a controlled external Origin."
        ),
        execute=cors.validate,
    )

    registry.register(
        name="csrf_validate",
        description=(
            "Perform a controlled CSRF validation against an approved "
            "state-changing endpoint."
        ),
        execute=csrf.validate,
    )

    registry.register(
        name="authenticated_resource_probe",
        description=(
            "Establish a controlled authenticated session and retrieve "
            "the authorized user's own resource to expose an object "
            "identifier for authorization analysis."
        ),
        execute=authenticated_resource.probe,
    )

    registry.register(
        name="idor_validate",
        description=(
            "Compare same-session access to an owned object and a "
            "controlled alternate object identifier."
        ),
        execute=idor.validate,
    )

    registry.register(
        name="initial_web_scan",
        description="Perform a bounded unauthenticated localhost web baseline scan and create candidate attack signals.",
        execute=baseline.scan,
    )

    registry.register(
        name="xss_validate",
        description="Validate a suspected reflected XSS candidate with a controlled payload.",
        execute=xss.validate,
    )

    registry.register(
        name="sqli_validate",
        description="Validate a suspected SQL injection candidate with controlled differential/error probes.",
        execute=sqli.validate,
    )

    registry.register(
        name="sqli_login_validate",
        description="Validate a suspected login SQL injection with a bounded authentication-bypass probe.",
        execute=sqli_login.validate,
    )

    registry.register(
        name="dom_xss_validate",
        description="Validate a DOM-XSS hypothesis using bounded runtime JavaScript source-to-sink analysis.",
        execute=dom_xss.validate,
    )

    registry.register(
        name="tls_validate",
        description="Inspect TLS availability and certificate/protocol posture on an approved local target.",
        execute=tls.validate,
    )

    registry.register(
        name="security_header_validate",
        description="Validate security response headers, including CSP.",
        execute=headers.validate,
    )

    registry.register(
        name="auth_bruteforce_validate",
        description="Run a bounded invalid-login resilience check for rate limiting, lockout, and response consistency.",
        execute=brute.validate,
    )

    registry.register(
        name="jwt_validate",
        description="Inspect the approved authenticated JWT structure and claims without forging or modifying tokens.",
        execute=jwt.validate,
    )

    return registry
