from dataclasses import asdict, dataclass, field


@dataclass
class Finding:
    finding_id: str
    title: str
    category: str
    severity: str
    confidence: float
    status: str
    hypothesis: str
    evidence: list[dict] = field(default_factory=list)
    validation: dict = field(default_factory=dict)
    impact: str = ""
    remediation: str = ""

    def to_dict(self):
        return asdict(self)


class FindingEngine:
    """Turns validator evidence into explicit finding states."""

    def from_observation(self, action, data):
        if not isinstance(data, dict):
            return []

        handlers = {
            "cors_validate": self._cors,
            "csrf_validate": self._csrf,
            "idor_validate": self._idor,
            "security_header_validate": self._headers,
            "initial_web_scan": self._baseline,
            "xss_validate": self._xss,
            "sqli_validate": self._sqli,
            "sqli_login_validate": self._sqli_login,
            "dom_xss_validate": self._dom_xss,
            "auth_bruteforce_validate": self._auth_bruteforce,
            "jwt_validate": self._jwt,
        }
        handler = handlers.get(action)
        findings = handler(data) if handler else []
        default_methods = {
            "cors_validate": "Unauthenticated CORS baseline signal followed by controlled Origin validation.",
            "csrf_validate": "Authenticated context and state-changing endpoint drove controlled cross-origin validation.",
            "idor_validate": "Authenticated resource discovery exposed an object identifier; controlled alternate-object authorization validation followed.",
            "security_header_validate": "Live HTTP response header inspection during the infrastructure/application posture phase.",
            "auth_bruteforce_validate": "Authenticated phase identified the login surface and ran a bounded invalid-login resilience test.",
            "jwt_validate": "Authenticated phase established a bearer session and inspected JWT structure/validation controls.",
        }
        for finding in findings:
            finding.setdefault("discovery_method", default_methods.get(action, "Agent-selected security validation based on observed evidence."))
        return findings

    def _baseline(self, data):
        findings = []
        for item in data.get("xss_candidates", []):
            findings.append({"finding_id":"BF-XSS-%02d" % (len(findings)+1),"title":"Potential reflected XSS candidate","category":"XSS","severity":"MEDIUM","confidence":0.78,"status":"POTENTIAL","hypothesis":f"Input parameter '{item.get('parameter')}' reflected a controlled marker and requires targeted XSS validation.","evidence":[item],"validation":{"status":"POTENTIAL","validator":"initial_web_scan"},"discovery_method":"Unauthenticated baseline: controlled marker reflection scan","impact":"A reflected input may become script execution if it reaches an executable browser context.","remediation":"Validate encoding and context-specific output handling before treating the signal as exploitable."})
        for item in data.get("sqli_candidates", []):
            findings.append({"finding_id":"BF-SQLI-%02d" % (len(findings)+1),"title":"Potential SQL injection candidate","category":"SQL Injection","severity":"HIGH","confidence":0.82,"status":"POTENTIAL","hypothesis":f"Parameter '{item.get('parameter')}' produced a database/parser error under a controlled quote probe and requires targeted SQLi validation.","evidence":[item],"validation":{"status":"POTENTIAL","validator":"initial_web_scan"},"discovery_method":"Unauthenticated baseline: controlled quote/error differential scan","impact":"A server-side query construction weakness could expose or modify application data.","remediation":"Use parameterized queries and server-side input handling; validate the suspected parameter safely."})
        return findings

    def _xss(self, data):
        if not data.get("reflected"):
            return []
        status = "CONFIRMED" if data.get("executable_context") else "INCONCLUSIVE"
        return [{"finding_id":"F-XSS-001","title":"Reflected XSS validated" if status == "CONFIRMED" else "Reflected input requires XSS review","category":"XSS","severity":"HIGH" if status == "CONFIRMED" else "MEDIUM","confidence":0.95 if status == "CONFIRMED" else 0.75,"status":status,"hypothesis":"A user-controlled input may reach an executable browser context.","evidence":[data],"validation":{"status":status,"validator":"xss_validate"},"discovery_method":"Unauthenticated baseline reflected-input candidate followed by targeted XSS validation.","impact":"Successful reflected XSS can execute attacker-controlled script in a victim browser context.","remediation":"Contextually encode untrusted output, validate input, and deploy an appropriate CSP."}]

    def _sqli(self, data):
        if not data.get("confirmed"):
            return []
        return [{"finding_id":"F-SQLI-001","title":"SQL injection validated","category":"SQL Injection","severity":"CRITICAL","confidence":0.96,"status":"CONFIRMED","hypothesis":"A controlled quote probe reached a database/parser error path, supporting SQL injection in the tested parameter.","evidence":[data],"validation":{"status":"CONFIRMED","validator":"sqli_validate"},"discovery_method":"Unauthenticated baseline quote/error signal followed by targeted SQLi validation.","impact":"SQL injection can permit unauthorized data access or modification depending on query privileges and application behavior.","remediation":"Use parameterized queries/prepared statements and remove string concatenation from database queries."}]


    def _sqli_login(self, data):
        if not data.get("confirmed"):
            return []
        return [{
            "finding_id": "F-SQLI-LOGIN-001",
            "title": "SQL injection authentication bypass",
            "category": "SQL Injection / Authentication",
            "severity": "CRITICAL",
            "confidence": 0.99,
            "status": "CONFIRMED",
            "hypothesis": "The login email parameter accepts a controlled SQL injection payload that produces an authenticated response.",
            "evidence": [data],
            "validation": {"status": "CONFIRMED", "validator": "sqli_login_validate"},
            "discovery_method": "Unauthenticated baseline discovered the login surface; targeted SQLi login validation demonstrated authentication bypass.",
            "impact": "An attacker may bypass authentication and obtain an authenticated session without valid credentials.",
            "remediation": "Use parameterized queries/prepared statements and enforce server-side authentication logic independent of user-controlled SQL fragments.",
        }]

    def _dom_xss(self, data):
        if not data.get("confirmed"):
            return []
        return [{
            "finding_id": "F-XSS-DOM-001",
            "title": "DOM-based XSS source-to-sink path identified",
            "category": "XSS",
            "severity": "HIGH",
            "confidence": 0.90,
            "status": "CONFIRMED",
            "hypothesis": "A browser-controlled URL/search source reaches an unsafe HTML rendering sink in a served JavaScript bundle.",
            "evidence": [data],
            "validation": {"status": "CONFIRMED", "validator": "dom_xss_validate"},
            "discovery_method": "Unauthenticated baseline inspected served JavaScript and identified a DOM-XSS source/sink path; targeted runtime-bundle validation confirmed both signals.",
            "impact": "DOM XSS can execute attacker-controlled script in a victim browser context when the vulnerable route is reached.",
            "remediation": "Avoid unsafe HTML sinks, use framework-safe rendering, contextually encode untrusted data, and enforce an appropriate CSP.",
        }]

    def _auth_bruteforce(self, data):
        if not data.get("confirmed"):
            return []
        return [{
            "finding_id": "F-AUTH-001",
            "title": "Weak brute-force protection observed",
            "category": "Authentication",
            "severity": "MEDIUM",
            "confidence": 0.88,
            "status": "CONFIRMED",
            "hypothesis": "The login endpoint accepted repeated invalid credentials without an observed throttle or lockout response during the bounded test.",
            "evidence": [data],
            "validation": {"status": "CONFIRMED", "validator": "auth_bruteforce_validate"},
            "impact": "Insufficient login throttling can increase exposure to password guessing and credential-stuffing attempts.",
            "remediation": "Apply rate limiting, progressive delays, abuse detection, and appropriate account protection controls."
        }]

    def _jwt(self, data):
        if not data.get("confirmed"):
            return []
        return [{
            "finding_id": "F-JWT-001",
            "title": "JWT security weakness observed",
            "category": "JWT / Authentication",
            "severity": "HIGH" if data.get("authentication_bypass_observed") else "MEDIUM",
            "confidence": 0.96 if data.get("authentication_bypass_observed") else 0.90,
            "status": "CONFIRMED",
            "hypothesis": "The approved authenticated JWT or protected-resource authentication controls contain a common security weakness such as invalid-token acceptance, a missing expiration claim, unsafe algorithm, or sensitive claim data.",
            "evidence": [data],
            "validation": {"status": "CONFIRMED", "validator": "jwt_validate"},
            "impact": "Weak token controls can increase the impact of token theft or prolong unauthorized access.",
            "remediation": "Use a strong signing algorithm, enforce appropriate expiration and validation of issuer/audience where applicable, and never place secrets in token claims."
        }]

    def _headers(self, data):
        missing = data.get("missing_headers", [])
        if not missing:
            return []
        csp_missing = "Content-Security-Policy" in missing
        finding = Finding(
            finding_id="F-CSP-001" if csp_missing else "F-HEADERS-001",
            title="Missing Content Security Policy" if csp_missing else "Missing security response headers",
            category="CSP / Security Headers" if csp_missing else "Security Headers",
            severity="MEDIUM" if csp_missing else "LOW",
            confidence=0.99,
            status="CONFIRMED",
            hypothesis="The application response may lack browser-enforced security controls.",
            evidence=[{"missing_headers": missing, "present_headers": data.get("present_headers", []), "url": data.get("url")}],
            validation={"status": "CONFIRMED", "validator": "security_header_validate"},
            impact="Missing browser security headers can increase exposure to client-side attacks and weaken defense-in-depth.",
            remediation="Deploy an appropriate Content-Security-Policy and required security headers based on the application's architecture.",
        )
        return [finding.to_dict()]

    def _cors(self, data):
        if not (
            data.get("wildcard_detected")
            or data.get("origin_reflected")
        ):
            return []

        credentials = (
            data.get("access_control_allow_credentials")
            == "true"
        )

        severity = "MEDIUM" if (
            data.get("origin_reflected") and credentials
        ) else "LOW"

        finding = Finding(
            finding_id="F-CORS-001",
            title="Permissive CORS behavior validated",
            category="CORS",
            severity=severity,
            confidence=0.99,
            status="CONFIRMED",
            hypothesis=(
                "The application may expose cross-origin security-sensitive "
                "behavior because its CORS policy is permissive."
            ),
            evidence=[
                {
                    "allow_origin": data.get(
                        "access_control_allow_origin"
                    ),
                    "allow_credentials": data.get(
                        "access_control_allow_credentials"
                    ),
                    "origin_reflected": data.get(
                        "origin_reflected"
                    ),
                    "wildcard_detected": data.get(
                        "wildcard_detected"
                    ),
                }
            ],
            validation={
                "status": "CONFIRMED",
                "validator": "cors_validate",
            },
            impact=(
                "A permissive CORS policy can increase browser-based "
                "cross-origin exposure when combined with sensitive "
                "authenticated endpoints or unsafe credential handling."
            ),
            remediation=(
                "Allow only trusted origins, avoid wildcard access for "
                "sensitive resources, and review credentialed CORS behavior."
            ),
        )
        return [finding.to_dict()]

    def _csrf(self, data):
        if data.get("not_applicable"):
            return [{"finding_id":"F-CSRF-001","title":"CSRF not applicable to bearer-token authentication","category":"CSRF","severity":"INFO","confidence":0.95,"status":"NOT_APPLICABLE","hypothesis":"The target uses an Authorization bearer token rather than browser-managed ambient credentials for the tested flow.","evidence":[data],"validation":{"status":"NOT_APPLICABLE","validator":"csrf_validate"},"impact":"Bearer-token authentication is not automatically sent by a victim browser to an attacker-controlled origin, reducing the classic CSRF condition.","remediation":"Continue protecting state-changing endpoints with appropriate authorization and review token storage and CORS separately."}]
        if not data.get("cross_origin_request_accepted"):
            return []

        status = "CONFIRMED" if data.get("state_change_confirmed") else "INCONCLUSIVE"

        finding = Finding(
            finding_id="F-CSRF-001",
            title="Cross-origin request accepted without CSRF token",
            category="CSRF",
            severity="MEDIUM",
            confidence=0.85,
            status=status,
            hypothesis=(
                "A cross-origin request may be able to trigger an "
                "authenticated state-changing operation without CSRF "
                "protection."
            ),
            evidence=[
                {
                    "status_code": data.get("status_code"),
                    "csrf_token_present": data.get(
                        "csrf_token_present"
                    ),
                    "cross_origin_request_accepted": data.get(
                        "cross_origin_request_accepted"
                    ),
                    "state_change_confirmed": data.get(
                        "state_change_confirmed",
                        False,
                    ),
                }
            ],
            validation={
                "status": status,
                "validator": "csrf_validate",
            },
            impact=(
                "If the endpoint changes authenticated state, an attacker "
                "could potentially cause an authenticated victim's browser "
                "to submit an unwanted action."
            ),
            remediation=(
                "Use anti-CSRF tokens for state-changing requests, enforce "
                "appropriate SameSite cookie controls, and validate Origin/"
                "Referer where appropriate."
            ),
        )
        return [finding.to_dict()]

    def _idor(self, data):
        status = data.get("status", "INCONCLUSIVE")

        finding = Finding(
            finding_id="F-IDOR-001",
            title="Broken object-level authorization validated",
            category="IDOR/BOLA",
            severity="HIGH",
            confidence=0.95 if status == "CONFIRMED" else 0.75,
            status=status,
            hypothesis=(
                "An authenticated user may be able to access another "
                "object by changing a direct object identifier."
            ),
            evidence=[
                {
                    "baseline_url": data.get("baseline_url"),
                    "alternate_url": data.get("alternate_url"),
                    "baseline_status_code": data.get(
                        "baseline_status_code"
                    ),
                    "alternate_status_code": data.get(
                        "alternate_status_code"
                    ),
                    "alternate_object_accessible": data.get(
                        "alternate_object_accessible"
                    ),
                    "response_different": data.get(
                        "response_different"
                    ),
                }
            ],
            validation={
                "status": status,
                "validator": "idor_validate",
                "summary": data.get("evidence_summary"),
            },
            impact=(
                "Unauthorized object access can expose another user's "
                "data or permit unauthorized object-level operations."
            ),
            remediation=(
                "Enforce server-side object ownership/authorization on "
                "every object access; never rely on the identifier itself "
                "to establish authorization."
            ),
        )
        return [finding.to_dict()]
