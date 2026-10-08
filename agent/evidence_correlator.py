from agent.hypothesis_graph import HypothesisGraph


class EvidenceCorrelator:
    """
    Converts observations/signals into candidate hypotheses.

    Importantly, validators are not chained directly. A new validation
    action becomes eligible only when the evidence creates its hypothesis.
    """

    def __init__(self):
        self.graph = HypothesisGraph()

    def correlate(self, observations):
        for observation in observations:
            for signal in observation.signals:
                self._process_signal(signal)

            if observation.source == "cors_validate":
                self._process_cors_observation(observation.data)

            if observation.source == "csrf_validate":
                self._process_csrf_observation(observation.data)

            if observation.source == "initial_web_scan":
                self._process_initial_scan(observation.data)

        return self.graph

    def _process_initial_scan(self, data):
        for item in data.get("xss_candidates", []):
            self.graph.add(
                hypothesis_id=f"xss-{item.get('parameter')}-{item.get('url')}",
                statement=f"The unauthenticated baseline reflected input in '{item.get('parameter')}' at {item.get('url')}; validate whether the input reaches an executable browser context.",
                category="XSS", confidence=0.78,
                supporting_signals=[item.get("evidence", "Reflected marker observed.")],
                candidate_actions=["xss_validate"],
            )
        for item in data.get("sqli_candidates", []):
            self.graph.add(
                hypothesis_id=f"sqli-{item.get('parameter')}-{item.get('url')}",
                statement=f"The unauthenticated baseline produced a database/parser error for '{item.get('parameter')}' at {item.get('url')}; validate for SQL injection.",
                category="SQL Injection", confidence=0.82,
                supporting_signals=[item.get("evidence", "Database error signature observed.")],
                candidate_actions=["sqli_validate"],
            )
        for item in data.get("login_candidates", []):
            self.graph.add(
                hypothesis_id="sqli-login-" + item.get("url", "login"),
                statement="The unauthenticated baseline discovered a JSON login surface; validate whether its email input is vulnerable to controlled SQL injection.",
                category="SQL Injection", confidence=0.86,
                supporting_signals=[item.get("evidence", "Login endpoint discovered.")],
                candidate_actions=["sqli_login_validate"],
            )
        for item in data.get("dom_xss_candidates", []):
            self.graph.add(
                hypothesis_id="dom-xss-" + item.get("bundle_url", "bundle"),
                statement="The public JavaScript bundle contains a URL/search-controlled source and an unsafe HTML sink; validate the DOM-XSS source-to-sink path.",
                category="XSS", confidence=0.84,
                supporting_signals=[item.get("evidence", "DOM-XSS source/sink signal observed in a served bundle.")],
                candidate_actions=["dom_xss_validate"],
            )

    def _process_signal(self, signal):
        category = signal.get("category")
        name = signal.get("name")
        value = signal.get("value")

        if category == "security_header":
            self._process_security_header(name, value)
        elif category == "technology":
            self._process_technology(signal)
        elif category == "cors":
            self._process_cors(name, value)
        elif category == "IDOR":
            self._process_idor_signal(signal)

    def _process_security_header(self, name, value):
        if name == "CSP" and value == "missing":
            self.graph.add(
                hypothesis_id="missing-csp",
                statement=(
                    "The application lacks a Content Security Policy "
                    "and may have reduced browser-side injection defenses."
                ),
                category="XSS",
                confidence=0.65,
                supporting_signals=[
                    "Content Security Policy header is missing."
                ],
                candidate_actions=["security_header_validate"],
            )

        elif name == "HSTS" and value == "missing":
            self.graph.add(
                hypothesis_id="missing-hsts",
                statement=(
                    "The application does not advertise HSTS "
                    "and may have weaker transport protection."
                ),
                category="TLS",
                confidence=0.60,
                supporting_signals=[
                    "Strict-Transport-Security header is missing."
                ],
                candidate_actions=["security_header_validate"],
            )

        elif name == "X-Frame-Options" and value == "missing":
            self.graph.add(
                hypothesis_id="missing-x-frame-options",
                statement=(
                    "The application may lack browser-level "
                    "clickjacking protection."
                ),
                category="Clickjacking",
                confidence=0.55,
                supporting_signals=[
                    "X-Frame-Options header is missing."
                ],
                candidate_actions=["security_header_validate"],
            )

    def _process_technology(self, signal):
        technology = signal.get("name")
        confidence = signal.get("confidence", 0.5)

        self.graph.add(
            hypothesis_id=(
                "technology-"
                + technology.lower().replace(" ", "-")
            ),
            statement=(
                f"The application uses {technology}; "
                "relevant technology-specific security checks may apply."
            ),
            category="Technology",
            confidence=confidence,
            supporting_signals=[
                f"{technology}: {signal.get('value')}"
            ],
            candidate_actions=["technology_validate"],
        )

    def _process_cors(self, name, value):
        if (
            name == "Access-Control-Allow-Origin"
            and value == "*"
        ):
            self.graph.add(
                hypothesis_id="cors-wildcard",
                statement=(
                    "The application permits wildcard cross-origin access "
                    "and may expose cross-origin security-sensitive behavior."
                ),
                category="CORS",
                confidence=0.80,
                supporting_signals=[
                    "Access-Control-Allow-Origin: *"
                ],
                candidate_actions=["cors_validate"],
            )

    def _process_cors_observation(self, data):
        if data.get("wildcard_detected") or data.get("origin_reflected"):
            self.graph.add(
                hypothesis_id="csrf-cross-origin-behavior",
                statement=(
                    "Controlled cross-origin behavior was validated; "
                    "an approved state-changing endpoint should be "
                    "evaluated for CSRF protection."
                ),
                category="CSRF",
                confidence=0.85,
                supporting_signals=[
                    "Controlled external Origin produced permissive CORS behavior."
                ],
                candidate_actions=["csrf_validate"],
            )

    def _process_csrf_observation(self, data):
        if data.get("cross_origin_request_accepted") is True:
            self.graph.add(
                hypothesis_id="csrf-state-changing-request",
                statement=(
                    "A controlled cross-origin request was accepted "
                    "without a CSRF token; authenticated state-changing "
                    "behavior requires further application context."
                ),
                category="CSRF",
                confidence=0.85,
                supporting_signals=[
                    "Controlled cross-origin request was accepted.",
                    "No CSRF token was supplied.",
                ],
                candidate_actions=["csrf_validate"],
            )

    def _process_idor_signal(self, signal):
        self.graph.add(
            hypothesis_id="idor-object-authorization",
            statement=(
                "An authenticated resource URL contains a direct object "
                "identifier; object-level authorization should be validated "
                "against a controlled alternate identifier."
            ),
            category="IDOR",
            confidence=signal.get("confidence", 0.90),
            supporting_signals=[
                signal.get("rationale", "Object identifier observed.")
            ],
            candidate_actions=["idor_validate"],
        )
