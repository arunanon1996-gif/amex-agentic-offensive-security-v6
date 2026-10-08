from agent.action_scorer import CandidateActionScorer
from agent.analysis_engine import AnalysisEngine
from agent.evidence_correlator import EvidenceCorrelator


class DecisionEngine:
    """Evidence-driven pentest planner with explicit unauthenticated/authenticated phases."""

    WEB_PORTS = {80, 443, 3000, 5000, 8000, 8080}
    UNAUTH_ACTIONS = {
        "nmap", "http_probe", "initial_web_scan", "cors_validate",
        "security_header_validate", "tls_validate", "xss_validate", "sqli_validate", "sqli_login_validate", "dom_xss_validate",
    }
    AUTH_ACTIONS = {
        "authenticated_resource_probe", "idor_validate", "csrf_validate",
        "auth_bruteforce_validate", "jwt_validate",
    }
    SUPPORTED_ACTIONS = UNAUTH_ACTIONS | AUTH_ACTIONS

    def __init__(self, default_ports=None):
        self.default_ports = default_ports or [80, 443, 3000, 5000, 8000, 8080]
        self.analysis_engine = AnalysisEngine()
        self.action_scorer = CandidateActionScorer()

    def decide_next_action(self, state, context=None):
        context = context or {}
        phase = state.phase or context.get("phase", "UNAUTHENTICATED")
        # Backward-compatible inference for direct planner tests: once an
        # authenticated session exists, the state is effectively in Phase 2.
        if phase == "UNAUTHENTICATED" and self._get_session_observation(state) and state.runtime_context.get("username"):
            phase = "AUTHENTICATED"

        if not state.observations:
            return {"action": "nmap", "reason": "No network observations exist yet. Perform approved service discovery.", "expected_evidence": "Open ports and discovered services.", "parameters": {"ports": context.get("ports", self.default_ports)}, "score": 0.50}

        nmap_decision = self._http_probe_decision(state)
        if nmap_decision:
            return nmap_decision

        if phase != "AUTHENTICATED" and any(o.source == "http_probe" for o in state.observations) and "initial_web_scan" not in state.actions_taken:
            return {"action": "initial_web_scan", "reason": "HTTP service is confirmed. Perform a bounded unauthenticated web baseline first, like a pentester's initial Burp-style assessment, to discover public endpoints, input parameters, security signals, and candidate injection points.", "expected_evidence": "Public endpoints, parameters, forms, technologies, passive security signals, and candidate XSS/SQLi observations.", "parameters": {"port": self._get_http_port(state)}, "hypothesis_id": "unauthenticated-web-baseline", "score": 0.70, "score_breakdown": {"evidence_value": 0.70, "exploitability": 0.75, "confidence": 0.70, "impact": 0.75, "coverage": 0.95}}

        if phase != "AUTHENTICATED" and any(o.source == "http_probe" for o in state.observations) and "security_header_validate" not in state.actions_taken:
            return {"action": "security_header_validate", "reason": "The public baseline is established. Validate the live browser security-header set as a separate infrastructure/application control check.", "expected_evidence": "Live security headers and missing/present browser controls.", "parameters": {"port": self._get_http_port(state)}, "hypothesis_id": "browser-security-baseline", "score": 0.68, "score_breakdown": {"evidence_value": 0.82, "exploitability": 0.50, "confidence": 0.82, "impact": 0.60, "coverage": 0.90}}

        if phase != "AUTHENTICATED" and any(o.source == "nmap" for o in state.observations) and "tls_validate" not in state.actions_taken and self._has_open_port(state, 443):
            return {"action": "tls_validate", "reason": "Service discovery identified TCP/443. Inspect the TLS protocol and certificate posture as part of the transport-security baseline.", "expected_evidence": "TLS negotiation, protocol, cipher and certificate posture.", "parameters": {"port": 443}, "hypothesis_id": "transport-security-baseline", "score": 0.66, "score_breakdown": {"evidence_value": 0.80, "exploitability": 0.50, "confidence": 0.80, "impact": 0.70, "coverage": 0.85}}

        self._analyze_http_observations(state)
        self._analyze_authenticated_resource_observations(state)
        self._add_baseline_hypotheses(state)

        if phase == "AUTHENTICATED":
            self._add_authenticated_hypotheses(state)
            self._add_csrf_hypothesis(state)
        else:
            self._add_unauth_hypotheses_from_scan(state)

        graph = EvidenceCorrelator().correlate(state.observations)
        if phase == "AUTHENTICATED":
            self._add_auth_graph_candidates(state, graph)

        ranked = self.action_scorer.rank(graph.get_candidates())
        executed = set(state.actions_taken)
        allowed_phase = self.UNAUTH_ACTIONS if phase != "AUTHENTICATED" else self.SUPPORTED_ACTIONS
        ranked = [c for c in ranked if c.action in allowed_phase and c.action in self.SUPPORTED_ACTIONS and c.action not in executed and self._action_is_available(c.action, state)]
        if not ranked:
            return None

        selected = ranked[0]
        return {
            "action": selected.action,
            "reason": selected.reason,
            "expected_evidence": self._expected_evidence(selected.action),
            "parameters": self._build_parameters(selected.action, state),
            "hypothesis_id": selected.hypothesis_id,
            "score": selected.score,
            "score_breakdown": {
                "evidence_value": round(selected.evidence, 3),
                "exploitability": round(selected.applicability, 3),
                "confidence": round(selected.evidence, 3),
                "impact": round(selected.impact, 3),
                "coverage": round(max(0.0, 1.0 - selected.cost), 3),
                "risk": round(selected.risk, 3),
            },
        }

    def _add_baseline_hypotheses(self, state):
        scan = next((o for o in state.observations if o.source == "initial_web_scan"), None)
        if not scan: return
        data = scan.data
        for item in data.get("xss_candidates", []):
            state.add_hypothesis(f"Unauthenticated baseline reflected input in parameter '{item.get('parameter')}' at {item.get('url')}; validate whether the input reaches an executable browser context.", 0.78, ["Baseline scanner observed the controlled marker in the response."])
        for item in data.get("sqli_candidates", []):
            state.add_hypothesis(f"Unauthenticated baseline observed a database/parser error for parameter '{item.get('parameter')}' at {item.get('url')}; validate for SQL injection using a controlled differential/error probe.", 0.82, [f"Baseline scanner observed error signature: {item.get('error_signature')}"])
        for signal in data.get("security_signals", []):
            if signal.get("category") == "cors":
                state.add_hypothesis("Unauthenticated response permits wildcard cross-origin access; validate the CORS policy against a controlled origin.", 0.80, [signal.get("rationale", "Wildcard CORS signal.")])
            if signal.get("category") == "security_header" and signal.get("name") == "CSP":
                state.add_hypothesis("The application lacks a Content Security Policy; validate the live security header set and its browser-side implications.", 0.70, [signal.get("rationale", "Missing CSP signal.")])

    def _add_unauth_hypotheses_from_scan(self, state):
        return

    def _add_authenticated_hypotheses(self, state):
        context = state.runtime_context
        if not (context.get("username") and context.get("password")): return
        if "authenticated_resource_probe" not in state.actions_taken:
            state.add_hypothesis("Approved authenticated test credentials are available; probe the configured user-owned resource to collect object-identifier evidence.", 0.90, ["Operator supplied an authenticated test account.", "Authentication phase is active." ])
        if "auth_bruteforce_validate" not in state.actions_taken:
            state.add_hypothesis("The application exposes a login endpoint; assess whether bounded invalid-login attempts trigger throttling or lockout controls.", 0.84, [f"Login endpoint discovered at {context.get('login_path', '/rest/user/login')}."])
        if self._get_session_observation(state) and "jwt_validate" not in state.actions_taken:
            state.add_hypothesis("An authenticated bearer session is available; inspect the JWT structure and common claim controls without forging the token.", 0.86, ["Authenticated resource probe established an in-memory session."])

    def _add_auth_graph_candidates(self, state, graph):
        context = state.runtime_context
        if context.get("username") and context.get("password") and "authenticated_resource_probe" not in state.actions_taken:
            graph.add("authenticated-resource-discovery", "Approved authenticated credentials can reveal user-owned resources and object identifiers.", "Authorization", 0.90, ["Operator-supplied test credentials"], ["authenticated_resource_probe"])
        if context.get("username") and "auth_bruteforce_validate" not in state.actions_taken:
            graph.add("authentication-resilience", "The login endpoint should be tested for bounded brute-force resilience controls.", "Authentication", 0.84, ["Login endpoint available"], ["auth_bruteforce_validate"])
        if self._get_session_observation(state) and "jwt_validate" not in state.actions_taken:
            graph.add("jwt-security", "The authenticated bearer token should be inspected for common JWT security weaknesses.", "Authentication", 0.86, ["Bearer session established"], ["jwt_validate"])

    def _add_csrf_hypothesis(self, state):
        session = self._get_session_observation(state)
        if not session or "csrf_validate" in state.actions_taken or not state.runtime_context.get("csrf_path"): return
        state.add_hypothesis("An authenticated session and configured state-changing endpoint are available; test whether a cross-origin request can perform that action without CSRF protection.", 0.88, ["Authenticated session established.", "Operator supplied a state-changing endpoint."])

    def _action_is_available(self, action, state):
        context = state.runtime_context
        if action == "authenticated_resource_probe": return bool(context.get("username") and context.get("password") and context.get("resource_template"))
        if action == "idor_validate": return bool(self._get_resource_observation(state))
        if action in {"xss_validate", "sqli_validate", "sqli_login_validate", "dom_xss_validate"}:
            scan = next((o for o in state.observations if o.source == "initial_web_scan"), None)
            if not scan: return False
            if action == "xss_validate": return bool(scan.data.get("xss_candidates"))
            if action == "dom_xss_validate": return bool(scan.data.get("dom_xss_candidates"))
            if action == "sqli_login_validate": return bool(scan.data.get("login_candidates"))
            return bool(scan.data.get("sqli_candidates"))
        if action == "csrf_validate": return bool(self._get_session_observation(state) and context.get("csrf_path"))
        if action == "jwt_validate": return bool(self._get_session_observation(state))
        if action == "tls_validate": return self._has_open_port(state, 443)
        if action == "auth_bruteforce_validate": return bool(context.get("username") and context.get("login_path"))
        return True

    def _build_parameters(self, action, state):
        port = self._get_http_port(state); context = state.runtime_context
        scan = next((o for o in state.observations if o.source == "initial_web_scan"), None)
        if action in {"initial_web_scan", "security_header_validate"}: return {"port": port}
        if action == "tls_validate": return {"port": 443}
        if action == "cors_validate": return {"port": port, "origin": "https://attacker.example"}
        if action == "csrf_validate":
            resource = self._get_session_observation(state)
            return {"port": port, "path": context.get("csrf_path", "/"), "method": "POST", "body": context.get("csrf_body", "test=value"), "content_type": "application/x-www-form-urlencoded", "origin": "https://attacker.example", "session_id": resource.data.get("session_id")}
        if action in {"xss_validate", "sqli_validate"}:
            key = "xss_candidates" if action == "xss_validate" else "sqli_candidates"
            item = scan.data.get(key, [])[0]
            parsed = item["url"].split("/", 3)
            return {"port": port, "url_path": "/" + parsed[3] if len(parsed) > 3 else "/", "parameter": item["parameter"]}
        if action == "sqli_login_validate":
            item = scan.data.get("login_candidates", [])[0]
            parts = item["url"].split("/", 3)
            return {"port": port, "login_path": "/" + parts[3] if len(parts) > 3 else "/rest/user/login"}
        if action == "dom_xss_validate":
            item = scan.data.get("dom_xss_candidates", [])[0]
            return {"port": port, "source_url": "/", "bundle_url": item.get("bundle_url", "")}
        if action == "authenticated_resource_probe": return {"port": port, "login_path": context.get("login_path", "/rest/user/login"), "resource_template": context.get("resource_template"), "object_id_field": context.get("object_id_field", "bid"), "resource_type": context.get("resource_type", "basket")}
        if action == "idor_validate":
            resource = self._get_resource_observation(state); object_id = str(resource.data["object_identifier"])
            return {"port": port, "session_id": resource.data["session_id"], "path_template": context.get("resource_template", "/rest/basket/{object_id}"), "object_identifier": object_id, "alternate_object_identifier": self._alternate_id(object_id, context.get("alternate_object_id"))}
        if action == "auth_bruteforce_validate": return {"port": port, "login_path": context.get("login_path", "/rest/user/login"), "attempts": 4, "interval_seconds": 0.15}
        if action == "jwt_validate":
            resource = self._get_session_observation(state)
            resource_url = resource.data.get("resource_url", "/")
            try:
                path = "/" + resource_url.split("/", 3)[3]
            except Exception:
                path = "/"
            return {"session_id": resource.data.get("session_id"), "port": port, "protected_path": path.split("?")[0]}
        return {"port": port}

    def _http_probe_decision(self, state):
        for observation in state.observations:
            if observation.source != "nmap": continue
            for port_data in observation.data.get("ports", []):
                port = port_data.get("port")
                if port_data.get("state") == "open" and port in self.WEB_PORTS and "http_probe" not in state.actions_taken:
                    statement = f"An HTTP application may be running on port {port}."
                    state.add_hypothesis(statement, 0.90, [f"Nmap identified open TCP port {port}."])
                    return {"action":"http_probe","reason":statement,"expected_evidence":"HTTP status, headers, server information, and application metadata.","parameters":{"port":port},"score":0.60,"score_breakdown":{"evidence_value":0.90,"exploitability":0.80,"confidence":0.90,"impact":0.70,"coverage":0.80}}
        return None

    def _analyze_http_observations(self, state):
        for observation in state.observations:
            if observation.source == "http_probe" and not observation.signals:
                observation.signals.extend(self._signal_to_dict(s) for s in self.analysis_engine.analyze_http(state.target, observation.data))

    def _analyze_authenticated_resource_observations(self, state):
        for observation in state.observations:
            if observation.source == "authenticated_resource_probe" and not observation.signals:
                observation.signals.extend(self._signal_to_dict(s) for s in self.analysis_engine.analyze_authenticated_resource(state.target, observation.data))

    def _get_resource_observation(self, state):
        return next((o for o in reversed(state.observations) if o.source == "authenticated_resource_probe" and o.data.get("session_id") and o.data.get("object_identifier")), None)
    def _get_session_observation(self, state): return self._get_resource_observation(state)
    @staticmethod
    def _alternate_id(object_id, configured=None):
        if configured is not None: return str(configured)
        try: return str(int(object_id) + 1)
        except ValueError: return object_id[:-1] + "1" if object_id else "1"
    @staticmethod
    def _has_open_port(state, port):
        return any(o.source == "nmap" and any(p.get("port") == port and p.get("state") == "open" for p in o.data.get("ports", [])) for o in state.observations)

    @staticmethod
    def _get_http_port(state):
        for o in state.observations:
            if o.source == "http_probe":
                try: return int(o.data.get("url", "").split(":")[2].split("/")[0])
                except (IndexError, ValueError): pass
        return 3000
    @staticmethod
    def _signal_to_dict(signal): return {"category":signal.category,"name":signal.name,"value":signal.value,"severity_hint":signal.severity_hint,"confidence":signal.confidence,"source":signal.source,"rationale":signal.rationale}
    @staticmethod
    def _expected_evidence(action):
        return {
            "initial_web_scan":"Public endpoints, parameters, forms, technologies, passive security signals, and candidate XSS/SQLi observations.",
            "cors_validate":"CORS behavior when a controlled external Origin is supplied.",
            "csrf_validate":"Authenticated cross-origin state-changing behavior and CSRF controls.",
            "authenticated_resource_probe":"Authenticated resource URL, object identifier, and baseline authorization response.",
            "idor_validate":"Same-session access comparison between the owned object and a controlled alternate object identifier.",
            "security_header_validate":"Live browser security-header evidence.",
            "xss_validate":"Controlled input reflection and executable-context evidence.",
            "sqli_validate":"Controlled SQL error/differential evidence.",
            "auth_bruteforce_validate":"Bounded invalid-login responses, throttling, lockout and consistency signals.",
            "jwt_validate":"JWT header/claims, expiration, issuer/audience and sensitive-claim evidence.",
            "tls_validate":"TLS negotiation, protocol version, cipher and certificate posture.",
        }.get(action, "Evidence relevant to the selected security hypothesis.")
