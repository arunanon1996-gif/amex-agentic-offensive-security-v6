class AttackSurfaceModel:
    """Build a UI-friendly attack-surface and attack-path model from evidence."""

    def build(self, state):
        services, technologies, endpoints, parameters, forms, signals = [], [], [], [], [], []
        auth_boundaries = []
        for obs in state.observations:
            if obs.source == "nmap":
                for p in obs.data.get("ports", []):
                    if p.get("state") == "open":
                        services.append({"port": p.get("port"), "service": p.get("service", "unknown")})
            elif obs.source == "http_probe":
                endpoints.append({"url": obs.data.get("url"), "method": "GET", "status": obs.data.get("status_code"), "phase": "UNAUTHENTICATED"})
                signals.extend(obs.signals)
            elif obs.source == "initial_web_scan":
                technologies.extend(obs.data.get("technologies", []))
                signals.extend(obs.data.get("security_signals", []))
                for e in obs.data.get("endpoints", []):
                    endpoints.append({**e, "phase": "UNAUTHENTICATED"})
                    parameters.extend([{"url": e.get("url"), "name": p, "phase": "UNAUTHENTICATED"} for p in e.get("parameters", [])])
                forms.extend(obs.data.get("forms", []))
                if any(x.get("parameter") for x in obs.data.get("xss_candidates", [])) or obs.data.get("dom_xss_candidates"):
                    auth_boundaries.append({"name": "Public input / browser execution surface", "type": "UNAUTHENTICATED"})
                if obs.data.get("login_candidates"):
                    auth_boundaries.append({"name": "Authentication boundary", "type": "LOGIN_ENDPOINT", "endpoint": obs.data.get("login_candidates")[0].get("url")})
            elif obs.source == "authenticated_resource_probe":
                endpoints.append({"url": obs.data.get("resource_url"), "method": "GET", "status": obs.data.get("status_code"), "auth": True, "phase": "AUTHENTICATED"})
                auth_boundaries.append({"name": "Bearer authentication", "type": "AUTHENTICATED", "session_established": bool(obs.data.get("session_id"))})
                signals.extend(obs.signals)

        tls = [o.data for o in state.observations if o.source == "tls_validate"]
        nmap_meta = next((o.data for o in state.observations if o.source == "nmap"), {})
        attack_paths = self._attack_paths(state)
        return {
            "target": state.target,
            "phase": state.phase,
            "services": services,
            "technologies": sorted(set(x for x in technologies if x)),
            "endpoints": endpoints,
            "parameters": parameters,
            "forms": forms,
            "security_signals": signals,
            "authentication_boundaries": auth_boundaries,
            "network_recon": {"engine": nmap_meta.get("engine", "nmap"), "warning": nmap_meta.get("warning"), "raw_output": nmap_meta.get("raw_output", "")[:3000]},
            "tls": tls,
            "trust_boundaries": [{"from": "browser/untrusted origin", "to": "application", "reason": "Cross-origin validation"}] if any(s.get("category") == "cors" for s in signals) else [],
            "attack_paths": attack_paths,
        }

    def _attack_paths(self, state):
        paths = []
        for finding in state.findings:
            if finding.get("status") != "CONFIRMED":
                continue
            category = finding.get("category", "Security finding")
            if category == "IDOR/BOLA":
                paths.append({"id": "AP-IDOR-001", "title": "Authenticated resource authorization bypass", "steps": ["Valid authentication", "User-owned resource discovered", "Object identifier mutated", "Authorization check failed", "Unauthorized resource access"]})
            elif category == "JWT / Authentication":
                paths.append({"id": "AP-JWT-001", "title": "Weak token control", "steps": ["Valid authentication", "JWT issued", "Token control weakness observed", "Increased token compromise impact"]})
            elif category == "Authentication":
                paths.append({"id": "AP-AUTH-001", "title": "Authentication resilience weakness", "steps": ["Login endpoint discovered", "Repeated invalid attempts", "No observed throttle/lockout", "Increased credential-guessing exposure"]})
            elif category in {"SQL Injection", "XSS", "CORS"}:
                paths.append({"id": "AP-" + category.upper().replace(" ", "-") + "-001", "title": finding.get("title", category), "steps": ["Public attack surface discovered", "Security hypothesis generated", "Targeted validation executed", finding.get("title", "Confirmed security finding")]})
        return paths
