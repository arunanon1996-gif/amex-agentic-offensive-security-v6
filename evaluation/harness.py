from dataclasses import dataclass


@dataclass
class EvaluationCase:
    name: str
    evidence: dict


class EvaluationHarness:
    """Offline decision-quality comparison for the frozen two-phase POC flow."""

    BASELINE_ACTIONS = [
        "nmap", "http_probe", "initial_web_scan", "cors_validate",
        "security_header_validate", "xss_validate", "sqli_validate",
        "auth_bruteforce_validate", "jwt_validate",
        "authenticated_resource_probe", "idor_validate", "csrf_validate",
    ]

    def run_case(self, case: EvaluationCase):
        actions = ["nmap", "http_probe", "initial_web_scan"]
        e = case.evidence
        if e.get("sqli_signal"): actions.append("sqli_validate")
        if e.get("xss_signal"): actions.append("xss_validate")
        if e.get("cors_signal"): actions.append("cors_validate")
        if e.get("missing_headers"): actions.append("security_header_validate")
        if e.get("authenticated_resource"):
            actions.append("authenticated_resource_probe")
            if e.get("idor_signal"): actions.append("idor_validate")
            if e.get("jwt_signal"): actions.append("jwt_validate")
            if e.get("login_endpoint"): actions.append("auth_bruteforce_validate")
            if e.get("csrf_applicable"): actions.append("csrf_validate")
        baseline_actions = list(self.BASELINE_ACTIONS)
        interventions = 1 if e.get("authenticated_resource") else 0
        return {
            "case": case.name,
            "baseline": self._metrics(baseline_actions, 0),
            "agentic": self._metrics(actions, interventions),
            "actions_saved": len(baseline_actions) - len(actions),
            "decision_reduction_percent": round((1 - len(actions) / len(baseline_actions)) * 100, 2),
        }

    @staticmethod
    def _metrics(actions, human_interventions):
        return {"action_count":len(actions),"actions":actions,"policy_violation_count":0,"human_interventions":human_interventions}

    def run_reference_cases(self):
        return [
            self.run_case(EvaluationCase("public-injection-signals", {"sqli_signal":True,"xss_signal":True,"cors_signal":True,"missing_headers":True})),
            self.run_case(EvaluationCase("authenticated-authorization", {"cors_signal":True,"missing_headers":True,"authenticated_resource":True,"idor_signal":True,"jwt_signal":True,"login_endpoint":True})),
            self.run_case(EvaluationCase("bearer-auth-no-csrf", {"authenticated_resource":True,"idor_signal":False,"jwt_signal":True,"login_endpoint":True,"csrf_applicable":False})),
        ]
