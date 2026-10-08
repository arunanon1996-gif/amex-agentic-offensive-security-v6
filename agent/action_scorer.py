from dataclasses import dataclass


@dataclass
class ScoredAction:
    action: str
    hypothesis_id: str
    score: float
    impact: float
    evidence: float
    applicability: float
    cost: float
    risk: float
    reason: str


class CandidateActionScorer:
    """
    Deterministic, explainable next-action ranking.

    The agent core is deliberately separated from vulnerability-specific
    validators. Each hypothesis contributes candidate actions, and the
    scorer ranks them using evidence, applicability, impact, cost, and risk.
    """

    ACTION_PROFILES = {
        "cors_validate": {
            "impact": 0.80,
            "cost": 0.20,
            "risk": 0.10,
        },
        "csrf_validate": {
            "impact": 0.75,
            "cost": 0.25,
            "risk": 0.10,
        },
        "authenticated_resource_probe": {
            "impact": 0.75,
            "cost": 0.45,
            "risk": 0.10,
        },
        "idor_validate": {
            "impact": 0.95,
            "cost": 0.35,
            "risk": 0.10,
        },
        "initial_web_scan": {"impact": 0.75, "cost": 0.30, "risk": 0.05},
        "sqli_validate": {"impact": 0.95, "cost": 0.50, "risk": 0.15},
        "sqli_login_validate": {"impact": 1.00, "cost": 0.45, "risk": 0.12},
        "dom_xss_validate": {"impact": 0.92, "cost": 0.35, "risk": 0.08},
        "xss_validate": {
            "impact": 0.90,
            "cost": 0.50,
            "risk": 0.20,
        },
        "tls_validate": {
            "impact": 0.70,
            "cost": 0.40,
            "risk": 0.10,
        },
        "header_validate": {
            "impact": 0.40,
            "cost": 0.10,
            "risk": 0.05,
        },
        "auth_bruteforce_validate": {"impact": 0.85, "cost": 0.30, "risk": 0.10},
        "jwt_validate": {"impact": 0.90, "cost": 0.20, "risk": 0.05},
        "security_header_validate": {
            "impact": 0.55,
            "cost": 0.10,
            "risk": 0.02,
        },
        "technology_validate": {
            "impact": 0.60,
            "cost": 0.20,
            "risk": 0.10,
        },
    }

    def score_hypothesis(self, hypothesis):
        results = []

        for action in hypothesis.candidate_actions:
            profile = self.ACTION_PROFILES.get(action)
            if not profile:
                continue

            evidence = hypothesis.confidence
            applicability = self._applicability(
                hypothesis.category,
                action,
            )

            score = (
                (profile["impact"] * 0.30)
                + (evidence * 0.30)
                + (applicability * 0.25)
                - (profile["cost"] * 0.10)
                - (profile["risk"] * 0.05)
            )

            reason = (
                f"Selected because impact={profile['impact']:.2f}, "
                f"evidence={evidence:.2f}, "
                f"applicability={applicability:.2f}, "
                f"cost={profile['cost']:.2f}, "
                f"risk={profile['risk']:.2f}."
            )

            results.append(
                ScoredAction(
                    action=action,
                    hypothesis_id=self._hypothesis_id(hypothesis),
                    score=round(score, 4),
                    impact=profile["impact"],
                    evidence=evidence,
                    applicability=applicability,
                    cost=profile["cost"],
                    risk=profile["risk"],
                    reason=reason,
                )
            )

        return results

    def rank(self, hypotheses):
        scored_actions = []
        for hypothesis in hypotheses:
            scored_actions.extend(
                self.score_hypothesis(hypothesis)
            )

        return sorted(
            scored_actions,
            key=lambda item: item.score,
            reverse=True,
        )

    def _applicability(self, category, action):
        if category == "CORS" and action == "cors_validate":
            return 0.95

        if category == "CSRF" and action == "csrf_validate":
            return 0.95

        if (
            category == "Authorization"
            and action == "authenticated_resource_probe"
        ):
            return 0.95

        if category == "IDOR" and action == "idor_validate":
            return 0.98

        if category == "XSS" and action == "xss_validate":
            return 0.92

        if category in {"SQLi", "SQL Injection"} and action in {"sqli_validate", "sqli_login_validate"}:
            return 0.98 if action == "sqli_login_validate" else 0.95

        if category == "XSS" and action == "dom_xss_validate":
            return 0.96

        if category == "Authentication" and action == "auth_bruteforce_validate":
            return 0.94

        if category == "Authentication" and action == "jwt_validate":
            return 0.93

        if category == "TLS" and action == "tls_validate":
            return 0.50

        if category == "Technology" and action == "technology_validate":
            return 0.70

        if category in {"XSS", "TLS", "Clickjacking", "Security Headers"} and action == "security_header_validate":
            return 0.90

        return 0.50

    @staticmethod
    def _hypothesis_id(hypothesis):
        return hypothesis.hypothesis_id
