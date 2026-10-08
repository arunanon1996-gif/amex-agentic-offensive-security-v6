from dataclasses import dataclass, field


@dataclass
class Observation:
    source: str
    data: dict
    signals: list[dict] = field(default_factory=list)


@dataclass
class Hypothesis:
    statement: str
    confidence: float
    supporting_observations: list[str] = field(default_factory=list)


@dataclass
class Decision:
    action: str
    reason: str
    expected_evidence: str
    parameters: dict = field(default_factory=dict)
    score: float | None = None
    hypothesis_id: str | None = None
    score_breakdown: dict = field(default_factory=dict)


@dataclass
class AgentState:
    assessment_id: str
    target: str
    objective: str

    observations: list[Observation] = field(default_factory=list)
    hypotheses: list[Hypothesis] = field(default_factory=list)
    decisions: list[Decision] = field(default_factory=list)
    actions_taken: list[str] = field(default_factory=list)
    findings: list[dict] = field(default_factory=list)
    evidence_links: list[dict] = field(default_factory=list)
    attack_surface: dict = field(default_factory=dict)

    action_count: int = 0
    status: str = "INITIALIZED"
    phase: str = "UNAUTHENTICATED"
    scoring_trace: list[dict] = field(default_factory=list)
    attack_paths: list[dict] = field(default_factory=list)

    # Runtime-only context. It is deliberately excluded from summary/evidence
    # so credentials and other sensitive configuration are not persisted.
    runtime_context: dict = field(
        default_factory=dict,
        repr=False,
    )

    def add_observation(self, source, data, signals=None):
        self.observations.append(
            Observation(
                source=source,
                data=data,
                signals=signals or [],
            )
        )

    def add_hypothesis(
        self,
        statement,
        confidence,
        supporting_observations=None,
    ):
        if any(
            item.statement == statement
            for item in self.hypotheses
        ):
            return

        self.hypotheses.append(
            Hypothesis(
                statement=statement,
                confidence=confidence,
                supporting_observations=(
                    supporting_observations or []
                ),
            )
        )

    def add_decision(
        self,
        action,
        reason,
        expected_evidence,
        parameters=None, score=None, hypothesis_id=None, score_breakdown=None,
    ):
        self.decisions.append(
            Decision(
                action=action,
                reason=reason,
                expected_evidence=expected_evidence,
                parameters=parameters or {},
                score=score,
                hypothesis_id=hypothesis_id,
                score_breakdown=score_breakdown or {},
            )
        )

    def add_action(self, action):
        self.actions_taken.append(action)
        self.action_count += 1

    def add_finding(self, finding):
        # Replace a baseline POTENTIAL finding when targeted validation
        # produces the corresponding confirmed/inconclusive result.
        if finding.get("status") in {"CONFIRMED", "INCONCLUSIVE", "NOT_CONFIRMED", "NOT_APPLICABLE"}:
            category = finding.get("category")
            self.findings = [
                existing for existing in self.findings
                if not (
                    existing.get("status") == "POTENTIAL"
                    and existing.get("category") == category
                )
            ]
        if not any(existing.get("finding_id") == finding.get("finding_id") for existing in self.findings):
            self.findings.append(finding)

    def add_evidence_link(self, relation, source, target, reason):
        self.evidence_links.append({
            "relation": relation, "source": source, "target": target, "reason": reason
        })

    def validation_results(self):
        results = []
        for observation in self.observations:
            if observation.source not in {
                "cors_validate",
                "csrf_validate",
                "idor_validate",
                "security_header_validate",
                "xss_validate",
                "sqli_validate",
                "sqli_login_validate",
                "dom_xss_validate",
                "auth_bruteforce_validate",
                "jwt_validate",
                "tls_validate",
            }:
                continue
            data = observation.data or {}
            if observation.source == "cors_validate":
                status = "CONFIRMED" if data.get("confirmed") else "NOT_CONFIRMED"
                conclusion = (
                    "Permissive CORS behavior validated."
                    if data.get("confirmed")
                    else "No permissive CORS behavior was validated."
                )
            elif observation.source == "csrf_validate":
                if data.get("not_applicable"):
                    status = "NOT_APPLICABLE"
                    conclusion = data.get("conclusion", "CSRF is not applicable to the tested authentication model.")
                elif data.get("state_change_confirmed"):
                    status = "CONFIRMED"
                    conclusion = data.get("conclusion") or "Authenticated state change was demonstrated cross-origin."
                elif data.get("cross_origin_request_accepted"):
                    status = "INCONCLUSIVE"
                    conclusion = data.get("conclusion") or "Cross-origin request was accepted, but authenticated state change was not demonstrated."
                else:
                    status = "NOT_CONFIRMED"
                    conclusion = data.get("conclusion") or "The controlled cross-origin state-changing request was not accepted."
            elif observation.source == "idor_validate":
                status = data.get("status", "INCONCLUSIVE")
                conclusion = data.get("evidence_summary", "IDOR validation completed.")
            elif observation.source == "xss_validate":
                status = "CONFIRMED" if data.get("confirmed") else ("INCONCLUSIVE" if data.get("reflected") else "NOT_CONFIRMED")
                conclusion = data.get("conclusion", "XSS validation completed.")
            elif observation.source in {"sqli_validate", "sqli_login_validate"}:
                status = "CONFIRMED" if data.get("confirmed") else "NOT_CONFIRMED"
                conclusion = data.get("conclusion", "SQL injection validation completed.")
            elif observation.source == "dom_xss_validate":
                status = "CONFIRMED" if data.get("confirmed") else "NOT_CONFIRMED"
                conclusion = data.get("conclusion", "DOM XSS validation completed.")
            elif observation.source == "tls_validate":
                status = "NOT_CONFIRMED" if not data.get("tls_enabled") else "OBSERVED"
                conclusion = data.get("conclusion", "TLS validation completed.")
            elif observation.source in {"auth_bruteforce_validate", "jwt_validate"}:
                status = "CONFIRMED" if data.get("confirmed") else "NOT_CONFIRMED"
                conclusion = data.get("conclusion", "Authentication validation completed.")
            else:
                status = "CONFIRMED" if data.get("confirmed") else "NOT_CONFIRMED"
                conclusion = data.get("conclusion", "Security-header validation completed.")
            results.append({"validator": observation.source, "status": status, "conclusion": conclusion, "data": data})
        return results

    def summary(self):
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        status_counts = {"CONFIRMED": 0, "POTENTIAL": 0, "INCONCLUSIVE": 0, "NOT_APPLICABLE": 0}
        for finding in self.findings:
            severity = finding.get("severity", "INFO")
            if severity in severity_counts:
                severity_counts[severity] += 1
            status = finding.get("status")
            if status in status_counts:
                status_counts[status] += 1
        return {
            "assessment_id": self.assessment_id,
            "target": self.target,
            "target_url": self.runtime_context.get("target_url", f"http://{self.target}:3000"),
            "objective": self.objective,
            "status": self.status,
            "phase": self.phase,
            "action_count": self.action_count,
            "finding_counts": severity_counts,
            "finding_status_counts": status_counts,
            "observations": [
                {
                    "source": observation.source,
                    "data": observation.data,
                    "signals": observation.signals,
                }
                for observation in self.observations
            ],
            "hypotheses": [
                {
                    "statement": hypothesis.statement,
                    "confidence": hypothesis.confidence,
                    "supporting_observations": (
                        hypothesis.supporting_observations
                    ),
                }
                for hypothesis in self.hypotheses
            ],
            "decisions": [
                {
                    "action": decision.action,
                    "reason": decision.reason,
                    "expected_evidence": decision.expected_evidence,
                    "parameters": decision.parameters,
                    "score": decision.score,
                    "hypothesis_id": decision.hypothesis_id,
                    "score_breakdown": decision.score_breakdown,
                }
                for decision in self.decisions
            ],
            "actions_taken": self.actions_taken,
            "findings": self.findings,
            "validation_results": self.validation_results(),
            "evidence_links": self.evidence_links,
            "attack_surface": self.attack_surface,
            "scoring_trace": self.scoring_trace,
            "attack_paths": self.attack_paths,
        }
