from dataclasses import dataclass, field


@dataclass
class AssessmentPolicy:
    allowed_targets: set[str] = field(
        default_factory=lambda: {
            "localhost",
            "127.0.0.1",
        }
    )

    allowed_tools: set[str] = field(
        default_factory=lambda: {
            "nmap",
            "http_probe",
            "cors_validate",
            "csrf_validate",
            "authenticated_resource_probe",
            "idor_validate",
            "security_header_validate",
            "initial_web_scan",
            "xss_validate",
            "sqli_validate",
            "sqli_login_validate",
            "dom_xss_validate",
            "auth_bruteforce_validate",
            "jwt_validate",
            "tls_validate",
        }
    )

    max_actions: int = 20
    max_runtime_seconds: int = 600


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str


class PolicyEngine:

    def __init__(self, policy: AssessmentPolicy | None = None):
        self.policy = policy or AssessmentPolicy()

    def check_target(self, target: str) -> PolicyDecision:

        if target in self.policy.allowed_targets:
            return PolicyDecision(
                allowed=True,
                reason="Target is within approved scope.",
            )

        return PolicyDecision(
            allowed=False,
            reason=f"Target '{target}' is outside the approved scope.",
        )

    def check_tool(self, tool: str) -> PolicyDecision:

        if tool in self.policy.allowed_tools:
            return PolicyDecision(
                allowed=True,
                reason="Tool is approved.",
            )

        return PolicyDecision(
            allowed=False,
            reason=f"Tool '{tool}' is not approved.",
        )

    def check_action_budget(self, action_count: int) -> PolicyDecision:

        if action_count < self.policy.max_actions:
            return PolicyDecision(
                allowed=True,
                reason="Action is within the configured budget.",
            )

        return PolicyDecision(
            allowed=False,
            reason="Maximum action budget exceeded.",
        )

    def authorize(
        self,
        target: str,
        tool: str,
        action_count: int,
    ) -> PolicyDecision:

        target_decision = self.check_target(target)

        if not target_decision.allowed:
            return target_decision

        tool_decision = self.check_tool(tool)

        if not tool_decision.allowed:
            return tool_decision

        budget_decision = self.check_action_budget(action_count)

        if not budget_decision.allowed:
            return budget_decision

        return PolicyDecision(
            allowed=True,
            reason="Action approved by policy.",
        )