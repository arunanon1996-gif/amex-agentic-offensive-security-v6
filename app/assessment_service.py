from dataclasses import asdict, is_dataclass

from evidence.evidence_store import EvidenceStore
from policy.policy_engine import PolicyEngine
from tools.register_tools import build_tool_registry


class AssessmentService:
    """Central policy and execution boundary."""

    SECRET_KEYS = {
        "password",
        "token",
        "authorization",
        "api_key",
        "secret",
    }

    def __init__(self):
        self.policy = PolicyEngine()
        self.evidence = EvidenceStore()
        self.tools = build_tool_registry()

    def execute(
        self,
        assessment_id: str,
        target: str,
        tool: str,
        action_count: int,
        **kwargs,
    ) -> dict:
        runtime_context = kwargs.pop(
            "_runtime_context",
            {},
        )

        if not self.tools.has(tool):
            self.evidence.add(
                assessment_id=assessment_id,
                evidence_type="execution_error",
                source="assessment_service",
                data={
                    "tool": tool,
                    "reason": "Requested tool is not registered.",
                },
            )
            return {
                "status": "FAILED",
                "reason": f"Tool '{tool}' is not registered.",
                "evidence": self.evidence.get_all(
                    assessment_id
                ),
            }

        decision = self.policy.authorize(
            target=target,
            tool=tool,
            action_count=action_count,
        )

        self.evidence.add(
            assessment_id=assessment_id,
            evidence_type="policy_decision",
            source="policy_engine",
            data={
                "allowed": decision.allowed,
                "reason": decision.reason,
                "target": target,
                "tool": tool,
                "action_count": action_count,
            },
        )

        if not decision.allowed:
            return {
                "status": "DENIED",
                "reason": decision.reason,
                "evidence": self.evidence.get_all(
                    assessment_id
                ),
            }

        tool_kwargs = dict(kwargs)

        # Credentials are injected only at the execution boundary and are
        # never included in the action/decision evidence records.
        if tool == "authenticated_resource_probe":
            tool_kwargs["username"] = runtime_context.get(
                "username"
            )
            tool_kwargs["password"] = runtime_context.get(
                "password"
            )

            if not tool_kwargs["username"] or not tool_kwargs["password"]:
                return {
                    "status": "FAILED",
                    "reason": (
                        "Authenticated resource probe requires an "
                        "operator-supplied test account."
                    ),
                    "evidence": self.evidence.get_all(
                        assessment_id
                    ),
                }

        if tool == "auth_bruteforce_validate":
            tool_kwargs["username"] = runtime_context.get("username")
            if not tool_kwargs["username"]:
                return {"status": "FAILED", "reason": "Authentication resilience validation requires the approved test username.", "evidence": self.evidence.get_all(assessment_id)}
        if tool == "jwt_validate":
            tool_kwargs["session_id"] = runtime_context.get("session_id")
            if not tool_kwargs["session_id"]:
                return {"status": "FAILED", "reason": "JWT validation requires an approved authenticated session.", "evidence": self.evidence.get_all(assessment_id)}

        self.evidence.add(
            assessment_id=assessment_id,
            evidence_type="action",
            source="assessment_service",
            data={
                "tool": tool,
                "target": target,
                "parameters": self._redact(kwargs),
                "reason": (
                    "Agent selected an approved registered security tool."
                ),
            },
        )

        try:
            result = self.tools.execute(
                tool,
                target=target,
                **tool_kwargs,
            )
        except Exception as exc:
            self.evidence.add(
                assessment_id=assessment_id,
                evidence_type="execution_error",
                source="assessment_service",
                data={
                    "tool": tool,
                    "error": str(exc),
                },
            )
            return {
                "status": "FAILED",
                "reason": str(exc),
                "evidence": self.evidence.get_all(
                    assessment_id
                ),
            }

        result_data = self._to_dict(result)

        self.evidence.add(
            assessment_id=assessment_id,
            evidence_type="tool_result",
            source=tool,
            data=self._redact(result_data),
        )

        return {
            "status": "COMPLETED",
            "result": result_data,
            "evidence": self.evidence.get_all(
                assessment_id
            ),
        }

    @classmethod
    def _redact(cls, value):
        if isinstance(value, dict):
            return {
                key: (
                    "***REDACTED***"
                    if key.lower() in cls.SECRET_KEYS
                    else cls._redact(item)
                )
                for key, item in value.items()
            }

        if isinstance(value, list):
            return [cls._redact(item) for item in value]

        return value

    @staticmethod
    def _to_dict(result):
        if is_dataclass(result):
            return asdict(result)

        return result
