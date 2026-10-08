import time
import uuid

from agent.agent_state import AgentState
from agent.decision_engine import DecisionEngine
from app.assessment_service import AssessmentService
from evidence.evidence_store import EvidenceStore
from agent.finding_engine import FindingEngine
from agent.attack_surface import AttackSurfaceModel


class AgentOrchestrator:

    def __init__(self):
        self.assessment_service = AssessmentService()
        self.decision_engine = DecisionEngine()
        self.evidence = EvidenceStore()
        self.finding_engine = FindingEngine()
        self.attack_surface_model = AttackSurfaceModel()

    # ======================================================
    # START ASSESSMENT
    # ======================================================

    def start_assessment(
        self,
        target: str,
        objective: str,
    ) -> AgentState:

        assessment_id = str(uuid.uuid4())

        state = AgentState(
            assessment_id=assessment_id,
            target=target,
            objective=objective,
        )

        state.status = "RUNNING"
        state._orchestrator = self

        self.evidence.add(
            assessment_id=assessment_id,
            evidence_type="assessment_started",
            source="orchestrator",
            data={
                "target": target,
                "objective": objective,
                "status": state.status,
            },
        )

        return state

    # ======================================================
    # GENERIC AGENT LOOP
    # ======================================================

    def run_assessment(
        self,
        state: AgentState,
        initial_parameters: dict | None = None,
        phase: str | None = None,
    ) -> AgentState:

        start_time = time.monotonic()

        policy = self.assessment_service.policy.policy

        first_iteration = True
        if initial_parameters:
            state.runtime_context.update(dict(initial_parameters))
        if phase:
            state.phase = phase

        while True:

            # --------------------------------------------------
            # Runtime safety boundary
            # --------------------------------------------------

            elapsed = time.monotonic() - start_time

            if elapsed >= policy.max_runtime_seconds:

                state.status = "BLOCKED"

                self.evidence.add(
                    assessment_id=state.assessment_id,
                    evidence_type="assessment_timeout",
                    source="orchestrator",
                    data={
                        "max_runtime_seconds":
                            policy.max_runtime_seconds,
                        "elapsed_seconds":
                            elapsed,
                    },
                )

                break

            # --------------------------------------------------
            # Action budget safety boundary
            # --------------------------------------------------

            if state.action_count >= policy.max_actions:

                state.status = "BLOCKED"

                self.evidence.add(
                    assessment_id=state.assessment_id,
                    evidence_type="action_budget_exceeded",
                    source="orchestrator",
                    data={
                        "action_count":
                            state.action_count,
                        "max_actions":
                            policy.max_actions,
                    },
                )

                break

            # --------------------------------------------------
            # AGENT REASONING
            # --------------------------------------------------

            context = None

            if first_iteration:
                context = initial_parameters or {}

            decision = self.decide(
                state,
                context=context,
            )

            first_iteration = False

            # --------------------------------------------------
            # Explicit phase terminal decision
            # --------------------------------------------------

            if decision is None:
                if state.phase == "UNAUTHENTICATED" and state.action_count > 0:
                    decision = {
                        "action": "PHASE_COMPLETE",
                        "reason": "Unauthenticated baseline and all currently supported public-surface validations are complete. Approved credentials can unlock the authenticated assessment phase.",
                        "expected_evidence": "Unauthenticated assessment summary",
                        "parameters": {},
                        "score": 0.0,
                        "score_breakdown": {},
                    }
                else:
                    decision = {
                        "action": "STOP",
                        "reason": "No additional relevant security validation is supported by the current evidence.",
                        "expected_evidence": "Assessment completion",
                        "parameters": {},
                        "score": 0.0,
                        "score_breakdown": {},
                    }

            state.add_decision(
                action=decision["action"],
                reason=decision.get("reason", ""),
                expected_evidence=decision.get("expected_evidence", ""),
                parameters=decision.get("parameters", {}),
                score=decision.get("score"),
                hypothesis_id=decision.get("hypothesis_id"),
                score_breakdown=decision.get("score_breakdown", {}),
            )
            self.evidence.add_reasoning(
                assessment_id=state.assessment_id,
                reasoning_type="decision",
                data=decision,
            )
            if decision.get("hypothesis_id"):
                state.add_evidence_link(
                    "hypothesis_drives_action",
                    decision.get("hypothesis_id"),
                    decision.get("action"),
                    decision.get("reason", "Evidence-backed hypothesis selected this action."),
                )

            if decision["action"] == "PHASE_COMPLETE":
                state.status = "WAITING_FOR_AUTH"
                self.evidence.add_reasoning(assessment_id=state.assessment_id, reasoning_type="phase_complete", data={"phase": state.phase, "reason": decision["reason"], "action_count": state.action_count})
                break

            if decision["action"] == "STOP":
                state.status = "COMPLETED"
                self.evidence.add_reasoning(
                    assessment_id=state.assessment_id,
                    reasoning_type="agent_stop",
                    data={"reason": decision["reason"], "action_count": state.action_count},
                )
                break

            # --------------------------------------------------
            # Execute through centralized security boundary
            # --------------------------------------------------

            action = decision["action"]

            parameters = decision.get(
                "parameters",
                {},
            )

            state.status = "EXECUTING"

            result = self.assessment_service.execute(
                assessment_id=state.assessment_id,
                target=state.target,
                tool=action,
                action_count=state.action_count,
                _runtime_context=state.runtime_context,
                **parameters,
            )

            # --------------------------------------------------
            # Handle denied / failed execution
            # --------------------------------------------------

            if result["status"] != "COMPLETED":

                if result["status"] == "DENIED":
                    state.status = "BLOCKED"
                else:
                    state.status = "FAILED"

                self.evidence.add(
                    assessment_id=state.assessment_id,
                    evidence_type="assessment_stopped",
                    source="orchestrator",
                    data={
                        "status":
                            result["status"],
                        "reason":
                            result.get("reason"),
                        "action":
                            action,
                    },
                )

                break

            # --------------------------------------------------
            # Convert tool output into agent observation
            # --------------------------------------------------

            tool_result = result["result"]

            state.add_observation(
                source=action,
                data=tool_result,
            )
            if action == "authenticated_resource_probe" and tool_result.get("session_id"):
                state.runtime_context["session_id"] = tool_result.get("session_id")
            observation_id = f"observation:{len(state.observations)}"
            state.add_evidence_link("action_produced_evidence", action, observation_id, "Tool execution produced new observable evidence.")
            if action == "initial_web_scan":
                for item in tool_result.get("xss_candidates", []):
                    state.add_evidence_link("baseline_candidate", observation_id, f"candidate:XSS:{item.get('parameter')}", "Unauthenticated scanner found reflected input requiring targeted XSS validation.")
                for item in tool_result.get("sqli_candidates", []):
                    state.add_evidence_link("baseline_candidate", observation_id, f"candidate:SQLi:{item.get('parameter')}", "Unauthenticated scanner observed a database/parser error requiring targeted SQLi validation.")
                for item in tool_result.get("login_candidates", []):
                    state.add_evidence_link("baseline_candidate", observation_id, "candidate:SQLi:login", "Unauthenticated baseline discovered the login surface and created a hypothesis for controlled login SQLi validation.")
                for item in tool_result.get("dom_xss_candidates", []):
                    state.add_evidence_link("baseline_candidate", observation_id, "candidate:XSS:DOM", "Unauthenticated baseline identified a browser-controlled source and unsafe HTML sink in a served JavaScript bundle.")

            for finding in self.finding_engine.from_observation(
                action,
                tool_result,
            ):
                state.add_finding(finding)
                state.add_evidence_link("evidence_validates_finding", f"observation:{len(state.observations)}", finding["finding_id"], finding["title"])
                self.evidence.add_reasoning(
                    assessment_id=state.assessment_id,
                    reasoning_type="finding",
                    data=finding,
                )

            # --------------------------------------------------
            # Record action
            # --------------------------------------------------

            state.add_action(action)
            state.attack_surface = self.attack_surface_model.build(state)
            state.attack_paths = state.attack_surface.get("attack_paths", [])

            state.status = "RUNNING"

        # ======================================================
        # COMPLETE / FINALIZE
        # ======================================================

        state.attack_surface = self.attack_surface_model.build(state)
        state.attack_paths = state.attack_surface.get("attack_paths", [])
        if state.status == "RUNNING":
            state.status = "COMPLETED"

        self.evidence.add(
            assessment_id=state.assessment_id,
            evidence_type="assessment_completed" if state.status == "COMPLETED" else "phase_completed",
            source="orchestrator",
            data={
                "status":
                    state.status,
                "action_count":
                    state.action_count,
                "actions_taken":
                    state.actions_taken,
                "elapsed_seconds":
                    time.monotonic() - start_time,
            },
        )

        return state

    # ======================================================
    # DECISION
    # ======================================================

    def decide(
        self,
        state: AgentState,
        context: dict | None = None,
    ):

        decision = self.decision_engine.decide_next_action(
            state,
            context=context,
        )

        # --------------------------------------------------
        # No further action
        # --------------------------------------------------

        if decision is None:
            # STOP/COMPLETED is a deliberate terminal decision handled by
            # run_assessment(). Do not persist a second completion event here.
            return None

        # --------------------------------------------------
        # Persist newly created hypotheses
        # --------------------------------------------------

        existing_evidence = self.evidence.get_all(
            state.assessment_id
        )

        for hypothesis in state.hypotheses:

            hypothesis_already_saved = any(
                item["evidence_type"] == "hypothesis"
                and item["data"].get("statement")
                == hypothesis.statement
                for item in existing_evidence
            )

            if not hypothesis_already_saved:

                self.evidence.add_reasoning(
                    assessment_id=state.assessment_id,
                    reasoning_type="hypothesis",
                    data={
                        "statement":
                            hypothesis.statement,
                        "confidence":
                            hypothesis.confidence,
                        "supporting_observations":
                            hypothesis.supporting_observations,
                    },
                )

        # Decision persistence belongs to run_assessment(), which also
        # preserves score and hypothesis_id. Keeping this method side-effect
        # free for decisions prevents duplicate timeline entries.
        state.status = "WAITING_FOR_ACTION"

        return decision

    # ======================================================
    # BACKWARD-COMPATIBILITY WRAPPER
    # ======================================================

    def run_initial_discovery(
        self,
        state: AgentState,
        ports: list[int],
    ) -> AgentState:

        return self.run_assessment(
            state=state,
            initial_parameters={
                "ports": ports,
            },
        )