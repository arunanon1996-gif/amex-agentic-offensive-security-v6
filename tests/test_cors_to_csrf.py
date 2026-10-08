from agent.orchestrator import AgentOrchestrator


def main():

    print()
    print("======================================")
    print(" CORS → CSRF AGENT FLOW TEST")
    print("======================================")

    orchestrator = AgentOrchestrator()

    state = orchestrator.start_assessment(
        target="localhost",
        objective=(
            "Demonstrate evidence-driven transition "
            "from CORS validation to CSRF validation."
        ),
    )

    final_state = orchestrator.run_assessment(
        state=state,
        initial_parameters={
            "ports": [3000],
        },
    )

    print()
    print("Final state:")
    print(final_state.summary())

    assert final_state.status == "COMPLETED"

    assert final_state.actions_taken == [
        "nmap",
        "http_probe",
        "cors_validate",
        "csrf_validate",
    ]

    assert final_state.action_count == 4

    assert len(final_state.observations) == 4

    assert (
        final_state.observations[0].source
        == "nmap"
    )

    assert (
        final_state.observations[1].source
        == "http_probe"
    )

    assert (
        final_state.observations[2].source
        == "cors_validate"
    )

    assert (
        final_state.observations[3].source
        == "csrf_validate"
    )

    csrf_result = final_state.observations[3].data

    assert csrf_result["status_code"] == 200

    assert (
        csrf_result["cross_origin_request_accepted"]
        is True
    )

    assert (
        csrf_result["csrf_token_present"]
        is False
    )

    assert (
        csrf_result["access_control_allow_origin"]
        == "*"
    )

    assert csrf_result["confirmed"] is True

    csrf_hypotheses = [
        hypothesis
        for hypothesis in final_state.hypotheses
        if "CSRF" in hypothesis.statement
        or "cross-origin" in hypothesis.statement
    ]

    assert len(csrf_hypotheses) >= 1

    csrf_decisions = [
        decision.action
        for decision in final_state.decisions
        if decision.action == "csrf_validate"
    ]

    assert csrf_decisions == [
        "csrf_validate",
    ]

    print()
    print("CORS → CSRF agent flow test PASSED.")


if __name__ == "__main__":
    main()