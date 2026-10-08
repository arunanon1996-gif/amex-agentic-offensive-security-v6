from agent.orchestrator import AgentOrchestrator


def main():
    print()
    print("======================================")
    print(" GENERIC AGENT LOOP TEST")
    print("======================================")

    orchestrator = AgentOrchestrator()

    state = orchestrator.start_assessment(
        target="localhost",
        objective=(
            "Identify exposed services and "
            "security-relevant HTTP applications."
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

    # ---------------------------------------------------------
    # Assessment completion
    # ---------------------------------------------------------

    assert final_state.status == "COMPLETED"

    # ---------------------------------------------------------
    # Expected agent workflow:
    #
    # 1. Nmap
    # 2. HTTP Probe
    # 3. CORS Validation
    # 4. CSRF Validation
    # ---------------------------------------------------------

    assert final_state.action_count == 4

    assert final_state.actions_taken == [
        "nmap",
        "http_probe",
        "cors_validate",
        "csrf_validate",
    ]

    # ---------------------------------------------------------
    # Observations
    # ---------------------------------------------------------

    assert len(final_state.observations) == 4

    assert final_state.observations[0].source == "nmap"

    assert final_state.observations[1].source == "http_probe"

    assert (
        final_state.observations[2].source
        == "cors_validate"
    )

    assert (
        final_state.observations[3].source
        == "csrf_validate"
    )

    # ---------------------------------------------------------
    # Hypotheses
    # ---------------------------------------------------------

    assert len(final_state.hypotheses) >= 1

    assert (
        final_state.hypotheses[0].statement
        == "An HTTP application may be running on port 3000."
    )

    # ---------------------------------------------------------
    # Decisions
    # ---------------------------------------------------------

    assert len(final_state.decisions) == 4

    # Decision 1: Nmap
    assert (
        final_state.decisions[0].action
        == "nmap"
    )

    assert (
        final_state.decisions[0].parameters
        == {"ports": [3000]}
    )

    # Decision 2: HTTP Probe
    assert (
        final_state.decisions[1].action
        == "http_probe"
    )

    assert (
        final_state.decisions[1].parameters
        == {"port": 3000}
    )

    # Decision 3: CORS Validation
    assert (
        final_state.decisions[2].action
        == "cors_validate"
    )

    assert (
        final_state.decisions[2].parameters
        == {
            "port": 3000,
            "origin": "https://attacker.example",
        }
    )

    # Decision 4: CSRF Validation
    assert (
        final_state.decisions[3].action
        == "csrf_validate"
    )

    assert (
        final_state.decisions[3].parameters
        == {
            "port": 3000,
            "path": "/",
            "method": "POST",
            "body": "test=value",
            "content_type": (
                "application/x-www-form-urlencoded"
            ),
            "origin": "https://attacker.example",
        }
    )

    # ---------------------------------------------------------
    # CORS validation result
    # ---------------------------------------------------------

    cors_result = final_state.observations[2].data

    assert cors_result["status_code"] == 200

    assert (
        cors_result["access_control_allow_origin"]
        == "*"
    )

    assert cors_result["wildcard_detected"] is True

    assert cors_result["confirmed"] is True

    assert cors_result["error"] is None

    # ---------------------------------------------------------
    # CSRF validation result
    # ---------------------------------------------------------

    csrf_result = final_state.observations[3].data

    assert csrf_result["status_code"] == 200

    assert (
        csrf_result["cross_origin_request_accepted"]
        is True
    )

    assert csrf_result["csrf_token_present"] is False

    assert csrf_result["confirmed"] is True

    assert csrf_result["error"] is None

    # ---------------------------------------------------------
    # Test completed successfully
    # ---------------------------------------------------------

    print()
    print("Generic agent loop test PASSED.")


if __name__ == "__main__":
    main()