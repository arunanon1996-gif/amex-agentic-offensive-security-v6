from agent.agent_state import AgentState
from agent.decision_engine import DecisionEngine


def main():
    print()
    print("=" * 45)
    print(" DECISION ENGINE SCORING INTEGRATION TEST")
    print("=" * 45)

    state = AgentState(
        assessment_id="decision-demo-001",
        target="localhost",
        objective="Identify and validate relevant security hypotheses",
    )

    engine = DecisionEngine()

    # ---------------------------------------------------------
    # Step 1: Agent should initially select Nmap
    # ---------------------------------------------------------
    decision = engine.decide_next_action(
        state,
        context={
            "ports": [3000],
        },
    )

    print()
    print("Step 1:")
    print(f"Action: {decision['action']}")
    print(f"Reason: {decision['reason']}")

    assert decision["action"] == "nmap"

    # Simulate Nmap evidence.
    state.add_observation(
        source="nmap",
        data={
            "target": "localhost",
            "ports": [
                {
                    "port": 3000,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ppp?",
                    "version": None,
                }
            ],
        },
    )

    state.add_action("nmap")

    # ---------------------------------------------------------
    # Step 2: Agent should select HTTP probe
    # ---------------------------------------------------------
    decision = engine.decide_next_action(state)

    print()
    print("Step 2:")
    print(f"Action: {decision['action']}")
    print(f"Reason: {decision['reason']}")

    assert decision["action"] == "http_probe"

    # Simulate HTTP evidence from Juice Shop.
    state.add_observation(
        source="http_probe",
        data={
            "url": "http://localhost:3000/",
            "status_code": 200,
            "headers": {
                "Access-Control-Allow-Origin": "*",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "SAMEORIGIN",
            },
            "body_preview": (
                "<html>"
                "<script src='main.js'></script>"
                "</html>"
            ),
        },
    )

    state.add_action("http_probe")

    # ---------------------------------------------------------
    # Step 3: Agent should perform the unauthenticated baseline before targeted validation
    # ---------------------------------------------------------
    decision = engine.decide_next_action(state)

    print()
    print("Step 3:")
    print(f"Action: {decision['action']}")
    print(f"Reason: {decision['reason']}")
    print(
        f"Expected evidence: "
        f"{decision['expected_evidence']}"
    )

    assert decision["action"] == "initial_web_scan"

    print()
    print("Agent decision successfully driven by evidence.")
    print()
    print("Decision engine scoring integration test PASSED.")


if __name__ == "__main__":
    main()