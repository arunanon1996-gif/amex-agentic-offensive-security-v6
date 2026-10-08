from agent.agent_state import AgentState
from agent.decision_engine import DecisionEngine


def test_decision_engine_does_not_repeat_executed_action():
    state = AgentState(
        assessment_id="test-no-repeat",
        target="localhost",
        objective="Test controlled offensive security workflow",
    )

    state.add_observation(
        source="nmap",
        data={
            "ports": [
                {
                    "port": 3000,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "http",
                    "version": None,
                }
            ]
        },
    )
    state.add_action("nmap")

    state.add_observation(
        source="http_probe",
        data={
            "url": "http://localhost:3000/",
            "status_code": 200,
            "headers": {
                "Access-Control-Allow-Origin": "*",
            },
            "body_preview": "<html><script></script></html>",
        },
    )
    state.add_action("http_probe")

    engine = DecisionEngine()

    decision = engine.decide_next_action(state)

    assert decision is not None
    assert decision["action"] == "initial_web_scan"

    state.add_action("initial_web_scan")

    next_decision = engine.decide_next_action(state)

    assert (
        next_decision is None
        or next_decision["action"] != "initial_web_scan"
    )


if __name__ == "__main__":
    test_decision_engine_does_not_repeat_executed_action()
    print("Decision engine no-repeat test PASSED.")