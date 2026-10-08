from agent.agent_state import AgentState


def main():
    state = AgentState(
        assessment_id="demo-001",
        target="localhost",
        objective="Identify security-relevant services",
    )

    state.add_observation(
        source="nmap",
        data={
            "port": 3000,
            "protocol": "tcp",
            "state": "open",
        },
    )

    state.add_hypothesis(
        statement="An HTTP application may be running on port 3000.",
        confidence=0.90,
        supporting_observations=[
            "Nmap identified an open TCP port 3000."
        ],
    )

    state.add_decision(
        action="http_probe",
        reason=(
            "Port 3000 is open and may expose a web application."
        ),
        expected_evidence=(
            "HTTP status, headers, server information, "
            "and application metadata."
        ),
    )

    state.add_action("nmap")

    print()
    print("======================================")
    print(" AGENT STATE TEST")
    print("======================================")

    print(state.summary())


if __name__ == "__main__":
    main()