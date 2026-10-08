from agent.orchestrator import AgentOrchestrator


def main():

    orchestrator = AgentOrchestrator()

    state = orchestrator.start_assessment(
        target="localhost",
        objective="Identify security-relevant services",
    )

    state = orchestrator.run_initial_discovery(
        state=state,
        ports=[3000],
    )

    print()
    print("======================================")
    print(" FIRST AGENT ORCHESTRATOR TEST")
    print("======================================")

    print(state.summary())


if __name__ == "__main__":
    main()