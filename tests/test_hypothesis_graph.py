from agent.agent_state import AgentState
from agent.analysis_engine import AnalysisEngine
from agent.evidence_correlator import EvidenceCorrelator
from tools.http_adapter import HttpAdapter


def main():

    print()
    print("======================================")
    print(" HYPOTHESIS GRAPH TEST")
    print("======================================")

    # --------------------------------------------------
    # 1. Collect real HTTP evidence
    # --------------------------------------------------

    http = HttpAdapter()

    result = http.probe(
        target="localhost",
        port=3000,
    )

    # --------------------------------------------------
    # 2. Analyze HTTP evidence
    # --------------------------------------------------

    analysis_engine = AnalysisEngine()

    signals = analysis_engine.analyze_http(
        target="localhost",
        http_result={
            "url": result.url,
            "status_code": result.status_code,
            "headers": result.headers,
            "body_preview": result.body_preview,
        },
    )

    # --------------------------------------------------
    # 3. Display discovered security signals
    # --------------------------------------------------

    print()
    print("Signals discovered:")

    for signal in signals:
        print(
            f"- {signal.name}: "
            f"{signal.value}"
        )

    # --------------------------------------------------
    # 4. Normalize SecuritySignal objects
    #    into dictionaries for AgentState
    # --------------------------------------------------

    signal_dicts = [
        {
            "category": signal.category,
            "name": signal.name,
            "value": signal.value,
            "severity_hint": signal.severity_hint,
            "confidence": signal.confidence,
            "source": signal.source,
            "rationale": signal.rationale,
        }
        for signal in signals
    ]

    # --------------------------------------------------
    # 5. Create agent state
    # --------------------------------------------------

    state = AgentState(
        assessment_id="hypothesis-test-001",
        target="localhost",
        objective=(
            "Evaluate security-relevant "
            "HTTP evidence."
        ),
    )

    # --------------------------------------------------
    # 6. Store HTTP analysis as an observation
    # --------------------------------------------------

    state.add_observation(
        source="http_analysis",
        data={
            "url": result.url,
            "status_code": result.status_code,
        },
        signals=signal_dicts,
    )

    # --------------------------------------------------
    # 7. Correlate evidence into hypotheses
    # --------------------------------------------------

    correlator = EvidenceCorrelator()

    graph = correlator.correlate(
        state.observations
    )

    # --------------------------------------------------
    # 8. Display hypotheses
    # --------------------------------------------------

    print()
    print("Hypotheses:")

    for hypothesis in graph.get_candidates():

        print()

        print(
            "ID:",
            hypothesis.hypothesis_id,
        )

        print(
            "Statement:",
            hypothesis.statement,
        )

        print(
            "Category:",
            hypothesis.category,
        )

        print(
            "Confidence:",
            hypothesis.confidence,
        )

        print(
            "Candidate actions:",
            hypothesis.candidate_actions,
        )

    # --------------------------------------------------
    # 9. Validate that hypotheses were generated
    # --------------------------------------------------

    assert len(
        graph.get_candidates()
    ) > 0

    print()
    print("Hypothesis graph test PASSED.")


if __name__ == "__main__":
    main()