from agent.action_scorer import CandidateActionScorer
from agent.hypothesis_graph import HypothesisGraph


def main():
    print()
    print("=" * 38)
    print(" CANDIDATE ACTION SCORER TEST")
    print("=" * 38)

    graph = HypothesisGraph()

    graph.add(
        hypothesis_id="missing-csp",
        statement=(
            "The application lacks a Content Security Policy "
            "and may have reduced browser-side injection defenses."
        ),
        category="XSS",
        confidence=0.65,
        supporting_signals=[
            "Content Security Policy header is missing."
        ],
        candidate_actions=[
            "xss_validate"
        ],
    )

    graph.add(
        hypothesis_id="missing-hsts",
        statement=(
            "The application does not advertise HSTS "
            "and may have weaker transport protection."
        ),
        category="TLS",
        confidence=0.60,
        supporting_signals=[
            "Strict-Transport-Security header is missing."
        ],
        candidate_actions=[
            "tls_validate"
        ],
    )

    graph.add(
        hypothesis_id="cors-wildcard",
        statement=(
            "The application permits wildcard cross-origin access "
            "and may expose cross-origin security-sensitive behavior."
        ),
        category="CORS",
        confidence=0.80,
        supporting_signals=[
            "Access-Control-Allow-Origin: *"
        ],
        candidate_actions=[
            "cors_validate"
        ],
    )

    scorer = CandidateActionScorer()

    ranked = scorer.rank(graph.get_candidates())

    print()
    print("Ranked candidate actions:")
    print()

    for index, action in enumerate(ranked, start=1):
        print(
            f"{index}. {action.action}"
            f" | score={action.score}"
            f" | hypothesis={action.hypothesis_id}"
        )
        print(f"   {action.reason}")

    assert ranked
    assert ranked[0].action == "cors_validate"

    print()
    print("Top action selected: cors_validate")
    print()
    print("Candidate action scorer test PASSED.")


if __name__ == "__main__":
    main()