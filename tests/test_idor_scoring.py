import unittest

from agent.action_scorer import CandidateActionScorer
from agent.hypothesis_graph import HypothesisGraph


class IdorScoringTests(unittest.TestCase):
    def test_idor_is_ranked_from_idor_hypothesis(self):
        graph = HypothesisGraph()
        graph.add(
            hypothesis_id="idor-object-authorization",
            statement="Object authorization may be missing.",
            category="IDOR",
            confidence=0.92,
            supporting_signals=[
                "Authenticated resource URL contains object ID."
            ],
            candidate_actions=["idor_validate"],
        )

        ranked = CandidateActionScorer().rank(
            graph.get_candidates()
        )

        self.assertEqual(ranked[0].action, "idor_validate")
        self.assertGreater(ranked[0].score, 0.70)

    def test_csrf_has_generic_scoring_profile(self):
        graph = HypothesisGraph()
        graph.add(
            hypothesis_id="csrf",
            statement="Cross-origin state change may lack protection.",
            category="CSRF",
            confidence=0.85,
            supporting_signals=["CORS validation"],
            candidate_actions=["csrf_validate"],
        )

        ranked = CandidateActionScorer().rank(
            graph.get_candidates()
        )

        self.assertEqual(ranked[0].action, "csrf_validate")


if __name__ == "__main__":
    unittest.main()
