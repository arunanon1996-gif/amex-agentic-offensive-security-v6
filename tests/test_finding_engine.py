import unittest

from agent.finding_engine import FindingEngine


class FindingEngineTests(unittest.TestCase):
    def test_confirmed_idor_finding(self):
        findings = FindingEngine().from_observation(
            "idor_validate",
            {
                "status": "CONFIRMED",
                "baseline_url": "http://localhost:3000/rest/basket/1",
                "alternate_url": "http://localhost:3000/rest/basket/2",
                "baseline_status_code": 200,
                "alternate_status_code": 200,
                "alternate_object_accessible": True,
                "response_different": True,
                "evidence_summary": "Alternate object was accessible.",
            },
        )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["category"], "IDOR/BOLA")
        self.assertEqual(findings[0]["status"], "CONFIRMED")
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_csrf_behavior_is_not_called_exploitable_by_default(self):
        findings = FindingEngine().from_observation(
            "csrf_validate",
            {
                "status_code": 200,
                "cross_origin_request_accepted": True,
                "csrf_token_present": False,
                "state_change_confirmed": False,
            },
        )

        self.assertEqual(findings[0]["status"], "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
