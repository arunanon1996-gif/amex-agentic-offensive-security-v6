import unittest

from agent.agent_state import AgentState
from agent.decision_engine import DecisionEngine


class DecisionEngineIdorTests(unittest.TestCase):
    def test_idor_is_selected_only_after_authenticated_resource_evidence(self):
        state = AgentState(
            assessment_id="idor-decision-001",
            target="localhost",
            objective="Test IDOR decision logic",
        )
        state.runtime_context = {
            "username": "test@example.com",
            "password": "test-password",
            "resource_template": "/rest/basket/{object_id}",
        }

        state.add_observation(
            "nmap",
            {
                "ports": [
                    {
                        "port": 3000,
                        "state": "open",
                    }
                ]
            },
        )
        state.add_action("nmap")

        state.add_observation(
            "http_probe",
            {
                "url": "http://localhost:3000/",
                "status_code": 200,
                "headers": {},
                "body_preview": "<html></html>",
            },
        )
        state.add_action("http_probe")

        # The unauthenticated baseline must run before authenticated object testing.
        decision = DecisionEngine().decide_next_action(state)
        self.assertEqual(decision["action"], "initial_web_scan")
        state.add_action("initial_web_scan")
        state.add_observation("initial_web_scan", {"xss_candidates": [], "sqli_candidates": [], "security_signals": [], "endpoints": []})

        state.add_observation(
            "authenticated_resource_probe",
            {
                "authenticated": True,
                "session_id": "session-1",
                "resource_url": (
                    "http://localhost:3000/rest/basket/1"
                ),
                "object_identifier": "1",
                "status_code": 200,
            },
        )
        state.add_action("authenticated_resource_probe")

        decision = DecisionEngine().decide_next_action(state)
        self.assertEqual(
            decision["action"],
            "idor_validate",
        )
        self.assertEqual(
            decision["parameters"]["object_identifier"],
            "1",
        )


if __name__ == "__main__":
    unittest.main()
