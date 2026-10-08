import unittest

from agent.orchestrator import AgentOrchestrator


class OrchestratorAgenticFlowTests(unittest.TestCase):
    def test_full_evidence_guided_flow(self):
        orchestrator = AgentOrchestrator()

        state = orchestrator.start_assessment(
            target="localhost",
            objective="Test complete evidence-guided POC flow",
        )

        def fake_execute(
            assessment_id,
            target,
            tool,
            action_count,
            _runtime_context=None,
            **kwargs,
        ):
            results = {
                "nmap": {
                    "target": target,
                    "ports": [
                        {
                            "port": 3000,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "http",
                        }
                    ],
                },
                "http_probe": {
                    "url": "http://localhost:3000/",
                    "status_code": 200,
                    "headers": {
                        "Access-Control-Allow-Origin": "*",
                        "X-Frame-Options": "SAMEORIGIN",
                    },
                    "body_preview": "<html></html>",
                },
                "initial_web_scan": {
                    "base_url": "http://localhost:3000",
                    "status_code": 200,
                    "discovered_urls": ["http://localhost:3000/"],
                    "endpoints": [],
                    "technologies": ["OWASP Juice Shop"],
                    "security_signals": [{"category":"cors","name":"Access-Control-Allow-Origin","value":"*","rationale":"Wildcard CORS"}],
                    "xss_candidates": [],
                    "sqli_candidates": [],
                    "forms": [],
                    "error": None,
                },
                "cors_validate": {
                    "status_code": 200,
                    "access_control_allow_origin": "*",
                    "access_control_allow_credentials": None,
                    "origin_reflected": False,
                    "wildcard_detected": True,
                    "confirmed": True,
                    "error": None,
                },
                "csrf_validate": {
                    "status_code": 200,
                    "cross_origin_request_accepted": True,
                    "csrf_token_present": False,
                    "same_site_cookie_present": False,
                    "access_control_allow_origin": "*",
                    "access_control_allow_credentials": None,
                    "confirmed": True,
                    "state_change_confirmed": False,
                    "error": None,
                },
                "authenticated_resource_probe": {
                    "authenticated": True,
                    "username": "tester@example.com",
                    "user_id": "1",
                    "session_id": "test-session",
                    "resource_url": (
                        "http://localhost:3000/rest/basket/1"
                    ),
                    "status_code": 200,
                    "object_identifier": "1",
                    "object_identifier_name": "basket",
                    "resource_type": "basket",
                    "response_preview": '{"id":1}',
                    "error": None,
                },
                "security_header_validate": {
                    "url": "http://localhost:3000/",
                    "status_code": 200,
                    "headers": {"Access-Control-Allow-Origin": "*", "X-Frame-Options": "SAMEORIGIN"},
                    "missing_headers": ["Content-Security-Policy", "Strict-Transport-Security", "Referrer-Policy", "Permissions-Policy"],
                    "present_headers": ["X-Frame-Options"],
                    "csp_present": False,
                    "confirmed": True,
                    "conclusion": "One or more recommended security headers are absent.",
                    "error": None,
                },
                "auth_bruteforce_validate": {
                    "login_url": "http://localhost:3000/rest/user/login", "attempts": 4, "interval_seconds": 0.15,
                    "status_codes": [401,401,401,401], "response_lengths": [120,120,120,120],
                    "rate_limited": False, "account_lockout_observed": False, "response_consistency": True,
                    "credential_enumeration_signal": False, "confirmed": True,
                    "conclusion": "No rate limiting or lockout signal was observed during the bounded invalid-login test.", "error": None,
                },
                "jwt_validate": {
                    "session_id": "test-session", "token_present": True, "algorithm": "HS256", "token_type": "JWT",
                    "claims": {"sub":"1"}, "has_exp": False, "expired": None, "has_issuer": False, "has_audience": False,
                    "sensitive_claims": [], "confirmed": True, "conclusion": "JWT has no expiration claim.", "error": None,
                },
                "idor_validate": {
                    "status": "CONFIRMED",
                    "url": (
                        "http://localhost:3000/rest/basket/2"
                    ),
                    "baseline_url": (
                        "http://localhost:3000/rest/basket/1"
                    ),
                    "alternate_url": (
                        "http://localhost:3000/rest/basket/2"
                    ),
                    "method": "GET",
                    "baseline_status_code": 200,
                    "alternate_status_code": 200,
                    "object_identifier": "1",
                    "alternate_object_identifier": "2",
                    "alternate_object_accessible": True,
                    "response_different": True,
                    "evidence_summary": "Alternate object accessible.",
                    "error": None,
                },
            }

            return {
                "status": "COMPLETED",
                "result": results[tool],
                "evidence": [],
            }

        orchestrator.assessment_service.execute = fake_execute

        final_state = orchestrator.run_assessment(
            state,
            initial_parameters={"ports": [3000]},
        )

        self.assertEqual(final_state.status, "WAITING_FOR_AUTH")
        self.assertEqual(final_state.actions_taken[0:3], ["nmap", "http_probe", "initial_web_scan"])
        final_state.runtime_context.update({
            "username": "tester@example.com",
            "password": "not-persisted",
            "resource_template": "/rest/basket/{object_id}",
            "login_path": "/rest/user/login",
        })
        final_state.phase = "AUTHENTICATED"
        final_state.status = "RUNNING"
        final_state = orchestrator.run_assessment(final_state, phase="AUTHENTICATED")

        self.assertEqual(final_state.status, "COMPLETED")
        self.assertIn("cors_validate", final_state.actions_taken)
        self.assertIn("authenticated_resource_probe", final_state.actions_taken)
        self.assertIn("idor_validate", final_state.actions_taken)
        self.assertTrue(any(a in final_state.actions_taken for a in ["jwt_validate", "auth_bruteforce_validate"]))
        self.assertIn("security_header_validate", final_state.actions_taken)
        self.assertTrue(
            any(
                finding["category"] == "IDOR/BOLA"
                and finding["status"] == "CONFIRMED"
                for finding in final_state.findings
            )
        )


if __name__ == "__main__":
    unittest.main()
