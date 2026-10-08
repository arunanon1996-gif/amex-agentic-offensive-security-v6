import unittest

from app.assessment_service import AssessmentService


class SecretRedactionTests(unittest.TestCase):
    def test_nested_secret_values_are_redacted(self):
        value = {
            "username": "tester@example.com",
            "password": "secret",
            "nested": {
                "token": "jwt",
                "safe": "value",
            },
        }

        redacted = AssessmentService._redact(value)

        self.assertEqual(redacted["username"], "tester@example.com")
        self.assertEqual(redacted["password"], "***REDACTED***")
        self.assertEqual(
            redacted["nested"]["token"],
            "***REDACTED***",
        )
        self.assertEqual(redacted["nested"]["safe"], "value")


if __name__ == "__main__":
    unittest.main()
