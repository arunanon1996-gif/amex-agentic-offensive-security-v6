import unittest

from tools.idor_analyzer import IdorAnalyzer


class IdorAnalyzerTests(unittest.TestCase):
    def test_authenticated_object_identifier_creates_signal(self):
        result = IdorAnalyzer().analyze(
            "localhost",
            {
                "authenticated": True,
                "resource_url": (
                    "http://localhost:3000/rest/basket/7"
                ),
                "object_identifier": "7",
            },
        )

        self.assertEqual(len(result.signals), 1)
        signal = result.signals[0]
        self.assertEqual(signal.category, "IDOR")
        self.assertEqual(
            signal.name,
            "authenticated_object_identifier",
        )
        self.assertEqual(signal.value, "basket/7")

    def test_unauthenticated_resource_does_not_create_idor_signal(self):
        result = IdorAnalyzer().analyze(
            "localhost",
            {
                "authenticated": False,
                "resource_url": (
                    "http://localhost:3000/rest/basket/7"
                ),
                "object_identifier": "7",
            },
        )

        self.assertEqual(result.signals, [])

    def test_non_identifier_path_does_not_create_signal(self):
        result = IdorAnalyzer().analyze(
            "localhost",
            {
                "authenticated": True,
                "resource_url": (
                    "http://localhost:3000/rest/basket/current"
                ),
            },
        )

        self.assertEqual(result.signals, [])


if __name__ == "__main__":
    unittest.main()
