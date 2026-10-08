import unittest
from unittest.mock import patch

from tools.idor_validator import IdorValidator
from tools.session_store import SESSION_STORE


class FakeResponse:
    def __init__(self, status, body):
        self.status = status
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, _size):
        return self._body.encode()


class IdorValidatorTests(unittest.TestCase):
    def setUp(self):
        SESSION_STORE.clear()
        self.session = SESSION_STORE.create(
            token="test-token",
            username="tester@example.com",
        )

    def test_alternate_object_access_is_confirmed(self):
        responses = [
            FakeResponse(200, '{"id":1,"owner":"A"}'),
            FakeResponse(200, '{"id":2,"owner":"B"}'),
        ]

        with patch(
            "tools.idor_validator.urlopen",
            side_effect=responses,
        ):
            result = IdorValidator().validate(
                target="localhost",
                port=3000,
                session_id=self.session.session_id,
                path_template="/rest/basket/{object_id}",
                object_identifier="1",
                alternate_object_identifier="2",
            )

        self.assertEqual(result.status, "CONFIRMED")
        self.assertTrue(result.alternate_object_accessible)
        self.assertTrue(result.response_different)

    def test_alternate_object_denied_is_rejected(self):
        responses = [
            FakeResponse(200, '{"id":1}'),
            FakeResponse(403, '{"error":"forbidden"}'),
        ]

        with patch(
            "tools.idor_validator.urlopen",
            side_effect=responses,
        ):
            result = IdorValidator().validate(
                target="localhost",
                port=3000,
                session_id=self.session.session_id,
                path_template="/rest/basket/{object_id}",
                object_identifier="1",
                alternate_object_identifier="2",
            )

        self.assertEqual(result.status, "REJECTED")

    def test_missing_session_is_inconclusive(self):
        result = IdorValidator().validate(
            target="localhost",
            port=3000,
            session_id="missing",
            path_template="/rest/basket/{object_id}",
            object_identifier="1",
            alternate_object_identifier="2",
        )
        self.assertEqual(result.status, "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()
