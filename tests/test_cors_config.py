import os
import unittest
from unittest.mock import patch

from app.main import _build_cors_options


class TestCorsConfig(unittest.TestCase):
    def test_wildcard_is_converted_to_regex_for_credentials_requests(self):
        with patch.dict(os.environ, {"CORS_ALLOW_ORIGINS": "*"}, clear=False):
            options = _build_cors_options()

        self.assertEqual(options["allow_origins"], [])
        self.assertEqual(options["allow_origin_regex"], ".*")
        self.assertTrue(options["allow_credentials"])

    def test_explicit_origin_list_is_preserved(self):
        with patch.dict(
            os.environ,
            {
                "CORS_ALLOW_ORIGINS": "http://18.222.237.167:5173,http://localhost:5173",
                "CORS_ALLOW_CREDENTIALS": "true",
            },
            clear=False,
        ):
            options = _build_cors_options()

        self.assertEqual(
            options["allow_origins"],
            ["http://18.222.237.167:5173", "http://localhost:5173"],
        )
        self.assertIsNone(options["allow_origin_regex"])
        self.assertTrue(options["allow_credentials"])


if __name__ == "__main__":
    unittest.main()
