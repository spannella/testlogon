import unittest
from unittest.mock import patch

from app.auth import deps


class TestCognitoJwksCache(unittest.TestCase):
    def setUp(self):
        self.original_cache = deps._JWKS_CACHE
        self.original_fetched = deps._JWKS_FETCHED_AT
        self.original_ttl = deps.S.cognito_jwks_ttl_seconds

    def tearDown(self):
        deps._JWKS_CACHE = self.original_cache
        deps._JWKS_FETCHED_AT = self.original_fetched
        object.__setattr__(deps.S, "cognito_jwks_ttl_seconds", self.original_ttl)

    def test_jwks_refreshes_when_stale(self):
        object.__setattr__(deps.S, "cognito_jwks_ttl_seconds", 10)
        deps._JWKS_CACHE = {"keys": [{"kid": "old"}]}
        deps._JWKS_FETCHED_AT = 0
        with patch.object(deps, "_fetch_cognito_jwks", return_value=({"keys": [{"kid": "new"}]}, 20)) as fetch, \
             patch.object(deps.time, "time", return_value=20):
            keys = deps._cognito_jwks()
            self.assertEqual(keys["keys"][0]["kid"], "new")
            fetch.assert_called_once()

    def test_resolve_key_forces_refresh_on_miss(self):
        object.__setattr__(deps.S, "cognito_jwks_ttl_seconds", 3600)
        deps._JWKS_CACHE = {"keys": [{"kid": "old"}]}
        deps._JWKS_FETCHED_AT = 0
        with patch.object(deps, "_fetch_cognito_jwks", return_value=({"keys": [{"kid": "new"}]}, 5)) as fetch, \
             patch.object(deps.time, "time", return_value=5):
            key = deps._resolve_cognito_key("new")
            self.assertEqual(key["kid"], "new")
            fetch.assert_called_once()
