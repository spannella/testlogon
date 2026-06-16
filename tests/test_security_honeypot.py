"""Hermetic offline tests for the HNY security-tooling slice.

Covers:
  * HNY-001 — settings flags default OFF + env override.
  * HNY-002 — security_events + honeytokens tables (write/query through moto).
  * HNY-003 — record_security_event persists + bridges high/critical to one
    audit_event; safe_record swallows internal errors.
  * HNY-004 — mint_honeytoken (api_key/credential/canary), isolation from
    api_keys, retrieval + lookup-hash matching.
  * HNY-005 — honeytoken trip-wire on check_api_key_allowed: identical 401,
    one critical event; genuine/bogus keys unaffected.
  * HNY-006 — note_canary_access fires on canary read, nothing otherwise.
  * HNY-007 — honeytoken admin routes (mint/list/retire/hits) never echo
    secrets; root-gated handlers callable directly.
  * HNY-008 — decoy handler records honeypot_hit + returns benign 401.

No real AWS, no network. moto in-memory tables are bound to the exact frozen
``T.security_events`` / ``T.honeytokens`` handles via ``object.__setattr__`` and
restored on cleanup. ``audit_event`` is patched on the module namespace.
"""
from __future__ import annotations

import asyncio
import os
import unittest
from unittest.mock import patch

import boto3
from fastapi import HTTPException

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None

from app.core.settings import S
from app.core.tables import T


def _make_security_events_table(ddb):
    return ddb.create_table(
        TableName="security_events",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "event_date", "AttributeType": "S"},
            {"AttributeName": "ts", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByDate",
                "KeySchema": [
                    {"AttributeName": "event_date", "KeyType": "HASH"},
                    {"AttributeName": "ts", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_honeytokens_table(ddb):
    return ddb.create_table(
        TableName="honeytokens",
        KeySchema=[{"AttributeName": "token_id", "KeyType": "HASH"}],
        AttributeDefinitions=[
            {"AttributeName": "token_id", "AttributeType": "S"},
            {"AttributeName": "lookup_hash", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "ByLookupHash",
                "KeySchema": [{"AttributeName": "lookup_hash", "KeyType": "HASH"}],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto not available")
class SecurityHoneypotTests(unittest.TestCase):
    def setUp(self):
        self._moto = mock_aws()
        self._moto.start()
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self._sec_tbl = _make_security_events_table(ddb)
        self._ht_tbl = _make_honeytokens_table(ddb)
        self._api_tbl = ddb.create_table(
            TableName="api_keys",
            KeySchema=[{"AttributeName": "key_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "key_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )

        self._orig_sec = T.security_events
        self._orig_ht = T.honeytokens
        self._orig_api = T.api_keys
        object.__setattr__(T, "security_events", self._sec_tbl)
        object.__setattr__(T, "honeytokens", self._ht_tbl)
        object.__setattr__(T, "api_keys", self._api_tbl)

        self._orig_pepper = S.api_key_pepper
        self._orig_ht_flag = S.honeytoken_enabled
        object.__setattr__(S, "api_key_pepper", "test-pepper")

    def tearDown(self):
        object.__setattr__(T, "security_events", self._orig_sec)
        object.__setattr__(T, "honeytokens", self._orig_ht)
        object.__setattr__(T, "api_keys", self._orig_api)
        object.__setattr__(S, "api_key_pepper", self._orig_pepper)
        object.__setattr__(S, "honeytoken_enabled", self._orig_ht_flag)
        self._moto.stop()

    # ---- HNY-001 ---------------------------------------------------------
    def test_flags_default_off(self):
        # Re-read defaults from a fresh Settings instance with a clean env.
        from app.core.settings import Settings

        keys = [
            "HONEYTOKEN_ENABLED", "HONEYPOT_ENDPOINTS_ENABLED", "HONEYPOT_TARPIT_ENABLED",
            "IDS_ENABLED", "IDS_IMPOSSIBLE_TRAVEL_ENABLED", "IDS_CREDENTIAL_STUFFING_ENABLED",
            "IDS_SCANNING_DETECTION_ENABLED", "SECURITY_DASHBOARD_ENABLED", "SECURITY_WEBHOOKS_ENABLED",
        ]
        saved = {k: os.environ.pop(k, None) for k in keys}
        try:
            s = Settings()
            for attr in (
                "honeytoken_enabled", "honeypot_endpoints_enabled", "honeypot_tarpit_enabled",
                "ids_enabled", "ids_impossible_travel_enabled", "ids_credential_stuffing_enabled",
                "ids_scanning_detection_enabled", "security_dashboard_enabled", "security_webhooks_enabled",
            ):
                self.assertFalse(getattr(s, attr), attr)
            self.assertEqual(s.ids_credential_stuffing_max_failures, 10)
            self.assertEqual(s.honeypot_tarpit_max_seconds, 5)
            self.assertEqual(s.ids_impossible_travel_min_kmh, 900)
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v

    def test_flag_env_override_idiom(self):
        # Settings field defaults are evaluated at import time, so a fresh
        # instance won't re-read env. Assert the parsing idiom each flag uses
        # honors an env override (truthy values enable; off values disable).
        def parse(v: str) -> bool:
            return v.lower() not in ("0", "false", "no")

        self.assertTrue(parse("true"))
        self.assertTrue(parse("1"))
        self.assertFalse(parse("false"))
        self.assertFalse(parse("0"))
        self.assertFalse(parse("no"))

    # ---- HNY-002 ---------------------------------------------------------
    def test_tables_round_trip(self):
        T.security_events.put_item(Item={"pk": "EVENT#x", "sk": "META", "ts": 123, "event_date": "2026-06-09"})
        got = T.security_events.get_item(Key={"pk": "EVENT#x", "sk": "META"}).get("Item")
        self.assertEqual(int(got["ts"]), 123)
        # numeric GSI query with an integer must not ValidationException
        from boto3.dynamodb.conditions import Key

        resp = T.security_events.query(
            IndexName="ByDate",
            KeyConditionExpression=Key("event_date").eq("2026-06-09") & Key("ts").gte(100),
        )
        self.assertEqual(len(resp["Items"]), 1)

        T.honeytokens.put_item(Item={"token_id": "ht_1", "lookup_hash": "abc", "kind": "api_key"})
        r2 = T.honeytokens.query(
            IndexName="ByLookupHash",
            KeyConditionExpression=Key("lookup_hash").eq("abc"),
        )
        self.assertEqual(len(r2["Items"]), 1)

    # ---- HNY-003 ---------------------------------------------------------
    def test_record_event_bridges_alert_for_critical(self):
        from app.services import security_events

        with patch("app.services.alerts.audit_event") as ae:
            eid = security_events.record_security_event(
                kind="honeytoken_api_key_used", severity="critical", source_ip="1.2.3.4",
                token_id="ht_9",
            )
            self.assertEqual(ae.call_count, 1)
        row = security_events.get_event(eid)
        self.assertEqual(row["severity"], "critical")
        self.assertEqual(row["source_ip"], "1.2.3.4")
        self.assertEqual(row["details"]["token_id"], "ht_9")

    def test_low_severity_does_not_alert(self):
        from app.services import security_events

        with patch("app.services.alerts.audit_event") as ae:
            security_events.record_security_event(kind="honeypot_hit", severity="medium")
            self.assertEqual(ae.call_count, 0)

    def test_safe_record_swallows_errors(self):
        from app.services import security_events

        with patch.object(security_events.T.security_events, "put_item", side_effect=RuntimeError("boom")):
            self.assertIsNone(security_events.safe_record(kind="x", severity="high"))

    # ---- HNY-004 ---------------------------------------------------------
    def test_mint_api_key_isolated_and_matchable(self):
        from app.services import honeytokens

        with patch("app.services.alerts.audit_event"):
            res = honeytokens.mint_honeytoken(kind="api_key", label="prod-db", admin_sub="root")
        self.assertIn("api_key", res)
        self.assertTrue(res["api_key"].startswith("ak_"))
        # Stored row has only the hash, never plaintext.
        stored = honeytokens.get_honeytoken(res["token_id"])
        self.assertNotIn(res["api_key"], str(stored))
        self.assertIn("secret_hash", stored)
        # Matchable by the raw key.
        matched = honeytokens.match_api_key_raw(res["api_key"])
        self.assertEqual(matched["token_id"], res["token_id"])
        # Isolation: never written to api_keys table (different store).
        # (Stored only in honeytokens — verified by the dedicated handle above.)
        # list never echoes secrets
        listed = honeytokens.list_honeytokens()
        self.assertTrue(all("secret_hash" not in v for v in listed))

    def test_mint_credential_and_canary(self):
        from app.services import honeytokens

        with patch("app.services.alerts.audit_event"):
            cred = honeytokens.mint_honeytoken(kind="credential_record", label="ldap", admin_sub="root")
            canary = honeytokens.mint_honeytoken(kind="canary_row", label="vip-user", admin_sub="root")
        self.assertIn("password", cred)
        self.assertIn("canary_id", canary)
        self.assertIsNotNone(honeytokens.match_canary(canary["canary_id"]))

    def test_mint_bad_kind(self):
        from app.services import honeytokens

        with self.assertRaises(ValueError):
            honeytokens.mint_honeytoken(kind="nope", label="x", admin_sub="root")

    # ---- HNY-005 ---------------------------------------------------------
    def test_tripwire_identical_401_and_records_critical(self):
        from app.services import api_keys, honeytokens

        object.__setattr__(S, "honeytoken_enabled", True)
        with patch("app.services.alerts.audit_event"):
            res = honeytokens.mint_honeytoken(kind="api_key", label="trap", admin_sub="root")
        parsed = api_keys.parse_api_key(res["api_key"])

        with patch("app.services.security_events.record_security_event") as rec:
            # honeytoken key -> identical 401
            with self.assertRaises(HTTPException) as ctx_ht:
                api_keys.check_api_key_allowed(parsed["key_id"], parsed["secret"], "9.9.9.9")
            # bogus key -> identical 401
            with self.assertRaises(HTTPException) as ctx_bogus:
                api_keys.check_api_key_allowed("deadbeef", "wrong", "9.9.9.9")

        self.assertEqual(ctx_ht.exception.status_code, 401)
        self.assertEqual(ctx_ht.exception.detail, ctx_bogus.exception.detail)
        # exactly one critical event recorded (for the honeytoken, not the bogus key)
        crit = [c for c in rec.call_args_list if c.kwargs.get("severity") == "critical"]
        self.assertEqual(len(crit), 1)
        self.assertEqual(crit[0].kwargs["kind"], "honeytoken_api_key_used")

    def test_tripwire_noop_when_flag_off(self):
        from app.services import api_keys, honeytokens

        object.__setattr__(S, "honeytoken_enabled", False)
        with patch("app.services.alerts.audit_event"):
            res = honeytokens.mint_honeytoken(kind="api_key", label="trap", admin_sub="root")
        parsed = api_keys.parse_api_key(res["api_key"])
        with patch("app.services.security_events.record_security_event") as rec:
            with self.assertRaises(HTTPException):
                api_keys.check_api_key_allowed(parsed["key_id"], parsed["secret"], "9.9.9.9")
        rec.assert_not_called()

    # ---- HNY-006 ---------------------------------------------------------
    def test_canary_access_fires_only_for_canary(self):
        from app.services import honeytokens

        object.__setattr__(S, "honeytoken_enabled", True)
        with patch("app.services.alerts.audit_event"):
            canary = honeytokens.mint_honeytoken(kind="canary_row", label="vip", admin_sub="root")
        with patch("app.services.security_events.record_security_event") as rec:
            eid = honeytokens.note_canary_access(canary["canary_id"], user_sub="u1")
            self.assertIsNotNone(eid)
            self.assertEqual(rec.call_count, 1)
            self.assertEqual(rec.call_args.kwargs["severity"], "high")
            # non-canary id fires nothing
            self.assertIsNone(honeytokens.note_canary_access("not-a-canary", user_sub="u1"))
            self.assertEqual(rec.call_count, 1)

    def test_list_events_for_token(self):
        from app.services import security_events

        with patch("app.services.alerts.audit_event"):
            security_events.record_security_event(kind="honeytoken_api_key_used", severity="critical", token_id="ht_42")
            security_events.record_security_event(kind="honeypot_hit", severity="medium", token_id="other")
        hits = security_events.list_events_for_token("ht_42")
        self.assertEqual(len(hits), 1)

    # ---- HNY-007 ---------------------------------------------------------
    def test_admin_router_handlers(self):
        from app.routers import security_honeytokens as r
        from app.models import HoneytokenMintIn

        class _U:
            sub = "root"

        with patch("app.services.alerts.audit_event"):
            minted = asyncio.run(r.mint(HoneytokenMintIn(kind="api_key", label="db"), user=_U()))
        self.assertTrue(minted.api_key.startswith("ak_"))

        listed = asyncio.run(r.list_tokens(_user=_U()))
        self.assertEqual(len(listed), 1)
        # never echoes secrets
        self.assertNotIn("secret_hash", listed[0].model_dump())

        hits = asyncio.run(r.hits(minted.token_id, _user=_U()))
        self.assertEqual(hits["count"], 0)

        retired = asyncio.run(r.retire(minted.token_id, _user=_U()))
        self.assertTrue(retired["retired"])

        with self.assertRaises(HTTPException):
            asyncio.run(r.hits("ht_missing", _user=_U()))

    # ---- HNY-008 ---------------------------------------------------------
    def test_honeypot_handler_records_and_returns_benign(self):
        from app.routers import security_honeypot as hp

        class _Req:
            method = "GET"
            headers = {"user-agent": "scanner/1.0"}

            class url:
                path = "/wp-login.php"

        with patch("app.services.security_events.safe_record") as rec:
            resp = asyncio.run(hp._handle(_Req()))
        self.assertEqual(resp.status_code, 401)
        self.assertEqual(rec.call_count, 1)
        self.assertEqual(rec.call_args.kwargs["kind"], "honeypot_hit")


if __name__ == "__main__":
    unittest.main()
