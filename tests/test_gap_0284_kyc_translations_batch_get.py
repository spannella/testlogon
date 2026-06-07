"""Offline regression test for GAP-0284 (KYC-020).

``KycTranslationService._bulk_fetch`` previously fetched each translation key
with an individual ``GetItem`` call inside a ``for`` loop (the N+1 pattern). A
30-question questionnaire localization issued up to 60 serial DynamoDB reads.
The fix replaces the loop with ``BatchGetItem`` (chunked at 100 keys per call,
re-queuing any ``UnprocessedKeys``).

This test is fully offline and hermetic:
  * A real in-memory DynamoDB ``kyc_translations`` table is created with moto.
  * The exact ``T.kyc_translations`` handle used by the service is monkeypatched
    via ``object.__setattr__`` (``Tables`` is a frozen dataclass), and restored
    afterward — so no @mock_aws interception leaks to real AWS.
  * The boto3 client's ``batch_get_item`` is wrapped with a spy to prove the
    batch path is used and is chunked at 100.

FAILS BEFORE FIX: the old loop never calls ``batch_get_item`` → the spy asserts
fail. PASSES AFTER FIX: a single (or chunked) ``batch_get_item`` returns every
seeded value.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover - moto optional
    mock_aws = None


def _make_kyc_translations_table(ddb):
    """Mirror the kyc_translations schema: PK=language_code (S), SK=key (S)."""
    return ddb.create_table(
        TableName="kyc_translations",
        KeySchema=[
            {"AttributeName": "language_code", "KeyType": "HASH"},
            {"AttributeName": "key", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "language_code", "AttributeType": "S"},
            {"AttributeName": "key", "AttributeType": "S"},
            {"AttributeName": "status", "AttributeType": "S"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "status-language-index",
                "KeySchema": [
                    {"AttributeName": "status", "KeyType": "HASH"},
                    {"AttributeName": "language_code", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            },
        ],
        BillingMode="PAY_PER_REQUEST",
    )


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestBulkFetchBatchGetGap0284(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock_aws())
        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.table = _make_kyc_translations_table(ddb)

        from app.core.tables import T
        from app.services.kyc_translations import KycTranslationService

        self.T = T
        self.svc = KycTranslationService()

        # Patch the exact frozen-dataclass handle the service reads (module-level
        # ``T.kyc_translations``); restore the original on cleanup.
        original = T.kyc_translations
        object.__setattr__(T, "kyc_translations", self.table)
        self.addCleanup(lambda: object.__setattr__(T, "kyc_translations", original))

    def _seed(self, language: str, key: str, value: str, status: str = "published"):
        self.table.put_item(
            Item={
                "language_code": language,
                "key": key,
                "value": value,
                "status": status,
            }
        )

    def test_bulk_fetch_uses_batch_get_and_returns_all_over_100(self):
        """>100 seeded keys are all returned via chunked batch_get_item.

        FAILS BEFORE FIX: the old N+1 loop never calls batch_get_item (and calls
        get_item once per key); both spy assertions fail.
        PASSES AFTER FIX: batch_get_item is used, chunked at 100 (2 calls for 130
        keys), get_item is not used, and every value is returned.
        """
        n = 130
        keys = [f"kyc.question.label.q{i:04d}" for i in range(n)]
        for i, k in enumerate(keys):
            self._seed("es", k, f"valor-{i:04d}")

        client = self.table.meta.client
        with patch.object(
            client, "batch_get_item", wraps=client.batch_get_item
        ) as batch_spy, patch.object(
            self.svc, "_get_item", wraps=self.svc._get_item
        ) as get_spy:
            result = self.svc._bulk_fetch(language="es", keys=keys)

        # Every seeded value returned, return shape identical (key -> str value).
        self.assertEqual(len(result), n)
        for i, k in enumerate(keys):
            self.assertEqual(result[k], f"valor-{i:04d}")

        # Batch path used and chunked at 100: ceil(130/100) == 2 calls.
        batch_spy.assert_called()
        self.assertEqual(batch_spy.call_count, 2)
        # No individual GetItem fallback when the batch path succeeds.
        get_spy.assert_not_called()

    def test_bulk_fetch_single_chunk_under_100(self):
        """A small key set is fetched in a single batch_get_item call."""
        keys = [f"kyc.k.{i}" for i in range(5)]
        for i, k in enumerate(keys):
            self._seed("fr", k, f"v{i}")

        client = self.table.meta.client
        with patch.object(
            client, "batch_get_item", wraps=client.batch_get_item
        ) as batch_spy:
            result = self.svc._bulk_fetch(language="fr", keys=keys)

        self.assertEqual(result, {f"kyc.k.{i}": f"v{i}" for i in range(5)})
        batch_spy.assert_called_once()

    def test_bulk_fetch_empty_keys_returns_empty(self):
        result = self.svc._bulk_fetch(language="en", keys=[])
        self.assertEqual(result, {})

    def test_bulk_fetch_missing_keys_omitted(self):
        """Keys with no item are simply absent from the result (unchanged shape)."""
        self._seed("de", "kyc.present", "Da")
        result = self.svc._bulk_fetch(
            language="de", keys=["kyc.present", "kyc.absent"]
        )
        self.assertEqual(result, {"kyc.present": "Da"})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
