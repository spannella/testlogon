"""GAP-0076 regression: budget bypass via record_usage status-flip race.

Offline test — no real AWS. Uses:
  * moto's in-memory DynamoDB so ``ConditionExpression`` semantics are
    enforced exactly as on real DynamoDB (the bug fix relies on a conditional
    ``update_item`` winning exactly once).
  * a mock-KMS shim (``kms_encrypt``/``kms_decrypt`` monkeypatched on the
    service module) so ``add_key`` does not touch AWS KMS.

The bug: ``record_usage`` did an atomic ``ADD`` to the usage counter, then a
*separate* ``get_item`` + unconditional ``update_item`` to flip
``status -> budget_exceeded``. Concurrent callers could each read
``status == "active"`` after the budget was already crossed and let further LLM
requests through — bypassing the cap.

The fix: the status-flip ``update_item`` carries
``ConditionExpression="#st = :active"`` so exactly one concurrent caller wins
the transition; the rest catch ``ConditionalCheckFailedException`` and skip.
Plus ``get_decrypted_api_key`` refuses to hand out a non-active key
(defense-in-depth).

Fails-before / passes-after:
  * Before the fix the final status was deterministically flipped (idempotent
    overwrite) BUT a second flip from an ``active`` baseline would silently
    succeed again — and, more importantly, the
    ``test_status_flip_is_conditional`` test below directly asserts the
    ConditionExpression behaviour, which the pre-fix code lacks.
"""
from __future__ import annotations

import threading
import unittest
from contextlib import ExitStack
from types import SimpleNamespace
from unittest.mock import patch

import boto3

try:  # pragma: no cover - import guard
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None

from app.services import llm_provider_keys as svc

TABLE_NAME = "llm_provider_keys_test"


def _create_table():
    ddb = boto3.resource("dynamodb", region_name="us-east-1")
    ddb.create_table(
        TableName=TABLE_NAME,
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
        ],
        BillingMode="PAY_PER_REQUEST",
    )
    return ddb.Table(TABLE_NAME)


@unittest.skipIf(mock_aws is None, "moto is not installed")
class TestGap0076BudgetRace(unittest.TestCase):
    def setUp(self):
        self.user_id = "u1"
        self.key_id = "k1"
        self.stack = ExitStack()
        self.stack.enter_context(mock_aws())
        self.table = _create_table()

        # Point the service's table handle at the moto table.
        self.stack.enter_context(
            patch.object(svc, "T", SimpleNamespace(llm_provider_keys=self.table))
        )

        # Mock-KMS: deterministic, reversible, no AWS. The service imports the
        # crypto helpers by name, so patch them on the service module.
        self.stack.enter_context(
            patch.object(svc, "kms_encrypt", lambda pt: "ENC::" + pt)
        )
        self.stack.enter_context(
            patch.object(svc, "kms_decrypt", lambda ct: ct[len("ENC::"):].encode("utf-8"))
        )

    def tearDown(self):
        self.stack.close()

    def _add_key(self, budget_cents: int):
        return svc.add_key(
            user_id=self.user_id,
            provider="openai",
            label="test",
            api_key="sk-test1234",
            monthly_budget_cents=budget_cents,
        )

    def _status(self) -> str:
        item = self.table.get_item(
            Key={"pk": f"USER#{self.user_id}", "sk": f"KEY#{self._key_id}"}
        )["Item"]
        return item["status"]

    # ------------------------------------------------------------------
    # Core race test
    # ------------------------------------------------------------------
    def test_concurrent_record_usage_marks_exceeded_and_blocks_use(self):
        """5 concurrent callers each spend 30c against a 100c budget (total 150c).

        After the fix the status must end up ``budget_exceeded`` exactly, the
        counter must be exactly 150 (every ADD committed), and the key must no
        longer be usable (``get_decrypted_api_key`` raises).
        """
        created = self._add_key(budget_cents=100)
        self._key_id = created["key_id"]

        errors: list[Exception] = []
        barrier = threading.Barrier(5)

        def spend():
            try:
                barrier.wait()  # release all threads at once to force the race
                svc.record_usage(
                    self.user_id, self._key_id, tokens=100, cost_cents=30
                )
            except Exception as exc:  # pragma: no cover - surfaced via assert
                errors.append(exc)

        threads = [threading.Thread(target=spend) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], f"record_usage raised: {errors}")

        item = self.table.get_item(
            Key={"pk": f"USER#{self.user_id}", "sk": f"KEY#{self._key_id}"}
        )["Item"]
        self.assertEqual(int(item["current_month_usage_cents"]), 150)
        self.assertEqual(item["status"], "budget_exceeded")

        # Defense-in-depth: the key can no longer be provisioned to a worker.
        with self.assertRaises(ValueError):
            svc.get_decrypted_api_key(self.user_id, self._key_id)

    # ------------------------------------------------------------------
    # Direct atomicity assertion: the status flip must be conditional.
    #
    # This is the deterministic fails-before / passes-after test. It forces the
    # exact TOCTOU window the bug describes: two callers each read a *stale*
    # ``status == "active"`` snapshot (because the get_item happens before
    # either has flipped the status), then both attempt the SET. Pre-fix both
    # SETs succeed unconditionally; post-fix only the first wins and the second
    # hits ConditionalCheckFailedException (swallowed). We detect the bug by
    # counting how many SET-to-budget_exceeded writes actually land on DDB.
    # ------------------------------------------------------------------
    def test_status_flip_is_conditional(self):
        created = self._add_key(budget_cents=100)
        self._key_id = created["key_id"]

        # Force every record_usage's budget-check read to observe the stale
        # "active" snapshot — recreating two concurrent callers both seeing
        # the key as still-active right after the budget was crossed.
        stale_item = {
            "pk": f"USER#{self.user_id}",
            "sk": f"KEY#{self._key_id}",
            "monthly_budget_cents": 100,
            "current_month_usage_cents": 200,  # already over budget
            "status": "active",                # the STALE read
        }

        real_update = self.table.update_item
        flip_writes = {"count": 0}

        def counting_update(*args, **kwargs):
            # Count only status-flip writes that actually COMMIT. Post-fix the
            # conditional second write raises ConditionalCheckFailedException
            # (counted via the real call raising), so it is NOT counted.
            is_flip = kwargs.get("UpdateExpression") == "SET #st = :exceeded"
            result = real_update(*args, **kwargs)  # raises if condition fails
            if is_flip:
                flip_writes["count"] += 1
            return result

        original_get = self.table.get_item

        def stale_get(*args, **kwargs):
            # The ADD step still uses update_item; only the budget-check
            # get_item returns the stale active snapshot.
            return {"Item": dict(stale_item)}

        with patch.object(self.table, "get_item", side_effect=stale_get), patch.object(
            self.table, "update_item", side_effect=counting_update
        ):
            # Two "concurrent" callers, each with the stale active read.
            svc.record_usage(self.user_id, self._key_id, tokens=10, cost_cents=30)
            svc.record_usage(self.user_id, self._key_id, tokens=10, cost_cents=30)

        # Post-fix: exactly ONE flip write lands (the conditional guard rejects
        # the second). Pre-fix: BOTH unconditional writes land -> count == 2.
        self.assertEqual(
            flip_writes["count"],
            1,
            "expected exactly one budget_exceeded status flip to commit; "
            f"got {flip_writes['count']} — ConditionExpression missing "
            "(GAP-0076 regression)",
        )
        # Restore the real get_item before reading final status.
        self.table.get_item = original_get
        self.assertEqual(self._status(), "budget_exceeded")

    def test_under_budget_stays_active(self):
        created = self._add_key(budget_cents=1000)
        self._key_id = created["key_id"]
        svc.record_usage(self.user_id, self._key_id, tokens=5, cost_cents=10)
        self.assertEqual(self._status(), "active")
        # Still usable.
        self.assertEqual(
            svc.get_decrypted_api_key(self.user_id, self._key_id), "sk-test1234"
        )


if __name__ == "__main__":
    unittest.main()
