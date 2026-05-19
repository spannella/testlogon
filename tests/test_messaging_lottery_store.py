from __future__ import annotations

import pytest
import threading

from app.services import messaging_lottery_store as store


class _FakeTable:
    def __init__(self) -> None:
        self.items = {}
        self.last_condition = None
        self._lock = threading.Lock()

    def put_item(self, *, Item, ConditionExpression=None):
        with self._lock:
            self.last_condition = ConditionExpression
            key = tuple(Item.get(k) for k in ("message_id", "recipient_id") if k in Item)
            if len(key) == 1:
                key = key[0]
            if key in self.items:
                raise store.ClientError(
                    {"Error": {"Code": "ConditionalCheckFailedException", "Message": "duplicate"}},
                    "PutItem",
                )
            self.items[key] = dict(Item)

    def get_item(self, *, Key):
        with self._lock:
            key = tuple(Key.get(k) for k in ("message_id", "recipient_id") if k in Key)
            if len(key) == 1:
                key = key[0]
            item = self.items.get(key)
            return {"Item": dict(item)} if item else {}


def test_put_lottery_config_enforces_weight_total() -> None:
    table = _FakeTable()
    try:
        store.put_lottery_config(
            message_id="m1",
            conversation_id="c1",
            sender_id="u1",
            lottery_config={
                "version": "v1",
                "outcomes": [
                    {"outcome_id": "o1", "weight_bps": 7000, "payload_type": "text", "text_content": "A"},
                    {"outcome_id": "o2", "weight_bps": 2999, "payload_type": "text", "text_content": "B"},
                ],
            },
            created_at=123,
            table=table,
        )
        assert False, "expected LotteryConfigValidationError"
    except store.LotteryConfigValidationError:
        pass


def test_put_lottery_config_rejects_outcome_count_out_of_range() -> None:
    table = _FakeTable()
    with pytest.raises(store.LotteryConfigValidationError) as exc:
        store.put_lottery_config(
            message_id="m1",
            conversation_id="c1",
            sender_id="u1",
            lottery_config={
                "version": "v1",
                "outcomes": [
                    {"outcome_id": "o1", "weight_bps": 10_000, "payload_type": "text", "text_content": "A"},
                ],
            },
            created_at=123,
            table=table,
        )
    assert exc.value.issues[0]["field"] == "lottery_config.outcomes"


def test_put_lottery_config_rejects_unsupported_payload_type() -> None:
    table = _FakeTable()
    with pytest.raises(store.LotteryConfigValidationError) as exc:
        store.put_lottery_config(
            message_id="m1",
            conversation_id="c1",
            sender_id="u1",
            lottery_config={
                "version": "v1",
                "outcomes": [
                    {"outcome_id": "o1", "weight_bps": 5000, "payload_type": "text", "text_content": "A"},
                    {"outcome_id": "o2", "weight_bps": 5000, "payload_type": "gif"},
                ],
            },
            created_at=123,
            table=table,
        )
    assert exc.value.issues[0]["field"] == "lottery_config.outcomes[1].payload_type"


def test_put_lottery_config_persists_conditionally() -> None:
    table = _FakeTable()
    item = store.put_lottery_config(
        message_id="m1",
        conversation_id="c1",
        sender_id="u1",
        lottery_config={
            "version": "v1",
            "outcomes": [
                {"outcome_id": "o1", "weight_bps": 7000, "payload_type": "text", "text_content": "A"},
                {"outcome_id": "o2", "weight_bps": 3000, "payload_type": "image", "media_asset_id": "asset-1"},
            ],
        },
        created_at=123,
        table=table,
    )
    assert item["total_weight_bps"] == 10_000
    assert table.last_condition == "attribute_not_exists(message_id)"


def test_put_lottery_unlock_is_one_row_per_recipient() -> None:
    table = _FakeTable()

    first = store.put_lottery_unlock(
        message_id="m1",
        recipient_id="u2",
        selected_outcome_id="o1",
        unlocked_at=100,
        rng_roll=55,
        table=table,
    )
    assert first.created is True
    assert table.last_condition == "attribute_not_exists(message_id) AND attribute_not_exists(recipient_id)"

    second = store.put_lottery_unlock(
        message_id="m1",
        recipient_id="u2",
        selected_outcome_id="o2",
        unlocked_at=200,
        rng_roll=88,
        table=table,
    )
    assert second.created is False
    assert second.item["selected_outcome_id"] == "o1"
    fetched = store.get_lottery_unlock(message_id="m1", recipient_id="u2", table=table)
    assert fetched is not None
    assert fetched["selected_outcome_id"] == "o1"


def test_put_lottery_config_rejects_missing_payload_fields() -> None:
    table = _FakeTable()

    with pytest.raises(store.LotteryConfigValidationError) as text_err:
        store.put_lottery_config(
            message_id="m-text-missing",
            conversation_id="c1",
            sender_id="u1",
            lottery_config={
                "version": "v1",
                "outcomes": [
                    {"outcome_id": "o1", "weight_bps": 5000, "payload_type": "text"},
                    {"outcome_id": "o2", "weight_bps": 5000, "payload_type": "text", "text_content": "ok"},
                ],
            },
            created_at=123,
            table=table,
        )
    assert text_err.value.issues[0]["code"] == "missing-text-content"

    with pytest.raises(store.LotteryConfigValidationError) as media_err:
        store.put_lottery_config(
            message_id="m-media-missing",
            conversation_id="c1",
            sender_id="u1",
            lottery_config={
                "version": "v1",
                "outcomes": [
                    {"outcome_id": "o1", "weight_bps": 5000, "payload_type": "image"},
                    {"outcome_id": "o2", "weight_bps": 5000, "payload_type": "text", "text_content": "ok"},
                ],
            },
            created_at=123,
            table=table,
        )
    assert media_err.value.issues[0]["code"] == "missing-media-asset-id"


def test_put_lottery_unlock_parallel_requests_are_idempotent_per_recipient() -> None:
    table = _FakeTable()
    barrier = threading.Barrier(8)
    results: list[store.UnlockWriteResult] = []
    errors: list[Exception] = []
    lock = threading.Lock()

    def worker(idx: int) -> None:
        try:
            barrier.wait()
            res = store.put_lottery_unlock(
                message_id="m-parallel",
                recipient_id="u-parallel",
                selected_outcome_id=f"o{idx}",
                unlocked_at=100 + idx,
                rng_roll=10 + idx,
                table=table,
            )
            with lock:
                results.append(res)
        except Exception as exc:  # pragma: no cover - diagnostic path
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors
    assert len(results) == 8
    created_count = sum(1 for r in results if r.created)
    assert created_count == 1
    selected_ids = {r.item["selected_outcome_id"] for r in results}
    assert len(selected_ids) == 1
    persisted = table.get_item(Key={"message_id": "m-parallel", "recipient_id": "u-parallel"}).get("Item")
    assert persisted is not None
    assert persisted["selected_outcome_id"] in selected_ids
