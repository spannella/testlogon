from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping, Sequence

try:
    from botocore.exceptions import ClientError
except Exception:  # pragma: no cover - fallback for lightweight test environments
    class ClientError(Exception):
        def __init__(self, response: dict[str, Any], operation_name: str):
            super().__init__(f"{operation_name}: {response}")
            self.response = response

class LotteryConfigValidationError(ValueError):
    """Raised when a lottery config payload is invalid."""

    def __init__(self, message: str, *, issues: list[dict[str, str]] | None = None):
        super().__init__(message)
        self.issues = issues or []


@dataclass(frozen=True)
class UnlockWriteResult:
    created: bool
    item: dict[str, Any]


def _config_table():
    from app.core.aws import ddb
    from app.core.settings import S

    return ddb.Table(S.lottery_message_config_table_name)


def _unlocks_table():
    from app.core.aws import ddb
    from app.core.settings import S

    return ddb.Table(S.lottery_message_unlocks_table_name)


def _normalized_outcomes(outcomes: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    if len(outcomes) < 2 or len(outcomes) > 10:
        raise LotteryConfigValidationError(
            "lottery outcomes count must be between 2 and 10",
            issues=[{"field": "lottery_config.outcomes", "code": "outcome-count-out-of-range"}],
        )
    normalized: list[dict[str, Any]] = []
    total = 0
    for idx, raw in enumerate(outcomes):
        weight = int(raw.get("weight_bps") or 0)
        if weight <= 0:
            raise LotteryConfigValidationError(
                f"outcome[{idx}] weight_bps must be > 0",
                issues=[{"field": f"lottery_config.outcomes[{idx}].weight_bps", "code": "invalid-weight"}],
            )
        payload_type = str(raw.get("payload_type") or "").strip()
        if payload_type not in {"text", "image", "video"}:
            raise LotteryConfigValidationError(
                f"outcome[{idx}] payload_type is invalid",
                issues=[{"field": f"lottery_config.outcomes[{idx}].payload_type", "code": "invalid-payload-type"}],
            )
        item = {
            "outcome_id": str(raw.get("outcome_id") or "").strip(),
            "display_label": str(raw.get("display_label") or "").strip() or None,
            "weight_bps": weight,
            "payload_type": payload_type,
            "text_content": str(raw.get("text_content") or "").strip() or None,
            "media_asset_id": str(raw.get("media_asset_id") or "").strip() or None,
            "media_metadata": dict(raw.get("media_metadata") or {}) if isinstance(raw.get("media_metadata"), Mapping) else None,
        }
        if not item["outcome_id"]:
            raise LotteryConfigValidationError(
                f"outcome[{idx}] outcome_id is required",
                issues=[{"field": f"lottery_config.outcomes[{idx}].outcome_id", "code": "missing-outcome-id"}],
            )
        if payload_type == "text" and not item["text_content"]:
            raise LotteryConfigValidationError(
                f"outcome[{idx}] text_content is required for text payload",
                issues=[{"field": f"lottery_config.outcomes[{idx}].text_content", "code": "missing-text-content"}],
            )
        if payload_type in {"image", "video"} and not item["media_asset_id"]:
            raise LotteryConfigValidationError(
                f"outcome[{idx}] media_asset_id is required for media payload",
                issues=[{"field": f"lottery_config.outcomes[{idx}].media_asset_id", "code": "missing-media-asset-id"}],
            )
        normalized.append(item)
        total += weight

    if total != 10_000:
        raise LotteryConfigValidationError(
            "lottery weights must sum to 10,000 basis points",
            issues=[{"field": "lottery_config.outcomes", "code": "invalid-weight-total"}],
        )
    return normalized


def put_lottery_config(
    *,
    message_id: str,
    conversation_id: str,
    sender_id: str,
    lottery_config: Mapping[str, Any],
    created_at: int,
    table: Any = None,
) -> dict[str, Any]:
    """Persist immutable lottery config, rejecting duplicate message_id writes."""
    table = table or _config_table()
    outcomes = lottery_config.get("outcomes") or []
    normalized_outcomes = _normalized_outcomes(outcomes)
    item = {
        "message_id": str(message_id),
        "conversation_id": str(conversation_id),
        "sender_id": str(sender_id),
        "version": str(lottery_config.get("version") or "v1"),
        "outcomes": normalized_outcomes,
        "created_at": str(int(created_at)),
        "updated_at": str(int(created_at)),
        "total_weight_bps": 10_000,
    }
    table.put_item(
        Item=item,
        ConditionExpression="attribute_not_exists(message_id)",
    )
    return item


def get_lottery_config(*, message_id: str, table: Any = None) -> dict[str, Any] | None:
    table = table or _config_table()
    return table.get_item(Key={"message_id": str(message_id)}).get("Item")


def put_lottery_unlock(
    *,
    message_id: str,
    recipient_id: str,
    selected_outcome_id: str,
    unlocked_at: int,
    rng_roll: int | None = None,
    table: Any = None,
) -> UnlockWriteResult:
    """Insert one unlock record per recipient, idempotently returning existing row."""
    table = table or _unlocks_table()
    item = {
        "message_id": str(message_id),
        "recipient_id": str(recipient_id),
        "selected_outcome_id": str(selected_outcome_id),
        "unlocked_at": str(int(unlocked_at)),
    }
    if rng_roll is not None:
        item["rng_roll"] = int(rng_roll)

    try:
        table.put_item(
            Item=item,
            ConditionExpression="attribute_not_exists(message_id) AND attribute_not_exists(recipient_id)",
        )
        return UnlockWriteResult(created=True, item=item)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ConditionalCheckFailedException":
            raise
        existing = table.get_item(Key={"message_id": str(message_id), "recipient_id": str(recipient_id)}).get("Item") or item
        return UnlockWriteResult(created=False, item=existing)


def get_lottery_unlock(*, message_id: str, recipient_id: str, table: Any = None) -> dict[str, Any] | None:
    table = table or _unlocks_table()
    return table.get_item(Key={"message_id": str(message_id), "recipient_id": str(recipient_id)}).get("Item")
