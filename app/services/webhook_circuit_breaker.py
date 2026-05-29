"""Circuit breaker for webhook endpoint delivery (ENTERPRISE-005).

Three states:
  closed    - healthy, all deliveries attempted
  open      - failing, deliveries skipped until cooldown expires
  half_open - testing, one delivery attempted to see if endpoint recovered
"""
from __future__ import annotations

import logging
from typing import Any, Dict

from app.core.settings import S
from app.core.tables import T
from app.core.time import now_ts

logger = logging.getLogger(__name__)


def get_circuit_state(endpoint: Dict[str, Any]) -> str:
    """Get the current circuit breaker state for an endpoint."""
    return endpoint.get("circuit_state", "closed")


def should_attempt_delivery(endpoint: Dict[str, Any], now: int) -> bool:
    """Check whether a delivery should be attempted based on circuit state."""
    if not S.webhooks_circuit_breaker_enabled:
        return True

    state = get_circuit_state(endpoint)

    if state == "closed":
        return True

    if state == "half_open":
        return True

    if state == "open":
        test_at = endpoint.get("circuit_test_at", 0)
        if test_at and now >= int(test_at):
            # Cooldown expired, transition to half-open
            transition_circuit(
                endpoint["endpoint_id"],
                endpoint["user_sub"],
                "half_open",
            )
            return True
        return False

    return True


def record_delivery_result(
    endpoint: Dict[str, Any],
    success: bool,
) -> None:
    """Update circuit breaker state based on delivery result."""
    if not S.webhooks_circuit_breaker_enabled:
        return

    state = get_circuit_state(endpoint)
    endpoint_id = endpoint["endpoint_id"]
    user_sub = endpoint["user_sub"]
    now = now_ts()

    if success:
        if state != "closed":
            transition_circuit(endpoint_id, user_sub, "closed")
            logger.info(
                "Circuit breaker closed for endpoint %s (delivery succeeded)",
                endpoint_id,
            )
        _reset_consecutive_failures(endpoint_id, user_sub)
    else:
        consecutive = int(endpoint.get("circuit_consecutive_failures", 0)) + 1
        threshold = int(
            endpoint.get(
                "circuit_failure_threshold",
                S.webhooks_default_circuit_failure_threshold,
            )
        )

        _increment_consecutive_failures(endpoint_id, user_sub, consecutive)

        if state == "half_open":
            current_cooldown = int(
                endpoint.get("circuit_cooldown_seconds", S.webhooks_circuit_initial_cooldown_seconds)
            )
            new_cooldown = min(
                current_cooldown * 2,
                S.webhooks_circuit_max_cooldown_seconds,
            )
            transition_circuit(
                endpoint_id,
                user_sub,
                "open",
                cooldown_seconds=new_cooldown,
                test_at=now + new_cooldown,
            )
            logger.warning(
                "Circuit breaker re-opened for endpoint %s (half-open test failed, cooldown=%ds)",
                endpoint_id,
                new_cooldown,
            )

        elif state == "closed" and consecutive >= threshold:
            initial_cooldown = S.webhooks_circuit_initial_cooldown_seconds
            transition_circuit(
                endpoint_id,
                user_sub,
                "open",
                cooldown_seconds=initial_cooldown,
                test_at=now + initial_cooldown,
            )
            logger.warning(
                "Circuit breaker opened for endpoint %s (%d consecutive failures >= threshold %d)",
                endpoint_id,
                consecutive,
                threshold,
            )


def transition_circuit(
    endpoint_id: str,
    user_sub: str,
    new_state: str,
    cooldown_seconds: int | None = None,
    test_at: int | None = None,
) -> None:
    """Update the circuit breaker state on the endpoint record."""
    now = now_ts()
    update_expr = "SET circuit_state = :cs, updated_at = :u"
    expr_vals: Dict[str, Any] = {":cs": new_state, ":u": now}

    if new_state == "open":
        update_expr += ", circuit_opened_at = :oa"
        expr_vals[":oa"] = now
        if cooldown_seconds is not None:
            update_expr += ", circuit_cooldown_seconds = :cd"
            expr_vals[":cd"] = cooldown_seconds
        if test_at is not None:
            update_expr += ", circuit_test_at = :ct"
            expr_vals[":ct"] = test_at
    elif new_state == "closed":
        update_expr += ", circuit_consecutive_failures = :zero"
        update_expr += ", circuit_cooldown_seconds = :icd"
        expr_vals[":zero"] = 0
        expr_vals[":icd"] = S.webhooks_circuit_initial_cooldown_seconds

    T.webhook_endpoints.update_item(
        Key={"pk": f"USER#{user_sub}", "sk": f"ENDPOINT#{endpoint_id}"},
        UpdateExpression=update_expr,
        ExpressionAttributeValues=expr_vals,
    )


def reset_circuit(endpoint_id: str, user_sub: str) -> None:
    """Manually reset circuit breaker to closed state (admin action)."""
    transition_circuit(endpoint_id, user_sub, "closed")
    _reset_consecutive_failures(endpoint_id, user_sub)
    logger.info("Circuit breaker manually reset for endpoint %s", endpoint_id)


def _increment_consecutive_failures(
    endpoint_id: str, user_sub: str, count: int
) -> None:
    T.webhook_endpoints.update_item(
        Key={"pk": f"USER#{user_sub}", "sk": f"ENDPOINT#{endpoint_id}"},
        UpdateExpression="SET circuit_consecutive_failures = :c",
        ExpressionAttributeValues={":c": count},
    )


def _reset_consecutive_failures(endpoint_id: str, user_sub: str) -> None:
    T.webhook_endpoints.update_item(
        Key={"pk": f"USER#{user_sub}", "sk": f"ENDPOINT#{endpoint_id}"},
        UpdateExpression="SET circuit_consecutive_failures = :z",
        ExpressionAttributeValues={":z": 0},
    )
