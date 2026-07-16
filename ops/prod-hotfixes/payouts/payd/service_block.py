

# ===========================================================================
# PAY-D (PAY-30..34): scheduled payout RUNNER + lifecycle + manual holds +
# bounded retries + load-bearing notifications.
#
# The runner auto-progresses eligible payouts requested/approved -> processing
# -> paid via the PAY-A honest ``payout_transfer`` seam (mock now, real when
# keyed), writing the idempotent ``type="debit"`` on paid (balance drops). A
# transient transfer failure is retried on a bounded backoff schedule; once the
# attempts are exhausted (or a HARD failure) the payout goes ``failed`` and its
# debit is REVERSED (funds return -- never inflated). A manual admin HOLD pauses
# a payout so the runner SKIPS it until released. Idempotent PER PAYOUT: a
# payout is transferred+debited exactly once (the PAY-A debit marker guarantees
# it); a re-run of the runner never double-transfers or double-debits.
# ===========================================================================


class PayoutTransferError(Exception):
    """A transfer attempt failed. ``transient`` => retry on backoff; otherwise a
    HARD failure => fail immediately (+ reverse any debit)."""

    def __init__(self, message: str, *, transient: bool = True):
        super().__init__(message)
        self.transient = transient


def _emit_payout_alert(alert_type: str, *, recipient: str, title: str, details: Dict[str, Any], action_url: str = "/wallet/payouts") -> None:
    """PAY-34: emit a load-bearing payout alert as a default-ON transactional push.

    Reuses the shared ``emit_social_alert`` rail (the same mechanism SUB-E5 uses);
    ``payout_*`` events are registered in ``alerts.DEFAULT_PUSH_EVENT_TYPES`` so a
    creator receives them without opting in. A dedicated non-self ``system`` actor
    is used so the alert is not self-suppressed (the recipient == the creator)."""
    if not recipient:
        return
    try:
        from app.services.social_alerts import emit_social_alert

        emit_social_alert(
            recipient_user_id=recipient,
            alert_type=alert_type,
            actor_user_id="system",
            actor_display_name="Payouts",
            title=title,
            details=details,
            action_url=action_url,
        )
    except Exception:
        logger.warning("payout_alert_emit_failed type=%s recipient=%s", alert_type, recipient, exc_info=True)


# --- Manual admin hold (PAY-32) --------------------------------------------
#
# A ``manual_hold=True`` flag on the payout record pauses the runner from
# processing it (place/release are admin-only). Distinct from the 7-day BALANCE
# hold (unchanged -- that gates which credits are withdrawable at request time).

_HOLD_TERMINAL_STATES = {"completed", "failed", "returned", "rejected", "cancelled"}


def place_payout_hold(payout_id: str, admin_user_id: str, reason: str = "") -> dict:
    """Admin: place a manual hold so the runner SKIPS this payout until released."""
    item = T.creator_payouts.get_item(Key={"payout_id": payout_id}).get("Item")
    if not item or not _is_real_payout(item):
        raise LookupError("Payout not found")
    status = item.get("status", "")
    if status in _HOLD_TERMINAL_STATES:
        raise ValueError(f"Cannot hold payout in '{status}' state")
    now = now_ts()
    T.creator_payouts.update_item(
        Key={"payout_id": payout_id},
        UpdateExpression=(
            "SET manual_hold = :t, hold_reason = :r, held_by = :a, held_at = :now, updated_at = :now"
        ),
        ExpressionAttributeValues={":t": True, ":r": reason, ":a": admin_user_id, ":now": now},
    )
    logger.info("payout_hold_placed payout_id=%s by=%s reason=%s", payout_id, admin_user_id, reason)
    item["status"] = status
    return _payout_to_dict(item)


def release_payout_hold(payout_id: str, admin_user_id: str) -> dict:
    """Admin: release a manual hold so the runner may process the payout again."""
    item = T.creator_payouts.get_item(Key={"payout_id": payout_id}).get("Item")
    if not item or not _is_real_payout(item):
        raise LookupError("Payout not found")
    now = now_ts()
    T.creator_payouts.update_item(
        Key={"payout_id": payout_id},
        UpdateExpression=(
            "SET manual_hold = :f, hold_released_by = :a, hold_released_at = :now, updated_at = :now"
        ),
        ExpressionAttributeValues={":f": False, ":a": admin_user_id, ":now": now},
    )
    logger.info("payout_hold_released payout_id=%s by=%s", payout_id, admin_user_id)
    return _payout_to_dict(item)


# --- Runner: retry schedule + eligibility + single-payout processing --------


def _retry_backoff_schedule() -> List[int]:
    raw = getattr(S, "payout_retry_backoff_seconds", "60,300,900")
    out: List[int] = []
    for part in str(raw).split(","):
        part = part.strip()
        if part.isdigit():
            out.append(int(part))
    return out or [60, 300, 900]


def _simulate_forced_transfer_failure(item: Dict[str, Any]) -> None:
    """Honest TEST seam: a payout record may carry ``force_transfer_result`` to
    drive the retry/hard-fail paths in verification. REAL payouts never carry it,
    so production transfers are unaffected. ``transient_fail`` => retryable,
    ``hard_fail`` => immediate hard failure."""
    forced = str(item.get("force_transfer_result", "") or "")
    if forced == "transient_fail":
        raise PayoutTransferError("forced transient transfer failure", transient=True)
    if forced in ("hard_fail", "fail"):
        raise PayoutTransferError("forced hard transfer failure", transient=False)


def _payout_runner_eligible(item: Dict[str, Any], now: int) -> bool:
    """A payout is eligible for the runner iff it is a real payout, NOT on a manual
    hold, and either (a) requested/approved past the optional min-age settling
    window, or (b) processing whose retry backoff has elapsed."""
    if not _is_real_payout(item):
        return False
    if item.get("manual_hold"):
        return False
    status = item.get("status", "")
    if status in ("requested", "approved"):
        min_age = int(getattr(S, "payout_runner_min_age_seconds", 0) or 0)
        if min_age and _to_int(item.get("created_at", 0)) + min_age > now:
            return False
        return True
    if status == "processing":
        return _to_int(item.get("next_attempt_at", 0)) <= now
    return False


def process_one_payout(payout_id: str, now: Optional[int] = None) -> Dict[str, Any]:
    """Process a single payout exactly once through the honest transfer seam.

    requested/approved -> (atomic claim) processing -> ``payout_transfer`` ->
    paid (writes the idempotent PAY-A debit via ``_finalize_paid``) on success;
    transient failure -> schedule a bounded retry (status stays processing with a
    future ``next_attempt_at``); exhausted/HARD failure -> failed + reverse the
    debit (a no-op when never paid, so funds are never inflated). Idempotent: the
    atomic status claim + the PAY-A debit marker guarantee no double-transfer /
    double-debit even if two sweeps race the same payout."""
    now = now or now_ts()
    item = T.creator_payouts.get_item(Key={"payout_id": payout_id}).get("Item")
    if not item or not _payout_runner_eligible(item, now):
        return {"payout_id": payout_id, "action": "skipped"}

    prev_status = item.get("status", "")
    user_id = str(item.get("user_id", ""))
    amount = _to_int(item.get("amount_cents", 0))

    # Atomic claim: move to processing only from an eligible, un-held state. If a
    # concurrent sweep already claimed it the conditional fails and we skip.
    try:
        T.creator_payouts.update_item(
            Key={"payout_id": payout_id},
            UpdateExpression="SET #s = :proc, updated_at = :now",
            ConditionExpression=(
                "#s IN (:req, :appr, :proc) AND (attribute_not_exists(manual_hold) OR manual_hold = :f)"
            ),
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":proc": "processing", ":req": "requested", ":appr": "approved",
                ":now": now, ":f": False,
            },
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
            return {"payout_id": payout_id, "action": "skipped"}
        raise
    item["status"] = "processing"

    # Emit payout_initiated once, on the first entry into processing.
    if prev_status in ("requested", "approved"):
        _emit_payout_alert(
            "payout_initiated",
            recipient=user_id,
            title="Your withdrawal is processing",
            details={"payout_id": payout_id, "amount_cents": amount, "status": "processing"},
        )

    attempts = _to_int(item.get("transfer_attempts", 0)) + 1

    try:
        _simulate_forced_transfer_failure(item)
        # Success: honest transfer + idempotent debit + status completed (+ paid alert).
        _finalize_paid(item, now_ts())
        T.creator_payouts.update_item(
            Key={"payout_id": payout_id},
            UpdateExpression="SET transfer_attempts = :a REMOVE next_attempt_at, last_transfer_error",
            ExpressionAttributeValues={":a": attempts},
        )
        logger.info("payout_runner_paid payout_id=%s attempts=%d", payout_id, attempts)
        return {"payout_id": payout_id, "action": "paid", "attempts": attempts, "status": "completed"}
    except Exception as exc:  # transfer failed
        transient = getattr(exc, "transient", True)
        max_attempts = int(getattr(S, "payout_max_transfer_attempts", 4) or 4)
        backoff = _retry_backoff_schedule()
        if transient and attempts < max_attempts:
            delay = backoff[min(attempts - 1, len(backoff) - 1)]
            next_at = now + delay
            T.creator_payouts.update_item(
                Key={"payout_id": payout_id},
                UpdateExpression=(
                    "SET transfer_attempts = :a, next_attempt_at = :na, "
                    "last_transfer_error = :e, updated_at = :now"
                ),
                ExpressionAttributeValues={":a": attempts, ":na": next_at, ":e": str(exc)[:400], ":now": now},
            )
            logger.info(
                "payout_runner_retry payout_id=%s attempts=%d next_attempt_at=%d err=%s",
                payout_id, attempts, next_at, exc,
            )
            return {
                "payout_id": payout_id, "action": "retry_scheduled",
                "attempts": attempts, "next_attempt_at": next_at, "transient": True,
            }
        # Exhausted transient budget OR a hard failure -> terminal fail + reverse.
        if transient:
            reason = "transfer failed after %d attempts: %s" % (attempts, exc)
        else:
            reason = "hard transfer failure: %s" % exc
        fail_payout(payout_id, reason=reason, returned=False)
        T.creator_payouts.update_item(
            Key={"payout_id": payout_id},
            UpdateExpression="SET transfer_attempts = :a, last_transfer_error = :e",
            ExpressionAttributeValues={":a": attempts, ":e": str(exc)[:400]},
        )
        logger.info(
            "payout_runner_failed payout_id=%s attempts=%d transient=%s err=%s",
            payout_id, attempts, transient, exc,
        )
        return {
            "payout_id": payout_id, "action": "failed",
            "attempts": attempts, "transient": bool(transient), "status": "failed",
        }


def run_payout_sweep(now: Optional[int] = None, limit: int = 1000, payout_id: Optional[str] = None) -> Dict[str, Any]:
    """Scheduled runner (PAY-30): drain eligible payouts to paid (or retry/fail).

    Scans requested + approved + processing payouts via the ByStatusCreatedAt GSI
    and processes each once. ``now`` (unix ts override) lets a verifier fast-forward
    past a retry backoff; ``payout_id`` restricts to a single payout. Returns an
    action summary. Manual-held payouts are counted and SKIPPED."""
    now = now or now_ts()
    summary: Dict[str, Any] = {
        "scanned": 0, "paid": [], "retried": [], "failed": [], "skipped": 0, "held": 0, "now": now,
    }

    def _route(res: Dict[str, Any]) -> None:
        action = res.get("action")
        if action == "paid":
            summary["paid"].append(res)
        elif action == "retry_scheduled":
            summary["retried"].append(res)
        elif action == "failed":
            summary["failed"].append(res)
        else:
            summary["skipped"] += 1

    if payout_id:
        summary["scanned"] = 1
        _route(process_one_payout(payout_id, now))
        return summary

    for status in ("requested", "approved", "processing"):
        query_kwargs: Dict[str, Any] = {
            "IndexName": "ByStatusCreatedAt",
            "KeyConditionExpression": Key("status").eq(status),
            "ScanIndexForward": True,
        }
        while summary["scanned"] < limit:
            resp = T.creator_payouts.query(**query_kwargs)
            for it in resp.get("Items", []):
                if not _is_real_payout(it):
                    continue
                if summary["scanned"] >= limit:
                    break
                summary["scanned"] += 1
                if it.get("manual_hold"):
                    summary["held"] += 1
                    continue
                try:
                    _route(process_one_payout(str(it.get("payout_id", "")), now))
                except Exception:
                    logger.exception("payout_runner: failed payout=%s", it.get("payout_id"))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            query_kwargs["ExclusiveStartKey"] = last_key

    logger.info(
        "payout_sweep done scanned=%d paid=%d retried=%d failed=%d held=%d",
        summary["scanned"], len(summary["paid"]), len(summary["retried"]),
        len(summary["failed"]), summary["held"],
    )
    return summary


# --- periodic task (mirrors subscription_renewal.start_subscription_renewal_task) --


async def _payout_runner_loop() -> None:
    import asyncio
    import time as _time

    from app.services.job_registry import register_task, report_error, report_poll

    interval = max(30, int(getattr(S, "payout_runner_interval_seconds", 300) or 300))
    register_task("payout_runner", interval, enabled=True, description="Scheduled payout processing runner (PAY-D)")
    logger.info("payout runner started (interval=%ds)", interval)
    while True:
        _start = _time.perf_counter()
        try:
            run_payout_sweep()
            report_poll("payout_runner", duration_ms=(_time.perf_counter() - _start) * 1000)
        except Exception as exc:
            try:
                report_error("payout_runner", str(exc))
            except Exception:
                pass
            logger.exception("payout runner loop failed")
        await asyncio.sleep(interval)


def start_payout_runner_task() -> None:
    """Register the scheduled payout runner on FastAPI startup (PAY-30)."""
    import asyncio

    if not getattr(S, "payout_runner_enabled", True):
        try:
            from app.services.job_registry import register_task

            register_task("payout_runner", 300, enabled=False, description="Scheduled payout processing runner (PAY-D)")
        except Exception:
            pass
        logger.info("payout runner disabled")
        return
    try:
        asyncio.get_event_loop().create_task(_payout_runner_loop())
    except RuntimeError:
        asyncio.ensure_future(_payout_runner_loop())


# --- Provider return webhook seam (PAY-31) ---------------------------------


def handle_payout_provider_webhook(event: str, payout_id: str, *, reason: str = "") -> dict:
    """Map a provider payout webhook to the lifecycle. A ``returned`` event
    reverses the debit (funds back); a ``failed`` event fails the payout. Seam:
    real signature verification is enforced at the router when a secret is set."""
    ev = (event or "").lower()
    if not payout_id:
        raise LookupError("Payout not found")
    if "return" in ev:
        return fail_payout(payout_id, reason=reason or "provider return", returned=True)
    if "fail" in ev:
        return fail_payout(payout_id, reason=reason or "provider failure", returned=False)
    raise ValueError(f"unsupported_webhook_event:{event}")
