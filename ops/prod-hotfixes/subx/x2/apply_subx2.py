import sys

p = "app/routers/subscription_server.py"
s = open(p, encoding="utf-8").read()

anchor_model = 'class SubscriptionResumeIn(BaseModel):\n    reason: Optional[str] = None\n'
model = '''class SubscriptionResumeIn(BaseModel):
    reason: Optional[str] = None


class SubscriptionRetryPaymentIn(BaseModel):
    # SUBX-22: subscriber-driven PAST_DUE recovery. Optionally swap the PM (the
    # subscriber just added / selected a card) then retry the failed renewal charge
    # on the SAME funds-guarded rail the sweeper uses. Clears past_due ONLY on a real
    # collected charge (no phantom credit, no free extension).
    payment_method_id: Optional[str] = None
    reason: Optional[str] = None
'''
assert s.count(anchor_model) == 1, ("model anchor", s.count(anchor_model))
s = s.replace(anchor_model, model, 1)

anchor_ep = '@router.post("/api/subscriptions/{subscription_id}/change-plan", response_model=SubscriptionOut)\nasync def change_subscription_plan('
endpoint = '''@router.post("/api/subscriptions/{subscription_id}/retry-payment", response_model=SubscriptionOut)
async def retry_subscription_payment(
    subscription_id: str,
    body: SubscriptionRetryPaymentIn,
    request: Request,
    x_user_id: Optional[str] = Header(default=None),
):
    """SUBX-22: subscriber-driven PAST_DUE recovery. The dunning notification
    ("update your card") deep-links the subscriber here. Optionally swap the PM,
    then retry the failed renewal charge on the SAME funds-guarded rail the sweeper
    uses (subscription_renewal._attempt_renewal). A real collected charge clears
    past_due -> active and advances the period; a decline / missing PM raises 402
    and leaves the sub in dunning (NO phantom credit, NO free extension)."""
    sub = ddb_get_item(pk_subscription(subscription_id), "META")
    if not sub:
        raise HTTPException(status_code=404, detail="Subscription not found")
    sub = normalize_subscription(sub)
    user_id = require_user(x_user_id)
    if user_id not in (sub["subscriber_id"], sub["creator_id"]):
        raise HTTPException(status_code=403, detail="Not authorized to retry this subscription")
    status = (sub.get("status") or "").lower()
    if status == "active":
        # Idempotent: already recovered (e.g. the sweeper retried first). Nothing to charge.
        return attach_subscription_profiles(sub)
    if status != "past_due":
        raise HTTPException(
            status_code=409,
            detail={"code": "not_recoverable", "message": "This subscription is not awaiting a payment retry."},
        )
    # SUBX-22: an explicit PM swap (the subscriber added / selected a new card) is
    # validated + adopted BEFORE the retry so the charge uses the fresh card. A
    # missing / unowned PM raises 402 (resolve_subscription_payment_method).
    if body.payment_method_id:
        pm = resolve_subscription_payment_method(sub["subscriber_id"], body.payment_method_id)
        sub["payment_method_id"] = pm
        sub["updated_at"] = now_ts()
        save_subscription(sub)

    from app.services.subscription_renewal import _attempt_renewal

    ts = now_ts()
    _subx_summary: Dict[str, Any] = {
        "renewed": [], "dunning": [], "expired": [], "canceled": [],
        "idempotent_skips": [], "grandfather_skips": [], "trial_converted": [],
        "plan_changed": [], "expiring_soon": [],
    }
    _attempt_renewal(sub, ts, _subx_summary)
    if (sub.get("status") or "").lower() != "active":
        # decline / no payment method -> stays past_due (dunning); nothing credited.
        raise HTTPException(
            status_code=402,
            detail={"code": "payment_failed", "message": "The retry charge did not succeed. Update your payment method and try again."},
        )
    audit_event(
        "subscription_payment_retried",
        sub["subscriber_id"],
        request,
        outcome="success",
        subscription_id=subscription_id,
        plan_id=sub.get("plan_id"),
        creator_id=sub["creator_id"],
    )
    refresh_subscription_calendar_events(sub)
    return attach_subscription_profiles(sub)


'''
assert s.count(anchor_ep) == 1, ("ep anchor", s.count(anchor_ep))
s = s.replace(anchor_ep, endpoint + anchor_ep, 1)

open(p, "w", encoding="utf-8").write(s)
print("OK dev edit done")
