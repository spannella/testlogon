import re, sys

PATH = sys.argv[1]
src = open(PATH, encoding='utf-8').read()
orig = src

def rep(old, new, label):
    global src
    n = src.count(old)
    if n != 1:
        raise SystemExit('FAIL %s: expected 1 occurrence, found %d' % (label, n))
    src = src.replace(old, new)
    print('OK', label)

def rep_re(pattern, new, label):
    global src
    m = re.findall(pattern, src, flags=re.DOTALL)
    if len(m) != 1:
        raise SystemExit('FAIL %s: regex matched %d' % (label, len(m)))
    src = re.sub(pattern, lambda _: new, src, count=1, flags=re.DOTALL)
    print('OK', label)

# ---- import is_platform_admin (SUBX-02) ----
rep(
 'from app.services.subscription_access import get_subscription_settings, set_subscription_settings',
 'from app.services.subscription_access import get_subscription_settings, set_subscription_settings, is_platform_admin',
 'import-is_platform_admin')

# ---- SUBX-01: real charge via renewal rail in convert_trial ----
start = '    ts = now_ts()\n    sub["status"] = "active"'
end   = '\n    audit_event(\n        "subscription_trial_converted",'
pat = re.escape(start) + r'.*?' + re.escape(end)
new01 = (
'    # SUBX-01: route the MANUAL trial conversion through the SAME funds-guarded rail\n'
'    # the sweeper uses (subscription_renewal._attempt_renewal, trial_conversion=True)\n'
'    # so it REALLY charges the card captured up front. A missing / declined PM -> 402\n'
'    # and NO creator credit / NO period advance (was: a phantom stub_inv invoice plus a\n'
'    # real creator credit with ZERO dollars collected).\n'
'    from app.services.subscription_renewal import _attempt_renewal\n'
'\n'
'    ts = now_ts()\n'
'    _subx_summary: Dict[str, Any] = {\n'
'        "renewed": [], "dunning": [], "expired": [], "canceled": [],\n'
'        "idempotent_skips": [], "grandfather_skips": [], "trial_converted": [],\n'
'        "plan_changed": [], "expiring_soon": [],\n'
'    }\n'
'    _attempt_renewal(sub, ts, _subx_summary, trial_conversion=True)\n'
'    if (sub.get("status") or "").lower() != "active":\n'
'        # decline / no payment method -> dunning (past_due); nothing was credited\n'
'        raise HTTPException(\n'
'            status_code=402,\n'
'            detail={"code": "payment_failed", "message": "Trial conversion charge did not succeed. Update your payment method and try again."},\n'
'        )\n'
'\n'
'    audit_event(\n'
'        "subscription_trial_converted",'
)
rep_re(pat, new01, 'SUBX-01-convert_trial')

# ---- SUBX-02a: privileged computation ----
rep(
 '        raise HTTPException(status_code=403, detail="Not authorized to refund this subscription")\n    now = now_ts()',
 '        raise HTTPException(status_code=403, detail="Not authorized to refund this subscription")\n'
 '    # SUBX-02: only the creator / gifter / platform-admin may issue a FULL (>=1.0)\n'
 '    # refund; a subscriber may only self-refund the unused prorated remainder.\n'
 '    privileged = (user_id in (sub["creator_id"], sub.get("gifter_id"))) or is_platform_admin(user_id)\n'
 '    now = now_ts()',
 'SUBX-02a-privileged')

# ---- SUBX-02b: full-refund restriction + revoke access ----
rep(
 '    if frac <= 0:\n'
 '        raise HTTPException(status_code=400, detail="Nothing to refund for the current period")\n'
 '    receipt = _reverse_subscription_charge(sub, now=now, refund_fraction=frac, reason=(body.reason or "refund"), actor=user_id)\n'
 '    audit_event(',
 '    if frac >= 1.0 and not privileged:\n'
 '        raise HTTPException(status_code=403, detail="Only the creator or an admin can issue a full refund")\n'
 '    if frac <= 0:\n'
 '        raise HTTPException(status_code=400, detail="Nothing to refund for the current period")\n'
 '    receipt = _reverse_subscription_charge(sub, now=now, refund_fraction=frac, reason=(body.reason or "refund"), actor=user_id)\n'
 '    # SUBX-02: a refunded cycle no longer grants access -> REVOKE now (mirror the\n'
 '    # immediate-cancel path) so has_active_subscription flips False + content re-locks;\n'
 '    # no refund-and-keep-access. Idempotent (an idempotent replay reverses nothing).\n'
 '    if not receipt.get("idempotent_replay"):\n'
 '        sub["status"] = "canceled"\n'
 '        sub["canceled_at"] = now\n'
 '        sub["current_period_end"] = now\n'
 '        sub["auto_renew"] = False\n'
 '        sub["cancel_at_period_end"] = False\n'
 '        sub["updated_at"] = now\n'
 '        save_subscription(sub)\n'
 '        record_billing_subscription(sub)\n'
 '    audit_event(',
 'SUBX-02b-revoke')

# ---- SUBX-03a: authenticate the webhook ----
rep(
 'async def billing_webhook(provider: str, body: WebhookIn):\n'
 '    if provider not in ("stub", "paypal", "ccbill"):\n'
 '        raise HTTPException(status_code=400, detail="Unsupported provider")\n',
 'async def billing_webhook(\n'
 '    provider: str,\n'
 '    body: WebhookIn,\n'
 '    x_webhook_secret: Optional[str] = Header(default=None, alias="X-Subscription-Webhook-Secret"),\n'
 '):\n'
 '    if provider not in ("stub", "paypal", "ccbill"):\n'
 '        raise HTTPException(status_code=400, detail="Unsupported provider")\n'
 '    # SUBX-03: authenticate the billing webhook with a shared secret (seam mirrors\n'
 '    # admin_payouts.payout_provider_webhook). When SUBSCRIPTION_WEBHOOK_SECRET is set,\n'
 '    # an unsigned / forged caller is rejected 401 and mutates NOTHING -- closing the\n'
 '    # free un-expire / extend / dunning-bypass hole.\n'
 '    _wh_secret = os.environ.get("SUBSCRIPTION_WEBHOOK_SECRET", "") or getattr(S, "subscription_webhook_secret", "") or ""\n'
 '    if _wh_secret:\n'
 '        import hmac as _hmac\n'
 '        if not _hmac.compare_digest(str(x_webhook_secret or ""), str(_wh_secret)):\n'
 '            raise HTTPException(status_code=401, detail="invalid_webhook_secret")\n',
 'SUBX-03a-auth')

# ---- SUBX-03b: invoice.paid bookkeeping-only ----
rep(
 '    elif event_type == "invoice.paid":\n'
 '        sub["status"] = "active"\n'
 '        sub["current_period_end"] = ts + interval_seconds(sub.get("interval", "month"))\n'
 '        sub["auto_renew"] = True\n'
 '        if sub.get("discount_remaining_months"):\n'
 '            sub["discount_remaining_months"] = max(0, int(sub["discount_remaining_months"]) - 1)\n'
 '\n'
 '        amount_cents =',
 '    elif event_type == "invoice.paid":\n'
 '        # SUBX-03: BOOKKEEPING-ONLY. A signed invoice.paid must NOT extend the period /\n'
 '        # un-expire / re-enable auto-renew off a webhook alone; only a real captured charge\n'
 '        # (the funds-guarded renewal sweeper) advances the lifecycle. Record the invoice\n'
 '        # for audit but leave status / current_period_end / auto_renew intact.\n'
 '        amount_cents =',
 'SUBX-03b-invoice-paid')

open(PATH, 'w', encoding='utf-8').write(src)
print('WROTE', PATH, 'delta_bytes', len(src)-len(orig))
