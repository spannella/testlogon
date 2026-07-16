#!/usr/bin/env python3
"""SUBX Epic X5 — subscription notifications backend patch.
Idempotent-ish: asserts each replacement applies exactly once.
Applies to alerts.py, subscription_renewal.py, subscription_server.py under the repo ROOT passed as argv[1].
"""
import sys, ast, io, os

ROOT = sys.argv[1] if len(sys.argv) > 1 else "."

def rd(p):
    with io.open(os.path.join(ROOT, p), "r", encoding="utf-8") as f:
        return f.read()

def wr(p, s):
    with io.open(os.path.join(ROOT, p), "w", encoding="utf-8") as f:
        f.write(s)

def sub_once(s, old, new, tag):
    n = s.count(old)
    if n != 1:
        raise SystemExit("PATCH-FAIL [%s]: expected 1 occurrence, found %d" % (tag, n))
    return s.replace(old, new)

# ===================================================================
# FILE 1: app/services/alerts.py
# ===================================================================
A = "app/services/alerts.py"
a = rd(A)

# (A) new alert types in ALERT_EVENT_TYPES
a = sub_once(a,
    '    "subscription_new_subscriber","subscription_canceled","subscription_gifted",\n',
    '    "subscription_new_subscriber","subscription_canceled","subscription_gifted",\n'
    '    # SUBX-51: plan-change / creator-removal / trial-conversion lifecycle alerts (default-on)\n'
    '    "subscription_changed","subscription_removed","subscription_converted",\n',
    "alerts:ALERT_EVENT_TYPES")

# (B) default-on push
a = sub_once(a,
    '    "subscription_gifted",          # SUB-E5: a gift subscription\n',
    '    "subscription_gifted",          # SUB-E5: a gift subscription\n'
    '    "subscription_changed",         # SUBX-51: your plan changed (upgrade / scheduled downgrade)\n'
    '    "subscription_removed",         # SUBX-51: a creator removed your subscription\n'
    '    "subscription_converted",       # SUBX-51: your trial converted to paid\n',
    "alerts:DEFAULT_PUSH")

# (C) _build_action_url new fallback entries (explicit action_url still wins at emit sites)
a = sub_once(a,
    '        "subscription_canceled": "/subscriptions/manage",\n'
    '        "subscription_gifted": "/subscriptions/manage",\n',
    '        "subscription_canceled": "/subscriptions/manage",\n'
    '        "subscription_changed": "/subscriptions/manage",\n'
    '        "subscription_removed": "/subscriptions/manage",\n'
    '        "subscription_converted": "/subscriptions/manage",\n'
    '        "subscription_gifted": "/subscriptions/manage",\n',
    "alerts:build_action_url")

# (D) SUBX-52 de-dupe: the audit_event alert-mirror mis-types subscription_* audit rows as
# security_event and double-writes an alert already delivered via emit_social_alert/put_notification.
# Suppress the mirror (keep webhook/siem audit) for all subscription_* audit events.
a = sub_once(a,
    '        if event not in _NO_ALERT_EVENTS:\n',
    '        if event not in _NO_ALERT_EVENTS and not event.startswith("subscription_"):\n',
    "alerts:no_alert_events")

ast.parse(a); wr(A, a)
print("OK", A)

# ===================================================================
# FILE 2: app/services/subscription_renewal.py
# ===================================================================
R = "app/services/subscription_renewal.py"
r = rd(R)

# helper _manage_url right after _emit()
r = sub_once(r,
    '    except Exception:\n'
    '        logger.warning("subscription alert %s failed recipient=%s", alert_type, recipient, exc_info=True)\n',
    '    except Exception:\n'
    '        logger.warning("subscription alert %s failed recipient=%s", alert_type, recipient, exc_info=True)\n'
    '\n'
    'def _manage_url(sub: Dict[str, Any]) -> str:\n'
    '    """SUBX-50: deep-link the SUBSCRIBER to the SPECIFIC sub\'s Manage/PAST_DUE recovery\n'
    '    screen (SUBX-21/22) instead of the arg-less manage list, so a multi-creator\n'
    '    subscriber lands on the right one."""\n'
    '    sid = str(sub.get("subscription_id") or "")\n'
    '    cid = str(sub.get("creator_id") or "")\n'
    '    if not sid:\n'
    '        return "/subscriptions/manage"\n'
    '    return "/subscriptions/manage?subscriptionId=%s&creatorId=%s" % (sid, cid)\n',
    "renewal:_manage_url")

# _decline: renewal_failed -> deep-link to PAST_DUE recovery (specific sub)
r = sub_once(r,
    '    _emit(\n'
    '        "subscription_renewal_failed",\n'
    '        recipient=sub["subscriber_id"],\n'
    '        actor=sub["creator_id"],\n'
    '        title="Your subscription payment failed — update your card",\n'
    '        details={"subscription_id": sub["subscription_id"], "plan_id": sub.get("plan_id"), "creator_id": sub["creator_id"], "attempt": attempts, "reason": reason},\n'
    '    )\n',
    '    _emit(\n'
    '        "subscription_renewal_failed",\n'
    '        recipient=sub["subscriber_id"],\n'
    '        actor=sub["creator_id"],\n'
    '        title="Your subscription payment failed — update your card",\n'
    '        details={"subscription_id": sub["subscription_id"], "plan_id": sub.get("plan_id"), "creator_id": sub["creator_id"], "attempt": attempts, "reason": reason},\n'
    '        action_url=_manage_url(sub),  # SUBX-50: land on the PAST_DUE update-card recovery screen\n'
    '    )\n',
    "renewal:decline_failed")

# _decline: expiring (grace) -> specific sub
r = sub_once(r,
    '        _emit(\n'
    '            "subscription_expiring",\n'
    '            recipient=sub["subscriber_id"],\n'
    '            actor=sub["creator_id"],\n'
    '            title="Your subscription is about to expire",\n'
    '            details={"subscription_id": sub["subscription_id"], "grace_until": sub["grace_until"], "creator_id": sub["creator_id"]},\n'
    '        )\n',
    '        _emit(\n'
    '            "subscription_expiring",\n'
    '            recipient=sub["subscriber_id"],\n'
    '            actor=sub["creator_id"],\n'
    '            title="Your subscription is about to expire",\n'
    '            details={"subscription_id": sub["subscription_id"], "grace_until": sub["grace_until"], "creator_id": sub["creator_id"]},\n'
    '            action_url=_manage_url(sub),\n'
    '        )\n',
    "renewal:decline_expiring")

# _expire: expired -> specific sub
r = sub_once(r,
    '    _emit(\n'
    '        "subscription_expired",\n'
    '        recipient=sub["subscriber_id"],\n'
    '        actor=sub["creator_id"],\n'
    '        title="Your subscription has expired",\n'
    '        details={"subscription_id": sub["subscription_id"], "plan_id": sub.get("plan_id"), "creator_id": sub["creator_id"], "reason": reason},\n'
    '    )\n',
    '    _emit(\n'
    '        "subscription_expired",\n'
    '        recipient=sub["subscriber_id"],\n'
    '        actor=sub["creator_id"],\n'
    '        title="Your subscription has expired",\n'
    '        details={"subscription_id": sub["subscription_id"], "plan_id": sub.get("plan_id"), "creator_id": sub["creator_id"], "reason": reason},\n'
    '        action_url=_manage_url(sub),\n'
    '    )\n',
    "renewal:expire")

# _maybe_expiring_notice: advance notice -> specific sub
r = sub_once(r,
    '    _emit(\n'
    '        "subscription_expiring",\n'
    '        recipient=sub["subscriber_id"],\n'
    '        actor=sub["creator_id"],\n'
    '        title="Your subscription is ending soon",\n'
    '        details={"subscription_id": sub["subscription_id"], "plan_id": sub.get("plan_id"), "creator_id": sub["creator_id"], "ends_at": boundary},\n'
    '    )\n',
    '    _emit(\n'
    '        "subscription_expiring",\n'
    '        recipient=sub["subscriber_id"],\n'
    '        actor=sub["creator_id"],\n'
    '        title="Your subscription is ending soon",\n'
    '        details={"subscription_id": sub["subscription_id"], "plan_id": sub.get("plan_id"), "creator_id": sub["creator_id"], "ends_at": boundary},\n'
    '        action_url=_manage_url(sub),\n'
    '    )\n',
    "renewal:expiring_notice")

# _apply_pending_change: emit subscription_changed when a scheduled downgrade/change applies
r = sub_once(r,
    '    for k in ("pending_change", "pending_plan_id", "pending_interval", "pending_price_cents", "pending_apply_at"):\n'
    '        sub.pop(k, None)\n'
    '    return True\n',
    '    for k in ("pending_change", "pending_plan_id", "pending_interval", "pending_price_cents", "pending_apply_at"):\n'
    '        sub.pop(k, None)\n'
    '    # SUBX-51: notify the subscriber that their SCHEDULED plan change is now in effect.\n'
    '    _emit(\n'
    '        "subscription_changed",\n'
    '        recipient=sub["subscriber_id"],\n'
    '        actor=sub["creator_id"],\n'
    '        title="Your subscription plan changed",\n'
    '        details={"subscription_id": sub["subscription_id"], "plan_id": sub.get("plan_id"), "creator_id": sub["creator_id"], "direction": (pending.get("direction") or "change"), "applied": True},\n'
    '        action_url=_manage_url(sub),\n'
    '    )\n'
    '    return True\n',
    "renewal:apply_pending_change")

# pre-renewal reminder function + wiring
r = sub_once(r,
    'def _process(sub: Dict[str, Any], now: int, summary: Dict[str, Any]) -> None:\n',
    'def _maybe_prerenewal_notice(sub: Dict[str, Any], now: int, boundary: int, summary: Dict[str, Any]) -> None:\n'
    '    """SUBX-52: emit a "Renews in Nd for $X" advance reminder N days before an\n'
    '    AUTO-RENEW subscription re-bills. Fires ONCE per boundary (idempotent via the\n'
    '    ``prerenewal_notified_period`` marker)."""\n'
    '    if not boundary or boundary <= now:\n'
    '        return\n'
    '    window = _expiring_notice_days() * 86400\n'
    '    if boundary - now > window:\n'
    '        return\n'
    '    if int(sub.get("prerenewal_notified_period") or 0) == boundary:\n'
    '        return\n'
    '    amount = _renewal_amount(sub)\n'
    '    days = max(1, int(round((boundary - now) / 86400.0)))\n'
    '    sub["prerenewal_notified_period"] = boundary\n'
    '    sub["updated_at"] = now\n'
    '    _save(sub)\n'
    '    _emit(\n'
    '        "subscription_renewed",\n'
    '        recipient=sub["subscriber_id"],\n'
    '        actor=sub["creator_id"],\n'
    '        title="Your subscription renews in %d day%s for $%.2f" % (days, "" if days == 1 else "s", amount / 100.0),\n'
    '        details={"subscription_id": sub["subscription_id"], "plan_id": sub.get("plan_id"), "creator_id": sub["creator_id"], "renews_at": boundary, "amount_cents": amount, "advance": True},\n'
    '        action_url=_manage_url(sub),\n'
    '    )\n'
    '    summary.setdefault("prerenewal_soon", []).append({"subscription_id": sub["subscription_id"], "renews_at": boundary})\n'
    '    logger.info("subscription_prerenewal_advance id=%s renews_at=%s", sub["subscription_id"], boundary)\n'
    '\n'
    '\n'
    'def _process(sub: Dict[str, Any], now: int, summary: Dict[str, Any]) -> None:\n',
    "renewal:prerenewal_fn")

# wire pre-renewal into branch (3): active + auto_renew on + not due
r = sub_once(r,
    '        due = (nbd and nbd <= now) or (cpe and cpe <= now)\n'
    '        if not due:\n'
    '            if not auto_renew or cancel_ape:\n'
    '                _maybe_expiring_notice(sub, now, cpe, summary)\n'
    '            return\n',
    '        due = (nbd and nbd <= now) or (cpe and cpe <= now)\n'
    '        if not due:\n'
    '            if not auto_renew or cancel_ape:\n'
    '                _maybe_expiring_notice(sub, now, cpe, summary)\n'
    '            else:\n'
    '                # SUBX-52: auto-renew sub still active -> advance "renews in Nd for $X" reminder\n'
    '                _maybe_prerenewal_notice(sub, now, (nbd or cpe), summary)\n'
    '            return\n',
    "renewal:prerenewal_wire")

ast.parse(r); wr(R, r)
print("OK", R)

# ===================================================================
# FILE 3: app/routers/subscription_server.py
# ===================================================================
S = "app/routers/subscription_server.py"
s = rd(S)

# (A) subscribe: creator gets the dedicated new_subscriber type + Subscribers deep-link
s = sub_once(s,
    '        emit_social_alert(\n'
    '            recipient_user_id=plan["creator_id"],\n'
    '            alert_type="subscription_started",\n'
    '            actor_user_id=subscriber_id,\n'
    '            actor_display_name=actor_name,\n'
    '            title=f"{actor_name} subscribed to you",\n'
    '            details={"plan_id": plan_id, "subscriber_id": subscriber_id, "subscription_id": subscription_id},\n'
    '            action_url="/subscriptions",\n'
    '        )\n',
    '        emit_social_alert(\n'
    '            recipient_user_id=plan["creator_id"],\n'
    '            alert_type="subscription_new_subscriber",  # SUBX-51: dedicated type (was mis-typed subscription_started)\n'
    '            actor_user_id=subscriber_id,\n'
    '            actor_display_name=actor_name,\n'
    '            title=f"{actor_name} subscribed to you",\n'
    '            details={"plan_id": plan_id, "subscriber_id": subscriber_id, "subscription_id": subscription_id},\n'
    '            action_url="/subscriptions/subscribers",  # SUBX-50: land on the E4 Subscribers console\n'
    '        )\n',
    "server:subscribe_creator")

# (B) renewal-toggle: push subscription_canceled to BOTH parties when auto-renew is turned OFF
s = sub_once(s,
    '    audit_event(\n'
    '        "subscription_renewal_updated",\n'
    '        sub["subscriber_id"],\n'
    '        request,\n'
    '        outcome="success",\n'
    '        subscription_id=subscription_id,\n'
    '        auto_renew=body.auto_renew,\n'
    '        effective=body.effective,\n'
    '    )\n'
    '    refresh_subscription_calendar_events(sub)\n'
    '    return attach_subscription_profiles(sub)\n',
    '    audit_event(\n'
    '        "subscription_renewal_updated",\n'
    '        sub["subscriber_id"],\n'
    '        request,\n'
    '        outcome="success",\n'
    '        subscription_id=subscription_id,\n'
    '        auto_renew=body.auto_renew,\n'
    '        effective=body.effective,\n'
    '    )\n'
    '    # SUBX-51: turning auto-renew OFF is a cancel — it was silent before. Push both parties.\n'
    '    if not body.auto_renew:\n'
    '        try:\n'
    '            from app.services.social_alerts import emit_social_alert as _emit_sa\n'
    '            from app.services.profile import get_profile_identity as _gpi\n'
    '            _c_name = _gpi(sub["creator_id"]).get("display_name") or sub["creator_id"]\n'
    '            _s_name = _gpi(sub["subscriber_id"]).get("display_name") or sub["subscriber_id"]\n'
    '            _immediate = (body.effective == "immediate")\n'
    '            _sub_title = ("Your subscription to %s is canceled" % _c_name) if _immediate else ("Your subscription to %s will not renew" % _c_name)\n'
    '            _emit_sa(\n'
    '                recipient_user_id=sub["subscriber_id"],\n'
    '                alert_type="subscription_canceled",\n'
    '                actor_user_id=sub["creator_id"],\n'
    '                actor_display_name=_c_name,\n'
    '                title=_sub_title,\n'
    '                details={"subscription_id": subscription_id, "creator_id": sub["creator_id"], "ends_at": int(sub.get("current_period_end") or 0), "cancel_at_period_end": not _immediate},\n'
    '                action_url=f"/subscriptions/manage?subscriptionId={subscription_id}&creatorId={sub[\'creator_id\']}",\n'
    '            )\n'
    '            _emit_sa(\n'
    '                recipient_user_id=sub["creator_id"],\n'
    '                alert_type="subscription_canceled",\n'
    '                actor_user_id=sub["subscriber_id"],\n'
    '                actor_display_name=_s_name,\n'
    '                title=f"{_s_name} turned off auto-renew" if not _immediate else f"{_s_name} canceled their subscription",\n'
    '                details={"subscription_id": subscription_id, "subscriber_id": sub["subscriber_id"]},\n'
    '                action_url="/subscriptions/subscribers",\n'
    '            )\n'
    '        except Exception:\n'
    '            logger.warning("renewal-toggle cancel alert failed sub=%s", subscription_id, exc_info=True)\n'
    '    refresh_subscription_calendar_events(sub)\n'
    '    return attach_subscription_profiles(sub)\n',
    "server:renewal_toggle")

# (C1) change-plan SCHEDULED (downgrade / period-end): push a "change scheduled" note
s = sub_once(s,
    '        audit_event(\n'
    '            "subscription_plan_change_scheduled",\n'
    '            sub["subscriber_id"],\n'
    '            request,\n'
    '            outcome="success",\n'
    '            subscription_id=subscription_id,\n'
    '            plan_id=body.plan_id,\n'
    '            effective="period_end",\n'
    '        )\n'
    '        refresh_subscription_calendar_events(sub, plan)\n'
    '        return attach_subscription_profiles(sub)\n',
    '        audit_event(\n'
    '            "subscription_plan_change_scheduled",\n'
    '            sub["subscriber_id"],\n'
    '            request,\n'
    '            outcome="success",\n'
    '            subscription_id=subscription_id,\n'
    '            plan_id=body.plan_id,\n'
    '            effective="period_end",\n'
    '        )\n'
    '        _emit_subscription_changed(sub, plan, request, applied=False, direction=("upgrade" if is_upgrade else "downgrade"))\n'
    '        refresh_subscription_calendar_events(sub, plan)\n'
    '        return attach_subscription_profiles(sub)\n',
    "server:change_scheduled")

# (C2) change-plan IMMEDIATE upgrade: push a "plan changed" note
s = sub_once(s,
    '    audit_event(\n'
    '        "subscription_plan_changed",\n'
    '        sub["subscriber_id"],\n'
    '        request,\n'
    '        outcome="success",\n'
    '        subscription_id=subscription_id,\n'
    '        plan_id=body.plan_id,\n'
    '        proration_amount_cents=proration_amount,\n'
    '    )\n'
    '    refresh_subscription_calendar_events(sub, plan)\n'
    '    return attach_subscription_profiles(sub)\n',
    '    audit_event(\n'
    '        "subscription_plan_changed",\n'
    '        sub["subscriber_id"],\n'
    '        request,\n'
    '        outcome="success",\n'
    '        subscription_id=subscription_id,\n'
    '        plan_id=body.plan_id,\n'
    '        proration_amount_cents=proration_amount,\n'
    '    )\n'
    '    _emit_subscription_changed(sub, plan, request, applied=True, direction="upgrade")\n'
    '    refresh_subscription_calendar_events(sub, plan)\n'
    '    return attach_subscription_profiles(sub)\n',
    "server:change_immediate")

# (D) remove: promote the in-app-only removal notification to a real push
s = sub_once(s,
    '    put_notification(\n'
    '        recipient_user_id=sub["subscriber_id"],\n'
    '        notif_type="subscription_removed",\n'
    '        payload={"subscription_id": subscription_id, "creator_id": creator_id},\n'
    '    )\n'
    '    refresh_subscription_calendar_events(sub)\n'
    '    return attach_subscription_profiles(sub)\n',
    '    put_notification(\n'
    '        recipient_user_id=sub["subscriber_id"],\n'
    '        notif_type="subscription_removed",\n'
    '        payload={"subscription_id": subscription_id, "creator_id": creator_id},\n'
    '    )\n'
    '    # SUBX-51: promote removal from in-app-only to a real default-on push + deep-link.\n'
    '    try:\n'
    '        from app.services.social_alerts import emit_social_alert as _emit_sa\n'
    '        from app.services.profile import get_profile_identity as _gpi\n'
    '        _c_name = _gpi(creator_id).get("display_name") or creator_id\n'
    '        _emit_sa(\n'
    '            recipient_user_id=sub["subscriber_id"],\n'
    '            alert_type="subscription_removed",\n'
    '            actor_user_id=creator_id,\n'
    '            actor_display_name=_c_name,\n'
    '            title=f"Your subscription to {_c_name} was ended by the creator",\n'
    '            details={"subscription_id": subscription_id, "creator_id": creator_id, "refunded": refunded},\n'
    '            action_url=f"/subscriptions/manage?subscriptionId={subscription_id}&creatorId={creator_id}",\n'
    '        )\n'
    '    except Exception:\n'
    '        logger.warning("removal social alert failed sub=%s", subscription_id, exc_info=True)\n'
    '    refresh_subscription_calendar_events(sub)\n'
    '    return attach_subscription_profiles(sub)\n',
    "server:remove_push")

# (E) trial convert: push a receipt to the subscriber (was silent)
s = sub_once(s,
    '    audit_event(\n'
    '        "subscription_trial_converted",\n'
    '        sub["subscriber_id"],\n'
    '        request,\n'
    '        outcome="success",\n'
    '        subscription_id=subscription_id,\n'
    '        plan_id=sub["plan_id"],\n'
    '        creator_id=sub["creator_id"],\n'
    '    )\n'
    '    refresh_subscription_calendar_events(sub, plan)\n'
    '    return attach_subscription_profiles(sub)\n',
    '    audit_event(\n'
    '        "subscription_trial_converted",\n'
    '        sub["subscriber_id"],\n'
    '        request,\n'
    '        outcome="success",\n'
    '        subscription_id=subscription_id,\n'
    '        plan_id=sub["plan_id"],\n'
    '        creator_id=sub["creator_id"],\n'
    '    )\n'
    '    # SUBX-51: trial conversion was silent — push the subscriber a receipt + deep-link.\n'
    '    try:\n'
    '        from app.services.social_alerts import emit_social_alert as _emit_sa\n'
    '        from app.services.profile import get_profile_identity as _gpi\n'
    '        _c_name = _gpi(sub["creator_id"]).get("display_name") or sub["creator_id"]\n'
    '        _emit_sa(\n'
    '            recipient_user_id=sub["subscriber_id"],\n'
    '            alert_type="subscription_converted",\n'
    '            actor_user_id=sub["creator_id"],\n'
    '            actor_display_name=_c_name,\n'
    '            title=f"Your trial converted to a paid subscription to {_c_name}",\n'
    '            details={"subscription_id": subscription_id, "creator_id": sub["creator_id"], "plan_id": sub["plan_id"], "amount_cents": int(sub.get("price_cents") or 0)},\n'
    '            action_url=f"/subscriptions/manage?subscriptionId={subscription_id}&creatorId={sub[\'creator_id\']}",\n'
    '        )\n'
    '    except Exception:\n'
    '        logger.warning("trial-convert social alert failed sub=%s", subscription_id, exc_info=True)\n'
    '    refresh_subscription_calendar_events(sub, plan)\n'
    '    return attach_subscription_profiles(sub)\n',
    "server:convert_receipt")

# module-level helper _emit_subscription_changed — insert right before change_subscription_plan route
s = sub_once(s,
    '@router.post("/api/subscriptions/{subscription_id}/change-plan", response_model=SubscriptionOut)\n',
    'def _emit_subscription_changed(sub, plan, request, *, applied: bool, direction: str) -> None:\n'
    '    """SUBX-51: notify the subscriber (and creator) of a plan change. ``applied`` False =\n'
    '    a scheduled downgrade/period-end change; True = an immediate upgrade now in effect."""\n'
    '    try:\n'
    '        from app.services.social_alerts import emit_social_alert as _emit_sa\n'
    '        from app.services.profile import get_profile_identity as _gpi\n'
    '        _c_name = _gpi(sub["creator_id"]).get("display_name") or sub["creator_id"]\n'
    '        _s_name = _gpi(sub["subscriber_id"]).get("display_name") or sub["subscriber_id"]\n'
    '        _plan_name = (plan or {}).get("name") or (plan or {}).get("title") or "a new plan"\n'
    '        if applied:\n'
    '            _sub_title = f"Your subscription to {_c_name} changed to {_plan_name}"\n'
    '        elif direction == "downgrade":\n'
    '            _sub_title = f"Your plan change to {_plan_name} is scheduled for the end of this period"\n'
    '        else:\n'
    '            _sub_title = f"Your plan change to {_plan_name} is scheduled"\n'
    '        _mgr = f"/subscriptions/manage?subscriptionId={sub[\'subscription_id\']}&creatorId={sub[\'creator_id\']}"\n'
    '        _emit_sa(\n'
    '            recipient_user_id=sub["subscriber_id"],\n'
    '            alert_type="subscription_changed",\n'
    '            actor_user_id=sub["creator_id"],\n'
    '            actor_display_name=_c_name,\n'
    '            title=_sub_title,\n'
    '            details={"subscription_id": sub["subscription_id"], "creator_id": sub["creator_id"], "plan_id": sub.get("plan_id"), "direction": direction, "applied": applied},\n'
    '            action_url=_mgr,\n'
    '        )\n'
    '        _emit_sa(\n'
    '            recipient_user_id=sub["creator_id"],\n'
    '            alert_type="subscription_changed",\n'
    '            actor_user_id=sub["subscriber_id"],\n'
    '            actor_display_name=_s_name,\n'
    '            title=(f"{_s_name} upgraded to {_plan_name}" if (applied and direction == "upgrade") else f"{_s_name} scheduled a plan change"),\n'
    '            details={"subscription_id": sub["subscription_id"], "subscriber_id": sub["subscriber_id"], "plan_id": sub.get("plan_id"), "direction": direction, "applied": applied},\n'
    '            action_url="/subscriptions/subscribers",\n'
    '        )\n'
    '    except Exception:\n'
    '        logger.warning("plan-change social alert failed sub=%s", sub.get("subscription_id"), exc_info=True)\n'
    '\n'
    '\n'
    '@router.post("/api/subscriptions/{subscription_id}/change-plan", response_model=SubscriptionOut)\n',
    "server:emit_changed_helper")

ast.parse(s); wr(S, s)
print("OK", S)
print("ALL PATCHES APPLIED")
