"""DISP E5 idempotent prod applier (DISP-050/052/053).

Anchor-based, re-runnable. Wires the dispute NOTIFICATIONS module into both
tracks, makes dispute events default-on push, adds the master flag, and adds the
subscription-webhook dispute-event ignore (DISP-052). Safe to run twice: every
patch is guarded on a sentinel already-present marker.

Run on PROD (repo root, e.g. /home/ubuntu/testlogon):
    set -a; . .env.local; set +a; python3 ops/prod-hotfixes/disp/e5/apply_e5_prod.py
Then restart the backend and run verify_e5.py.
"""
import ast, os, shutil, sys, time

ROOT = os.getcwd()
TS = int(time.time())
BAK = os.path.join(ROOT, f"disp_bak_e5_{TS}")
os.makedirs(BAK, exist_ok=True)
changed = []


def read(p):
    with open(os.path.join(ROOT, p)) as f:
        return f.read()


def write(p, s):
    ast.parse(s)  # never write a syntactically broken file
    full = os.path.join(ROOT, p)
    shutil.copy2(full, os.path.join(BAK, os.path.basename(p) + ".bak"))
    with open(full, "w") as f:
        f.write(s)
    changed.append(p)


def patch(p, old, new, *, tag):
    s = read(p)
    if new.strip().split("\n")[0] in s or tag in s:
        print(f"  SKIP {p} :: {tag} (already present)")
        return
    if old not in s:
        print(f"  !! ANCHOR MISS {p} :: {tag}")
        raise SystemExit(2)
    write(p, s.replace(old, new, 1))
    print(f"  OK   {p} :: {tag}")


# 0) drop the module (verbatim from the fold dir next to this script)
here = os.path.dirname(os.path.abspath(__file__))
dst = os.path.join(ROOT, "app/services/dispute_notify.py")
if not os.path.exists(dst) or open(dst).read() != open(os.path.join(here, "dispute_notify.py")).read():
    shutil.copy2(os.path.join(here, "dispute_notify.py"), dst)
    print("  OK   app/services/dispute_notify.py (module copied)")
else:
    print("  SKIP app/services/dispute_notify.py (identical)")

# 1) alerts.py: dispute events into ALERT_EVENT_TYPES + DEFAULT_PUSH_EVENT_TYPES
disp_events = ('"dispute_opened","dispute_filed_against","dispute_needs_response",'
               '"dispute_creator_responded","dispute_response_reminder","dispute_resolved",'
               '"dispute_resolved_against","dispute_resolved_favor","dispute_withdrawn",'
               '"dispute_sla_expired","dispute_chargeback_opened","dispute_chargeback_evidence_due",'
               '"dispute_chargeback_lost","dispute_chargeback_won",')
mod_line = ('    "moderation_content_deleted","moderation_content_removed","moderation_content_hidden",'
            '"moderation_content_reinstated","moderation_content_restored","moderation_violation_confirmed",'
            '"moderation_hold_escalated","moderation_report_received","moderation_report_resolved",'
            '"moderation_poster_responded","moderation_warning","moderation_ban","moderation_sla_breach",'
            '"moderation_extortion_criminal_surge","dmca_claim_filed","dmca_content_restored",'
            '"dmca_counter_notice_received","dmca_repeat_infringer_ban",\n]')
disp_block = (mod_line[:-2]
              + '    # DISP-050: payment-dispute events (default-on transactional push).\n    '
              + disp_events + '\n]')
s = read("app/services/alerts.py")
if "dispute_opened" in s:
    print("  SKIP app/services/alerts.py (dispute events present)")
else:
    n = s.count(mod_line)
    if n != 2:
        print(f"  !! alerts.py mod_line occurrences={n} (expected 2)")
        raise SystemExit(2)
    write("app/services/alerts.py", s.replace(mod_line, disp_block))
    print("  OK   app/services/alerts.py (both lists patched)")

# 2) settings.py: master flag
patch("app/core/settings.py",
      '    dispute_chargeback_reconcile_enabled: bool = os.environ.get("DISPUTE_CHARGEBACK_RECONCILE_ENABLED", "1") not in ("0", "false", "False")\n',
      '    dispute_chargeback_reconcile_enabled: bool = os.environ.get("DISPUTE_CHARGEBACK_RECONCILE_ENABLED", "1") not in ("0", "false", "False")\n'
      '    # DISP-050 (E5) master flag for dispute notifications (alert + tappable push).\n'
      '    dispute_notifications_enabled: bool = os.environ.get("DISPUTE_NOTIFICATIONS_ENABLED", "1") not in ("0", "false", "False")\n',
      tag="dispute_notifications_enabled")

# 3) billing_disputes.py: file_dispute ack -> notify_opened both parties
patch("app/services/billing_disputes.py",
      '''    # Acknowledge to the payer.
    write_alert(
        user_id,
        event="dispute_opened",
        outcome="info",
        title="Your dispute was opened",
        details={"dispute_id": dispute_id, "amount_cents": int(amount_cents), "reason": reason},
        action_url=f"/billing/disputes/{dispute_id}",
    )''',
      '''    # DISP-050: ack the payer AND alert the creator/seller (tappable push, default-on).
    try:
        from app.services import dispute_notify as DN
        DN.notify_opened(
            dispute_id=dispute_id,
            payer_id=user_id,
            recipient_id=recipient_id or None,
            amount_cents=int(amount_cents),
            reason=reason,
            charge_type=charge_type or "",
        )
    except Exception:
        logger.warning("file_dispute: notify_opened failed for %s", dispute_id, exc_info=True)''',
      tag="notify_opened")

# 4) billing_disputes.py: resolve_dispute notify -> notify_resolved
patch("app/services/billing_disputes.py",
      '''    # -- STEP 3: notify the parties. --
    if payer_id:
        write_alert(
            payer_id, event="dispute_resolved", outcome="info",
            title=f"Your dispute was resolved ({res})",
            details={"dispute_id": dispute_id, "resolution": res, "refunded_cents": moved_cents},
            action_url=f"/billing/disputes/{dispute_id}",
        )
    if recipient_id and res in (DL.RESOLUTION_REFUNDED, DL.RESOLUTION_PARTIAL):
        write_alert(
            recipient_id, event="dispute_resolved_against", outcome="warning",
            title="A dispute was resolved in the buyer's favor",
            details={"dispute_id": dispute_id, "resolution": res, "clawback_cents": moved_cents},
            action_url=f"/creator/disputes/{dispute_id}",
        )''',
      '''    # -- STEP 3: DISP-050 notify BOTH parties per the terminal outcome (tappable push). --
    try:
        from app.services import dispute_notify as DN
        DN.notify_resolved(
            dispute_id=dispute_id,
            payer_id=payer_id or None,
            recipient_id=recipient_id or None,
            resolution=res,
            moved_cents=int(moved_cents),
        )
    except Exception:
        logger.warning("resolve_dispute: notify_resolved failed for %s", dispute_id, exc_info=True)''',
      tag="notify_resolved")

# 5) dispute_lifecycle.py: open_response_window invite -> notify_needs_response
patch("app/services/dispute_lifecycle.py",
      '''    if changed and creator_id:
        write_alert(
            creator_id,
            event="dispute_response_invited",
            outcome="warning",
            title="A payment dispute needs your response",
            details={"dispute_id": dispute_id, "respond_by": respond_by, "reason": reason},
            action_url=f"/creator/disputes/{dispute_id}",
        )
        audit_event("billing_dispute_response_invited", creator_id, None,
                    outcome="info", dispute_id=dispute_id, respond_by=respond_by)''',
      '''    if changed and creator_id:
        # DISP-050: invite the creator/seller into the window with a tappable push.
        try:
            from app.services import dispute_notify as DN
            DN.notify_needs_response(
                dispute_id=dispute_id,
                recipient_id=creator_id,
                amount_cents=int(amount_cents),
                respond_by=respond_by,
                reason=reason,
            )
        except Exception:
            logger.warning("open_response_window: notify failed for %s", dispute_id, exc_info=True)
        audit_event("billing_dispute_response_invited", creator_id, None,
                    outcome="info", dispute_id=dispute_id, respond_by=respond_by)''',
      tag="notify_needs_response")

# 6) dispute_lifecycle.py: record_creator_response in-window -> notify payer
patch("app/services/dispute_lifecycle.py",
      '''    if status == STATE_NEEDS_RESPONSE:
        DD.guarded_dispute_transition(dispute_id, STATE_UNDER_REVIEW,
                                      expected_from=[STATE_NEEDS_RESPONSE])

    audit_event("billing_dispute_creator_responded", creator_id, None,''',
      '''    if status == STATE_NEEDS_RESPONSE:
        DD.guarded_dispute_transition(dispute_id, STATE_UNDER_REVIEW,
                                      expected_from=[STATE_NEEDS_RESPONSE])
        # DISP-050: tell the payer the counterparty responded + it is under review.
        try:
            from app.services import dispute_notify as DN
            DN.notify_creator_responded(dispute_id=dispute_id, payer_id=str(item.get("user_id") or "") or None)
        except Exception:
            logger.warning("record_creator_response: notify failed for %s", dispute_id, exc_info=True)

    audit_event("billing_dispute_creator_responded", creator_id, None,''',
      tag="notify_creator_responded")

# 7) dispute_chargeback.py: on_incident_transition -> chargeback opened/terminal notify
patch("app/services/dispute_chargeback.py",
      '''            except Exception:
                logger.exception("link_and_moot hook failed incident=%s", incident.get("incident_id"))
            return {"hold": hold, "link": link}
        if status in _TERMINAL:
            return {"reconcile": reconcile_terminal(incident, status, actor=actor)}''',
      '''            except Exception:
                logger.exception("link_and_moot hook failed incident=%s", incident.get("incident_id"))
            # DISP-050: tell the creator/seller a chargeback opened (funds held) +
            # evidence is due -- tappable push, best-effort.
            try:
                from app.services import dispute_notify as DN
                charge = resolve_incident_charge(incident)
                rid = charge.get("recipient_id")
                if rid:
                    DN.notify_chargeback_opened(
                        incident_id=str(incident.get("incident_id") or ""),
                        recipient_id=rid,
                        amount_cents=_chargeback_amount_cents(incident),
                        charge_type=charge.get("charge_type") or "",
                        respond_by=response_due_at(incident),
                    )
                    DN.notify_evidence_due(
                        incident_id=str(incident.get("incident_id") or ""),
                        recipient_id=rid,
                        due_at=response_due_at(incident),
                    )
            except Exception:
                logger.warning("chargeback-opened notify failed incident=%s", incident.get("incident_id"), exc_info=True)
            return {"hold": hold, "link": link}
        if status in _TERMINAL:
            rec = reconcile_terminal(incident, status, actor=actor)
            # DISP-050: notify the creator of the terminal outcome (lost/won).
            try:
                from app.services import dispute_notify as DN
                charge = resolve_incident_charge(incident)
                rid = charge.get("recipient_id")
                if rid:
                    DN.notify_chargeback_terminal(
                        incident_id=str(incident.get("incident_id") or ""),
                        recipient_id=rid,
                        outcome=status,
                        clawback_cents=int(rec.get("clawback_cents", 0) or 0),
                        fee_cents=int(rec.get("chargeback_fee_cents", 0) or 0),
                    )
            except Exception:
                logger.warning("chargeback-terminal notify failed incident=%s", incident.get("incident_id"), exc_info=True)
            return {"reconcile": rec}''',
      tag='DISP-050: tell the creator/seller a chargeback opened')

# 8) subscription_server.py: DISP-052 dispute-event ignore
patch("app/routers/subscription_server.py",
      '''    ts = now_ts()
    event_type = body.event_type.lower()
    sub_plan = ddb_get_item(pk_plan(sub.get("plan_id")), "META") or {"plan_id": sub.get("plan_id")}
    if event_type in ("invoice.proration", "subscription.proration"):''',
      '''    ts = now_ts()
    event_type = body.event_type.lower()
    sub_plan = ddb_get_item(pk_plan(sub.get("plan_id")), "META") or {"plan_id": sub.get("plan_id")}
    # DISP-052: the subscription webhook seam does NOT own chargeback/dispute events.
    # charge.dispute.* is owned SOLELY by the PaymentIncident endpoint
    # (POST /api/billing/webhooks/stripe, secret STRIPE_WEBHOOK_SECRET) so one
    # charge.dispute event drives exactly one ledger path. Here (secret
    # SUBSCRIPTION_WEBHOOK_SECRET) any dispute/chargeback event is an explicit
    # audited no-op -- the WEBHOOK# row above is retained for trace, nothing mutates.
    if event_type.startswith("charge.dispute") or event_type.startswith("charge.refund") or "dispute" in event_type or "chargeback" in event_type:
        return {"ok": True, "event_id": event_id, "ignored": "dispute_event_owned_by_payment_incidents"}
    if event_type in ("invoice.proration", "subscription.proration"):''',
      tag="dispute_event_owned_by_payment_incidents")

print("\nBACKUPS ->", BAK)
print("CHANGED  ->", changed or "(nothing; all already present)")
print("APPLY OK")
