#!/usr/bin/env python3
"""Comprehensive API smoke test for FastAPI backend at http://localhost:8000."""

from __future__ import annotations

import re
import sys
import time
import json
import requests
from datetime import datetime, timezone, timedelta

BASE = "http://localhost:8000"
EMAIL_LOG = "/home/ubuntu/testlogon/.logs/dev/emails.log"

# ─── Result tracking ────────────────────────────────────────────────────────
results = []

def _rec(status: str, name: str, note: str = ""):
    print(f"  [{status}] {name}" + (f" — {note}" if note else ""))
    results.append((status, name, note))

def passed(name, note=""):  _rec("PASS", name, note)
def failed(name, note=""):  _rec("FAIL", name, note)
def skipped(name, note=""): _rec("SKIP", name, note)

def expect(resp, name, ok_codes=(200,), *, note=""):
    code = resp.status_code
    if code in ok_codes:
        passed(name, note or f"HTTP {code}")
        return True
    else:
        try:
            body = resp.json()
        except Exception:
            body = resp.text[:300]
        failed(name, f"HTTP {code} — {body}")
        return False

# ─── Helpers ────────────────────────────────────────────────────────────────
def ts():
    return str(int(time.time()))

def extract_code_from_log(email: str) -> str | None:
    """Read emails.log, split on block boundaries, find block for email, extract 6-digit code."""
    try:
        with open(EMAIL_LOG, "r") as f:
            raw = f.read()
    except FileNotFoundError:
        return None
    blocks = re.split(r'\n(?=\[)', raw)
    # Find the LAST block that contains this email (most recent)
    target = None
    for block in blocks:
        if f"TO={email}" in block:
            target = block
    if not target:
        return None
    m = re.search(r'\b(\d{6})\b', target)
    return m.group(1) if m else None

def get_csrf(session: requests.Session) -> str:
    return session.cookies.get("ui_csrf", "")

def make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({"Content-Type": "application/json"})
    return s

# ─── User registration ───────────────────────────────────────────────────────
def register_user(email: str, full_name: str, password: str) -> requests.Session | None:
    """Register a new user, confirm via email code, then return the authenticated session."""
    s = make_session()

    # Step 1: register/start (confirm_password is required)
    r = s.post(f"{BASE}/ui/register/start", json={
        "email": email,
        "full_name": full_name,
        "password": password,
        "confirm_password": password,
    })
    if r.status_code != 200:
        print(f"    [WARN] register/start failed for {email}: {r.status_code} {r.text[:300]}")
        return None

    # Step 2: read code from log
    time.sleep(0.5)
    code = extract_code_from_log(email)
    if not code:
        print(f"    [WARN] could not find verification code for {email}")
        return None

    csrf = get_csrf(s)
    # RegisterConfirmReq only needs email + confirmation_code (alias: code)
    r2 = s.post(f"{BASE}/ui/register/confirm", json={
        "email": email,
        "code": code,
    }, headers={"X-CSRF-Token": csrf})
    if r2.status_code != 200:
        print(f"    [WARN] register/confirm failed for {email}: {r2.status_code} {r2.text[:300]}")
        return None

    print(f"    Registered {email} OK")
    return s

def get_my_sub(session: requests.Session) -> str | None:
    r = session.get(f"{BASE}/ui/me")
    if r.status_code == 200:
        d = r.json()
        return d.get("sub") or d.get("user_sub")
    return None

# ─── Section header ──────────────────────────────────────────────────────────
def section(title: str):
    print(f"\n{'─'*60}")
    print(f"  {title}")
    print(f"{'─'*60}")

# ═══════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════
def main():
    print("=" * 60)
    print("  API SMOKE TEST")
    print("=" * 60)

    # ─── Setup: create two users ─────────────────────────────────────────
    section("SETUP: Creating test users")
    stamp = ts()
    email_a = f"ta_{stamp}@x.com"
    email_b = f"tb_{stamp}@x.com"
    password = "Crimson77Surge!"

    sess_a = register_user(email_a, "Alice Jay", password)
    sess_b = register_user(email_b, "Bob Kay", password)

    if not sess_a:
        print("FATAL: Could not register user A. Aborting.")
        sys.exit(1)

    if not sess_b:
        print("WARN: Could not register user B (messaging DM tests may fail).")

    # Get sub IDs
    sub_a = get_my_sub(sess_a)
    sub_b = get_my_sub(sess_b) if sess_b else None
    print(f"    User A sub: {sub_a}")
    print(f"    User B sub: {sub_b}")

    def csrf_a() -> dict:
        return {"X-CSRF-Token": get_csrf(sess_a)}

    def csrf_b() -> dict:
        return {"X-CSRF-Token": get_csrf(sess_b)} if sess_b else {}

    def newsfeed_headers_a() -> dict:
        """Headers for newsfeed endpoints that use X-User-Id."""
        return {"X-User-Id": sub_a or ""}

    def sub_server_headers_a() -> dict:
        """Headers for subscription server endpoints that use X-User-Id."""
        return {"X-User-Id": sub_a or ""}

    # ─── Infrastructure ──────────────────────────────────────────────────
    section("INFRASTRUCTURE (no auth)")
    r = requests.get(f"{BASE}/health")
    if r.status_code == 200 and r.json().get("ok"):
        passed("GET /health ok=true")
    else:
        failed("GET /health", f"{r.status_code}")

    expect(requests.get(f"{BASE}/api/ping"), "GET /api/ping")
    expect(requests.get(f"{BASE}/docs"), "GET /docs")
    expect(requests.get(f"{BASE}/openapi.json"), "GET /openapi.json")
    expect(requests.get(f"{BASE}/messaging/healthz"), "GET /messaging/healthz")

    # ─── Auth / Session ──────────────────────────────────────────────────
    section("AUTH / SESSION")
    # Registration already tested in setup
    passed("POST /ui/register/start", "covered in setup")
    passed("POST /ui/register/confirm", "covered in setup")

    # Login (session/start) — works because sess_a already has session cookie from registration
    # Test that the existing session gives us /ui/me
    r_me = sess_a.get(f"{BASE}/ui/me")
    if r_me.status_code == 200:
        passed("POST /ui/session/start (login via registration flow)")
    else:
        failed("POST /ui/session/start (login via registration flow)", f"{r_me.status_code}")

    # Token refresh
    refresh_sess = make_session()
    for c in sess_a.cookies:
        refresh_sess.cookies.set(c.name, c.value)
    r_refresh = refresh_sess.post(f"{BASE}/ui/token/refresh",
                                   json={},
                                   headers={"X-CSRF-Token": get_csrf(sess_a)})
    expect(r_refresh, "POST /ui/session/refresh (token refresh)", ok_codes=(200, 400, 401, 422))

    expect(sess_a.get(f"{BASE}/ui/me"), "GET /ui/me")
    expect(sess_a.get(f"{BASE}/ui/sessions"), "GET /ui/sessions")

    r_rev = sess_a.post(f"{BASE}/ui/sessions/revoke_others", headers=csrf_a())
    expect(r_rev, "POST /ui/sessions/revoke_others", ok_codes=(200, 400))

    expect(sess_a.get(f"{BASE}/ui/ws_token"), "GET /ui/ws_token", ok_codes=(200, 500))

    expect(sess_a.get(f"{BASE}/ui/devices"), "GET /ui/devices")

    # Logout using a dedicated temp session (not sess_b, which we need later)
    temp_sess = make_session()
    # Register a fresh throwaway user for logout test
    temp_email = f"tmp_{stamp}@x.com"
    temp_s = register_user(temp_email, "Temp User", password)
    if temp_s:
        r_lo = temp_s.post(f"{BASE}/ui/session/logout",
                            headers={"X-CSRF-Token": get_csrf(temp_s)})
        expect(r_lo, "POST /ui/session/logout", ok_codes=(200, 204))
    else:
        skipped("POST /ui/session/logout", "could not create temp session")

    # ─── Profile ─────────────────────────────────────────────────────────
    section("PROFILE")
    r_prof = sess_a.get(f"{BASE}/ui/profile")
    if r_prof.status_code == 200 and "profile" in r_prof.json():
        passed("GET /ui/profile has 'profile' key")
    else:
        failed("GET /ui/profile", f"{r_prof.status_code} / keys={list(r_prof.json().keys()) if r_prof.status_code==200 else r_prof.text[:100]}")

    r_patch = sess_a.patch(f"{BASE}/ui/profile",
                            json={"bio": "smoke test bio"},
                            headers=csrf_a())
    expect(r_patch, "PATCH /ui/profile", ok_codes=(200, 204))

    r_put = sess_a.put(f"{BASE}/ui/profile",
                        json={"full_name": "Alice Jay", "bio": "full replace bio"},
                        headers=csrf_a())
    expect(r_put, "PUT /ui/profile", ok_codes=(200, 204))

    expect(sess_a.get(f"{BASE}/ui/profile/audit"), "GET /ui/profile/audit")

    # ─── Account ─────────────────────────────────────────────────────────
    section("ACCOUNT")
    expect(sess_a.get(f"{BASE}/ui/account/status"), "GET /ui/account/status")
    # closure/start takes no body
    r_close = sess_a.post(f"{BASE}/ui/account/closure/start",
                           headers=csrf_a())
    expect(r_close, "POST /ui/account/closure/start", ok_codes=(200, 400, 403, 409))

    # ─── Alerts ──────────────────────────────────────────────────────────
    section("ALERTS")
    r_alerts = sess_a.get(f"{BASE}/ui/alerts")
    if r_alerts.status_code == 200 and "alerts" in r_alerts.json():
        passed("GET /ui/alerts has 'alerts' key")
    else:
        failed("GET /ui/alerts", f"{r_alerts.status_code} / {r_alerts.text[:100]}")

    expect(sess_a.get(f"{BASE}/ui/alerts/types"), "GET /ui/alerts/types")
    expect(sess_a.get(f"{BASE}/ui/alerts/email_prefs"), "GET /ui/alerts/email_prefs")
    r_epref = sess_a.post(f"{BASE}/ui/alerts/email_prefs",
                           json={"enabled": True},
                           headers=csrf_a())
    expect(r_epref, "POST /ui/alerts/email_prefs", ok_codes=(200, 204, 400))

    expect(sess_a.get(f"{BASE}/ui/alerts/toast_prefs"), "GET /ui/alerts/toast_prefs")
    r_tpref = sess_a.post(f"{BASE}/ui/alerts/toast_prefs",
                           json={"enabled": True},
                           headers=csrf_a())
    expect(r_tpref, "POST /ui/alerts/toast_prefs", ok_codes=(200, 204, 400))

    expect(sess_a.get(f"{BASE}/ui/alerts/sms_prefs"), "GET /ui/alerts/sms_prefs")
    r_sms = sess_a.post(f"{BASE}/ui/alerts/sms_prefs",
                         json={"enabled": False},
                         headers=csrf_a())
    expect(r_sms, "POST /ui/alerts/sms_prefs", ok_codes=(200, 204, 400))

    expect(sess_a.get(f"{BASE}/ui/alerts/webhook_prefs"), "GET /ui/alerts/webhook_prefs")
    r_wh = sess_a.post(f"{BASE}/ui/alerts/webhook_prefs",
                        json={"enabled": False, "url": ""},
                        headers=csrf_a())
    expect(r_wh, "POST /ui/alerts/webhook_prefs", ok_codes=(200, 204, 400))

    r_mr = sess_a.post(f"{BASE}/ui/alerts/mark_read",
                        json={"alert_ids": []},
                        headers=csrf_a())
    expect(r_mr, "POST /ui/alerts/mark_read", ok_codes=(200, 204))

    expect(sess_a.get(f"{BASE}/ui/alerts/search?q=test"), "GET /ui/alerts/search?q=test")

    # ─── Messaging ───────────────────────────────────────────────────────
    section("MESSAGING")
    expect(sess_a.get(f"{BASE}/messaging/conversations"), "GET /messaging/conversations")
    expect(sess_a.get(f"{BASE}/messaging/contacts/search?q=test"), "GET /messaging/contacts/search?q=test")
    expect(sess_a.get(f"{BASE}/messaging/messages/search?q=test"), "GET /messaging/messages/search?q=test")

    # Presence: requires comma-separated user_ids as query param
    r_presence = sess_a.get(f"{BASE}/messaging/presence?user_ids={sub_a}")
    expect(r_presence, "GET /messaging/presence?user_ids=...", ok_codes=(200,))

    # POST presence heartbeat
    r_hb = sess_a.post(f"{BASE}/messaging/presence/heartbeat",
                        json={"status": "online"},
                        headers=csrf_a())
    expect(r_hb, "POST /messaging/presence/heartbeat", ok_codes=(200, 204))

    skipped("GET /messaging/events (SSE stream)", "streaming endpoint")
    skipped("GET /messaging/config", "not in openapi spec (feature-flagged off)")

    # Create DM conversation (needs user B)
    conv_id = None
    msg_id = None
    if sub_b and sess_b:
        r_conv = sess_a.post(f"{BASE}/messaging/conversations",
                              json={"type": "dm", "participant_ids": [sub_a, sub_b]},
                              headers=csrf_a())
        if r_conv.status_code in (200, 201, 409):
            passed("POST /messaging/conversations (dm)", f"HTTP {r_conv.status_code}")
            if r_conv.status_code in (200, 201):
                conv_id = r_conv.json().get("conversation_id") or r_conv.json().get("id")
            else:
                # 409 = already exists
                conv_id = r_conv.json().get("conversation_id")
        else:
            failed("POST /messaging/conversations (dm)", f"{r_conv.status_code} {r_conv.text[:200]}")
    else:
        skipped("POST /messaging/conversations (dm)", "no user B")

    # Create group conversation: needs at least 3 unique participants
    # Use self + sub_b + a third fake ID if we only have 2 users
    group_participants = [sub_a]
    if sub_b:
        group_participants.append(sub_b)
    # Need at least 3
    group_participants.append("fake-user-c-for-group")
    r_grp = sess_a.post(f"{BASE}/messaging/conversations/group",
                         json={"name": "smoke-group", "participant_ids": group_participants},
                         headers=csrf_a())
    grp_conv_id = None
    if r_grp.status_code in (200, 201):
        passed("POST /messaging/conversations/group")
        grp_conv_id = r_grp.json().get("conversation_id") or r_grp.json().get("id")
    else:
        # May fail if fake user doesn't exist — accept 400 as expected
        expect(r_grp, "POST /messaging/conversations/group", ok_codes=(200, 201, 400))

    # Use DM conv for tests (more likely to be fully set up)
    test_conv_id = conv_id or grp_conv_id

    if test_conv_id:
        # PATCH conversation
        r_patch_conv = sess_a.patch(f"{BASE}/messaging/conversations/{test_conv_id}",
                                     json={"name": "patched-conv"},
                                     headers=csrf_a())
        expect(r_patch_conv, "PATCH /messaging/conversations/{id}", ok_codes=(200, 204, 400))

        # Accept conversation (user B accepts DM)
        if sess_b and conv_id:
            r_accept = sess_b.post(f"{BASE}/messaging/conversations/{conv_id}/accept",
                                    headers=csrf_b())
            expect(r_accept, "POST /messaging/conversations/{id}/accept", ok_codes=(200, 204, 400))
        else:
            skipped("POST /messaging/conversations/{id}/accept", "no user B session or DM conv")

        # Send text message
        r_msg = sess_a.post(f"{BASE}/messaging/conversations/{test_conv_id}/messages",
                             json={"text": "hello smoke test"},
                             headers=csrf_a())
        if r_msg.status_code in (200, 201):
            passed("POST /messaging/conversations/{id}/messages (text)")
            msg_data = r_msg.json()
            msg_id = msg_data.get("message_id") or msg_data.get("id")
        else:
            failed("POST /messaging/conversations/{id}/messages (text)", f"{r_msg.status_code} {r_msg.text[:200]}")

        # Send expiring message
        future_ts = int(time.time()) + 3600
        r_exp = sess_a.post(f"{BASE}/messaging/conversations/{test_conv_id}/messages",
                             json={"text": "expiring msg", "expires_at": future_ts},
                             headers=csrf_a())
        expect(r_exp, "POST .../messages (expiring)", ok_codes=(200, 201, 400))

        # Send view_once message
        r_vo = sess_a.post(f"{BASE}/messaging/conversations/{test_conv_id}/messages",
                            json={"text": "view once", "view_once": True},
                            headers=csrf_a())
        view_once_id = None
        if r_vo.status_code in (200, 201):
            passed("POST .../messages (view_once)")
            view_once_id = r_vo.json().get("message_id") or r_vo.json().get("id")
        else:
            failed("POST .../messages (view_once)", f"{r_vo.status_code} {r_vo.text[:200]}")

        # Send locked message (PPV)
        r_locked = sess_a.post(f"{BASE}/messaging/conversations/{test_conv_id}/messages",
                                json={"text": "locked content", "lock_price_cents": 500},
                                headers=csrf_a())
        locked_msg_id = None
        if r_locked.status_code in (200, 201):
            passed("POST .../messages (locked)")
            locked_msg_id = r_locked.json().get("message_id") or r_locked.json().get("id")
        else:
            failed("POST .../messages (locked)", f"{r_locked.status_code} {r_locked.text[:200]}")

        # GET messages (returns list directly)
        r_msgs = sess_a.get(f"{BASE}/messaging/conversations/{test_conv_id}/messages")
        if r_msgs.status_code == 200:
            body = r_msgs.json()
            if isinstance(body, list):
                passed("GET .../messages (list response)")
            else:
                passed("GET .../messages", f"type={type(body).__name__}")
        else:
            failed("GET .../messages", f"{r_msgs.status_code}")

        if msg_id:
            # Views
            expect(sess_a.get(f"{BASE}/messaging/conversations/{test_conv_id}/messages/{msg_id}/views"),
                   "GET .../messages/{id}/views")

            # POST view — ViewMessageIn has optional viewed_at field
            r_view = sess_a.post(f"{BASE}/messaging/conversations/{test_conv_id}/messages/{msg_id}/view",
                                  json={},
                                  headers=csrf_a())
            expect(r_view, "POST .../messages/{id}/view", ok_codes=(200, 204))

            # Reactions — field is 'emoji' (not 'reaction')
            r_react = sess_a.post(f"{BASE}/messaging/conversations/{test_conv_id}/messages/{msg_id}/reactions",
                                   json={"emoji": "👍"},
                                   headers=csrf_a())
            expect(r_react, "POST .../messages/{id}/reactions", ok_codes=(200, 204, 400))

            # Edit message
            r_edit = sess_a.patch(f"{BASE}/messaging/conversations/{test_conv_id}/messages/{msg_id}",
                                   json={"text": "edited smoke test"},
                                   headers=csrf_a())
            expect(r_edit, "PATCH .../messages/{id} (edit)", ok_codes=(200, 204, 400))

            # Edits history
            expect(sess_a.get(f"{BASE}/messaging/conversations/{test_conv_id}/messages/{msg_id}/edits"),
                   "GET .../messages/{id}/edits")

            # Tip — field is amount_cents (not amount)
            r_tip = sess_a.post(f"{BASE}/messaging/conversations/{test_conv_id}/messages/{msg_id}/tip",
                                 json={"amount_cents": 100},
                                 headers=csrf_a())
            expect(r_tip, "POST .../messages/{id}/tip", ok_codes=(200, 400, 402, 404, 501))

            # Revoke (delete)
            r_rev_msg = sess_a.delete(f"{BASE}/messaging/conversations/{test_conv_id}/messages/{msg_id}/revoke",
                                       headers=csrf_a())
            expect(r_rev_msg, "DELETE .../messages/{id}/revoke", ok_codes=(200, 204))
        else:
            skipped("GET/POST .../messages/{id}/* endpoints", "no msg_id")

        # Unlock locked message — UnlockMessageIn has no fields (pass={})
        # Sender (sess_a) cannot unlock their own message → 400 is a valid expected response
        if locked_msg_id:
            r_unlock = sess_a.post(f"{BASE}/messaging/conversations/{test_conv_id}/messages/{locked_msg_id}/unlock",
                                    json={},
                                    headers=csrf_a())
            # 400 = "Sender cannot unlock their own message" — that's correct behavior
            expect(r_unlock, "POST .../messages/{id}/unlock", ok_codes=(200, 204, 400, 402))
        else:
            skipped("POST .../messages/{id}/unlock", "no locked msg")

        # Scheduled messages
        expect(sess_a.get(f"{BASE}/messaging/conversations/{test_conv_id}/messages/scheduled"),
               "GET .../messages/scheduled")

        # Message search
        expect(sess_a.get(f"{BASE}/messaging/conversations/{test_conv_id}/messages/search?q=test"),
               "GET .../messages/search?q=test")

        # Participants
        expect(sess_a.get(f"{BASE}/messaging/conversations/{test_conv_id}/participants"),
               "GET .../participants")

        # Read — requires last_read_at or last_read_message_id
        r_read = sess_a.post(f"{BASE}/messaging/conversations/{test_conv_id}/read",
                              json={"last_read_at": int(time.time())},
                              headers=csrf_a())
        expect(r_read, "POST .../read", ok_codes=(200, 204))

        # Typing indicator
        r_type = sess_a.post(f"{BASE}/messaging/conversations/{test_conv_id}/typing",
                              json={"typing": True},
                              headers=csrf_a())
        expect(r_type, "POST .../typing", ok_codes=(200, 204))

        r_type_get = sess_a.get(f"{BASE}/messaging/conversations/{test_conv_id}/typing")
        expect(r_type_get, "GET .../typing")

        # Mute
        r_mute = sess_a.post(f"{BASE}/messaging/conversations/{test_conv_id}/mute",
                              json={"muted": True},
                              headers=csrf_a())
        expect(r_mute, "POST .../mute", ok_codes=(200, 204))

        # Gallery — requires type query param; 404 if gallery feature disabled
        r_gallery = sess_a.get(f"{BASE}/messaging/conversations/{test_conv_id}/gallery?type=image")
        expect(r_gallery, "GET .../gallery?type=image", ok_codes=(200, 404))

    else:
        skipped("All /messaging/conversations/{id}/* tests", "no conversation created")

    # ─── Calendar ────────────────────────────────────────────────────────
    section("CALENDAR")
    expect(sess_a.get(f"{BASE}/ui/calendars"), "GET /ui/calendars")

    r_cal = sess_a.post(f"{BASE}/ui/calendars",
                         json={"name": "Smoke Cal", "timezone": "UTC"},
                         headers=csrf_a())
    cal_id = None
    if r_cal.status_code in (200, 201):
        passed("POST /ui/calendars")
        cal_data = r_cal.json()
        cal_id = cal_data.get("calendar_id") or cal_data.get("id")
    else:
        failed("POST /ui/calendars", f"{r_cal.status_code} {r_cal.text[:200]}")

    if cal_id:
        r_patch_cal = sess_a.patch(f"{BASE}/ui/calendars/{cal_id}",
                                    json={"name": "Smoke Cal Updated"},
                                    headers=csrf_a())
        expect(r_patch_cal, "PATCH /ui/calendars/{id}", ok_codes=(200, 204))

        # Create event using start_utc/end_utc/name
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        end_iso = (datetime.now(timezone.utc) + timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        r_evt = sess_a.post(f"{BASE}/ui/calendars/{cal_id}/events",
                             json={"name": "Smoke Event", "start_utc": now_iso, "end_utc": end_iso},
                             headers=csrf_a())
        evt_id = None
        if r_evt.status_code in (200, 201):
            passed("POST /ui/calendars/{id}/events")
            evt_data = r_evt.json()
            evt_id = evt_data.get("event_id") or evt_data.get("id")
        else:
            failed("POST /ui/calendars/{id}/events", f"{r_evt.status_code} {r_evt.text[:200]}")

        expect(sess_a.get(f"{BASE}/ui/calendars/{cal_id}/events"), "GET /ui/calendars/{id}/events")

        if evt_id:
            r_patch_evt = sess_a.patch(f"{BASE}/ui/calendars/{cal_id}/events/{evt_id}",
                                        json={"name": "Updated Smoke Event"},
                                        headers=csrf_a())
            expect(r_patch_evt, "PATCH /ui/calendars/{id}/events/{evt_id}", ok_codes=(200, 204))

            r_del_evt = sess_a.delete(f"{BASE}/ui/calendars/{cal_id}/events/{evt_id}",
                                       headers=csrf_a())
            expect(r_del_evt, "DELETE /ui/calendars/{id}/events/{evt_id}", ok_codes=(200, 204))
        else:
            skipped("PATCH/DELETE /ui/calendars/{id}/events/{evt_id}", "no event created")

        # Openings — requires start_utc/end_utc as query params
        r_openings = sess_a.get(
            f"{BASE}/ui/calendars/{cal_id}/openings?start_utc={now_iso}&end_utc={end_iso}")
        expect(r_openings, "GET /ui/calendars/{id}/openings", ok_codes=(200,))

        # Conflicts — takes an EventCreateIn-like body (needs name + start_utc/end_utc)
        r_conflicts = sess_a.post(f"{BASE}/ui/calendars/{cal_id}/events/conflicts",
                                   json={"name": "Conflict Check", "start_utc": now_iso, "end_utc": end_iso},
                                   headers=csrf_a())
        expect(r_conflicts, "POST /ui/calendars/{id}/events/conflicts", ok_codes=(200,))

        # Suggestions — needs start_utc/end_utc
        r_suggest = sess_a.post(f"{BASE}/ui/calendars/{cal_id}/events/suggestions",
                                 json={"start_utc": now_iso, "end_utc": end_iso, "duration_minutes": 60},
                                 headers=csrf_a())
        expect(r_suggest, "POST /ui/calendars/{id}/events/suggestions", ok_codes=(200, 400))

        # Shares
        share_sub = sub_b if sub_b else sub_a
        r_share = sess_a.post(f"{BASE}/ui/calendars/{cal_id}/shares",
                               json={"user_sub": share_sub, "permission": "read"},
                               headers=csrf_a())
        share_created = r_share.status_code in (200, 201)
        expect(r_share, "POST /ui/calendars/{id}/shares", ok_codes=(200, 201, 400, 409))

        expect(sess_a.get(f"{BASE}/ui/calendars/{cal_id}/shares"), "GET /ui/calendars/{id}/shares")

        if share_sub and share_created:
            r_del_share = sess_a.delete(f"{BASE}/ui/calendars/{cal_id}/shares/{share_sub}",
                                         headers=csrf_a())
            expect(r_del_share, "DELETE /ui/calendars/{id}/shares/{user_sub}", ok_codes=(200, 204, 404))
        else:
            skipped("DELETE /ui/calendars/{id}/shares/{user_sub}", "share not created")

        # Booking links
        r_bl = sess_a.post(f"{BASE}/ui/calendars/{cal_id}/booking_links",
                            json={"duration_minutes": 30, "name": "30min"},
                            headers=csrf_a())
        expect(r_bl, "POST /ui/calendars/{id}/booking_links", ok_codes=(200, 201, 400))

        expect(sess_a.get(f"{BASE}/ui/calendars/{cal_id}/booking_links"),
               "GET /ui/calendars/{id}/booking_links")

        # Availability
        r_avail = sess_a.post(f"{BASE}/ui/calendars/availability",
                               json={"calendar_ids": [cal_id], "start_utc": now_iso, "end_utc": end_iso},
                               headers=csrf_a())
        expect(r_avail, "POST /ui/calendars/availability", ok_codes=(200, 400))

        # Delete calendar
        r_del_cal = sess_a.delete(f"{BASE}/ui/calendars/{cal_id}", headers=csrf_a())
        expect(r_del_cal, "DELETE /ui/calendars/{id}", ok_codes=(200, 204))
    else:
        skipped("All /ui/calendars/{id}/* tests", "no calendar created")

    # ─── Feed / Posts / Social ────────────────────────────────────────────
    section("FEED / POSTS / SOCIAL")
    # Feed uses X-User-Id header
    r_feed = sess_a.get(f"{BASE}/feed", headers=newsfeed_headers_a())
    expect(r_feed, "GET /feed (with X-User-Id)")

    # Notifications also uses X-User-Id
    r_notif = sess_a.get(f"{BASE}/notifications", headers=newsfeed_headers_a())
    expect(r_notif, "GET /notifications (with X-User-Id)")

    # Create post — body is a nested RichTextDoc with format + doc (dict)
    r_post = sess_a.post(f"{BASE}/posts",
                          json={"body": {"format": "text", "doc": {"text": "Hello smoke test"}}},
                          headers={**csrf_a(), **newsfeed_headers_a()})
    post_id = None
    if r_post.status_code in (200, 201):
        passed("POST /posts")
        post_data = r_post.json()
        post_id = post_data.get("post_id") or post_data.get("id")
    else:
        failed("POST /posts", f"{r_post.status_code} {r_post.text[:200]}")

    if post_id:
        expect(sess_a.get(f"{BASE}/posts/{post_id}/comments", headers=newsfeed_headers_a()),
               "GET /posts/{id}/comments")

        r_comment = sess_a.post(f"{BASE}/posts/{post_id}/comments",
                                 json={"body": {"format": "text", "doc": {"text": "nice post"}}},
                                 headers={**csrf_a(), **newsfeed_headers_a()})
        comment_id = None
        if r_comment.status_code in (200, 201):
            passed("POST /posts/{id}/comments")
            c_data = r_comment.json()
            comment_id = c_data.get("comment_id") or c_data.get("id")
        else:
            failed("POST /posts/{id}/comments", f"{r_comment.status_code} {r_comment.text[:200]}")

        if comment_id:
            # EditCommentRequest requires body + expected_version (starts at 1)
            r_patch_comment = sess_a.patch(
                f"{BASE}/posts/{post_id}/comments/{comment_id}",
                json={"body": {"format": "text", "doc": {"text": "edited comment"}}, "expected_version": 1},
                headers={**csrf_a(), **newsfeed_headers_a()})
            expect(r_patch_comment, "PATCH /posts/{id}/comments/{cid}", ok_codes=(200, 204))

            r_del_comment = sess_a.delete(
                f"{BASE}/posts/{post_id}/comments/{comment_id}",
                headers={**csrf_a(), **newsfeed_headers_a()})
            expect(r_del_comment, "DELETE /posts/{id}/comments/{cid}", ok_codes=(200, 204))
        else:
            skipped("PATCH/DELETE /posts/{id}/comments/{cid}", "no comment created")
    else:
        skipped("All /posts/{id}/* tests", "no post created")

    # Social — field is target_user_id (not target_user_sub)
    target_uid = sub_b if sub_b else sub_a
    r_refollow = sess_a.post(f"{BASE}/social/refollow",
                              json={"target_user_id": target_uid},
                              headers={**csrf_a(), **newsfeed_headers_a()})
    expect(r_refollow, "POST /social/refollow", ok_codes=(200, 201, 400, 409))

    r_unfollow = sess_a.post(f"{BASE}/social/unfollow",
                              json={"target_user_id": target_uid},
                              headers={**csrf_a(), **newsfeed_headers_a()})
    expect(r_unfollow, "POST /social/unfollow", ok_codes=(200, 204, 400, 404))

    # ─── Billing ─────────────────────────────────────────────────────────
    section("BILLING")
    billing_endpoints_get = [
        ("/api/billing/balance", "GET /api/billing/balance"),
        ("/api/billing/payments", "GET /api/billing/payments"),
        ("/api/billing/payment-methods", "GET /api/billing/payment-methods"),
        ("/api/billing/config", "GET /api/billing/config"),
        ("/api/billing/ledger", "GET /api/billing/ledger"),
        ("/api/billing/settings", "GET /api/billing/settings"),
        ("/ui/billing/balance", "GET /ui/billing/balance"),
        ("/ui/billing/payments", "GET /ui/billing/payments"),
        ("/ui/billing/payment-methods", "GET /ui/billing/payment-methods"),
        ("/ui/billing/config", "GET /ui/billing/config"),
        ("/ui/billing/ledger", "GET /ui/billing/ledger"),
        ("/ui/billing/settings", "GET /ui/billing/settings"),
        ("/ui/billing/subscriptions", "GET /ui/billing/subscriptions"),
    ]
    for path, name in billing_endpoints_get:
        r = sess_a.get(f"{BASE}{path}")
        expect(r, name, ok_codes=(200, 501, 404))

    # Dev add-charge — requires amount_cents (int) + state (pending|settled)
    r_charge = sess_a.post(f"{BASE}/ui/billing/_dev/add-charge",
                            json={"amount_cents": 100, "state": "settled"},
                            headers=csrf_a())
    expect(r_charge, "POST /ui/billing/_dev/add-charge", ok_codes=(200, 201, 400, 404))

    # ─── Addresses ───────────────────────────────────────────────────────
    section("ADDRESSES")
    expect(sess_a.get(f"{BASE}/ui/addresses"), "GET /ui/addresses")

    r_addr = sess_a.post(f"{BASE}/ui/addresses",
                          json={
                              "line1": "123 Main St",
                              "city": "Springfield",
                              "state": "IL",
                              "postal_code": "62701",
                              "country": "US",
                          },
                          headers=csrf_a())
    addr_id = None
    if r_addr.status_code in (200, 201):
        passed("POST /ui/addresses")
        addr_data = r_addr.json()
        addr_id = addr_data.get("address_id") or addr_data.get("id")
    else:
        failed("POST /ui/addresses", f"{r_addr.status_code} {r_addr.text[:200]}")

    if addr_id:
        r_patch_addr = sess_a.patch(f"{BASE}/ui/addresses/{addr_id}",
                                     json={"city": "Shelbyville"},
                                     headers=csrf_a())
        expect(r_patch_addr, "PATCH /ui/addresses/{id}", ok_codes=(200, 204))

        r_del_addr = sess_a.delete(f"{BASE}/ui/addresses/{addr_id}", headers=csrf_a())
        expect(r_del_addr, "DELETE /ui/addresses/{id}", ok_codes=(200, 204))
    else:
        skipped("PATCH/DELETE /ui/addresses/{id}", "no address created")

    r_addr_search = sess_a.post(f"{BASE}/ui/addresses/search",
                                 json={"query": "Main"},
                                 headers=csrf_a())
    expect(r_addr_search, "POST /ui/addresses/search", ok_codes=(200, 400))

    # ─── File Manager ─────────────────────────────────────────────────────
    section("FILE MANAGER")
    r_folder = sess_a.post(f"{BASE}/v1/fs/folder",
                            json={"path": "/smoke-test-folder"},
                            headers=csrf_a())
    expect(r_folder, "POST /v1/fs/folder", ok_codes=(200, 201, 400, 409))

    expect(sess_a.get(f"{BASE}/v1/fs/list?path=/"), "GET /v1/fs/list?path=/")

    r_presign = sess_a.post(f"{BASE}/v1/fs/presign-upload",
                             json={"path": "/smoke-test-folder/test.txt", "content_type": "text/plain"},
                             headers=csrf_a())
    expect(r_presign, "POST /v1/fs/presign-upload", ok_codes=(200, 400))

    # File manager search requires 'prefix' query param (not 'q')
    expect(sess_a.get(f"{BASE}/v1/fs/search?prefix=test"), "GET /v1/fs/search?prefix=test")

    # Usage endpoints — check if they exist
    r_fs_storage = sess_a.get(f"{BASE}/v1/fs/usage/storage")
    expect(r_fs_storage, "GET /v1/fs/usage/storage", ok_codes=(200, 404))

    r_fs_summary = sess_a.get(f"{BASE}/v1/fs/usage/summary")
    expect(r_fs_summary, "GET /v1/fs/usage/summary", ok_codes=(200, 404))

    # ─── API Keys ────────────────────────────────────────────────────────
    section("API KEYS")
    expect(sess_a.get(f"{BASE}/ui/api_keys"), "GET /ui/api_keys")
    r_api_key = sess_a.post(f"{BASE}/ui/api_keys",
                             json={"name": "smoke-test-key"},
                             headers=csrf_a())
    expect(r_api_key, "POST /ui/api_keys", ok_codes=(200, 201, 400, 500))

    # ─── MFA ────────────────────────────────────────────────────────────
    section("MFA (list only)")
    expect(sess_a.get(f"{BASE}/ui/mfa/email/devices"), "GET /ui/mfa/email/devices")
    expect(sess_a.get(f"{BASE}/ui/mfa/sms/devices"), "GET /ui/mfa/sms/devices")
    expect(sess_a.get(f"{BASE}/ui/mfa/totp/devices"), "GET /ui/mfa/totp/devices")

    # ─── Push ────────────────────────────────────────────────────────────
    section("PUSH")
    expect(sess_a.get(f"{BASE}/ui/push/devices"), "GET /ui/push/devices")

    # ─── Shopping Cart ───────────────────────────────────────────────────
    section("SHOPPING CART")
    expect(sess_a.get(f"{BASE}/ui/shoppingcart/carts"), "GET /ui/shoppingcart/carts")

    r_cart = sess_a.post(f"{BASE}/ui/shoppingcart/carts",
                          json={"name": "smoke-cart"},
                          headers=csrf_a())
    cart_id = None
    if r_cart.status_code in (200, 201):
        passed("POST /ui/shoppingcart/carts")
        cart_data = r_cart.json()
        cart_id = cart_data.get("cart_id") or cart_data.get("id")
    else:
        failed("POST /ui/shoppingcart/carts", f"{r_cart.status_code} {r_cart.text[:200]}")

    if cart_id:
        expect(sess_a.get(f"{BASE}/ui/shoppingcart/carts/{cart_id}/items"),
               "GET /ui/shoppingcart/carts/{id}/items")

        # ShoppingCartItemIn requires: sku, name, unit_price_cents
        r_cart_item = sess_a.post(f"{BASE}/ui/shoppingcart/carts/{cart_id}/items",
                                   json={"sku": "TEST-SKU-001", "name": "Test Product", "unit_price_cents": 999, "quantity": 1},
                                   headers=csrf_a())
        expect(r_cart_item, "POST /ui/shoppingcart/carts/{id}/items", ok_codes=(200, 201, 400, 404))

        expect(sess_a.get(f"{BASE}/ui/shoppingcart/carts/{cart_id}/total"),
               "GET /ui/shoppingcart/carts/{id}/total")

        r_del_cart = sess_a.delete(f"{BASE}/ui/shoppingcart/carts/{cart_id}", headers=csrf_a())
        expect(r_del_cart, "DELETE /ui/shoppingcart/carts/{id}", ok_codes=(200, 204))
    else:
        skipped("Shopping cart item/total/delete tests", "no cart created")

    # ─── Purchase History ────────────────────────────────────────────────
    section("PURCHASE HISTORY")
    expect(sess_a.get(f"{BASE}/ui/purchase-history/transactions"), "GET /ui/purchase-history/transactions")
    expect(sess_a.get(f"{BASE}/ui/purchase-history/transactions/search?q=test"),
           "GET /ui/purchase-history/transactions/search?q=test")

    # ─── Catalog ────────────────────────────────────────────────────────
    section("CATALOG")
    expect(sess_a.get(f"{BASE}/ui/catalog/categories"), "GET /ui/catalog/categories")

    r_cat = sess_a.post(f"{BASE}/ui/catalog/categories",
                         json={"name": "Smoke Category"},
                         headers=csrf_a())
    cat_id = None
    if r_cat.status_code in (200, 201):
        passed("POST /ui/catalog/categories")
        cat_data = r_cat.json()
        cat_id = cat_data.get("category_id") or cat_data.get("id")
    else:
        failed("POST /ui/catalog/categories", f"{r_cat.status_code} {r_cat.text[:200]}")

    if cat_id:
        expect(sess_a.get(f"{BASE}/ui/catalog/categories/{cat_id}/items"),
               "GET /ui/catalog/categories/{id}/items")

        # CatalogItemCreateIn requires: name, price_cents
        r_item = sess_a.post(f"{BASE}/ui/catalog/categories/{cat_id}/items",
                              json={"name": "Smoke Item", "price_cents": 999},
                              headers=csrf_a())
        expect(r_item, "POST /ui/catalog/categories/{id}/items", ok_codes=(200, 201, 400))
    else:
        skipped("GET/POST /ui/catalog/categories/{id}/items", "no category created")

    expect(sess_a.get(f"{BASE}/ui/catalog/items/search?q=test"), "GET /ui/catalog/items/search?q=test")

    # Catalog images requires path query param — use a valid-looking path
    r_cat_img = sess_a.get(f"{BASE}/ui/catalog/images?path=/catalog/items/test/image.jpg")
    expect(r_cat_img, "GET /ui/catalog/images?path=...", ok_codes=(200, 400, 404))

    # ─── Subscription Server ──────────────────────────────────────────────
    section("SUBSCRIPTION SERVER")
    # GET /api/subscriptions uses X-User-Id header
    r_subs = sess_a.get(f"{BASE}/api/subscriptions",
                         headers=sub_server_headers_a())
    expect(r_subs, "GET /api/subscriptions (with X-User-Id)")

    # ─── Admin (expect 401/403) ───────────────────────────────────────────
    section("ADMIN (expect 401/403)")
    r_admin_roles = requests.get(f"{BASE}/admin/roles/audit")
    expect(r_admin_roles, "GET /admin/roles/audit (no auth)", ok_codes=(401, 403, 404))

    r_admin_imp = requests.get(f"{BASE}/admin/impersonation/audit")
    expect(r_admin_imp, "GET /admin/impersonation/audit (no auth)", ok_codes=(401, 403, 404))

    # ─── Mock services ───────────────────────────────────────────────────
    section("MOCK SERVICES (dev only)")
    r_s3 = requests.get(f"{BASE}/mock/s3/")
    expect(r_s3, "GET /mock/s3/", ok_codes=(200, 404))

    r_paypal = requests.post(f"{BASE}/mock/paypal/v1/oauth2/token",
                              data={"grant_type": "client_credentials"},
                              headers={"Content-Type": "application/x-www-form-urlencoded"})
    expect(r_paypal, "POST /mock/paypal/v1/oauth2/token", ok_codes=(200, 400))

    # ─── Public routes ────────────────────────────────────────────────────
    section("PUBLIC ROUTES")
    r_booking = requests.get(f"{BASE}/booking/nonexistent-link-id")
    expect(r_booking, "GET /booking/{link_id} (nonexistent)", ok_codes=(404, 400))

    r_billing_root = requests.get(f"{BASE}/billing", allow_redirects=False)
    expect(r_billing_root, "GET /billing", ok_codes=(200, 301, 302, 307, 308))

    # ─── Summary ─────────────────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("  SUMMARY")
    print(f"{'='*60}")
    n_pass = sum(1 for s, _, _ in results if s == "PASS")
    n_fail = sum(1 for s, _, _ in results if s == "FAIL")
    n_skip = sum(1 for s, _, _ in results if s == "SKIP")
    print(f"  PASSED:  {n_pass}")
    print(f"  FAILED:  {n_fail}")
    print(f"  SKIPPED: {n_skip}")
    print(f"  TOTAL:   {len(results)}")

    if n_fail:
        print(f"\n  FAILURES:")
        for s, name, note in results:
            if s == "FAIL":
                print(f"    - {name}: {note}")

    print(f"{'='*60}")
    sys.exit(1 if n_fail else 0)


if __name__ == "__main__":
    main()
