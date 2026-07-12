#!/usr/bin/env python3
"""Seed a rich alice<->bob DM + a group chat for a messenger UX review.

Run AFTER `just restart`. Creates a realistic conversation exercising the main
message bubble types (text, encrypted, view-once, locked, reply) plus a group.
Prints per-call status so failures are visible.
"""
import json
import subprocess
import time
import urllib.error
import urllib.request

BASE = "http://localhost:8000"
TS = int(time.time())

raw = subprocess.check_output(
    ["python3", "/home/ubuntu/testlogon/e2e_admin_session_setup.py"],
    cwd="/home/ubuntu/testlogon", timeout=60,
).decode()
SESS = json.loads(raw[raw.index("{"):])


def _ident(key):
    s = SESS[key]
    cookie = "; ".join(f"{c['name']}={c['value']}" for c in s["cookies"])
    return cookie, s["csrf_token"], s["user_sub"]


ALICE_CK, ALICE_CSRF, ALICE_SUB = _ident("alice")
BOB_CK, BOB_CSRF, BOB_SUB = _ident("bob")
CHARLIE_CK, CHARLIE_CSRF, CHARLIE_SUB = _ident("charlie_admin")


def call(cookie, csrf, method, path, body=None, label=""):
    data = json.dumps(body).encode() if body is not None else None
    r = urllib.request.Request(f"{BASE}{path}", data=data, method=method)
    r.add_header("Cookie", cookie)
    r.add_header("Content-Type", "application/json")
    if method != "GET":
        r.add_header("x-csrf-token", csrf)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            out = json.loads(resp.read().decode() or "{}")
            st = resp.status
    except urllib.error.HTTPError as e:
        st, out = e.code, e.read().decode()[:200]
    except Exception as e:  # noqa
        st, out = 0, str(e)[:200]
    ok = "ok " if st in (200, 201) else "XX "
    detail = "" if st in (200, 201) else f"  -> {out}"
    print(f"  {ok}{st} {label}{detail}")
    return out if isinstance(out, dict) else {}


def alice(method, path, body=None, label=""):
    return call(ALICE_CK, ALICE_CSRF, method, path, body, label)


def bob(method, path, body=None, label=""):
    return call(BOB_CK, BOB_CSRF, method, path, body, label)


def charlie(method, path, body=None, label=""):
    return call(CHARLIE_CK, CHARLIE_CSRF, method, path, body, label)


ENVELOPE = {
    "version": 1, "alg": "AES-256-GCM", "kdf": "PBKDF2-SHA256",
    "iterations": 600000, "salt_b64": "AAAAAAAAAAAAAAAAAAAAAA==",
    "iv_b64": "AAAAAAAAAAAAAAAA",
    "ciphertext_b64": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
}

import base64
import io


def _demo_png(label="VENUE", size=(640, 400), color=(37, 99, 235)):
    """A real, visible demo image (PIL); falls back to a 1x1 PNG if PIL absent."""
    try:
        from PIL import Image, ImageDraw  # noqa
        img = Image.new("RGB", size, color)
        d = ImageDraw.Draw(img)
        d.rectangle([8, 8, size[0] - 8, size[1] - 8], outline=(255, 255, 255), width=4)
        d.text((size[0] // 2 - 40, size[1] // 2 - 8), label, fill=(255, 255, 255))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except Exception:
        return base64.b64decode(
            "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="
        )


_PNG = _demo_png()


def upload_image(cookie, csrf, conversation_id, filename="photo.png"):
    """presign + PUT a PNG; return (bucket, key) or (None, None)."""
    pres = call(cookie, csrf, "POST", f"/messaging/conversations/{conversation_id}/images/presign",
                {"content_type": "image/png", "filename": filename}, f"presign {filename}")
    if not pres.get("upload_url"):
        return None, None
    try:
        r = urllib.request.Request(BASE + pres["upload_url"], data=_PNG, method="PUT",
                                   headers={"Content-Type": "image/png"})
        urllib.request.urlopen(r, timeout=30)
    except Exception as e:  # noqa
        print(f"  XX PUT image failed: {str(e)[:120]}")
        return None, None
    return pres.get("bucket"), pres.get("key")

print("== DM alice <-> bob ==")
dm = alice("POST", "/messaging/conversations/dm/find-or-create",
           {"user_id": BOB_SUB}, "create DM")
cid = dm.get("conversation_id")
if cid:
    first = alice("POST", f"/messaging/conversations/{cid}/messages",
                  {"text": "Hey Bob! Did you get a chance to review the Q3 rollout plan?"},
                  "alice text 1")
    first_id = first.get("message_id")
    bob("POST", f"/messaging/conversations/{cid}/messages",
        {"text": "Morning! Yes — looks solid. Left a couple of notes on the timeline.",
         **({"reply_to_message_id": first_id} if first_id else {})}, "bob reply")
    alice("POST", f"/messaging/conversations/{cid}/messages",
          {"text": "Perfect, thanks. Sending the signed NDA over now."}, "alice text 2")
    alice("POST", f"/messaging/conversations/{cid}/messages",
          {"encryption": ENVELOPE, "text": None}, "alice encrypted")
    alice("POST", f"/messaging/conversations/{cid}/messages",
          {"text": "Here's the one-time access code: 4F9-22K", "view_once": True},
          "alice view-once")
    alice("POST", f"/messaging/conversations/{cid}/messages",
          {"text": "Full competitive teardown (12 pages) — unlock to read.",
           "lock_price_cents": 500, "lock_description": "Competitive teardown"},
          "alice locked")
    bob("POST", f"/messaging/conversations/{cid}/messages",
        {"text": "Awesome. Let's sync live tomorrow 👍"}, "bob text 2")

    # Image message (alice)
    bkt, key = upload_image(ALICE_CK, ALICE_CSRF, cid, "venue.png")
    if bkt and key:
        alice("POST", f"/messaging/conversations/{cid}/messages/image",
              {"bucket": bkt, "key": key, "content_type": "image/png",
               "filename": "venue.png", "filesize": len(_PNG), "kind": "image",
               "caption": "Proposed venue for the offsite"}, "alice image")

    # Meeting poll (alice)
    alice("POST", f"/messaging/conversations/{cid}/messages/meeting-poll",
          {"title": "Pick a time for the sync", "duration_minutes": 30,
           "text": "Which slot works for you?",
           "slots": [{"start_utc": "2026-06-24T15:00:00Z", "end_utc": "2026-06-24T15:30:00Z"},
                     {"start_utc": "2026-06-25T17:00:00Z", "end_utc": "2026-06-25T17:30:00Z"},
                     {"start_utc": "2026-06-26T16:00:00Z", "end_utc": "2026-06-26T16:30:00Z"}]},
          "alice meeting poll")

    # Calendar share + calendar event (alice creates a calendar + event first)
    cal = alice("POST", "/ui/calendars", {"name": "Alice — Work", "timezone": "UTC"}, "alice calendar")
    cal_id = cal.get("calendar_id")
    if cal_id:
        evt = alice("POST", f"/ui/calendars/{cal_id}/events",
                    {"name": "Quarterly Planning", "start_utc": "2026-06-27T16:00:00Z",
                     "end_utc": "2026-06-27T17:00:00Z", "timezone": "UTC"}, "alice event")
        evt_id = evt.get("event_id")
        alice("POST", f"/messaging/conversations/{cid}/messages/calendar-share",
              {"calendar_id": cal_id, "permission": "read", "include_booking_link": True,
               "text": "Here's my work calendar — grab any open slot."}, "alice calendar-share")
        if evt_id:
            alice("POST", f"/messaging/conversations/{cid}/messages/calendar-event",
                  {"calendar_id": cal_id, "event_id": evt_id,
                   "text": "Adding you to the planning session."}, "alice calendar-event")

    # Find-a-time poll
    alice("POST", f"/messaging/conversations/{cid}/messages/find-datetime",
          {"title": "Find time next week", "from_date": "2026-06-29", "to_date": "2026-07-01",
           "start_hour": 9, "end_hour": 17, "slot_duration_minutes": 30, "deadline_hours": 48,
           "text": "Mark your availability ↓"}, "alice find-a-time")

    # Reactions (bob reacts to alice's first message)
    if first_id:
        bob("POST", f"/messaging/conversations/{cid}/messages/{first_id}/reactions",
            {"emoji": "👍", "action": "add"}, "bob react 👍")
        bob("POST", f"/messaging/conversations/{cid}/messages/{first_id}/reactions",
            {"emoji": "🔥", "action": "add"}, "bob react 🔥")

print("== Group: Project Falcon ==")
grp = alice("POST", "/messaging/conversations/group",
            {"participant_ids": [BOB_SUB, CHARLIE_SUB], "title": "Project Falcon",
             "description": "Q3 launch coordination"}, "create group")
gid = grp.get("conversation_id")
if gid:
    bob("POST", f"/messaging/conversations/{gid}/accept", {}, "bob accept group")
    charlie("POST", f"/messaging/conversations/{gid}/accept", {}, "charlie accept group")
    alice("POST", f"/messaging/conversations/{gid}/messages",
          {"text": "Kicking off Project Falcon 🚀 Standups Mon/Wed/Fri."}, "grp alice")
    bob("POST", f"/messaging/conversations/{gid}/messages",
        {"text": "In. I'll own the backend milestones."}, "grp bob")
    charlie("POST", f"/messaging/conversations/{gid}/messages",
            {"text": "I'll handle infra + the launch checklist."}, "grp charlie")

print("done.")
