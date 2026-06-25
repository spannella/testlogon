#!/usr/bin/env python3
"""Seed alice-owned newsfeed + calendar + file-manager data for a UI review.
Run AFTER `just restart` (or against the running stack). Uses cookie+CSRF.
"""
import io
import json
import subprocess
import time

import requests

BASE = "http://localhost:8000"
TS = int(time.time())

out = subprocess.check_output(["python3", "e2e_admin_session_setup.py"],
                              cwd="/home/ubuntu/testlogon", timeout=60).decode()
S = json.loads(out[out.index("{"):])


def sess(key):
    s = S[key]
    r = requests.Session()
    for c in s["cookies"]:
        r.cookies.set(c["name"], c["value"])
    r.headers.update({"x-csrf-token": s["csrf_token"]})
    return r, s["user_sub"]


alice, ALICE = sess("alice")
bob, BOB = sess("bob")


def png(label, w=800, h=500, color=(37, 99, 235)):
    try:
        from PIL import Image, ImageDraw
        im = Image.new("RGB", (w, h), color)
        d = ImageDraw.Draw(im)
        d.rectangle([10, 10, w - 10, h - 10], outline=(255, 255, 255), width=5)
        d.text((w // 2 - 30, h // 2 - 8), label, fill=(255, 255, 255))
        b = io.BytesIO(); im.save(b, "PNG"); return b.getvalue()
    except Exception:
        import base64
        return base64.b64decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==")


def log(r, label):
    ok = "ok " if r.status_code in (200, 201) else "XX "
    print(f"  {ok}{r.status_code} {label}" + ("" if r.ok else f"  -> {r.text[:140]}"))
    return r


print("== NEWSFEED (alice) ==")
log(alice.post(f"{BASE}/posts", json={"body": "Shipping season is here — new behind-the-scenes drops every week. 🚀", "visibility": "public"}), "text post")
# image post
up = alice.post(f"{BASE}/uploads/image", files={"file": ("studio.png", png("STUDIO"), "image/png")})
log(up, "upload image")
img_url = up.json().get("url") if up.ok else None
if img_url:
    log(alice.post(f"{BASE}/posts", json={"body": "Fresh from the studio today 📸", "image_urls": [img_url], "visibility": "public"}), "image post")
# locked post
log(alice.post(f"{BASE}/posts", json={"body": "Exclusive: full editing workflow breakdown — unlock to read.", "lock_type": "fixed_price", "unlock_price_cents": 500, "visibility": "public"}), "locked post")
# public post + bob engagement
pr = log(alice.post(f"{BASE}/posts", json={"body": "What should I cover next? Drop ideas below 👇", "visibility": "public"}), "public post (for engagement)")
pid = pr.json().get("post_id") if pr.ok else None
if pid:
    log(bob.post(f"{BASE}/posts/{pid}/comments", json={"body": "A lighting tutorial would be 🔥"}), "bob comment")
    log(bob.post(f"{BASE}/posts/{pid}/reactions", json={"emoji": "🔥"}), "bob react 🔥")
    log(alice.post(f"{BASE}/posts/{pid}/reactions", json={"emoji": "❤️"}), "alice react ❤️")

print("== CALENDAR (alice) ==")
cal = log(alice.post(f"{BASE}/ui/calendars", json={"name": "Content Schedule", "timezone": "UTC"}), "calendar")
cid = cal.json().get("calendar_id") if cal.ok else None
if cid:
    import datetime as dt
    base = dt.datetime.utcnow().replace(microsecond=0, second=0)
    for name, dh, dur in [("Livestream Q&A", 26, 1), ("Studio Photo Shoot", 50, 3),
                          ("Subscriber AMA", 74, 1), ("Editing Workshop", 122, 2)]:
        s = base + dt.timedelta(hours=dh); e = s + dt.timedelta(hours=dur)
        log(alice.post(f"{BASE}/ui/calendars/{cid}/events",
                       json={"name": name, "start_utc": s.strftime("%Y-%m-%dT%H:%M:%SZ"),
                             "end_utc": e.strftime("%Y-%m-%dT%H:%M:%SZ"), "timezone": "UTC"}), f"event {name}")

print("== FILES (alice) ==")
for folder in ["/Projects", "/Projects/Falcon", "/Photos", "/Documents"]:
    log(alice.post(f"{BASE}/v1/fs/folder", json={"path": folder}), f"folder {folder}")
files = [("/Documents/proposal.txt", b"Q3 proposal draft\n\nScope, timeline, budget.\n", "text/plain"),
         ("/Documents/notes.md", b"# Notes\n\n- ship demo\n- review UI\n", "text/markdown"),
         ("/Photos/cover.png", png("COVER", color=(190, 60, 120)), "image/png"),
         ("/Photos/banner.png", png("BANNER", color=(20, 160, 110)), "image/png"),
         ("/Projects/Falcon/spec.txt", b"Falcon spec v1\n", "text/plain")]
for path, data, ct in files:
    r = alice.post(f"{BASE}/v1/fs/upload", params={"path": path}, files={"file": (path.split("/")[-1], data, ct)})
    log(r, f"upload {path}")

print("done.")
