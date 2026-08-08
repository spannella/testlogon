#!/usr/bin/env python3
"""
W2.5 codemod #2: email-bearer -> real-sub for the messaging/calls family.

Problem: ~17 specs authenticate cpp with `Authorization: Bearer <EMAIL>` (and
pass the same EMAIL as participant_ids / recipient ids in request bodies). cpp
rejects email-bearer and resolves message/convo participants by SUB, not email,
so these 401 / mis-resolve.

Backward-compatible fix: route every identity-bearing EMAIL through the session
map's `.user_sub`. Under the Python seeders user_sub == email (verified), so the
default Python run is byte-identical; under cpp user_sub is the real cpp SUB.

Concretely, per file that has a session accessor (`getSessions` or
`getAdminSessions`) in scope, rewrite in BOTH page.request header objects and
curl -H '...' template strings:
    Bearer ${userId}      -> Bearer ${<ACC>()[userId].user_sub}
    Bearer ${ALICE_ID}    -> Bearer ${<ACC>()[ALICE_ID].user_sub}
and the email-in-body identity interpolations:
    ${ALICE_ID} / ${BOB_ID} / ${CHARLIE_ID}   (only inside participant_ids /
    recipient_id / to / user_sub JSON contexts)  -> ${<ACC>()[<ID>].user_sub}

Files with NO session accessor in scope are reported as MANUAL (they have no cpp
session to resolve a sub from and need a fixture-sub map added by hand).
"""
import re
import sys
import glob
import os

E2E_DIR = os.path.dirname(os.path.abspath(__file__))

# The messaging/calls family that uses executable email-bearers.
TARGET = [
    "bug-fixes-2", "bug-fixes", "calendar-messaging", "call-screenshare",
    "countdown-messages", "find-datetime-messages", "gif-sticker-messages",
    "group-calls", "messaging-compliance", "messaging-drafts",
    "messaging-features", "messaging-group", "messaging-lottery",
    "messaging", "reply-threads", "voice-messages",
]

BEARER_VARS = ["userId", "ALICE_ID", "BOB_ID", "CHARLIE_ID"]


def accessor(text):
    if re.search(r"\bgetSessions\s*\(", text):
        return "getSessions"
    if re.search(r"\bgetAdminSessions\s*\(", text):
        return "getAdminSessions"
    return None


def transform(text):
    acc = accessor(text)
    if acc is None:
        return text, 0, False  # no session accessor -> manual
    n = 0

    # 1) Bearer ${VAR} -> Bearer ${acc()[VAR].user_sub}   (skip if already done)
    for var in BEARER_VARS:
        pat = re.compile(r"Bearer \$\{" + re.escape(var) + r"\}")
        repl = "Bearer ${%s()[%s].user_sub}" % (acc, var)
        text, k = pat.subn(repl, text)
        n += k

    # 2) Body identity interpolation: participant_ids:["${BOB_ID}"], recipient_id,
    #    "to":"${ALICE_ID}", user_sub. Only rewrite the ${ID} tokens that sit
    #    inside a quoted JSON value on a line that mentions an id/participant key.
    def body_line(m):
        nonlocal n
        line = m.group(0)
        for var in ["ALICE_ID", "BOB_ID", "CHARLIE_ID"]:
            tok = "${" + var + "}"
            newtok = "${%s()[%s].user_sub}" % (acc, var)
            if tok in line and newtok not in line:
                line = line.replace(tok, newtok)
                n += 1
        return line

    body_re = re.compile(
        r'.*(?:participant_ids|recipient_id|recipient|"to"|user_sub|member_ids|invitee)'
        r'.*\$\{(?:ALICE_ID|BOB_ID|CHARLIE_ID)\}.*',
    )
    text = body_re.sub(body_line, text)

    return text, n, True


def main():
    apply = "--apply" in sys.argv
    changed, manual, subs_total = [], [], 0
    for name in TARGET:
        p = os.path.join(E2E_DIR, name + ".spec.ts")
        if not os.path.exists(p):
            continue
        with open(p, "r", encoding="utf-8") as fh:
            text = fh.read()
        new, n, ok = transform(text)
        if not ok:
            manual.append(name + ".spec.ts (no session accessor in scope)")
            continue
        if n == 0:
            continue
        subs_total += n
        changed.append((name + ".spec.ts", n))
        if apply and new != text:
            with open(p, "w", encoding="utf-8") as fh:
                fh.write(new)
    print("MODE: %s" % ("APPLY" if apply else "DRY-RUN"))
    print("CHANGED_FILES: %d  TOTAL_SUBS: %d" % (len(changed), subs_total))
    for nm, n in changed:
        print("  ~ %s (%d)" % (nm, n))
    print("MANUAL_RESIDUAL: %d" % len(manual))
    for nm in manual:
        print("  ! %s" % nm)


if __name__ == "__main__":
    main()
