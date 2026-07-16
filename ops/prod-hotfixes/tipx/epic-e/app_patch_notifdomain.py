#!/usr/bin/env python3
"""TIPX-E2 (N2): normalize tip_* / *_tip tokens to NotificationType.TIP."""
import io, sys, time
PATH = "android/app/src/main/java/com/testlogon/android/data/notifications/NotificationDomain.kt"
src = io.open(PATH, encoding="utf-8").read()
orig = src
ts = int(time.time())

a = '''        fun fromToken(token: String?): NotificationType =
            entries.firstOrNull { it != UNKNOWN && it.name.equals(token, ignoreCase = true) } ?: UNKNOWN'''
b = '''        fun fromToken(token: String?): NotificationType {
            val t = token?.trim()?.lowercase() ?: return UNKNOWN
            // TIPX-E2 (N2): every tip vocabulary (tip_received / tip_sent / post_tip /
            // message_tip / tip_reversed / tip_refunded / tip_on_*) normalizes to TIP so
            // the client renders + deep-links tip notifications instead of dropping to UNKNOWN.
            if (t.startsWith("tip_") || t.endsWith("_tip")) return TIP
            return entries.firstOrNull { it != UNKNOWN && it.name.equals(t, ignoreCase = true) } ?: UNKNOWN
        }'''
assert src.count(a) == 1, f"anchor={src.count(a)}"
src = src.replace(a, b)
if src == orig:
    print("NO CHANGE"); sys.exit(1)
io.open(PATH, "w", encoding="utf-8").write(src)
print("PATCHED NotificationDomain.kt")
