#!/usr/bin/env python3
import io, sys, time
PATH = "app/services/alerts.py"
src = io.open(PATH, encoding="utf-8").read(); orig = src; ts = int(time.time())
a = """                 \"comment_reply\", \"mention\", \"subscription_started\", \"post_shared\",
                 \"post_tip\", \"message_tip\"},"""
b = """                 \"comment_reply\", \"mention\", \"subscription_started\", \"post_shared\",
                 \"post_tip\", \"message_tip\",
                 \"tip_received\", \"tip_sent\", \"tip_reversed\", \"tip_refunded\"},"""
assert src.count(a) == 1, "cat=%d" % src.count(a); src = src.replace(a, b)
a2 = """    \"post_tip\",\"message_tip\",
    # Subscriptions (SUB-E1/E5): lifecycle notifications (default-on transactional)"""
b2 = """    \"post_tip\",\"message_tip\",
    # TIPX-E1/E3: unified tip notifications — recipient/sender/reversal (default-on transactional)
    \"tip_received\",\"tip_sent\",\"tip_reversed\",\"tip_refunded\",
    # Subscriptions (SUB-E1/E5): lifecycle notifications (default-on transactional)"""
assert src.count(a2) == 1, "evt=%d" % src.count(a2); src = src.replace(a2, b2)
a3 = """    \"post_tip\",              # you received a tip
    \"message_tip\",           # you received a message tip"""
b3 = """    \"post_tip\",              # you received a tip
    \"message_tip\",           # you received a message tip
    \"tip_received\",          # TIPX-E1: you received a tip (comment/video/broadcast/profile/react)
    \"tip_sent\",              # TIPX-E1: your tip receipt
    \"tip_reversed\",          # TIPX-E3: a tip you received was reversed
    \"tip_refunded\",          # TIPX-E3: your tip was refunded"""
assert src.count(a3) == 1, "push=%d" % src.count(a3); src = src.replace(a3, b3)
if src == orig: print("NO CHANGE"); sys.exit(1)
io.open(PATH + ".bak_tipx_%d" % ts, "w", encoding="utf-8").write(orig)
io.open(PATH, "w", encoding="utf-8").write(src)
print("PATCHED alerts.py bak=.bak_tipx_%d" % ts)
