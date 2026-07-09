#!/usr/bin/env python3
"""In-process prod verify for MOD-1 / MOD-2 / MOD-6 / ADV-sign. Seeds fresh data on
prod DDB, exercises the real code paths, asserts, then cleans up."""
import sys, time
sys.path.insert(0, "/home/ubuntu/testlogon")
from app.core.tables import T
from app.core.aws import ddb
from app.routers import admin_moderation as AM
from app.routers import messaging as M
from app.services import dmca_content_operations as DC
from app.services import moderation_hide as MH
from app.services import billing_shared as BS
from app.services import video_comments as VC

R = []
def chk(name, cond, detail=""):
    R.append((name, bool(cond)))
    print(("PASS" if cond else "FAIL"), "|", name, ("- " + str(detail)) if detail else "")

TS = int(time.time())
cleanup_enf = []   # (user_id, enforcement_id)
cleanup_msg = []   # (conversation_id, message_id)
cleanup_app = []   # (pk, sk)

# ===================== MOD-1 =====================
try:
    offender = "verif_off_%d" % TS
    seed = [("tk_a", "active"), ("tk_b", "recorded"), ("tk_a", "active"), ("tk_c", "reversed")]
    for i, (tk, st) in enumerate(seed):
        eid = "enf_%d_%d" % (TS, i)
        T.user_enforcement_history.put_item(Item={
            "user_id": offender, "enforcement_id": eid,
            "entity_type": "user_enforcement", "status": st,
            "enforcement_type": "ban" if st == "active" else "content_violation",
            "source_ticket_id": "%s_%d" % (tk, TS), "created_at": str(1700000000 + i), "note": "v",
        })
        cleanup_enf.append((offender, eid))
    time.sleep(1.0)  # GSI eventual consistency
    hist = AM._query_enforcement_history_by_offender(offender)
    summ = AM._offender_history_summary(offender, [{"r": 1}, {"r": 2}])
    chk("MOD-1 GSI returns ALL records", len(hist) == 4, "got %d" % len(hist))
    chk("MOD-1 total_enforcements precise=4", summ.total_enforcements == 4, summ.total_enforcements)
    chk("MOD-1 total_tickets distinct=3", summ.total_tickets == 3, summ.total_tickets)
    chk("MOD-1 open_tickets active=2", summ.open_tickets == 2, summ.open_tickets)
    chk("MOD-1 newest-first order", (not hist) or hist[0]["created_at"] >= hist[-1]["created_at"],
        "%s..%s" % (hist[0]["created_at"], hist[-1]["created_at"]))

    # completeness vs the Limit-bounded base-table query (heavy offender > 100)
    heavy = "verif_heavy_%d" % TS
    N = 105
    for i in range(N):
        eid = "enfh_%d_%d" % (TS, i)
        T.user_enforcement_history.put_item(Item={
            "user_id": heavy, "enforcement_id": eid,
            "entity_type": "user_enforcement", "status": "active", "enforcement_type": "ban",
            "source_ticket_id": "htk_%d_%d" % (TS, i), "created_at": str(1700000000 + i), "note": "h",
        })
        cleanup_enf.append((heavy, eid))
    time.sleep(2.0)
    gsi = AM._query_enforcement_history_by_offender(heavy)
    base = AM._query_enforcement_history(heavy, limit=100)
    hsumm = AM._offender_history_summary(heavy, [])
    chk("MOD-1 complete GSI (%d) beats bounded base (<=100)" % N,
        len(gsi) == N and len(base) <= 100 and len(gsi) > len(base), "gsi=%d base=%d" % (len(gsi), len(base)))
    chk("MOD-1 heavy summary precise total_tickets=%d" % N, hsumm.total_tickets == N and hsumm.total_enforcements == N,
        "tickets=%d enf=%d" % (hsumm.total_tickets, hsumm.total_enforcements))
except Exception as e:
    import traceback; traceback.print_exc(); chk("MOD-1 (exception)", False, e)

# ===================== MOD-2 =====================
try:
    conv = "conv_verif_%d" % TS
    mid = "msg_verif_%d" % TS
    sender = "alice_%d" % TS
    recipient = "bob_%d" % TS
    secret = "TOP-SECRET-ORIGINAL-BODY-%d" % TS
    M.tbl_msgs.put_item(Item={"conversation_id": conv, "message_id": mid, "sender_id": sender,
                              "created_at": int(time.time()), "kind": "text", "text": secret})
    cleanup_msg.append((conv, mid))

    def row(mmid): return M.tbl_msgs.get_item(Key={"conversation_id": conv, "message_id": mmid})["Item"]
    out0 = M._message_out_from_item(row(mid), recipient)
    chk("MOD-2 baseline recipient sees real body", out0.text == secret)

    MH.hide_content(content_type="message", content_id=mid, metadata={"conversation_id": conv}, case_id="case_%d" % TS)
    r = row(mid)
    chk("MOD-2 body intact after hide (non-destructive)", r.get("text") == secret)
    out_r = M._message_out_from_item(r, recipient)
    chk("MOD-2 non-sender gets 'Message under review' placeholder", out_r.text == "Message under review", out_r.text)
    chk("MOD-2 non-sender under_review flag True", out_r.under_review is True)
    chk("MOD-2 non-sender does NOT leak real body/media/reactions",
        secret not in (out_r.text or "") and out_r.image is None and not out_r.reactions_counts and not out_r.file)
    chk("MOD-2 non-sender NOT removed (row still rendered)", out_r.message_id == mid)
    chk("MOD-2 _should_render_placeholder True for recipient", M._should_render_under_review_placeholder(r, recipient) is True)
    out_s = M._message_out_from_item(r, sender)
    chk("MOD-2 SENDER owner-view real body", out_s.text == secret)
    chk("MOD-2 _should_render_placeholder False for sender", M._should_render_under_review_placeholder(r, sender) is False)
    chk("MOD-2 filter hides for recipient / shows for sender",
        M._filter_message_visible(r, recipient) is False and M._filter_message_visible(r, sender) is True)

    MH.unhide_content(content_type="message", content_id=mid, metadata={"conversation_id": conv}, case_id="case_%d" % TS)
    out_r2 = M._message_out_from_item(row(mid), recipient)
    chk("MOD-2 restore byte-for-byte for recipient", out_r2.text == secret and out_r2.under_review is None)
except Exception as e:
    import traceback; traceback.print_exc(); chk("MOD-2 (exception)", False, e)

# ===================== MOD-6 =====================
try:
    # -- message_media --
    mid2 = "msg_dmca_%d" % TS
    s2 = "DMCA-MSG-SECRET-%d" % TS
    M.tbl_msgs.put_item(Item={"conversation_id": conv, "message_id": mid2, "sender_id": sender,
                              "created_at": int(time.time()), "kind": "text", "text": s2})
    cleanup_msg.append((conv, mid2))
    cid_claim = "dmca_verif_%d" % TS
    snap = DC.hide_content_for_dmca(claim_id=cid_claim, content_type="message_media", content_id="%s|%s" % (conv, mid2))
    rr = M.tbl_msgs.get_item(Key={"conversation_id": conv, "message_id": mid2})["Item"]
    chk("MOD-6 message_media DMCA hides + body intact", bool(rr.get("moderation_hidden")) and rr.get("text") == s2, snap)
    chk("MOD-6 message hidden from recipient", M._filter_message_visible(rr, recipient) is False)
    DC.restore_content_after_dmca(claim={"claim_id": cid_claim, "content_type": "message_media",
                                         "content_id": "%s|%s" % (conv, mid2), "content_snapshot": snap})
    rr = M.tbl_msgs.get_item(Key={"conversation_id": conv, "message_id": mid2})["Item"]
    chk("MOD-6 message_media DMCA restore byte-for-byte", (not rr.get("moderation_hidden")) and rr.get("text") == s2)

    # -- feed comment --
    post = "post_dmca_%d" % TS
    ccid = "cmt_%d" % TS
    cbody = "COMMENT-ORIGINAL-%d" % TS
    APP = ddb.Table(DC.APP_TABLE)
    cpk, csk = "POST#%s#COMMENTS" % post, "COMMENT#%s" % ccid
    APP.put_item(Item={"pk": cpk, "sk": csk, "comment_id": ccid, "user_id": sender, "body": cbody,
                       "created_at": int(time.time())})
    cleanup_app.append((cpk, csk))
    snapc = DC.hide_content_for_dmca(claim_id=cid_claim + "_c", content_type="comment", content_id="%s|%s" % (post, ccid))
    crow = MH._find_comment_row(post, ccid) or {}
    chk("MOD-6 feed comment DMCA hides + body intact", bool(crow.get("moderation_hidden")) and crow.get("body") == cbody, snapc)
    DC.restore_content_after_dmca(claim={"claim_id": cid_claim + "_c", "content_type": "comment",
                                         "content_id": "%s|%s" % (post, ccid), "content_snapshot": snapc})
    crow = MH._find_comment_row(post, ccid) or {}
    chk("MOD-6 feed comment DMCA restore byte-for-byte", (not crow.get("moderation_hidden")) and crow.get("body") == cbody)

    # -- video comment --
    vid = "vid_dmca_%d" % TS
    c = VC.add_comment(video_id=vid, user_id=sender, text="VIDEO-CMT-ORIG-%d" % TS)
    vcid, vtext = c["comment_id"], c["text"]
    cleanup_app.append(("VIDEO#%s" % vid, None))  # marker; deleted via VC below
    snapv = DC.hide_content_for_dmca(claim_id=cid_claim + "_v", content_type="video_comment", content_id="%s|%s" % (vid, vcid))
    vrow = VC.get_comment(video_id=vid, comment_id=vcid) or {}
    chk("MOD-6 video comment DMCA hides + text intact", bool(vrow.get("moderation_hidden")) and vrow.get("text") == vtext, snapv)
    DC.restore_content_after_dmca(claim={"claim_id": cid_claim + "_v", "content_type": "video_comment",
                                         "content_id": "%s|%s" % (vid, vcid), "content_snapshot": snapv})
    vrow = VC.get_comment(video_id=vid, comment_id=vcid) or {}
    chk("MOD-6 video comment DMCA restore byte-for-byte", (not vrow.get("moderation_hidden")) and vrow.get("text") == vtext)
    try:
        VC.delete_comment(video_id=vid, comment_id=vcid, user_id=sender)
    except Exception:
        try:
            ddb.Table(VC.T.video_comments.name).delete_item(Key={"pk": vrow["pk"], "sk": vrow["sk"]})
        except Exception:
            pass
except Exception as e:
    import traceback; traceback.print_exc(); chk("MOD-6 (exception)", False, e)

# ===================== ADV-sign =====================
try:
    chk("ADV-sign ad_revenue_reversal in LEDGER_ENTRY_SIGN == -1", BS.LEDGER_ENTRY_SIGN.get("ad_revenue_reversal") == -1,
        BS.LEDGER_ENTRY_SIGN.get("ad_revenue_reversal"))
    chk("ADV-sign sign_for_entry_type == -1", BS.sign_for_entry_type("ad_revenue_reversal") == -1)
    chk("ADV-sign derive_signed_amount_cents(-350)", BS.derive_signed_amount_cents("ad_revenue_reversal", 350) == -350)
except Exception as e:
    import traceback; traceback.print_exc(); chk("ADV-sign (exception)", False, e)

# ===================== cleanup =====================
for uid, eid in cleanup_enf:
    try: T.user_enforcement_history.delete_item(Key={"user_id": uid, "enforcement_id": eid})
    except Exception: pass
for c, m in cleanup_msg:
    try: M.tbl_msgs.delete_item(Key={"conversation_id": c, "message_id": m})
    except Exception: pass
for pk, sk in cleanup_app:
    if sk is None: continue
    try: ddb.Table(DC.APP_TABLE).delete_item(Key={"pk": pk, "sk": sk})
    except Exception: pass

npass = sum(1 for _, ok in R if ok)
print("\n===== SUMMARY %d/%d PASS  %s =====" % (npass, len(R), "ALL_PASS" if npass == len(R) else "FAILURES"))
