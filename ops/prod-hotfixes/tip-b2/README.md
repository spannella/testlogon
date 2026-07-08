# TIP-B2 prod hotfix (TIP-201 message tip-react + TIP-202 post tip-react + TIP-205 earnings classify)

Live prod hotfix applied 2026-07-07 via SSM against `/home/ubuntu/testlogon`
(instance `i-08f937fc705ebea75`, us-east-2) and mirrored to the `android-impl`
dev clone. Backend-only slice of epic B2. App tickets TIP-203/204/206 (the
reaction-picker "tip" option + money-reaction chip + 2-device UI) are separate.

Money-path rule respected: `charge_tip` is the ONLY charge/ledger. A self-tip
(400) or a failed charge (402) raises BEFORE any badge/event side effect, so a
failed tip-react writes NO badge and NO ledger row.

## What changed (5 files, all via `apply_tip_b2.py`)

### TIP-201 -- message tip-reaction endpoint  (app/routers/messaging.py)
- New `POST /messaging/conversations/{cid}/messages/{mid}/reactions/tip`
  (`tip_react_to_message`), DISTINCT from the free emoji `react_to_message`.
- Body `TipReactIn {amount_cents>=1, emoji?, payment_method_id?}`.
- Recipient = the MESSAGE AUTHOR (`msg["sender_id"]`) -- group-safe (the sender),
  never the actor. Self-tip -> 400 `cannot_tip_self`; revoked message -> 400.
- Routes through `charge_tip(content_type="message_react", content_id=mid)`.
- ONLY on a successful charge: appends a money-reaction badge to the message
  (`tip_reactions` list: {tipper_id, emoji, amount_cents, tip_payment_id, created_at})
  + `ADD tip_amount_cents`, then fans a realtime `reaction:tip` event to the
  thread + audits `messaging_message_tip_reaction`.

### TIP-202 -- post tip-reaction endpoint  (app/routers/newsfeed.py)
- New `POST /posts/{pid}/reactions/tip` (`tip_react_to_post`), DISTINCT from the
  free emoji `add_reaction`.
- Body `PostTipReactRequest {amount_cents>=1, currency=usd, emoji?, payment_method_id?}`.
- Recipient = the POST AUTHOR (`post["user_id"]`). Self-tip -> 400.
- Routes through `charge_tip(content_type="post_react", content_id=pid)`.
- ONLY on a successful charge: appends a money-reaction badge (`tip_reactions`)
  + bumps `tip_total_cents`, then emits a `post_tip` social alert (best-effort).

### TIP-201/202 allowlist -- message_react + post_react
- `app/services/tips.py`      `TIP_CONTENT_TYPES` += ("message_react","post_react").
- `app/services/tip_ledger.py` content_type set += those two + reason map:
  "message_react" -> "Tip: message reaction", "post_react" -> "Tip: post reaction".

### TIP-205 -- earnings classification  (app/services/creator_earnings.py)
- `classify_entry` tips allowlist now
  `{message, post, comment, message_react, post_react, video, video_comment}`
  so these credits report under the `tips` category explicitly (reason fallback
  already bucketed them; this is exactness).

## Backups (prod)
    app/services/tip_ledger.py.bak_tipb2_1783472059
    app/services/tips.py.bak_tipb2_1783472059
    app/services/creator_earnings.py.bak_tipb2_1783472059
    app/routers/messaging.py.bak_tipb2_1783472059
    app/routers/newsfeed.py.bak_tipb2_1783472059

## Re-apply / mirror
    /home/ubuntu/testlogon/.venv/bin/python ops/prod-hotfixes/tip-b2/apply_tip_b2.py <repo_root>
(idempotent-guarded: asserts each anchor's occurrence count; py_compiles each file)
then restart the backend: `su - ubuntu -c "bash /home/ubuntu/restart_backend.sh"`;
verify `curl -s -o /dev/null -w %{http_code} http://127.0.0.1:8000/openapi.json` -> 200.

## Verification (prod, live backend env, 2026-07-07) -- OVERALL ALL_PASS
Runner: `seed_verify_tipb2.py` (in-process TestClient, two identities A=tipper B=author).
- M1 message tip-react: 200; debit(A)=500 gross, credit(B)=400 net type=credit
  (20% fee), 1 money-reaction badge on the message.
- M2 self-tip on own message: 400 cannot_tip_self (no ledger).
- M3 forced 402 (monkeypatched `_charge_tip_payment_intent`): endpoint 402, credits
  1->1, badges 1->1 (NO ledger, NO badge on a failed charge).
- P1 post tip-react: 200; debit(A)=800, credit(B)=640 net type=credit, badge on
  post, tip_total_cents=800.
- P2 self-tip on own post: 400.
- E1 classify_entry(message_react)/(post_react) -> "tips".
