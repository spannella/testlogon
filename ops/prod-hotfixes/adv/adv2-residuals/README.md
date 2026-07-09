# ADV2 residuals R1 + R2 — syndicate-aware reversal + AdClicks.charged_cents

LIVE PROD HOTFIX (SSM), mirrored to the dev clone. Anchored + idempotent
(`apply_adv2res.py`), in-process prod-DDB verify (`verify_adv2res.py`, 30/30
ALL_PASS on prod).

## R1 — syndicate-aware reversal (`ad_billing.reverse_ad_charge`)
A 3-way syndicate charge denormalizes `is_syndicate_split` /
`member_share_cents` / `syndicate_treasury_share_cents` / `treasury_credit_sk` /
`syndicate_id` on the charge ledger row. Before this fix `reverse_ad_charge`
clawed the **full** `creator_share` from the member (the member was only credited
`member_share_cents` — the treasury took the remainder) and **never debited the
treasury**. Now:
- advertiser refunded the **full** charge (unchanged),
- member clawback = `member_share_cents` (not the full creator_share); the member
  credit row is flipped `state="reversed"` and a non-`credit`
  `ad_revenue_reversal` row is written (never inflates earnings),
- the syndicate **treasury is debited back** its `syndicate_treasury_share_cents`
  via new `syndicate_treasury.debit_placement_earning` (sign-flipped mirror of
  `credit_placement_earning`),
- platform share reversed (unchanged).
- `member_clawback + treasury_debit + platform_reversal == charge`.
- Idempotent + double-reversal guarded by the existing `REVERSAL#{entry_id}`
  marker (extended to carry the treasury/syndicate numbers for the replay
  receipt). **Non-syndicate tip/ad reversal path is UNCHANGED** (`is_syndicate_split`
  is False → `member_clawback == creator_share`, no treasury touched).

## R2 — `AdClicks.charged_cents` == the real charge (all surfaces)
The denormalized analytics field wrote 0. Real ledger debit/credit were always
correct; only the `ad_clicks` row field is fixed.
- **newsfeed impression/click** (`ad_serving.track_ad_event`): the post-charge
  row update wrote only `status`; now also
  `charged_cents = if_not_exists(charged_cents,0) + charge_cents` (accumulates
  impression+click; guarded by `charge_cents>0`).
- **CTA** (`ad_serving.record_cta_click`): added the same accumulate stamp after a
  billable CTA charge.
- **VOD pre-roll + broadcast pre/mid-roll** (`vod_ad_supported`,
  `broadcast_ads._charge_broadcast_completion`): the combined update
  **overwrote** `charged_cents` with `result.charge_cents`, which is **0 on the
  second (duplicate) impression/complete event** — clobbering the real amount
  back to 0. Now `charged_cents` is only written when the real charge `>0`
  (accumulate), so a duplicate completion preserves the stamped amount.
- **conversion** (`ad_attribution.attribute_conversion`): stamp the real CPA
  charge on the click row after `charge_conversion`.

## Apply / verify
```
# probe (no writes) against copies:  python apply_adv2res.py /tmp/probe
python apply_adv2res.py /home/ubuntu/testlogon      # idempotent; re-run = ALREADY_APPLIED
python verify_adv2res.py                            # in-process on prod DDB
```
Backup convention on prod: `app/services/<f>.py.bak_adv2res_<ts>`.
Files: ad_billing.py, ad_serving.py, ad_attribution.py, vod_ad_supported.py,
broadcast_ads.py, syndicate_treasury.py.

---

# ADV2 residuals R3 + R4 — self-promo moderation + F6 subscriber enumeration

LIVE PROD HOTFIX (SSM), mirrored to the dev clone. Anchored + idempotent
(`apply_adv2res_r3r4.py`), in-process prod-DDB verify
(`verify_adv2res_r3r4.py`, **10/10 ALL_PASS** on prod). Prod files backed up
`*.bak_adv2res_r3r4_1783605666`. Restart → openapi 200. No app change (no APK).

## R3 — self-promo serves ONLY approved (moderated) creatives (`ad_serving.serve_ad`)
Before: a self-promo (`is_self_promo`) with **no approved creative** fell back to
`list_creatives` (ALL creatives, incl. `pending`/`rejected`) and served an
UNMODERATED unit. Now the fallback is removed — a self-promo uses only
`list_approved_creatives` (`status == "approved"`); if the creator has **no
approved self-promo creative there is simply no self-promo fill** (the loop
`continue`s, buckets stay empty → house ad / no fill). Same moderation/fraud gate
as a paid ad; an unmoderated/rejected creative is NEVER auto-served.

Verify: a self-promo whose only creatives are `pending`+`rejected` → does NOT
fill self-promo (falls to `house_ad_001`, neither unmoderated creative served);
adding an `approved` creative → self-promo serves that approved creative.

## R4 — F6 mass-DM audience = followers UNION active subscribers (`ad_dm_audience.resolve_advertiser_audience`)
Before: audience was **followers-only** (DEC-2 — no ByCreator enumeration).
Now active SUBSCRIBERS of the advertiser are UNION'd in.

**No GSI/backfill was added.** Subscriptions already maintain a first-class
`CREATOR#{creator_id}` index partition (`SUB#` items carrying
`subscriber_id`/`status`, written by `subscription_server.save_subscription` —
the SAME index `count_active_subscribers` reads), so subscribers enumerate via a
native primary-key partition query. New helper
`subscription_access.list_active_subscriber_ids(creator_id)` (paginated,
`active`/`trialing`/`past_due`, deduped). This is cleaner + more reliable than a
new GSI (no eventual-consistency backfill, no throughput config).

`resolve_advertiser_audience` now, after the follower loop, unions the active
subscribers — each RE-VERIFIED via `_has_relationship` (accepts a follow OR an
active subscription), opt-out filtered (`allow_ad_messages`), deduped against
followers, honoring the same cap. The send-time re-gate (ADV2-606,
`is_recipient_eligible`) is unchanged and still drops any unfollow/opt-out
between resolve and dispatch. Return dict: `subscriber_enumeration` flips from
`deferred_dec2_followers_only` → `creator_index_partition` + adds
`subscribers_added`.

Verify: an active subscriber who does NOT follow → INCLUDED; an opted-out
subscriber → EXCLUDED (`excluded_optout`, never sent); a non-relationship
non-subscriber → never enumerated; a follower still included; send-time re-gate
consistent (subscriber eligible / opted-out + non-rel not).

## Apply / verify
```
ROOT=/home/ubuntu/testlogon python3 apply_adv2res_r3r4.py   # idempotent, anchored
# in the ubuntu venv with .env.local sourced:
.venv/bin/python verify_adv2res_r3r4.py                      # OVERALL ALL_PASS 10/10
```
