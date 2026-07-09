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
