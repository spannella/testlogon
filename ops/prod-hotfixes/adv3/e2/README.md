# ADV3 EPIC E2 — advertiser flow/UX (ADV3-3 / ADV3-4 / ADV3-5)

Backend live prod hotfix + Android app build. This folder holds the ONE backend
change (a router gate move) plus its verification; the rest of E2 is Android app
code committed under `android/`.

## Backend change (ADV3-3 / B1) — `app/routers/ads.py`

The guided create wizard forward-chained every brand-new advertiser
(`pending_review` account) straight into `POST …/campaigns`, which hard-403'd
("Account is not active") — a guaranteed dead-end at step 2.

Fix (plan option 2: *allow draft campaigns under a pending account, gate only
launch*):

- `create_campaign_endpoint`: removed the `status != "active"` 403. A campaign is
  created in `draft` and is INERT — `serve_ad` only ever reads
  `list_campaigns_by_status("active")`, so a draft never serves and no money can
  move before approval. Ownership (`_require_account_owner`) is unchanged.
- `submit_for_review_endpoint`: the launch gate MOVED here — it now 403s when the
  owning account is not `active`. A campaign can only enter the
  review→active→serving pipeline once an admin approves the ad account. This
  preserves the invariant "nothing serves under a non-active account".

Self-promo campaigns are unchanged (free, own-content, auto-active).

## Apply (idempotent, anchor-checked)

`patch_ads.py` performs two exact-string replacements (asserts the anchors).
Prod was byte-identical to the dev clone's pre-patch text, so the same patcher
applies to both. Applied to prod via SSM (SSM user is not root — sudo used):

```
TS=$(date +%s)
F=/home/ubuntu/testlogon/app/routers/ads.py
sudo cp $F $F.bak_adv3e2_$TS
cd /home/ubuntu/testlogon && sudo python3 patch_ads.py   # p="app/routers/ads.py"
sudo chown ubuntu:ubuntu $F
sudo -u ubuntu bash /home/ubuntu/restart_backend.sh
curl -s -o /dev/null -w '%{http_code}' http://localhost:8000/openapi.json   # 200
```

Prod backup: `app/routers/ads.py.bak_adv3e2_1784131603`.
Dev backup:  `app/routers/ads.py.bak_adv3e2_1784130012`.

## Verify — `adv3_e2_verify.py` (endpoint-level, moto, zero prod-DDB residue)

Spins its own in-process moto DynamoDB with the real ad-table schemas, imports
the REAL patched router functions, and exercises them. Run:

```
cd ~/dev/testlogon && . .venv/bin/activate && PYTHONPATH=$PWD python adv3_e2_verify.py
```

11/11 PASS:
- acct starts pending_review
- P1 create paid campaign under pending -> no 403; created campaign is inert draft
- N1 submit while pending -> 403 launch gate; campaign stays draft
- P2 submit after account active -> ok; campaign -> pending_review
- R1 non-owner create blocked (ownership guard intact, 404)
- R2 self-promo auto-active under pending (carve-out intact)
- R3 create+submit under active account -> ok
- cleanup: 0 synthetic accounts remain

## App side (committed under `android/`)

- ADV3-4 (B4): `AdsAccountsScreen` + `AdsAccountsNavigation` — the advertiser-
  accounts LIST (the "Advertise" hub landing). Routes billing / campaigns /
  analytics with a REAL accountId, killing the `firstOrNull()` single-account
  ceiling.
- ADV3-4 (B2/B10): `feature/ads/campaigns/detail/*` + `AdCampaignDetailNavigation`
  — campaign MANAGEMENT (pause/resume/edit-budget/edit-bid/archive) wired to the
  existing `PATCH …/campaigns/{id}` (new Retrofit `updateCampaign` + `getCampaign`
  + `AdCampaignUpdateIn` DTO + repo methods). Campaign-list rows now open it.
  Humanized status line.
- ADV3-4 (B3): "Add funds to this account" CTA in the create-campaign success
  card and on the campaign-detail, routed to the specific account's billing.
- ADV3-3 (B8): deposit sheet — on success the amount is cleared and Confirm is
  swapped for a terminal "Done" that dismisses (no double-deposit from the open
  sheet).
- ADV3-5 (B5): `MoreSection.ADVERTISING` + a single "Advertise (create & manage
  ads)" entry launching the accounts list; the advertiser entries are regrouped
  under it.
- ADV3-5 (B6): `AdsStudioSelection` now PERSISTS the account/campaign pick to
  SharedPreferences so a cold start no longer silently edits the "first
  campaign".
- ADV3-5 (B7): optional flight start/end date pickers on the create-campaign form
  (epoch millis -> Unix seconds on submit).

Build gate: `:app:assembleDebug` BUILD SUCCESSFUL. On-device (A15): Advertising
hub → accounts list (real "Demo Ads Co") → campaigns → pause→resume round-trip on
PROD (active→paused→active, humanized status), flight-date fields render.
