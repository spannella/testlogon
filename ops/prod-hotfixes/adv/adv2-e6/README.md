# ADV2-E6 (F7) — Syndicate advertising, phase 1 (ADV2-701..704 model + cross-member serve)

Final epic of the advertising-v2 program. **Phase 1** = the syndicate advertiser
model + cross-member serve eligibility (mints the *syndicate-tagged click*). The
NEW 3-way placement split is the **NEXT phase** (ADV2-704 split economics /
ADV2-705..708).

## What shipped (backend-only; LIVE PROD HOTFIX via SSM)
- **`app/services/ad_accounts.py`** — `create_syndicate_ad_account(syndicate_id, admin_sub, data)`
  creates a syndicate-owned ad account: `owner_type="syndicate"` +
  `owner_syndicate_id=<synd>`; `owner_sub` = the managing admin so the existing
  owner-scoped campaign/creative endpoints, funding (`deposit_funds`) and
  self-ad-exclusion keep working verbatim. Normal accounts now tag
  `owner_type="user"`. `list_syndicate_ad_accounts(synd, admin)` filters ByOwner.
- **`app/routers/ads.py`** — `POST/GET /ui/ads/syndicates/{syndicate_id}/accounts`,
  gated by `syndicates._require_admin` (admin passes, non-admin 403). Campaigns +
  creatives reuse the existing `/ui/ads/accounts/{account_id}/...` endpoints.
- **`app/services/ad_serving.py`** — cross-member eligibility: a syndicate-owned
  campaign is eligible on a slot ONLY when the slot `content_owner_id` is
  `syndicates.is_member(owner_syndicate_id, content_owner_id)`. It never serves on
  a non-member's content nor as a standalone unit (empty owner). Carries
  `is_syndicate_ad` + `syndicate_id` onto the **AdClicks** row and the serve
  response. An EXTERNAL (non-syndicate) campaign is unaffected — no membership
  gate, no skim (the 3-way split guard is the next phase).

## Contracts
- `create_syndicate_ad_account` -> account META with `owner_type="syndicate"`,
  `owner_syndicate_id`, `owner_sub=admin`, `status="pending_review"`.
- `serve_ad(...)` response + `T.ad_clicks` row now include
  `is_syndicate_ad: bool` and `syndicate_id: str` (falsey/"" for external + house).

## Apply / verify (idempotent, anchor-matched — runs on divergent dev clone AND prod)
```
# dev clone
.venv/bin/python ops/prod-hotfixes/adv/adv2-e6/apply_adv2e6.py <REPO_ROOT>
# prod (via SSM): probe anchors -> cp .bak_adv2e6_<ts> -> apply -> chown -> restart -> openapi 200
.venv/bin/python ops/prod-hotfixes/adv/adv2-e6/probe_adv2e6.py <REPO_ROOT>   # ALL_ANCHORS_OK
.venv/bin/python ops/prod-hotfixes/adv/adv2-e6/verify_adv2e6.py             # 10/10 OVERALL ALL_PASS
```

## Prod evidence
- Anchor probe: ALL_ANCHORS_OK (all 7 anchors count=1; prod did NOT diverge here).
- `.bak_adv2e6_1783574207` on all 3 files; IMPORT_OK; restart; openapi 200.
- **verify_adv2e6.py 10/10 OVERALL ALL_PASS** (in-process on prod DDB):
  - ADV2-701 account owner_type=syndicate + owner_syndicate_id + owner_sub=admin.
  - Admin-gated management (admin passes, plain member 403).
  - T1 serve on MEMBER content -> fills with the syndicate creative; response +
    AdClicks row carry `is_syndicate_ad=True`, `syndicate_id`, `content_owner=member`.
  - T2 serve on NON-member content -> house ad (syndicate creative NOT served; no tag).
  - T3 EXTERNAL ad still serves on a member slot, `is_syndicate_ad=False` (gate is
    syndicate-only, no skim).

## Residual
- The 3-way placement split (`_split_revenue` syndicate path: platform 30% +
  member configured-share-of-70% + syndicate treasury remainder) + the per-
  syndicate `member_share` config + treasury-funding rail (ADV2-702) + app
  surfaces (ADV2-709..711) are the NEXT phase. This phase only mints the tagged
  click that phase 2 charges/splits on.

---

# ADV2-E6 (F7) phase 2 — the 3-way syndicate placement split (ADV2-705..708)

**Phase 2** = the NEW money-path: a syndicate-OWNED ad charge on a member M splits
the content-owner (creator) 70% share between the member and the syndicate
treasury; platform 30% is untouched. An EXTERNAL advertiser on a member keeps the
full member-70/platform-30/syndicate-0 (NO skim). Reuses `_process_charge`
(funds-guarded, idempotent). LIVE PROD HOTFIX via SSM.

## Split economics (LOCKED)
- SYNDICATE-OWNED ad on member M: **platform 30% FIXED**; the remaining 70%
  (content-owner share) splits **member (`member_share_bps` of the 70%)** +
  **syndicate treasury (remainder of the 70%)**, both `type:"credit"`.
  `member_share_bps` is a **per-syndicate config** (default **7000 bps** = the
  member keeps 70% of the 70% ≈ 49% net; treasury 30% of the 70% ≈ 21% net).
- EXTERNAL (non-syndicate) advertiser on member M: **no syndicate skim** — member
  keeps the full 70%, platform 30%, syndicate 0. The 3-way fires **ONLY** for a
  syndicate-owned account (`owner_type=="syndicate"`) served in front of a
  **current member's** content (`is_member` re-checked at split time, churn-safe).

## What shipped (backend-only; LIVE PROD HOTFIX via SSM)
- **`app/services/syndicate_revenue_split.py`** — per-syndicate ad-placement
  config: `get_ad_placement_member_share_bps` / `get_ad_placement_config` /
  `set_ad_placement_member_share_bps` (admin-gated via `_require_admin`), stored
  at `pk=SYND#{id} sk=AD_PLACEMENT_CONFIG`; `DEFAULT_AD_PLACEMENT_MEMBER_SHARE_BPS=7000`.
- **`app/services/syndicate_treasury.py`** — `credit_placement_earning(...)`:
  credits the treasury its share (`balance_cents` ADD + one treasury ledger row,
  `direction`/`type` `"credit"`, `source_type="ad_placement"`); mirrors
  `refund_advertising`'s credit half. No-op for a non-positive amount.
- **`app/services/ad_billing.py`** — `_split_revenue` syndicate-aware 3-way path:
  after computing `creator_share`/`platform_share`, resolves the paying account;
  if `owner_type=="syndicate"` AND `is_member(owner_syndicate_id, creator_id)` it
  splits `creator_share` into `member_share_cents` (config bps) + `treasury_share_cents`
  (remainder), credits the MEMBER `member_share_cents` (existing `type:"credit"`
  path) and the TREASURY `treasury_share_cents`. Otherwise `member_share_cents ==
  creator_share`, `treasury_share_cents == 0` (byte-identical to the old 2-way).
  `_process_charge` denormalizes the split pointers (`member_share_cents`,
  `syndicate_treasury_share_cents`, `syndicate_id`, `is_syndicate_split`,
  `treasury_credit_sk`) onto the charge ledger row. **Sum invariant:**
  `platform_share + member_share_cents + treasury_share_cents == charge_cents`.
- **`app/routers/ads.py`** — `GET/PUT /ui/ads/syndicates/{syndicate_id}/ad-placement-config`,
  admin-gated (`_require_admin`); PUT body `{ "member_share_bps": <0..10000> }`.

## Apply / verify (idempotent, anchor-matched — dev clone AND prod)
```
python ops/prod-hotfixes/adv/adv2-e6/probe_adv2e6_p2.py  <REPO_ROOT>   # ALL_ANCHORS_OK
python ops/prod-hotfixes/adv/adv2-e6/apply_adv2e6_p2.py  <REPO_ROOT>   # PY_COMPILE_OK / APPLY_DONE
# prod verify (in-process on prod DDB, app env sourced):
bash   ops/prod-hotfixes/adv/adv2-e6/run_verify_p2.sh                  # 26/26 OVERALL ALL_PASS
```

## Prod evidence
- Anchor probe: **ALL_ANCHORS_OK** (all anchors count=1; prod did NOT diverge in
  the patched regions — only a pre-existing 3-line dev-only comment differs in
  `_split_revenue`, which the anchors avoid).
- `.bak_adv2e6p2_1783575296` on all 4 files; `PY_COMPILE_OK`; `import app.main`
  OK; restart via `/home/ubuntu/restart_backend.sh`; **openapi 200**; new route
  `/ui/ads/syndicates/{syndicate_id}/ad-placement-config` present.
- **verify_adv2e6_p2.py 26/26 OVERALL ALL_PASS** (in-process on prod DDB):
  - **A (default 7000):** syndicate ad on member M, $1.00 → content-owner 70c →
    member **49c** (`type:credit`) + treasury **21c** (`type:credit`) + platform
    **30c**; **49+21+30 == 100**; treasury balance +21c; member credit row `type=credit amt=49`.
  - **B (idempotent):** duplicate charge (same key) → `charge_cents 0` /
    `reason=duplicate`; treasury balance unchanged (no double-credit).
  - **C (configurable):** `member_share_bps → 5000` → member **35c** + treasury
    **35c** + platform **30c**; still sums 100c; treasury +35c.
  - **D (external, NO SKIM):** external advertiser on member M → member keeps
    **70c**, treasury **0**, platform 30c; `is_syndicate_split=False`; treasury
    balance unchanged; member credit row `type=credit amt=70`.
  - **E (funds-guard):** over-balance syndicate charge → `ok=False /
    insufficient_funds`; no credits.

## Residual
- App surfaces (ADV2-709..711 — syndicate ad management create/fund UI, the
  split-ratio config UI, the earnings/ROAS view) are thin clients over the now-live
  endpoints (`/ui/ads/syndicates/{id}/accounts`, `.../ad-placement-config`) and are
  the only remaining E6 client work. The backend money-path (the crux) is COMPLETE.
