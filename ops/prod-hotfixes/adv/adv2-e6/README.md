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
