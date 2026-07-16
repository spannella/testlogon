R3 — API-KEY residual (#118): VERIFY ads:* / kyc:* partner-subsystem enforcement (out-of-registry, BY DESIGN)
==========================================================================================================

VERDICT: SOUND AS DESIGNED. No code change. ads:* and kyc:* are enforced by their own partner
subsystems (advertiser_api / kyc_partner_api) with a DIRECT per-route capability check, deliberately
OUTSIDE the route-scope registry model. Verified fail-closed: no un-scoped access, no owner-injection,
no registry double-grant. Prod == dev clone byte-for-byte on all 6 enforcement files.

WHY OUT OF THE REGISTRY (design intent)
  The registry model (maybe_enforce_api_key_route_policy + api_key_route_scope_registry) governs the 5
  UI-shared products (messaging/newsfeed/filemanager/groups/video) where the SAME router serves both
  UI-session users and ak_ keys — there the registry maps each UI route to the scope an api-key needs, and
  the E0-4 marker (request.state.api_key_route_authorized) is what lets an admitted key borrow the owner
  identity via get_authenticated_user / require_ui_session.
  advertiser_api (/api/v1/ads) and kyc_partner_api (/api/v1/kyc) are DEDICATED, API-KEY-ONLY partner
  surfaces. They never share a route with UI-session auth, never call get_authenticated_user /
  require_ui_session, and never bridge a principal to owner. Each route instead does its OWN auth in two
  explicit steps, so the registry/marker machinery is neither needed nor wired.

ENFORCEMENT MAP  (spec-of-record = dev clone android-impl; prod hashes identical — see PROBE)
  Step 1 — AUTHN (who):  Depends(require_api_key_principal)   app/services/api_key_auth_dependency.py:54
    * extracts ak_ key (Authorization: ApiKey <k> | X-API-Key), parse_api_key + check_api_key_allowed
      (invalid/absent -> 401 api_key_invalid; bad origin -> 403 api_key_origin_denied).
    * builds principal = {user_sub, api_key_id, capabilities=effective_api_key_capabilities(item)}.
    * NOTE: does NOT set request.state.api_key_route_authorized -> even if one of these routers ever added
      a session dependency, E0-4 would fail it closed (401), never inject owner.
  Step 2 — AUTHZ (what): svc.require_scope(principal, "<domain>:<scope>")  called at the TOP of EVERY route
    * ads:  app/services/advertiser_api.py:47  -> 403 {code:"api_key_scope_missing", required_scope}
    * kyc:  app/services/kyc_partner_api.py:70  -> 403 {code:"kyc_api_forbidden",    required_scope}
    * both use expand_api_key_capabilities (app/services/api_key_capabilities.py:93) — a missing scope is
      DENIED. Implications: ads:manage=>ads:read/serve; kyc:admin=>kyc:{read,submit,upload,webhook}.
  Step 3 — TENANT (whose): identity is the KEY OWNER, partitioned by principal.user_sub, never injected:
    * ads:  resolve_account()  app/services/advertiser_api.py:70  (ad_accounts.list_accounts_by_owner)
    * kyc:  _partner_id()      app/services/kyc_partner_api.py:88  (PARTNER#<user_sub> partition)

  Routers on every route use ONLY Depends(require_api_key_principal) (grep-verified: maybe_enforce=False,
  require_ui_session=False, get_authenticated_user=False):
    app/routers/advertiser_api.py   (/api/v1/ads,  17 routes)
    app/routers/kyc_partner_api.py  (/api/v1/kyc,  12 routes)

NO COARSE / NO CROSS-DOMAIN GRANT
  api_key_capabilities.py has NO "*:write"-style coarse scope. The only capability that expands to ads:*/
  kyc:* is the admin:all WILDCARD, which is grant-gated to admin/root owners at key-creation time (E0-1) —
  the intended superuser path, not a hole. A 5-domain scope (e.g. messager:manage) or a sibling partner
  scope (ads:read vs a kyc route) expands to a set that contains NEITHER ads:* nor kyc:* -> require_scope
  denies. Money/moderation stay distinct high-priv scopes (ads:manage for spend/CRUD; kyc:submit/upload/
  webhook distinct from kyc:read).

REGISTRY: NOT double-granted, NOT bypassed
  * api_key_route_scope_registry.py has ZERO rows for /api/v1/ads or /api/v1/kyc (grep = 0/0).
  * main.py includes both routers WITHOUT the maybe_enforce dependency (main.py:902 kyc, :1026 ads).
  * the startup drift monitor (main.py ~L1408-1420) ONLY scans routes whose dependant carries
    maybe_enforce_api_key_route_policy; the ads/kyc routes carry it NOT, so they are excluded from the
    registry coverage check — no false "unregistered_live_route", and no generic-path grant can reach them.

PROBE (prod, read-only — probe_r3.py via SSM) — prod EC2 i-08f937fc705ebea75
  sha256 IDENTICAL to dev clone (android-impl 6651d3a5) for all 6 files:
    app/routers/advertiser_api.py             882fbbd5...939ea
    app/routers/kyc_partner_api.py            d8991806...caa9a5
    app/services/advertiser_api.py            f4d97fd5...b51ed
    app/services/kyc_partner_api.py           1d4eba34...88080
    app/services/api_key_auth_dependency.py   c2a23d3a...c9e6d
    app/services/api_key_capabilities.py      660edf02...87774
  wiring: routers included=1/1; registry ads/kyc refs=0/0; routers use require_api_key_principal only.

VERIFY (prod DDB, in-process TestClient, synthetic users/keys/ad-account, auto-cleaned)
  verify_r3.py  = 12/13 PASS  (the 1 "fail" was a test-body 422 on a missing required field BEFORE the
                  scope check — NOT a security gap; re-proven with a valid body in verify_r3b.py)
  verify_r3b.py = 2/2 PASS
  Representative ADS route  GET /api/v1/ads/account :
    POS  ads:read                 -> 200 (account)
    NEG  no key                   -> 401
    NEG  messager:manage (5-dom)  -> 403 api_key_scope_missing (required ads:read) — NOT owner-200
    NEG  kyc:read (cross-domain)  -> 403 (required ads:read)
    NEG  garbage key              -> 401
    GRANULAR ads:read -> POST /ads/campaigns -> 403 (required ads:manage)
    POS  ads:manage -> GET /ads/campaigns -> 200 (manage implies read)
  Representative KYC route  GET /api/v1/kyc/applications :
    POS  kyc:read                 -> 200 (list)
    NEG  no key                   -> 401
    NEG  messager:manage (5-dom)  -> 403 kyc_api_forbidden (required kyc:read) — NOT owner-200
    NEG  ads:read (cross-domain)  -> 403 (required kyc:read)
    NEG  garbage key              -> 401
    GRANULAR kyc:read (valid body) -> POST /kyc/applications -> 403 (required kyc:submit)  [verify_r3b]
    POS  kyc:submit (valid body)  -> 201 (created)                                          [verify_r3b]
  E0-4 posture confirmed: on BOTH partner routers a valid-but-wrong-scope key can NEVER act as owner —
  it is stopped at require_scope (403) and identity is only ever the key owner's own partition.
  Synthetic residue cleaned (ad-account row; kyc PARTNER# rows scan-deleted; kyc IDEMP# row TTL-expires).

DEPLOY: none — verify-only residual, no code changed. Fold committed to dev clone android-impl.
