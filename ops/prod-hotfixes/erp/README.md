# ERP finance router prod fold (P1)

Mounts the previously-unmounted GL/AR/pricing services on PROD
(i-08f937fc705ebea75, us-east-2) via SSM. Dev commits: 241478c6 (backend),
6b27150b (web).

## What
- Copies `erp_gl.py`, `erp_ar.py`, `erp_pricing.py` verbatim into
  `app/routers/` (md5: 8826da5e / fb03b223 / 7b619daf — identical to dev).
- Anchor-patches `app/main.py` after the entitlement_requests mount with the
  identical flag-gated `include_router` block (patch_main_erp.py, idempotent).
  Anchor block md5 d073c526 confirmed byte-identical dev==prod before patch;
  post-patch anchor+injection block md5 3df66c07 identical dev==prod.

## Apply
    python3 gen_apply_erp.py                          # regenerate apply_erp_prod.sh
    python3 /tmp/ssm_send.py < apply_erp_prod.sh      # backs up main.py, patches, restarts

Restart kills the root uvicorn first, then runs restart_backend.sh; verifies
openapi 200 + single worker + the 11 erp routes present.

## LIVE verify (prod)
GL accounts 200 (12 CoA), AR aging 200 (real invoices), non-admin 403.

## Rollback
Prod backup at `app/main.py.bak_erp_<TS>`. To revert:
`cp app/main.py.bak_erp_<TS> app/main.py && rm app/routers/erp_{gl,ar,pricing}.py`
then restart (root pkill + restart_backend.sh). The routers are flag-gated and
role-auth-only, so they add no attack surface when the ERP flags are off.
