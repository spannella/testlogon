# APIK EPIC E3 — Filemanager parity (#118)

Registry-only change on the already-gated `/v1/fs` router (`filemanager` product = `ga`
since E0). Enforcement reads ONLY the registry (exempt == unmapped == 403), so every
real filemanager route beyond the original 5 returned `unmapped_route` 403 for any key.
E3 promotes the real product surface from fail-closed exemptions into
`API_KEY_ROUTE_SCOPE_REGISTRY` with `filemanager:{read,write,share}` and clears the
`copy / batch-upload / crm-metadata / crm-search` unmapped drift. No router/handler code
touched -> app UI-session behavior unaffected.

## Result
- 45 filemanager registry rows: **read=17, write=26, share=2** (all `entitlement_required=True`,
  matching the existing FM/messager/newsfeed rows; entitlement gate is inert for `X-API-Key`
  auth because `_extract_user_sub` returns empty -> bypassed:missing_subject).
- filemanager drift -> **0** (73 live fs routes = 45 registered + 28 intentional exemptions;
  0 in both dicts). The 4 formerly-UNMAPPED routes (copy, batch-upload, crm-metadata,
  crm-search) are now covered.
- `filemanager:admin` inherits read+write+share; `write` does NOT imply `read` and `share`
  is standalone -> per-scope isolation holds (verified negative).

## Ticket-by-ticket
- **E3-1 flagship presign upload flow** — `presign-upload`+`complete-upload` -> `filemanager:write`.
  A write key completes presign -> PUT(bytes to presigned S3 key) -> complete and the file
  appears in `GET /v1/fs/list`.
- **E3-2 core mutations** — rename-file/rename-folder/move/copy/move-resume/move-rollback +
  DELETE file/folder/generic -> `filemanager:write`. Clears the `copy` drift.
- **E3-3 sharing symmetry** — `share`/`unshare` -> `filemanager:share`; shared-* reads
  (shared-with/-me, shared-list/-info/-download/-preview/-thumbnail, download-zip) -> `read`;
  shared-* mutations (shared-move/-rename-*/-folder/-upload*/DELETE shared-file/-folder) -> `write`.
  A key can create, list, consume (recipient shared-with-me), and revoke a share.
- **E3-4 read-side + orphans** — info/search/search-text/preview/thumbnail/crm-search -> `read`;
  batch-upload/crm-metadata -> `write`. drift -> 0.

## Intentional blocks kept fail-closed exempt (403)
mount-credential ops (all `/mounts*` incl. sftp/icloud/rotate-credential/revoke/validate/test/
status-override) + `/admin/*` + `client-telemetry` + `purge-deleted` + `usage/*`.

## Verify (in-process on PROD DDB + real S3, synthetic, auto-cleaned, 0 residue)
- BEFORE 5/5 (promoted routes `unmapped_route` 403; already-keyed list 200).
- AFTER **38/38** pass=38 fail=0 (flagship presign->PUT->complete->list; mutations; sharing
  create/list/consume/revoke; read-side; cross-user isolation; full per-scope negative matrix;
  intentional blocks stay 403; UI-session + dak_ delegation unaffected).
- Live-server HTTP smoke on the restarted prod uvicorn: **7/7** (write presign/folder 200,
  read list 200, read->folder / write->list / newsfeed:read->list 403 scope_denied, no-key 401).

## Apply / verify
    python ops/prod-hotfixes/apikey/E3/apply_apik_e3_patch.py           # idempotent, APIK_REG overrides target
    APIK_PHASE=AFTER APIK_REPO=<repo> python ops/prod-hotfixes/apikey/E3/verify_apik_e3.py
    python ops/prod-hotfixes/apikey/E3/gen_prod_deploy_e3.py {place|apply|verify_after}  # SSM probes

## .bak
- Prod (kept): `app/services/api_key_route_scope_registry.py.bak_apik_e3_1783913978`.
- Dev working-tree backup removed after verify (git is source-of-truth).
