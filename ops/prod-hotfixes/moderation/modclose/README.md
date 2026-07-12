# MOD close-out — full-lifecycle E2E verification (program complete)

Closing verification for the content-moderation program (EPIC A-F). No source
changes — these are the two prod-verified lifecycle lanes NOT already covered by
`../mode1/verify_mode1_e2e.py` (25/25), run in-process on prod (ubuntu venv +
.env.local, DEV_MODE=1) against real prod DDB and the exact `_create_report`
service the `/v1/moderation/reports` route runs.

- `verify_modclose_lanes.py` — 8/8 PASS:
  - GUARDED auto-hide (lower-severity `spam`): 1 report NOT hidden, 2 NOT hidden,
    3rd report -> auto-hidden in its store (report_threshold, report_count=3).
  - LICENSING/IP -> DMCA: a `licensing_ip` report routes to `file_dmca_claim`
    (status=submitted, `dmca_...` id), hides the content (`dmca_hidden`+claim id)
    in its store, records strike #1, and creates NO general moderation case.
- `cleanup_modclose.py` — removes the throwaway `e2e_` rows (bans / cases /
  syndicate / leftover posts) from the close-out runs.

Combined with `../mode1/verify_mode1_e2e.py` (25/25) the full lifecycle matrix is
33/33 PASS on prod: report -> auto-hide -> admin confirm(30d hold) ->
reinstate(byte-for-byte) / delete(hard) + ban(enforced), dismiss(un-hide),
syndicate hide-in-store, permanent-ban senior/dual-approval 403 gating,
guarded auto-hide, and licensing->DMCA.

Run: `bash /tmp/run_on_prod.sh <local.py> <remote.py>` (ships via SSM, runs as ubuntu).
