# Auth fixtures — capture provenance

These JSON fixtures mirror the verified wire shapes of the TestLogon FastAPI backend auth surface
(reconciled against the reviewed specs AND-046/047 and `src/api/types.ts`). They are **synthetic**:
all ids (`sess-1`, `chal_01HZX`, `usr_42`), IPs, and cookie values (`csrf-test-token`) are
placeholders — they contain no real PII, passwords, OTP secrets, or session tokens.

Shapes (verified):
- `session_start_*`     -> UiSessionStartResp { auth_required, challenge_id?, required_factors[], session_id? }
- `mfa_*_verify_ok`     -> MfaVerifyResp { status, session_id?, required_factors[], passed{}, remaining_factors[] }
- `mfa_sms_begin_ok`    -> ChallengeResp { challenge_id, sent_to? }
- `session_finalize_ok` -> SessionFinalizeResp { status, session_id?, required_factors[], passed{} }
- `session_refresh_ok`  -> StatusResp { status }
- `me`                  -> MeResp { user_sub, session_id, ip }
- `sessions`            -> SessionsResp { sessions: SessionInfo[] } (epoch-second timestamps, is_current, ip, user_agent)
- `error_detail_*`      -> the three FastAPI `detail` variants: string | [{loc,msg,type}] | {code,...}

## Re-capture procedure

1. Point a debug build / curl at a reachable backend (the dev host is plaintext + unreliable).
2. Drive the flow: POST /ui/session/start -> (sms/email begin) -> mfa verify -> POST /ui/session/finalize -> GET /ui/me;
   and GET /ui/sessions.
3. Strip `Authorization`, real `Set-Cookie`, emails/phones; replace ids with the synthetic placeholders above.
4. Run `FixtureValidationTest` (in core-data/app test source) to confirm each fixture still parses into its DTO.
