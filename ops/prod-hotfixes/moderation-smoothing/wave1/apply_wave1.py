#!/usr/bin/env python3
"""MODX WAVE-1 re-apply helper.

Wave-1 changes are of two kinds:

1. BYTE-MIRROR files — prod was identical to dev HEAD pre-edit, so the committed
   source IS the deployed source (deploy by copying these paths):
     app/services/moderation_case.py            (MODX-3 distinct/trust/velocity/protect + MODX-8 hook)
     app/services/moderation_lifecycle.py       (MODX-4 humane expiry/SLA/dispute/no-strike + MODX-5 reputation + MODX-8 guards)
     app/services/moderation_policy_engine.py   (MODX-6 fingerprint capture on ban)
     app/routers/admin_moderation.py            (MODX-3 DTO + MODX-5 COI + MODX-7 dual-approval + MODX-8 senior gate)
     app/services/moderation_reporter_reputation.py  (NEW, MODX-5)
     app/services/moderation_ban_fingerprint.py       (NEW, MODX-6)
     app/services/moderation_illegal_lane.py          (NEW, MODX-8)

2. DIVERGENT files — prod carries local deltas, so the wave applies IN-PLACE
   string edits (below) rather than overwriting:
     app/routers/moderation.py  — add illegal/csam topics + the under_review dispute endpoint
     app/core/settings.py       — flip dual-approval default to ON

Run from a testlogon checkout root:  python3 apply_wave1.py
Idempotent: re-running is a no-op if the edits are already present.
"""
import sys

MOD = 'app/routers/moderation.py'
SET = 'app/core/settings.py'

MOD_TOPICS_A = 'ALLOWED_TOPICS = {"sexual", "extortion", "criminal", "spam", "racist", "harassment", "hate", "violence_threats", "other", "licensing_ip"}'
MOD_TOPICS_B = 'ALLOWED_TOPICS = {"sexual", "extortion", "criminal", "spam", "racist", "harassment", "hate", "violence_threats", "other", "licensing_ip", "illegal", "csam"}'

MOD_DISPUTE_FN = '''def _hold_dispute(case_id: str, ctx: Dict[str, str], inp: HoldRespondIn) -> HoldActionOut:
    """MODX-4 (C9): under_review recourse — poster contests a fresh auto-hide."""
    uid = str(ctx.get("user_sub") or "").strip()
    if not uid:
        raise HTTPException(status_code=401, detail="Unauthorized")
    from app.services import moderation_lifecycle as _life
    try:
        res = _life.poster_dispute(case_id=case_id, owner_user_id=uid, statement=inp.statement)
    except PermissionError:
        raise HTTPException(status_code=403, detail="not the content owner")
    except ValueError as exc:
        msg = str(exc)
        if msg == "case_not_found":
            raise HTTPException(status_code=404, detail="case not found") from exc
        raise HTTPException(status_code=409, detail=msg) from exc
    return HoldActionOut(ok=True, case_id=case_id, state=str(res.get("state") or ""))


def _hold_close(case_id: str, ctx: Dict[str, str]) -> HoldActionOut:'''
MOD_DISPUTE_ANCHOR = 'def _hold_close(case_id: str, ctx: Dict[str, str]) -> HoldActionOut:'

MOD_EP = '''@router.post("/holds/{case_id}/dispute", response_model=HoldActionOut)
def hold_dispute(case_id: str, inp: HoldRespondIn, ctx=Depends(require_ui_session)):
    return _hold_dispute(case_id, ctx, inp)


@compat_router.post("/holds/{case_id}/dispute", response_model=HoldActionOut)
def hold_dispute_compat(case_id: str, inp: HoldRespondIn, ctx=Depends(require_ui_session)):
    return _hold_dispute(case_id, ctx, inp)


@router.post("/holds/{case_id}/close", response_model=HoldActionOut)
def hold_close(case_id: str, ctx=Depends(require_ui_session)):
    return _hold_close(case_id, ctx)'''
MOD_EP_ANCHOR = '@router.post("/holds/{case_id}/close", response_model=HoldActionOut)\ndef hold_close(case_id: str, ctx=Depends(require_ui_session)):\n    return _hold_close(case_id, ctx)'

SET_A = '''    moderation_dual_approval_permanent_ban_enabled: bool = os.environ.get(
        "MODERATION_DUAL_APPROVAL_PERMANENT_BAN_ENABLED",
        "false",
    ).lower() in ("1", "true", "yes", "on")'''
SET_B = '''    moderation_dual_approval_permanent_ban_enabled: bool = os.environ.get(
        "MODERATION_DUAL_APPROVAL_PERMANENT_BAN_ENABLED",
        "true",  # MODX-7: real dual-approval ON by default
    ).lower() in ("1", "true", "yes", "on")'''


def patch(path, edits):
    s = open(path, encoding='utf-8').read()
    for a, b in edits:
        if b.split(chr(10))[0] in s and a not in s:
            print('  already applied:', path); continue
        if s.count(a) != 1:
            print('  ANCHOR MISS (%d) in %s: %s' % (s.count(a), path, a[:50])); return False
        s = s.replace(a, b)
    open(path, 'w', encoding='utf-8').write(s)
    print('  patched', path); return True


ok = True
print('moderation.py:')
ok &= patch(MOD, [(MOD_TOPICS_A, MOD_TOPICS_B), (MOD_DISPUTE_ANCHOR, MOD_DISPUTE_FN), (MOD_EP_ANCHOR, MOD_EP)])
print('settings.py:')
ok &= patch(SET, [(SET_A, SET_B)])
sys.exit(0 if ok else 1)
