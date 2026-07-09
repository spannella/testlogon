#!/usr/bin/env python3
"""MOD-D2 backend hotfix: append a GET to list the poster's OWN moderation cases.

Idempotent + anchor-free (pure append-if-absent) so it runs on the dev clone AND
the (line-offset-diverged) prod copy. Adds:
  GET /v1/moderation/cases/mine   (router)
  GET /moderation/cases/mine      (compat_router)
returning the caller's under_review / hold / awaiting_final cases with the
category, state, hold_until + days-remaining countdown, and any poster response.
"""
import io, os, sys, py_compile

ROOT = os.environ.get("ROOT", os.path.expanduser("~/dev/testlogon"))
PATH = os.path.join(ROOT, "app/routers/moderation.py")

MARKER = "def _list_my_cases("
BLOCK = '''

# ── MOD-D2: poster lists their OWN moderation cases (My content under review) ──
class MyModerationCaseOut(BaseModel):
    case_id: str
    content_type: str = ""
    content_id: str = ""
    state: str = ""
    categories: List[str] = []
    report_count: int = 0
    hold_until: Optional[int] = None
    days_remaining: Optional[int] = None
    poster_response: Optional[str] = None
    responded_at: Optional[int] = None
    created_at: int = 0
    updated_at: int = 0


class MyModerationCasesOut(BaseModel):
    cases: List[MyModerationCaseOut]


# States surfaced on the poster's "My content under review" screen.
_MY_REVIEW_STATES = {"under_review", "hold", "awaiting_final"}


def _mod_coerce_int(v: Any) -> Optional[int]:
    try:
        return None if v is None else int(v)
    except (TypeError, ValueError):
        return None


def _case_to_my_out(item: Dict[str, Any], *, now_ts: int) -> "MyModerationCaseOut":
    cats_raw = item.get("categories") or []
    if isinstance(cats_raw, (set, frozenset)):
        cats = sorted(str(c) for c in cats_raw)
    elif isinstance(cats_raw, (list, tuple)):
        cats = [str(c) for c in cats_raw]
    else:
        cats = [str(cats_raw)]
    state = str(item.get("state") or "")
    hold_until = _mod_coerce_int(item.get("hold_until"))
    days_remaining = None
    if state == "hold" and hold_until:
        days_remaining = max(0, (int(hold_until) - int(now_ts) + 86399) // 86400)
    resp_txt = item.get("poster_response")
    return MyModerationCaseOut(
        case_id=str(item.get("case_id") or ""),
        content_type=str(item.get("content_type") or ""),
        content_id=str(item.get("content_id") or ""),
        state=state,
        categories=cats,
        report_count=_mod_coerce_int(item.get("report_count")) or 0,
        hold_until=hold_until,
        days_remaining=days_remaining,
        poster_response=(str(resp_txt) if resp_txt else None),
        responded_at=_mod_coerce_int(item.get("responded_at")),
        created_at=_mod_coerce_int(item.get("created_at")) or 0,
        updated_at=_mod_coerce_int(item.get("updated_at")) or 0,
    )


def _list_my_cases(ctx: Dict[str, str]) -> "MyModerationCasesOut":
    uid = str(ctx.get("user_sub") or "").strip()
    if not uid:
        raise HTTPException(status_code=401, detail="Unauthorized")
    now = int(time.time())
    out: List[MyModerationCaseOut] = []
    try:
        scan_kwargs: Dict[str, Any] = {"FilterExpression": Attr("owner_user_id").eq(uid)}
        pages = 0
        while True:
            resp = T.moderation_cases.scan(**scan_kwargs)
            for it in resp.get("Items", []) or []:
                if str(it.get("state") or "") in _MY_REVIEW_STATES:
                    out.append(_case_to_my_out(it, now_ts=now))
            lek = resp.get("LastEvaluatedKey")
            pages += 1
            if not lek or pages >= 20:
                break
            scan_kwargs["ExclusiveStartKey"] = lek
    except ClientError:
        logger.exception("moderation._list_my_cases scan failed for %s", uid)
        raise HTTPException(status_code=503, detail="unavailable")
    out.sort(key=lambda c: c.updated_at, reverse=True)
    return MyModerationCasesOut(cases=out)


@router.get("/cases/mine", response_model=MyModerationCasesOut)
def list_my_cases(ctx=Depends(require_ui_session)):
    return _list_my_cases(ctx)


@compat_router.get("/cases/mine", response_model=MyModerationCasesOut)
def list_my_cases_compat(ctx=Depends(require_ui_session)):
    return _list_my_cases(ctx)
'''

with io.open(PATH, "r", encoding="utf-8") as f:
    src = f.read()

if MARKER in src:
    print("SKIP already applied:", PATH)
    sys.exit(0)

if not src.endswith("\n"):
    src += "\n"
src += BLOCK
with io.open(PATH, "w", encoding="utf-8") as f:
    f.write(src)
py_compile.compile(PATH, doraise=True)
print("APPLIED + py_compile OK:", PATH)
