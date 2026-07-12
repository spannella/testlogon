#!/usr/bin/env python3
"""MOD-C2 hotfix - enable WHOLE-VIDEO + VIDEO-COMMENT reports end-to-end.

The consumer app (MOD-C2) wires Report actions on a video detail (POSTs
content_type="video") and on video comments (content_type="video_comment").
Three gaps blocked those surfaces on the live backend:

  1. The CreateModerationReportIn Literal omitted "video" (prod had only
     "video_comment"; the dev clone had neither) -> whole-video reports 422'd.
  2. moderation_hide.resolve_owner handled neither "video" nor "video_comment",
     so the moderation CASE recorded owner_user_id=None for video content -> it
     never appeared in the poster's GET /moderation/cases/mine and owner-notify
     relied on a fallback.
  3. (prod only) _video_comment_exists called the keyword-only get_comment()
     positionally -> TypeError -> video_comment reports 500'd at validation.

Idempotent + presence-guarded + anchor-tolerant; py_compile-validated.
Run:  ROOT=/home/ubuntu/testlogon .venv/bin/python apply_video_report.py
"""
import os, re, py_compile

ROOT = os.environ.get("ROOT", ".")
MOD = os.path.join(ROOT, "app/routers/moderation.py")
HIDE = os.path.join(ROOT, "app/services/moderation_hide.py")

CANON_LITERAL = ('    content_type: Literal["feed_post", "feed_comment", "feed_media", '
                 '"message", "message_media", "video", "video_comment", "profile_photo"]')

VALIDATE_VIDEO = '''    if inp.content_type == "video":
        # MODVIDEO: whole-video report; content_id is the video_id.
        try:
            _v = T.video_metadata.get_item(Key={"video_id": inp.content_id}).get("Item")
        except Exception:
            _v = True
        if not _v:
            raise HTTPException(status_code=404, detail="content not found")
        return

    if inp.content_type == "video_comment":
        # MODVIDEO: comment on a video; video_id carries the parent.
        if not inp.video_id:
            raise HTTPException(status_code=400, detail="video_id is required for video_comment")
        try:
            from app.services.video_comments import get_comment
            try:
                _vc = get_comment(video_id=inp.video_id, comment_id=inp.content_id)
            except TypeError:
                _vc = get_comment(inp.video_id, inp.content_id)
        except Exception:
            _vc = None
        if not _vc:
            raise HTTPException(status_code=404, detail="content not found")
        return

'''

RESOLVE_VIDEO = '''        if content_type == "video":
            # MODVIDEO
            _vid = str(md.get("video_id") or content_id)
            _it = T.video_metadata.get_item(Key={"video_id": _vid}).get("Item") or {}
            return _it.get("owner_sub") or _it.get("user_id") or _it.get("creator_id")
        if content_type == "video_comment":
            # MODVIDEO
            from app.services.video_comments import get_comment
            try:
                _row = get_comment(video_id=str(md.get("video_id") or ""), comment_id=content_id)
            except TypeError:
                _row = get_comment(str(md.get("video_id") or ""), content_id)
            return (_row or {}).get("user_id")
'''

BUGGY = '    return bool(get_comment(video_id, comment_id))'
FIXED = ('    try:\n'
         '        return bool(get_comment(video_id=video_id, comment_id=comment_id))\n'
         '    except TypeError:\n'
         '        return bool(get_comment(video_id, comment_id))')

def patch_moderation():
    src = open(MOD).read(); orig = src; changed = []
    new = re.sub(r'    content_type: Literal\[[^\]]*\]', CANON_LITERAL, src, count=1)
    if new != src: src = new; changed.append("literal")
    if re.search(r'\n    video_id: Optional\[str\]', src) is None:
        src2 = re.sub(r'(\n    conversation_id: Optional\[str\] = Field\(default=None, max_length=256\))',
                      r'\1\n    video_id: Optional[str] = Field(default=None, max_length=256)', src, count=1)
        if src2 != src: src = src2; changed.append("video_id_field")
    if 'inp.content_type == "video":' not in src or 'inp.content_type == "video_comment":' not in src:
        marker = '    if inp.content_type == "profile_photo":'
        idx = src.find(marker)
        if idx != -1:
            src = src[:idx] + VALIDATE_VIDEO + src[idx:]; changed.append("validate_branches")
    if BUGGY in src:
        src = src.replace(BUGGY, FIXED); changed.append("video_comment_exists_kwargs")
    open(MOD, "w").write(src)
    py_compile.compile(MOD, doraise=True)
    return changed if src != orig else []

def patch_hide():
    src = open(HIDE).read(); orig = src; changed = []
    if 'MODVIDEO' not in src:
        pos = src.rfind('return item.get("sender_id")')
        if pos != -1:
            end = src.find("\n", pos) + 1
            src = src[:end] + RESOLVE_VIDEO + src[end:]; changed.append("resolve_owner")
    open(HIDE, "w").write(src)
    py_compile.compile(HIDE, doraise=True)
    return changed if src != orig else []

if __name__ == "__main__":
    print("ROOT", ROOT)
    print("moderation.py changed:", patch_moderation() or "already-current")
    print("moderation_hide.py changed:", patch_hide() or "already-current")
    print("py_compile OK")
