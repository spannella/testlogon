#!/usr/bin/env python3
"""APIK-E5 (#118) video-publishing parity -- idempotent patcher.

Wires ``Depends(maybe_enforce_api_key_route_policy)`` onto the 5 video routers
(video_listing, vod, video_subtitles, transcode_jobs[router+video_router], vod_bridge)
and registers their routes into API_KEY_ROUTE_SCOPE_REGISTRY under product="video":
  reads->video:read; ingest/edit/clip/combine/subtitle/transcode mutations->video:write;
  gallery publish/unpublish->video:publish;
  MONEY (SECURITY): pricing + ad-config->video:monetize (standalone; manage does NOT inherit);
  MODERATION (SECURITY): admin by-status->video:moderate (admin-owner create-gated).
Intentionally NOT registered -> fail-closed (403 unmapped) to every key:
  tip / comment-tip / purchase / access / playback-complete / purchases-list (money+entitlement),
  view / like / comments / reactions (social), GET ad-config / ad-impression / ad-stats (ad serve),
  download (DRM). DRM router (vod_drm) is NOT wired (public key-serve / admin+CSRF revoke stay
  INTENTIONAL). Promotes the video product phase shadow->ga so scopes actually enforce.
Idempotent: re-running is a no-op.

Env overrides (prod targeting): APIK_ROUTERS_DIR, APIK_REG, APIK_SETTINGS.
"""
import io, os

ROOT = os.environ.get("APIK_ROOT", os.getcwd())
RDIR = os.environ.get("APIK_ROUTERS_DIR", os.path.join(ROOT, "app/routers"))
REG = os.environ.get("APIK_REG", os.path.join(ROOT, "app/services/api_key_route_scope_registry.py"))
SETTINGS = os.environ.get("APIK_SETTINGS", os.path.join(ROOT, "app/core/settings.py"))

IMPORT_LINE = "from app.services.api_key_policy_enforcement import maybe_enforce_api_key_route_policy\n"
DEP = "dependencies=[Depends(maybe_enforce_api_key_route_policy)]"

Q = chr(34)  # double-quote, to keep source ascii-safe


def _ctor(prefix, tag, var="router"):
    old = '%s = APIRouter(prefix=%s%s%s, tags=[%s%s%s])' % (var, Q, prefix, Q, Q, tag, Q)
    new = '%s = APIRouter(prefix=%s%s%s, tags=[%s%s%s], %s)' % (var, Q, prefix, Q, Q, tag, Q, DEP)
    return (old, new)


# (filename, [(old ctor line, new ctor line), ...])
ROUTER_EDITS = [
    ("video_listing.py", [_ctor("/ui/videos", "video-listing")]),
    ("vod.py", [_ctor("/ui/videos", "vod")]),
    ("video_subtitles.py", [_ctor("/ui/videos", "video-subtitles")]),
    ("transcode_jobs.py", [
        _ctor("/ui/transcode-jobs", "transcode"),
        _ctor("/ui/videos", "transcode", var="video_router"),
    ]),
    ("vod_bridge.py", [_ctor("/ui/vod-bridge", "vod-bridge")]),
]


def patch_router(fn, edits):
    p = os.path.join(RDIR, fn)
    with io.open(p, "r", encoding="utf-8") as f:
        src = f.read()
    changed = False
    if "api_key_policy_enforcement import maybe_enforce_api_key_route_policy" not in src:
        lines = src.splitlines(keepends=True)
        out, done = [], False
        for ln in lines:
            out.append(ln)
            if (not done) and ln.startswith("from fastapi import"):
                out.append(IMPORT_LINE)
                done = True
        src = "".join(out)
        changed = True
    for old, new in edits:
        if new not in src:
            assert old in src, "router ctor not found in %s: %s" % (fn, old)
            src = src.replace(old, new, 1)
            changed = True
    if changed:
        with io.open(p, "w", encoding="utf-8") as f:
            f.write(src)
    print("router %-22s %s" % (fn, "patched" if changed else "already"))


READ = [
    ("GET", "/ui/videos"), ("GET", "/ui/videos/public"),
    ("GET", "/ui/videos/creator/{creator_id}"), ("GET", "/ui/videos/by-creator/{creator_id}"),
    ("GET", "/ui/videos/gallery"), ("GET", "/ui/videos/gallery/search"),
    ("GET", "/ui/videos/gallery/categories"), ("GET", "/ui/videos/{video_id}"),
    ("GET", "/ui/videos/{video_id}/subtitles"),
    ("GET", "/ui/transcode-jobs"), ("GET", "/ui/transcode-jobs/{job_id}"),
    ("GET", "/ui/videos/{video_id}/transcode/status"),
    ("GET", "/ui/vod-bridge/status/{video_id}"),
]
WRITE = [
    ("PATCH", "/ui/videos/{video_id}"), ("DELETE", "/ui/videos/{video_id}"),
    ("POST", "/ui/videos/{video_id}/clip"), ("POST", "/ui/videos/combine"),
    ("POST", "/ui/videos/upload/presign"), ("POST", "/ui/videos/upload/complete"),
    ("POST", "/ui/videos/{video_id}/upload/complete"),
    ("POST", "/ui/videos/{video_id}/subtitles"),
    ("DELETE", "/ui/videos/{video_id}/subtitles/{track_id}"),
    ("PATCH", "/ui/videos/{video_id}/subtitles/{track_id}"),
    ("POST", "/ui/transcode-jobs"), ("POST", "/ui/videos/{video_id}/transcode"),
    ("POST", "/ui/vod-bridge/import"), ("DELETE", "/ui/vod-bridge/{video_id}/link"),
]
PUBLISH = [
    ("POST", "/ui/videos/{video_id}/gallery/publish"),
    ("POST", "/ui/videos/{video_id}/gallery/unpublish"),
]
MONETIZE = [
    ("PATCH", "/ui/videos/{video_id}/pricing"),
    ("PATCH", "/ui/videos/{video_id}/ad-config"),
]
MODERATE = [
    ("GET", "/ui/videos/admin/by-status/{status}"),
]


def rows():
    out = {}
    for m, p in READ: out["%s:%s" % (m, p)] = "video:read"
    for m, p in WRITE: out["%s:%s" % (m, p)] = "video:write"
    for m, p in PUBLISH: out["%s:%s" % (m, p)] = "video:publish"
    for m, p in MONETIZE: out["%s:%s" % (m, p)] = "video:monetize"
    for m, p in MODERATE: out["%s:%s" % (m, p)] = "video:moderate"
    return out


def build_reg_block():
    R = rows()
    lines = [
        "    # Video -- APIK-E5 (#118): video-publishing parity. product=video.",
        "    # reads->video:read; ingest(presign/complete)/transcode/edit/clip/combine/subtitle",
        "    # mutations->video:write; gallery publish/unpublish->video:publish.",
        "    # MONEY (SECURITY): pricing + ad-config->video:monetize (standalone high-priv;",
        "    # manage inherits write+publish but NOT monetize/moderate). MODERATION (SECURITY):",
        "    # admin by-status->video:moderate (admin-owner create-gated via require_admin_or_root).",
        "    # tip/comment-tip/purchase/access/playback-complete/purchases-list/view/like/comments/",
        "    # GET-ad-config/ad-impression/ad-stats/download are intentionally UNREGISTERED ->",
        "    # fail-closed (403 unmapped) to every key. DRM router not wired (public serve intact).",
    ]
    for key in sorted(R.keys()):
        lines.append('    "%s": {"product": "video", "required_scopes": ["%s"], "entitlement_required": True},' % (key, R[key]))
    return [l + "\n" for l in lines]


def patch_registry():
    with io.open(REG, "r", encoding="utf-8") as f:
        lines = f.readlines()
    if any("# Video -- APIK-E5" in l for l in lines):
        print("registry already has Video block")
        return
    open_idx = next(i for i, l in enumerate(lines) if l.startswith("API_KEY_ROUTE_SCOPE_REGISTRY"))
    close_idx = next(i for i in range(open_idx, len(lines)) if lines[i].rstrip("\n") == "}")
    new = lines[:close_idx] + build_reg_block() + lines[close_idx:]
    with io.open(REG, "w", encoding="utf-8") as f:
        f.writelines(new)
    print("registry Video block inserted rows=%d" % len(rows()))


def patch_settings():
    with io.open(SETTINGS, "r", encoding="utf-8") as f:
        src = f.read()
    old = 'os.environ.get("API_KEY_VIDEO_PHASE", "shadow")'
    new = 'os.environ.get("API_KEY_VIDEO_PHASE", "ga")'
    if new in src:
        print("settings video phase already ga")
        return
    assert old in src, "video phase default not found in settings"
    src = src.replace(old, new, 1)
    with io.open(SETTINGS, "w", encoding="utf-8") as f:
        f.write(src)
    print("settings video phase shadow->ga (APIK-E5)")


def main():
    for fn, edits in ROUTER_EDITS:
        patch_router(fn, edits)
    patch_registry()
    patch_settings()
    print("E5 patch complete: registry_rows=%d" % len(rows()))


if __name__ == "__main__":
    main()
