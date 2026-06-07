"""Regression test for GAP-0381: dev-mode placeholder ad creatives must exist.

`app/services/ad_placement.py`'s ``DEV_AD_CREATIVES`` references static URLs
(``/static/ads/placeholder_preroll.mp4`` etc.). ``/static`` is mounted onto
``app/static/`` in ``app/main.py``. If the files are missing the player gets a
404, breaking the dev/test ad flow. This test locks the assets against deletion
by asserting each file exists at the path derived from the constants, is
non-empty, and has a valid container/image signature.

Offline: no AWS, no network, no app startup.
"""

from __future__ import annotations

from pathlib import Path

from app.services.ad_placement import DEV_AD_CREATIVES

# app/static/ -> mounted at /static in app/main.py
STATIC_DIR = Path(__file__).resolve().parent.parent / "app" / "static"

_STATIC_URL_PREFIX = "/static/"


def _url_to_path(url: str) -> Path:
    assert url.startswith(_STATIC_URL_PREFIX), f"unexpected static url: {url}"
    rel = url[len(_STATIC_URL_PREFIX) :]
    return STATIC_DIR / rel


def test_dev_ad_creatives_resolve_to_existing_nonempty_files() -> None:
    assert DEV_AD_CREATIVES, "DEV_AD_CREATIVES must not be empty"
    for creative in DEV_AD_CREATIVES:
        url = creative["url"]
        path = _url_to_path(url)
        assert path.is_file(), f"placeholder asset missing: {url} -> {path}"
        assert path.stat().st_size > 0, f"placeholder asset is empty: {path}"


def test_dev_ad_creative_files_have_valid_signatures() -> None:
    for creative in DEV_AD_CREATIVES:
        url = creative["url"]
        path = _url_to_path(url)
        data = path.read_bytes()
        if url.endswith(".mp4"):
            # ISO BMFF / MP4: bytes 4..8 are the 'ftyp' box type.
            assert data[4:8] == b"ftyp", (
                f"{path} is not a valid MP4 (missing ftyp box): {data[:8]!r}"
            )
        elif url.endswith(".png"):
            # PNG magic number.
            assert data[:8] == b"\x89PNG\r\n\x1a\n", (
                f"{path} is not a valid PNG: {data[:8]!r}"
            )
        else:  # pragma: no cover - guards against new creative types
            raise AssertionError(f"unhandled creative url extension: {url}")


def test_dev_ad_creatives_cover_expected_filenames() -> None:
    names = {Path(c["url"]).name for c in DEV_AD_CREATIVES}
    assert names == {
        "placeholder_preroll.mp4",
        "placeholder_midroll.mp4",
        "placeholder_overlay.png",
    }, f"unexpected creative filenames: {names}"
