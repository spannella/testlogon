"""GAP-0384 (SEC-012 §4.4): VTT sanitizer must use an allowlist, not a denylist.

Offline / pure-function tests. No AWS, no moto, no network. The
``sanitize_vtt_content`` function strips every tag except the WebVTT-permitted
set (`<b>`, `<i>`, `<u>`, `<v NAME>`, `<ruby>`, `<rt>` and their closers), removes
all attributes from permitted tags, and strips every other tag so no executable
markup survives. These assertions FAIL against the old denylist (which let
``<svg>``/``<img>``/``<details>`` through and kept attributes on permitted tags)
and PASS after the allowlist fix.
"""
from __future__ import annotations

from app.services.vod_subtitle_manager import sanitize_vtt_content


def _cue(payload: str) -> str:
    """Wrap a cue-payload line in a minimal VTT cue (timestamp + blank line)."""
    return f"WEBVTT\n\n00:00:01.000 --> 00:00:04.000\n{payload}\n"


# ─── Allowed tags survive ────────────────────────────────────────────────────


def test_bold_italic_underline_preserved():
    out = sanitize_vtt_content(_cue("<b>bold</b> <i>it</i> <u>under</u>"))
    assert "<b>bold</b>" in out
    assert "<i>it</i>" in out
    assert "<u>under</u>" in out


def test_voice_tag_with_name_preserved():
    out = sanitize_vtt_content(_cue("<v Roger>hi there</v>"))
    assert "<v Roger>" in out
    assert "</v>" in out
    assert "hi there" in out


def test_ruby_rt_preserved():
    out = sanitize_vtt_content(_cue("<ruby>kanji<rt>reading</rt></ruby>"))
    assert "<ruby>" in out
    assert "<rt>reading</rt>" in out
    assert "</ruby>" in out


# ─── Disallowed tags stripped ────────────────────────────────────────────────


def test_svg_onload_stripped():
    out = sanitize_vtt_content(_cue("<svg onload=alert(1)>x</svg>"))
    assert "<svg" not in out.lower()
    assert "onload" not in out.lower()
    assert "alert(1)" not in out


def test_img_onerror_stripped():
    out = sanitize_vtt_content(_cue("<img src=x onerror=alert(1)>"))
    assert "<img" not in out.lower()
    assert "onerror" not in out.lower()


def test_details_stripped():
    out = sanitize_vtt_content(_cue("<details open ontoggle=alert(1)>boo</details>"))
    assert "<details" not in out.lower()
    assert "ontoggle" not in out.lower()
    # Inner text preserved, only the tag is removed.
    assert "boo" in out


def test_base_tag_stripped():
    out = sanitize_vtt_content(_cue("<base href=//evil.example/>"))
    assert "<base" not in out.lower()


def test_script_stripped():
    out = sanitize_vtt_content(_cue("<script>alert(1)</script>"))
    assert "<script" not in out.lower()
    assert "</script" not in out.lower()


def test_anchor_with_javascript_uri_stripped():
    out = sanitize_vtt_content(_cue('<a href="javascript:alert(1)">click</a>'))
    assert "<a " not in out.lower()
    assert "<a>" not in out.lower()
    assert "javascript:" not in out.lower()
    assert "href" not in out.lower()


# ─── Attributes removed from permitted tags ──────────────────────────────────


def test_attributes_stripped_from_bold():
    out = sanitize_vtt_content(_cue('<b onclick="x()">hi</b>'))
    assert "<b>hi</b>" in out
    assert "onclick" not in out.lower()


def test_style_attr_stripped():
    out = sanitize_vtt_content(_cue('<i style="position:fixed">t</i>'))
    assert "<i>t</i>" in out
    assert "style" not in out.lower()


def test_event_attr_on_underline_stripped():
    out = sanitize_vtt_content(_cue('<u onmouseover="evil()">u</u>'))
    assert "<u>u</u>" in out
    assert "onmouseover" not in out.lower()


def test_voice_tag_drops_extra_attributes():
    out = sanitize_vtt_content(_cue('<v Roger onclick="x()">hi</v>'))
    assert "<v Roger>" in out
    assert "onclick" not in out.lower()


# ─── Timestamps and plain text preserved ─────────────────────────────────────


def test_timestamp_preserved():
    out = sanitize_vtt_content(_cue("plain text"))
    assert "00:00:01.000 --> 00:00:04.000" in out
    assert "WEBVTT" in out
    assert "plain text" in out


def test_multi_cue_preserved():
    vtt = (
        "WEBVTT\n\n"
        "00:00:01.000 --> 00:00:02.000\n<b>one</b>\n\n"
        "00:00:03.000 --> 00:00:04.000\n<svg onload=alert(1)>two\n"
    )
    out = sanitize_vtt_content(vtt)
    assert "00:00:01.000 --> 00:00:02.000" in out
    assert "00:00:03.000 --> 00:00:04.000" in out
    assert "<b>one</b>" in out
    assert "<svg" not in out.lower()
    assert "two" in out


def test_no_executable_markup_remains():
    """Composite adversarial cue: nothing dangerous should survive."""
    payload = (
        "<svg/onload=alert(1)><img src=x onerror=alert(1)>"
        '<base href=//evil><details open ontoggle=alert(1)>'
        '<b onclick="x">keep</b>'
    )
    out = sanitize_vtt_content(_cue(payload)).lower()
    for bad in ("<svg", "<img", "<base", "<details", "onload", "onerror", "ontoggle", "onclick"):
        assert bad not in out, f"{bad!r} survived sanitization"
    assert "<b>keep</b>" in out
