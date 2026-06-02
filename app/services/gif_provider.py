"""Mock GIF search provider for MSG-008.

In dev mode this returns deterministic placeholder results so development and
testing work offline without external GIF API dependencies. The shape mirrors
what a real provider (Tenor / Giphy) adapter would return: a list of dicts with
``id``, ``url``, ``alt_text``, ``width`` and ``height``.
"""
from __future__ import annotations

import zlib
from typing import Any, Dict, List

# 20 deterministic mock GIF entries. Alt texts are chosen so common search
# queries (e.g. "happy", "laugh", "cat") surface relevant-looking results.
MOCK_GIFS: List[Dict[str, Any]] = [
    {"id": "mock_gif_001", "url": "/mock/gifs/placeholder_1.gif", "alt_text": "Happy dance animation", "width": 320, "height": 240},
    {"id": "mock_gif_002", "url": "/mock/gifs/placeholder_2.gif", "alt_text": "Laughing out loud", "width": 280, "height": 210},
    {"id": "mock_gif_003", "url": "/mock/gifs/placeholder_3.gif", "alt_text": "Thumbs up approval", "width": 320, "height": 240},
    {"id": "mock_gif_004", "url": "/mock/gifs/placeholder_4.gif", "alt_text": "Excited celebration", "width": 400, "height": 300},
    {"id": "mock_gif_005", "url": "/mock/gifs/placeholder_5.gif", "alt_text": "Cat typing on keyboard", "width": 320, "height": 320},
    {"id": "mock_gif_006", "url": "/mock/gifs/placeholder_6.gif", "alt_text": "Mind blown reaction", "width": 360, "height": 240},
    {"id": "mock_gif_007", "url": "/mock/gifs/placeholder_7.gif", "alt_text": "Happy clapping hands", "width": 320, "height": 240},
    {"id": "mock_gif_008", "url": "/mock/gifs/placeholder_8.gif", "alt_text": "Celebration confetti", "width": 400, "height": 300},
    {"id": "mock_gif_009", "url": "/mock/gifs/placeholder_9.gif", "alt_text": "Jumping for joy", "width": 320, "height": 320},
    {"id": "mock_gif_010", "url": "/mock/gifs/placeholder_10.gif", "alt_text": "Facepalm disappointment", "width": 300, "height": 225},
    {"id": "mock_gif_011", "url": "/mock/gifs/placeholder_11.gif", "alt_text": "Rolling on the floor laughing", "width": 320, "height": 240},
    {"id": "mock_gif_012", "url": "/mock/gifs/placeholder_12.gif", "alt_text": "Slow clap sarcasm", "width": 340, "height": 240},
    {"id": "mock_gif_013", "url": "/mock/gifs/placeholder_13.gif", "alt_text": "Dancing happy puppy", "width": 320, "height": 320},
    {"id": "mock_gif_014", "url": "/mock/gifs/placeholder_14.gif", "alt_text": "Eye roll annoyed", "width": 280, "height": 210},
    {"id": "mock_gif_015", "url": "/mock/gifs/placeholder_15.gif", "alt_text": "Heart eyes love", "width": 320, "height": 240},
    {"id": "mock_gif_016", "url": "/mock/gifs/placeholder_16.gif", "alt_text": "Shrug whatever", "width": 300, "height": 225},
    {"id": "mock_gif_017", "url": "/mock/gifs/placeholder_17.gif", "alt_text": "Wink and point", "width": 320, "height": 240},
    {"id": "mock_gif_018", "url": "/mock/gifs/placeholder_18.gif", "alt_text": "Crying tears of joy", "width": 320, "height": 240},
    {"id": "mock_gif_019", "url": "/mock/gifs/placeholder_19.gif", "alt_text": "Surprised gasp", "width": 360, "height": 240},
    {"id": "mock_gif_020", "url": "/mock/gifs/placeholder_20.gif", "alt_text": "Waving goodbye", "width": 320, "height": 240},
]


def _stable_hash(text: str) -> int:
    """Deterministic, process-independent hash (Python's built-in ``hash`` is
    salted per-process for ``str``)."""
    return zlib.crc32(text.encode("utf-8"))


def search_gifs(query: str, limit: int = 20, offset: int = 0) -> List[Dict[str, Any]]:
    """Search the mock GIF provider.

    Returns deterministic results based on the query string. An empty query is
    treated as a request for trending GIFs (the full list). Results are stable
    across calls and across processes for a given query.
    """
    limit = max(0, min(int(limit), len(MOCK_GIFS)))
    offset = max(0, int(offset))
    if not query or not query.strip():
        return MOCK_GIFS[offset:offset + limit]
    h = _stable_hash(query.lower().strip()) % len(MOCK_GIFS)
    rotated = MOCK_GIFS[h:] + MOCK_GIFS[:h]
    return rotated[offset:offset + limit]


def trending_gifs(limit: int = 20) -> List[Dict[str, Any]]:
    """Return trending GIFs (mock: the head of the full list)."""
    limit = max(0, min(int(limit), len(MOCK_GIFS)))
    return MOCK_GIFS[:limit]
