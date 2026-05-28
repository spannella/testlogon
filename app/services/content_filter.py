"""Simple keyword-based content filter for broadcast chat messages.

Provides a word filter that replaces blocked words with asterisks.
This is a basic MVP implementation; a more sophisticated system (ML-based,
external API) can replace the word list later.
"""

from __future__ import annotations

import re
from typing import Tuple

# Basic profanity / policy-violation words.
# Keep sorted for easy maintenance.  Case-insensitive matching.
_BLOCKED_WORDS: set[str] = {
    "asshole",
    "bastard",
    "bitch",
    "cunt",
    "damn",
    "dick",
    "fuck",
    "motherfucker",
    "nigger",
    "piss",
    "shit",
    "slut",
    "whore",
}

# Pre-compile the regex once at module load.
_PATTERN: re.Pattern[str] | None = None


def _get_pattern() -> re.Pattern[str]:
    global _PATTERN
    if _PATTERN is None:
        # Sort longest-first so "motherfucker" is matched before "fuck".
        words = sorted(_BLOCKED_WORDS, key=len, reverse=True)
        escaped = [re.escape(w) for w in words]
        _PATTERN = re.compile(r"\b(" + "|".join(escaped) + r")\b", re.IGNORECASE)
    return _PATTERN


def filter_message(text: str) -> Tuple[str, bool]:
    """Filter blocked words from *text*, replacing them with asterisks.

    Returns:
        (filtered_text, was_filtered) — *was_filtered* is True if at least
        one word was replaced.
    """
    pattern = _get_pattern()
    was_filtered = False

    def _replace(match: re.Match) -> str:
        nonlocal was_filtered
        was_filtered = True
        return "*" * len(match.group(0))

    filtered = pattern.sub(_replace, text)
    return filtered, was_filtered
