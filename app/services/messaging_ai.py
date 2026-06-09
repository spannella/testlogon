"""Messenger Voice & Translation AI provider callers (MVA-003).

Thin, dev-mode-aware wrappers around the AI providers used by the messaging
AI features:

  * ``translate_text``     — per-message translation (Anthropic Messages API)
  * ``transcribe_audio``   — speech-to-text (ElevenLabs /speech-to-text)
  * ``synthesize_speech``  — text-to-speech (ElevenLabs /text-to-speech/{voice})

Each caller is ``S.dev_mode``-aware (SECOPS-007 parity): in dev mode it returns
deterministic mock output with NO network / SDK import; in prod it makes the
real provider call. Provider keys are resolved through the existing
``llm_provider_keys`` store (per-user active key for the configured provider),
honoring budget/status guards, with an ANTHROPIC_API_KEY env fallback for
translation (mirrors ``agent_memory``). Successful calls record usage/cost back
onto the key so monthly budgets are enforced.

No third-party SDK (``anthropic`` / httpx) is imported at module load — imports
are lazy and only happen on the prod path.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Dict, List, Optional, Tuple

from app.core.settings import S
from app.services import llm_provider_keys as keys_svc

logger = logging.getLogger(__name__)


# A tiny, valid silent MP3 frame blob returned by the dev TTS mock so the
# downstream voice-message pipeline has real bytes to store/serve.
_DEV_MOCK_MP3 = (
    b"\xff\xfb\x90\x64\x00" + b"\x00" * 415
)


class MessagingAiError(Exception):
    """Typed error for AI-provider resolution/call failures."""

    def __init__(self, code: str, message: str):
        self.code = code
        self.message = message
        super().__init__(f"{code}: {message}")


# ---------------------------------------------------------------------------
# Key resolution
# ---------------------------------------------------------------------------


def _resolve_active_key(user_id: str, provider: str) -> Optional[Dict[str, Any]]:
    """Return the user's most-recently-created active key for ``provider``.

    Returns ``None`` if the user has no active key for the provider. Never
    decrypts here — callers fetch the decrypted key only when they actually
    make the network call (and only for active keys, per
    ``get_decrypted_api_key``'s guard).
    """
    try:
        candidates = [
            k
            for k in keys_svc.list_keys(user_id)
            if k.get("provider") == provider and k.get("status") == "active"
        ]
    except Exception:
        return None
    if not candidates:
        return None
    candidates.sort(key=lambda k: int(k.get("created_at", 0) or 0), reverse=True)
    return candidates[0]


def _decrypt_or_raise(user_id: str, key_id: str) -> str:
    try:
        return keys_svc.get_decrypted_api_key(user_id, key_id)
    except ValueError as exc:
        raise MessagingAiError("key_not_active", str(exc))


def _record(user_id: str, key_id: str, *, tokens: int, cost_cents: int) -> None:
    try:
        keys_svc.record_usage(user_id, key_id, tokens=tokens, cost_cents=cost_cents)
    except Exception:
        logger.warning("messaging_ai record_usage failed key_id=%s", key_id, exc_info=True)


def _validate_url(url: str) -> None:
    from app.services.webhook_ssrf import validate_webhook_url

    validate_webhook_url(url)


# ---------------------------------------------------------------------------
# Cost estimation (MVA-011)
# ---------------------------------------------------------------------------


def estimate_translation_cost_cents(text: str) -> int:
    # ~4 chars/token; Anthropic Haiku ~ $0.0008/1k in + out. Round up to >=1.
    tokens = max(1, len(text) // 4)
    return max(1, (tokens * 2) // 1000 // 10 or 1)


def estimate_tts_cost_cents(text: str) -> int:
    # ElevenLabs ~ $0.30 / 1k chars on creator tier. Round up to >=1.
    return max(1, (len(text) * 30) // 1000)


def estimate_stt_cost_cents(audio_bytes: bytes) -> int:
    # Approx 16KB/sec audio; ElevenLabs STT ~ $0.40/hr. Round up to >=1.
    seconds = max(1, len(audio_bytes) // 16000)
    return max(1, (seconds * 40) // 3600 or 1)


# ---------------------------------------------------------------------------
# Translation (Anthropic)
# ---------------------------------------------------------------------------


def translate_text(
    *,
    user_id: str,
    text: str,
    target_lang: str,
    source_lang: str = "auto",
) -> Tuple[str, str]:
    """Translate ``text`` into ``target_lang``. Returns ``(translated, source_lang)``.

    Dev mode returns a deterministic mock (``"[<target_lang>] <text>"``). Prod
    calls the Anthropic Messages API using the user's active anthropic key, or
    falls back to the ANTHROPIC_API_KEY env var (mirrors agent_memory).
    """
    provider = S.messaging_translation_provider
    key = _resolve_active_key(user_id, provider)

    if S.dev_mode:
        if key:
            _record(user_id, key["key_id"], tokens=max(1, len(text) // 4), cost_cents=estimate_translation_cost_cents(text))
        return f"[{target_lang}] {text}", (source_lang if source_lang != "auto" else "en")

    api_key = ""
    key_id = ""
    if key:
        key_id = key["key_id"]
        api_key = _decrypt_or_raise(user_id, key_id)
    else:
        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise MessagingAiError("no_key", f"No active {provider} key and no ANTHROPIC_API_KEY fallback")

    import anthropic  # lazy — never needed in dev/tests

    client = anthropic.Anthropic(api_key=api_key)
    system = (
        "You are a translation engine. Translate the user's message into the "
        f"target language (BCP-47 code: {target_lang}). Output ONLY the "
        "translated text with no commentary, quotes, or prefixes."
    )
    resp = client.messages.create(
        model="claude-haiku-3-5-20241022",
        max_tokens=2048,
        system=system,
        messages=[{"role": "user", "content": text}],
    )
    translated = resp.content[0].text.strip()
    if key_id:
        _record(user_id, key_id, tokens=max(1, len(text) // 4), cost_cents=estimate_translation_cost_cents(text))
    return translated, source_lang


# ---------------------------------------------------------------------------
# Speech-to-text (ElevenLabs)
# ---------------------------------------------------------------------------


def transcribe_audio(
    *,
    user_id: str,
    audio_bytes: bytes,
    content_type: str = "audio/webm",
) -> Tuple[str, str]:
    """Transcribe ``audio_bytes``. Returns ``(transcript, language_code)``.

    Dev returns a fixed mock transcript. Prod posts to the ElevenLabs
    /speech-to-text endpoint with the user's active key.
    """
    provider = S.messaging_stt_provider
    key = _resolve_active_key(user_id, provider)
    if not key:
        raise MessagingAiError("no_key", f"No active {provider} key for transcription")

    if S.dev_mode:
        _record(user_id, key["key_id"], tokens=0, cost_cents=estimate_stt_cost_cents(audio_bytes))
        return "[mock transcript] This is a transcribed voice message.", "en"

    api_key = _decrypt_or_raise(user_id, key["key_id"])
    registry = keys_svc.PROVIDER_REGISTRY.get(provider, {})
    base_url = key.get("base_url") or registry.get("base_url", "")
    url = f"{base_url.rstrip('/')}/speech-to-text"
    _validate_url(url)

    import httpx  # lazy

    headers = {"xi-api-key": api_key}
    files = {"file": ("audio", audio_bytes, content_type)}
    data = {"model_id": registry.get("stt_model", "scribe_v1")}
    with httpx.Client(timeout=60, follow_redirects=False) as client:
        resp = client.post(url, headers=headers, files=files, data=data)
    if resp.status_code != 200:
        logger.debug("messaging_ai stt http_error status=%d", resp.status_code)
        raise MessagingAiError("provider_error", f"STT provider returned HTTP {resp.status_code}")
    body = resp.json()
    transcript = str(body.get("text", "")) if isinstance(body, dict) else ""
    lang = str(body.get("language_code", "")) if isinstance(body, dict) else ""
    _record(user_id, key["key_id"], tokens=0, cost_cents=estimate_stt_cost_cents(audio_bytes))
    return transcript, lang


# ---------------------------------------------------------------------------
# Text-to-speech (ElevenLabs)
# ---------------------------------------------------------------------------


def synthesize_speech(
    *,
    user_id: str,
    text: str,
    voice_id: str = "",
    model_id: str = "",
) -> Tuple[bytes, str]:
    """Synthesize ``text`` into audio. Returns ``(audio_bytes, content_type)``.

    Dev returns a tiny fixed MP3 blob. Prod posts to the ElevenLabs
    /text-to-speech/{voice_id} endpoint with the user's active key.
    """
    provider = S.messaging_tts_provider
    key = _resolve_active_key(user_id, provider)
    if not key:
        raise MessagingAiError("no_key", f"No active {provider} key for TTS")

    registry = keys_svc.PROVIDER_REGISTRY.get(provider, {})
    voice = voice_id or key.get("voice_preference") or registry.get("default_voice_id", "")
    model = model_id or key.get("model_preference") or (registry.get("models", ["eleven_multilingual_v2"]) or [""])[0]

    if S.dev_mode:
        _record(user_id, key["key_id"], tokens=0, cost_cents=estimate_tts_cost_cents(text))
        return _DEV_MOCK_MP3, "audio/mpeg"

    api_key = _decrypt_or_raise(user_id, key["key_id"])
    base_url = key.get("base_url") or registry.get("base_url", "")
    url = f"{base_url.rstrip('/')}/text-to-speech/{voice}"
    _validate_url(url)

    import httpx  # lazy

    headers = {"xi-api-key": api_key, "accept": "audio/mpeg", "content-type": "application/json"}
    payload = {"text": text, "model_id": model}
    with httpx.Client(timeout=60, follow_redirects=False) as client:
        resp = client.post(url, headers=headers, json=payload)
    if resp.status_code != 200:
        logger.debug("messaging_ai tts http_error status=%d", resp.status_code)
        raise MessagingAiError("provider_error", f"TTS provider returned HTTP {resp.status_code}")
    _record(user_id, key["key_id"], tokens=0, cost_cents=estimate_tts_cost_cents(text))
    return resp.content, "audio/mpeg"
