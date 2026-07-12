# Messenger Voice & Translation (AI) — Implementation Tickets

This backlog adds AI-powered messaging features — per-message translation (Anthropic), speech-to-text transcription of voice messages, and text-to-speech voice-message generation (ElevenLabs preferred) — on top of the existing voice-message infrastructure (`app/routers/messaging.py:8521-8710`) and the LLM provider-key store (`app/services/llm_provider_keys.py`). ElevenLabs is **NOT** currently a registered provider (`PROVIDER_REGISTRY` at `app/services/llm_provider_keys.py:42-98` has only `openai`, `anthropic`, `deepseek`, `gemini`, `custom`); it is used today only by the standalone `scripts/render_voiceover.py` (`scripts/render_voiceover.py:59-79`), never in-app.

## Milestone 1 — Provider & Settings Foundation

### MVA-001: Register ElevenLabs as a TTS/STT provider in the LLM provider-key registry
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add an `"elevenlabs"` entry to `PROVIDER_REGISTRY` in `app/services/llm_provider_keys.py:42-98` with `display_name="ElevenLabs"`, `base_url="https://api.elevenlabs.io/v1"`, `auth_header="xi-api-key"`, `auth_prefix=""`, a working `test_endpoint`/`test_method` (e.g. `GET /voices`), and `supports_usage_api=False` (mirror the header convention proven in `scripts/render_voiceover.py:67-72`).
- Extend the provider metadata to carry TTS/STT capability config: a `models` list for TTS model IDs (e.g. `eleven_multilingual_v2`, `eleven_turbo_v2_5`), an STT model id (e.g. `scribe_v1`), and a `default_voice_id`. Keep `add_key()` (`app/services/llm_provider_keys.py:106-157`) accepting `model_preference` and add an optional `voice_preference` field stored on the key item (default to registry `default_voice_id`).
- Update `test_key()` (`app/services/llm_provider_keys.py:196-283`) so the ElevenLabs probe parses the `/voices` response shape (not the OpenAI `data[].id` shape at line 253) when computing `available_models`/voices; keep the dev-mode mock-success branch (`app/services/llm_provider_keys.py:213-222`) returning the registry defaults.
- Surface the new provider in the picker via `GET /ui/agent/llm-providers` (`app/routers/llm_provider_keys.py:32-46`) and add `voice_preference` to the `LlmKeyOut`/`LlmKeyCreateIn` models in `app/models.py`; ensure `_safe_out()` (`app/services/llm_provider_keys.py:590-611`) never leaks the encrypted key.

**Acceptance Criteria**
- `PROVIDER_REGISTRY["elevenlabs"]` exists and `GET /ui/agent/llm-providers` returns it with display name and model/voice metadata.
- A user can `POST /ui/agent/llm-keys` with `provider="elevenlabs"`, a `voice_preference`, and `model_preference`; the raw key is KMS-encrypted (`kms_encrypt`, `app/services/llm_provider_keys.py:124`) and never returned by any list/get endpoint.
- `test_key()` returns mock success in dev mode and parses the real `/voices` response in prod; budget/status guards in `get_decrypted_api_key()` (`app/services/llm_provider_keys.py:178-193`) apply unchanged.

**Dependencies**
- None.

---

### MVA-002: AI messaging settings, feature flags, and DynamoDB tables
**Type:** Chore  
**Priority:** P0  
**Estimate:** 1 day

**Description**
- Add feature flags to `app/core/settings.py` alongside the existing voice flags (`voice_message_enabled` at `app/core/settings.py:1832`, `voicemail_enabled` at line 1838): `messaging_translation_enabled` (`MESSAGING_TRANSLATION_ENABLED`, default true), `messaging_transcription_enabled` (`MESSAGING_TRANSCRIPTION_ENABLED`, default false), `messaging_tts_enabled` (`MESSAGING_TTS_ENABLED`, default false).
- Add provider/limit settings: `messaging_translation_provider` (default `anthropic`), `messaging_tts_provider` / `messaging_stt_provider` (default `elevenlabs`), `messaging_tts_max_chars` (default 5000), `messaging_translation_cache_ttl_seconds`, and per-feature rate-limit caps (`MESSAGING_AI_*_RL_*`).
- Add a `message_ai_cache` DynamoDB table (PK `cache_key`, optional `ttl` attribute) to `scripts/local-ddb-init.py` to back translation/transcript caching, and wire a handle in `app/core/tables.py` (follow the existing `T.translations`/`translations_table_name` pattern at `app/core/settings.py:1983`). Numeric attributes (e.g. `created_at`, `ttl`) declared with `attr_types` per the CLAUDE.md GSI gotcha.
- Document the new env vars in `.env.local.example` and the feature-flag table in `CLAUDE.md`.

**Acceptance Criteria**
- All three feature flags default safely (translation on; transcription/TTS off until keys configured) and gate their endpoints with `404` when disabled, mirroring `presign_voice_message` (`app/routers/messaging.py:8531-8532`).
- `just restart` recreates `message_ai_cache` with correct key/attr types; `T.message_ai_cache` resolves in dev and prod.
- New settings read from env with documented defaults; no hard dependency on any SDK at import time.

**Dependencies**
- None.

---

### MVA-003: Shared AI-provider call helper (decrypt key → call provider) with dev mock
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Create `app/services/messaging_ai.py` housing thin provider callers: `translate_text(...)` (Anthropic Messages API, lazy `import anthropic` exactly as `app/services/agent_memory.py:633-639`), `transcribe_audio(audio_bytes, ...)` (ElevenLabs STT `/speech-to-text`), and `synthesize_speech(text, voice_id, ...)` (ElevenLabs TTS `/text-to-speech/{voice}` using `xi-api-key` per `scripts/render_voiceover.py:60-72`).
- Resolve the provider key via the existing store: pick the calling user's active key for the configured provider (reuse `list_keys()` + `get_decrypted_api_key()`, `app/services/llm_provider_keys.py:160-193`), honoring budget/status guards; fall back to an env key (`ANTHROPIC_API_KEY`) for translation as `agent_memory` does.
- Record usage/cost back onto the key via `record_usage()` (`app/services/llm_provider_keys.py:347-372`) after each call so budgets are enforced.
- Every caller is `S.dev_mode`-aware (SECOPS-007 parity): dev returns deterministic mock output (e.g. translation = `"[xx] " + text`, transcript = a fixed string, TTS = a tiny fixed WAV/MP3 byte blob) so no network/SDK is needed; prod runs the real call. All outbound URLs reuse the SSRF guard `validate_webhook_url` already used in `test_key` (`app/services/llm_provider_keys.py:233-236`).

**Acceptance Criteria**
- `translate_text`, `transcribe_audio`, `synthesize_speech` each return mock data in dev mode with no SDK/network and real provider results in prod.
- A missing/non-active provider key raises a typed error (no decryption of inactive keys, per `get_decrypted_api_key` at line 190); a missing key for translation falls back to the env-configured key.
- Successful calls invoke `record_usage(...)` with a cost estimate; budget-exceeded keys are rejected before the network call.

**Dependencies**
- MVA-001, MVA-002.

---

## Milestone 2 — Translation (Anthropic)

### MVA-004: Per-message translation endpoint (cached, target language)
**Type:** Feature  
**Priority:** P0  
**Estimate:** 2 days

**Description**
- Add `POST /conversations/{conversation_id}/messages/{message_id}/translate` to `app/routers/messaging.py` (near `edit_message` at `app/routers/messaging.py:11298`), guarded by `S.messaging_translation_enabled` and `require_participant_active` (the access check used throughout, e.g. `app/routers/messaging.py:8533`).
- Body: `{ "target_lang": "<BCP-47>" }`. Resolve the message text via the existing item read path used by `_message_out_from_item` (`app/routers/messaging.py:4177+`); only `kind="text"` (and the `text` field of other kinds) is translatable — reject view-once/locked-not-unlocked/hidden content.
- Cache by `cache_key = sha256(message_id|target_lang|text_hash)` in `T.message_ai_cache` (write `ttl` from `messaging_translation_cache_ttl_seconds`); cache hit short-circuits the provider call. Call `app/services/messaging_ai.translate_text(...)`.
- Apply per-user rate limiting via `_bucket_limit(...)` (`app/services/rate_limit.py:60`) with the `MESSAGING_AI_*` caps from MVA-002; return `429` + `Retry-After` on exhaustion.
- Add a `TranslateMessageRequest`/`TranslateMessageOut` (`{ translated_text, source_lang, target_lang, cached: bool }`) to `app/models.py`.

**Acceptance Criteria**
- Translating a text message returns `translated_text` and `cached=false`; a second identical request returns `cached=true` without a provider call.
- Non-participants get `403`; non-text/hidden/locked messages get `400`; disabled flag gives `404`.
- Rate-limit cap exceeded returns `429` with `Retry-After`; cost recorded on the provider key on cache-miss only.

**Dependencies**
- MVA-003.

---

### MVA-005: Per-conversation auto-translate preference
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Persist a per-user, per-conversation auto-translate preference (`enabled: bool`, `target_lang`) on the participant record (the GSI1-queried participant items at `app/routers/messaging.py:8573-8576`) or a sibling settings row; expose `GET`/`PUT /conversations/{conversation_id}/translate-preference`.
- When auto-translate is on for the viewer, `_message_out_from_item` (`app/routers/messaging.py:4177`) augments outgoing text-message projections with a `translation` sub-object (reusing the MVA-004 cache so the projection never blocks on a live provider call — populate lazily/best-effort, never raise). Add a `translation: Optional[Dict]` field to `MessageOut` in `app/models.py`.
- Preference reads/writes are DDB-only (dev parity); changing the preference invalidates nothing (cache is keyed on target_lang).

**Acceptance Criteria**
- A viewer with auto-translate on sees `translation` populated for cached text messages in the list/get projections; viewers without it see `translation=null`.
- `PUT` persists `enabled`/`target_lang` per viewer per conversation; the other participant's view is unaffected.
- Projection never raises if a translation is uncached/unavailable (best-effort).

**Dependencies**
- MVA-004.

---

### MVA-006: Inline "Translate" / auto-translate toggle UI
**Type:** Feature  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Add a "Translate" action to `frontend/src/pages/messages/MessageBubble.tsx` (in the existing per-message action menu) that calls the MVA-004 endpoint with the user's target language and renders the returned text beneath the original with a "Show original" toggle.
- Add a per-conversation "Auto-translate" control to the conversation header in `frontend/src/pages/messages/ConversationView.tsx`, wired to the MVA-005 preference endpoints via a new endpoint wrapper in `frontend/src/api/endpoints/` and React Query (`useMutation`/`useQuery`), invalidating the messages query on toggle.
- Add `translation` to the `Message` type in `frontend/src/api/types.ts`; when present (auto-translate path), render the translation inline without an extra fetch.

**Acceptance Criteria**
- Clicking "Translate" shows the translated text and a working "Show original" toggle; repeated clicks reuse the cached result.
- Toggling auto-translate persists across reloads and translates eligible text messages in the open conversation.
- No translation UI appears when `messaging_translation_enabled` is false.

**Dependencies**
- MVA-005.

---

## Milestone 3 — Speech-to-Text (Transcription)

### MVA-007: Transcribe-voice-message endpoint (store + cache transcript)
**Type:** Feature  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Add `POST /conversations/{conversation_id}/messages/{message_id}/transcribe` to `app/routers/messaging.py`, guarded by `S.messaging_transcription_enabled` + `require_participant_active`; only `kind="voice_message"` / `voicemail` messages are eligible (read the stored `audio_url` S3 key written at `app/routers/messaging.py:8612`).
- Fetch the audio bytes from S3 (dev: in-process moto via `s3` client used at `app/routers/messaging.py:8547`; prod: real `get_object`), call `app/services/messaging_ai.transcribe_audio(...)`, and persist the result back onto the message item as a `transcript` field (+ `transcript_lang`, `transcribed_at`) via an `update_item` on `tbl_msgs`.
- Cache/idempotency: a message already carrying `transcript` returns it without re-calling the provider; concurrent calls are safe (best-effort conditional write). Apply `_bucket_limit` rate limiting and `record_usage` cost accounting.
- Project `transcript`/`transcript_lang` in the voice-message branch of `_message_out_from_item` (`app/routers/messaging.py:4086-4102`) and add the fields to `MessageOut.voice_message`/`voicemail` dicts in `app/models.py`.

**Acceptance Criteria**
- Transcribing a voice message returns and persists a `transcript`; a second call returns the stored transcript with no provider call.
- Non-voice messages → `400`; non-participants → `403`; disabled flag → `404`; rate-limit → `429`.
- The transcript appears in subsequent `GET .../messages` projections for all participants.

**Dependencies**
- MVA-003.

---

### MVA-008: "Show transcript" UI on voice messages
**Type:** Feature  
**Priority:** P1  
**Estimate:** 1 day

**Description**
- Add a "Show transcript" affordance to `frontend/src/pages/messages/VoicemailBubble.tsx` and the voice-message render path (the `WaveformPlayer` usage at `frontend/src/pages/messages/VoicemailBubble.tsx:32-38`); on first click it calls the MVA-007 endpoint, then renders the transcript text below the waveform.
- Add `transcript`/`transcript_lang` to the voice-message/voicemail shapes in `frontend/src/api/types.ts`; if the projection already includes a transcript, render it directly and collapse the "Show transcript" button into a toggle.
- Add an endpoint wrapper + React Query mutation that invalidates the messages query so the persisted transcript shows for everyone after the first transcription.

**Acceptance Criteria**
- "Show transcript" appears only on voice/voicemail bubbles and only when `messaging_transcription_enabled` is true.
- First click transcribes and shows the text; reloading shows it without re-transcribing.
- The transcribed text is selectable and (when MVA-006 ships) translatable via the same per-message action.

**Dependencies**
- MVA-007, MVA-006 (optional, for translate-the-transcript).

---

## Milestone 4 — Text-to-Speech (ElevenLabs)

### MVA-009: TTS endpoint — synthesize text into a stored voice message
**Type:** Feature  
**Priority:** P1  
**Estimate:** 3 days

**Description**
- Add `POST /conversations/{conversation_id}/tts-voice-message` to `app/routers/messaging.py` (next to `create_voice_message` at `app/routers/messaging.py:8559`), guarded by `S.messaging_tts_enabled` + `S.voice_message_enabled` + `require_participant_active`.
- Body: `{ text, voice_id?, model_id?, reply_to_message_id?, send_at? }` with `text` length capped at `messaging_tts_max_chars`. Call `app/services/messaging_ai.synthesize_speech(...)` to get audio bytes, then `put_object` them to `voice-messages/{conversation_id}/{msg_id}.mp3` (the exact S3 key scheme used at `app/routers/messaging.py:8543`) via the same `s3` client — bypassing the browser presign step (server is the uploader).
- Create the message item identically to `create_voice_message` (`app/routers/messaging.py:8605-8654`): `kind="voice_message"`, `audio_url`=s3 key, `audio_content_type="audio/mpeg"`, `duration_seconds` (estimate from audio), `waveform_data` (computed or a placeholder envelope), plus a `tts_source_text`/`is_tts=true` marker and the original `text` for accessibility. Reuse `_send_single_destination_message` and emit the same lifecycle/audit events (`app/routers/messaging.py:8643-8708`).
- Honor scheduling (`send_at` ≥ now+5s, `app/routers/messaging.py:8593-8597`), reply linkage, retention TTL, and `record_usage` cost accounting. Rate-limit via `_bucket_limit`.

**Acceptance Criteria**
- Posting text returns a `MessageOut` of `kind="voice_message"` whose `voice_message.audio_url` resolves (dev: `/mock/s3/...`) and plays in the existing `WaveformPlayer`.
- `text` over `messaging_tts_max_chars` → `400`; disabled flag → `404`; non-participant → `403`; rate-limit → `429`.
- The synthesized message behaves like any other voice message (reactions, reply, scheduling, retention, receipts) and records provider cost.

**Dependencies**
- MVA-003.

---

### MVA-010: "Speak this" compose UI for TTS
**Type:** Feature  
**Priority:** P2  
**Estimate:** 2 days

**Description**
- Add a "Speak this" control to `frontend/src/pages/messages/ComposeBar.tsx` (near the existing `VoiceRecorder` integration at `frontend/src/pages/messages/ComposeBar.tsx:37`) that takes the current draft text and a voice selector, calling the MVA-009 endpoint via a new `onSendTtsVoice` callback wired through `ConversationView.tsx`.
- Voice options come from the user's ElevenLabs key voices (`voice_preference` + `available_models`/voices from MVA-001); default to the key's `voice_preference`. Show a small spinner while synthesizing and surface `400/404/429` errors as toasts (consistent with existing send error handling).
- Add the endpoint wrapper in `frontend/src/api/endpoints/` and the optimistic/refetch handling mirroring the voice-message send flow.

**Acceptance Criteria**
- With TTS enabled and an ElevenLabs key configured, "Speak this" turns the draft into a playable voice message in the conversation.
- The control is hidden when `messaging_tts_enabled` is false or no ElevenLabs key exists.
- Errors (over-length, rate-limit, missing key) surface as user-visible toasts without losing the draft.

**Dependencies**
- MVA-009, MVA-001.

---

## Milestone 5 — Hardening & Tests

### MVA-011: Cost, rate-limit, and budget hardening across AI features
**Type:** Chore  
**Priority:** P1  
**Estimate:** 2 days

**Description**
- Centralize cost estimation in `app/services/messaging_ai.py`: per-call cost (translation = token-based; TTS = per-character; STT = per-audio-minute) feeding `record_usage(...)` (`app/services/llm_provider_keys.py:347-372`) so monthly budgets and the `budget_exceeded` status flip (`app/services/llm_provider_keys.py:381-414`) gate AI usage exactly like agent usage.
- Confirm each endpoint (MVA-004, MVA-007, MVA-009) applies a distinct `_bucket_limit` category (`app/services/rate_limit.py:60`) with env-configurable caps from MVA-002, returning `429` + `Retry-After`.
- Ensure cache hits (translation, transcript) never incur cost and that disabled-feature endpoints `404` before any key decryption.

**Acceptance Criteria**
- A budget-exceeded ElevenLabs/Anthropic key blocks TTS/STT/translation with a typed error and no provider call.
- Each AI endpoint enforces its own rate-limit bucket independent of message-send quotas.
- Cache hits and disabled flags short-circuit before any usage is recorded or any key is decrypted.

**Dependencies**
- MVA-004, MVA-007, MVA-009.

---

### MVA-012: Offline regression tests (hermetic, mocked providers)
**Type:** Chore  
**Priority:** P0  
**Estimate:** 3 days

**Description**
- Add `tests/test_messenger_voice_ai.py` (offline/hermetic per CLAUDE.md): NO real AWS/network/SDK. Patch `app/services/messaging_ai`'s `translate_text`/`transcribe_audio`/`synthesize_speech` (or run them through the dev-mode mock branch) and patch the provider-key decrypt/`record_usage` so no `anthropic`/ElevenLabs import is required — mirror the moto + `object.__setattr__` frozen-`T`/`S` pattern from `tests/test_gap_0233_0234_ssh_session_recording.py` and the in-memory-table approach in `tests/test_gap_0286_0287_kyc_partner_api.py`.
- Cover: ElevenLabs registry entry + key add/test (mock success); translation endpoint (success, cache hit, non-text 400, non-participant 403, disabled 404, 429); auto-translate preference round-trip + projection augmentation; transcribe endpoint (success, idempotent stored transcript, non-voice 400, disabled 404); TTS endpoint (success creates a voice_message item with correct S3 key + `audio_content_type`, over-length 400, scheduling, disabled 404); budget-exceeded rejection and cost recording on cache-miss.
- Bind moto in-memory `messages`/`conversations`/`participants`/`message_ai_cache`/`llm_provider_keys` tables to the frozen `T` handles via `object.__setattr__`, restored on cleanup; flip `S` flags via `object.__setattr__`; drive async route handlers on a fresh event loop where needed.
- Add a lightweight frontend test (Vitest) for the MVA-006 translate toggle and the MVA-008 "Show transcript" toggle following existing `*.test.tsx` patterns in `frontend/src/pages/messages/`.

**Acceptance Criteria**
- `just test` passes the new pytest module with no network/AWS/SDK access (mock-provider calls only).
- Tests assert cache-hit-no-cost, budget-exceeded rejection, rate-limit `429`, disabled-flag `404`, and the TTS-creates-voice-message item shape.
- Frontend tests verify the translate and transcript toggles render and call the right endpoints.

**Dependencies**
- MVA-006, MVA-008, MVA-010, MVA-011.

---
