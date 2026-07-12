import { api } from "@/api/client";
import type {
  Message,
  TranslateMessageResp,
  TranscribeMessageResp,
  TtsVoiceMessageReq,
} from "@/api/types";
import { adaptMessage } from "./messagingAdapter";

/**
 * Messenger Voice & AI (MVA) endpoint wrappers.
 *
 * Backend: app/routers/messaging.py (prefix /messaging).
 * - MVA-004/006: POST /conversations/{cid}/messages/{mid}/translate
 * - MVA-007/008: POST /conversations/{cid}/messages/{mid}/transcribe
 * - MVA-009/010: POST /conversations/{cid}/tts-voice-message
 *
 * These features are server-gated by feature flags
 * (messaging_translation_enabled / messaging_transcription_enabled /
 * messaging_tts_enabled). When a flag is off the endpoint returns 404; the
 * UI surfaces that as a toast and hides the action where it can.
 */

export async function translateMessage(
  conversationId: string,
  messageId: string,
  targetLang: string,
): Promise<TranslateMessageResp> {
  return api.post<TranslateMessageResp>(
    `/messaging/conversations/${conversationId}/messages/${messageId}/translate`,
    { target_lang: targetLang },
  );
}

export async function transcribeMessage(
  conversationId: string,
  messageId: string,
): Promise<TranscribeMessageResp> {
  return api.post<TranscribeMessageResp>(
    `/messaging/conversations/${conversationId}/messages/${messageId}/transcribe`,
    {},
  );
}

export async function createTtsVoiceMessage(
  conversationId: string,
  body: TtsVoiceMessageReq,
): Promise<Message> {
  const res = await api.post<Message>(
    `/messaging/conversations/${conversationId}/tts-voice-message`,
    body,
  );
  return adaptMessage(res);
}
