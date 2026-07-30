/**
 * cpp-aware glue for broadcast-chat-rich.spec.ts (TRACK: seed).
 *
 * PROBLEM: setExpiresAtToPast() queries the Python 'BroadcastChatMessages' table
 * at :8001 to force expires_at=1; under cpp the message lives in cpp's own moto
 * (tlc_broadcast_chat) so the Python query raises "Message not found" and the
 * test errors. This wrapper runs the expire shim against cpp's moto instead.
 *
 * Reuses the shared cpp-seed.ts runCppShim primitive. No-op off the cpp path.
 */
import { runCppShim, usingCpp } from "./cpp-seed";

export { usingCpp };

const SHIM = "expire_broadcast_chat_message.py";

/** Force-expire a live broadcast chat message in cpp's moto (expires_at=1) so
 *  the read-time redaction path fires. No-op unless usingCpp(). */
export function cppExpireBroadcastChatMessage(sessionId: string, messageId: string): void {
  if (!usingCpp()) return;
  runCppShim(SHIM, { session_id: sessionId, message_id: messageId });
}
