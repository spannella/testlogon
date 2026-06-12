package com.testlogon.android.feature.call.incoming

import com.testlogon.android.data.call.CallEvent
import com.testlogon.android.data.call.CallEventType
import com.testlogon.android.data.call.CallMode
import javax.inject.Inject

/**
 * AND-297 — pure parser turning an FCM data map (strings only) into a typed [CallEvent].
 *
 * Framework-free (no android.*) so the full matrix is JVM-unit-testable. FCM `data` is always
 * Map<String,String>. Every field is treated as UNTRUSTED input (AND-297 §8): values are length-bounded
 * and malformed/oversized/wrong-type payloads are dropped (return null), never throwing.
 *
 * Field names mirror CallInviteOut (`call_id`, `conversation_id`, `caller_user_id`, `initial_mode`) plus
 * push-augmented display-only fields (`caller_name`, `caller_avatar_url`) and an advisory `expires_at`
 * (epoch seconds; AND-297 §13 Open Q2 — advisory, the client owns the 45s ceiling). The `type` token set
 * mirrors the SSE EVENT_TYPES (AND-297 §13 Open Q1).
 *
 * The FCM message delivery itself stays behind the existing flagged push seam: this parser is inert until
 * a real `call.invite` data message is delivered.
 */
class CallPushParser @Inject constructor() {

    fun parse(data: Map<String, String>): CallEvent? {
        val type = data["type"]?.takeIf { it.isNotBlank() } ?: return null
        if (!CallEventType.isCallEvent(type)) return null

        val callId = data.bounded("call_id") ?: return null
        return when (type) {
            CallEventType.INVITE -> CallEvent.Invite(
                callId = callId,
                conversationId = data.bounded("conversation_id") ?: return null,
                callerUserId = data.bounded("caller_user_id") ?: return null,
                callerName = data.bounded("caller_name", MAX_DISPLAY),
                callerAvatarUrl = data.bounded("caller_avatar_url", MAX_URL),
                mode = CallMode.fromWire(data["initial_mode"]),
                expiresAtEpochSeconds = data["expires_at"]?.toLongOrNull()?.takeIf { it > 0 },
            )
            CallEventType.ACCEPT -> CallEvent.Accepted(callId)
            CallEventType.DECLINE -> CallEvent.Declined(callId)
            CallEventType.END -> CallEvent.Ended(callId)
            CallEventType.MISSED -> CallEvent.Missed(callId)
            else -> CallEvent.Ignore(type)
        }
    }

    private fun Map<String, String>.bounded(key: String, max: Int = MAX_ID): String? =
        this[key]?.takeIf { it.isNotBlank() && it.length <= max }

    private companion object {
        const val MAX_ID = 128
        const val MAX_DISPLAY = 256
        const val MAX_URL = 2048
    }
}
