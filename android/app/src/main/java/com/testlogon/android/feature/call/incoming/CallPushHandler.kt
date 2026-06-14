package com.testlogon.android.feature.call.incoming

import com.testlogon.android.data.call.CallEvent
import com.testlogon.android.feature.call.domain.CallManager
import com.testlogon.android.push.PushLog
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-297 — the bridge from the flagged FCM push seam to the call orchestrators.
 *
 * [NotificationDisplaySink] (the single bound PushMessageSink, AND-107) consults [tryHandle] FIRST: a
 * `call.*` data message is parsed by [CallPushParser] and routed to the [IncomingCallController] (incoming
 * invite -> ring + full-screen) and the [CallManager] (terminal events for an in-progress outgoing call),
 * returning true so the generic notification path is skipped. Any non-call payload returns false and falls
 * through to the normal channel display.
 *
 * Inert without FCM: nothing calls [tryHandle] until a real `call.invite` is delivered (no
 * google-services.json -> no delivery), matching the flagged push seam.
 */
@Singleton
class CallPushHandler @Inject constructor(
    private val parser: CallPushParser,
    private val incomingController: IncomingCallController,
    private val callManager: CallManager,
) {

    /** @return true if [data] was a recognized call event and was handled (skip generic notification). */
    fun tryHandle(data: Map<String, String>): Boolean {
        val event = parser.parse(data) ?: return false
        return when (event) {
            is CallEvent.Invite -> {
                PushLog.d("call push: invite")
                incomingController.onInvite(event)
                true
            }
            is CallEvent.Declined, is CallEvent.Ended, is CallEvent.Missed -> {
                PushLog.d("call push: terminal")
                incomingController.onCallEvent(event)
                callManager.onCallEvent(event)
                true
            }
            is CallEvent.Accepted -> {
                callManager.onCallEvent(event)
                true
            }
            is CallEvent.Ignore -> false
        }
    }
}
