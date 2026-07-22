package com.testlogon.android.feature.call.service

import android.content.Context
import com.testlogon.android.data.call.CallMode
import com.testlogon.android.feature.call.domain.CallManager
import com.testlogon.android.feature.call.domain.CallPhase
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton

/**
 * CALL-PIP FIX — app-scoped observer that keeps a [CallForegroundService] running for the exact lifetime
 * of an active 1:1 call.
 *
 * Mirrors the `presenceBootstrap.start()` / `callSignalingHub.start()` pattern: a singleton wired into
 * [com.testlogon.android.TestLogonApp.onCreate]. It collects [CallManager.state] and:
 *  - starts the foreground service as soon as a call occupies the manager (any non-Idle, non-terminal
 *    phase — Inviting/Ringing/Connecting/Connected/Ending), so backgrounding (Home) can NEVER strand the
 *    call's media/heartbeat in an unprivileged process (the root cause of the "call ended (network)"
 *    teardown that also killed the camera + PiP float); and
 *  - stops it the moment the call goes terminal or returns to Idle.
 *
 * The camera foreground type is requested only for a VIDEO call; audio calls hold microphone only. This
 * lives independent of the in-call Activity/composable so it survives config changes and backgrounding.
 */
@Singleton
class CallForegroundController @Inject constructor(
    @ApplicationContext private val context: Context,
    private val callManager: CallManager,
    private val scope: CoroutineScope,
) {

    /** True while we hold the service, so start/stop are edge-triggered (idempotent re-starts avoided). */
    private var running = false

    fun start() {
        scope.launch {
            callManager.state
                .map { state ->
                    val active = state.call != null && isHoldingPhase(state.phase)
                    ServiceIntent(
                        active = active,
                        video = state.call?.mode == CallMode.VIDEO,
                        peerName = state.peerName,
                    )
                }
                .distinctUntilChanged()
                .collect { intent -> apply(intent) }
        }
    }

    private fun apply(intent: ServiceIntent) {
        if (intent.active) {
            // (Re)start is safe: startForegroundService is idempotent for our single-instance service and
            // lets us refresh the notification (peer name / video type) if the call's shape changed.
            CallForegroundService.start(context, video = intent.video, peerName = intent.peerName)
            running = true
        } else if (running) {
            CallForegroundService.stop(context)
            running = false
        }
    }

    /** Any phase where a call is live enough that its media/heartbeat must be kept process-privileged. */
    private fun isHoldingPhase(phase: CallPhase): Boolean =
        phase != CallPhase.Idle && !phase.isTerminal

    private data class ServiceIntent(
        val active: Boolean,
        val video: Boolean,
        val peerName: String?,
    )
}
