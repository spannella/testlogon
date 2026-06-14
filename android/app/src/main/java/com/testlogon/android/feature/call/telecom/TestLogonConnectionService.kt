package com.testlogon.android.feature.call.telecom

import android.os.Build
import android.telecom.Connection
import android.telecom.ConnectionRequest
import android.telecom.ConnectionService
import android.telecom.PhoneAccountHandle
import androidx.annotation.RequiresApi
import com.testlogon.android.core.call.audio.CallAudioRouter
import com.testlogon.android.push.PushLog
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject

/**
 * AND-304 — the app's self-managed [ConnectionService]. The OS instantiates it (via the manifest
 * BIND_TELECOM_CONNECTION_SERVICE entry) when [TelecomCallController] places / reports a call; @AndroidEntryPoint
 * so Hilt supplies the registry, the [CallSignaling] backend, and the [CallAudioRouter].
 *
 * Each create-connection callback pulls the app's call id out of the [ConnectionRequest] extras (round-tripped
 * by the controller), builds a [TestLogonConnection] in the correct initial state (RINGING incoming / DIALING
 * outgoing), and registers it (FR-9: one per call id). The *Failed callbacks are the graceful-degradation
 * seam: they only LOG — the AND-296/297 flow that ran alongside the Telecom attempt remains the source of
 * truth, so a Telecom create failure never strands the user (the existing UI/notification still drives the
 * call). Self-managed surface is API 26+, so the create paths are @RequiresApi 26 and the service is inert on
 * older OS (the controller never reports to it there).
 */
@AndroidEntryPoint
class TestLogonConnectionService : ConnectionService() {

    @Inject lateinit var registry: ConnectionRegistry

    @Inject lateinit var signaling: CallSignaling

    @Inject lateinit var audioRouter: CallAudioRouter

    @RequiresApi(Build.VERSION_CODES.O)
    override fun onCreateIncomingConnection(
        connectionManagerPhoneAccount: PhoneAccountHandle?,
        request: ConnectionRequest?,
    ): Connection {
        val connection = newConnection(request)
        connection.setRinging()
        return connection
    }

    @RequiresApi(Build.VERSION_CODES.O)
    override fun onCreateOutgoingConnection(
        connectionManagerPhoneAccount: PhoneAccountHandle?,
        request: ConnectionRequest?,
    ): Connection {
        val connection = newConnection(request)
        connection.setDialing()
        return connection
    }

    override fun onCreateIncomingConnectionFailed(
        connectionManagerPhoneAccount: PhoneAccountHandle?,
        request: ConnectionRequest?,
    ) {
        // Graceful degradation: do NOT touch app state. The AND-297 notification path already handled (or
        // will handle) this invite; Telecom simply declined to model the call.
        PushLog.d("telecom incoming connection failed; using AND-297 fallback")
    }

    override fun onCreateOutgoingConnectionFailed(
        connectionManagerPhoneAccount: PhoneAccountHandle?,
        request: ConnectionRequest?,
    ) {
        // Graceful degradation: the AND-296 outgoing flow is already in flight; nothing to do but log.
        PushLog.d("telecom outgoing connection failed; using AND-296 fallback")
    }

    @RequiresApi(Build.VERSION_CODES.O)
    private fun newConnection(request: ConnectionRequest?): TestLogonConnection {
        val callId = request?.extras?.getString(TelecomCallController.EXTRA_CALL_ID)
            ?: request?.address?.schemeSpecificPart
            ?: FALLBACK_CALL_ID
        val displayName = request?.extras?.getString(TelecomCallController.EXTRA_DISPLAY_NAME)
        val connection = TestLogonConnection(
            callId = callId,
            displayName = displayName,
            signaling = signaling,
            audioRouter = audioRouter,
            registry = registry,
        )
        registry.put(callId, connection)
        return connection
    }

    private companion object {
        const val FALLBACK_CALL_ID = "unknown"
    }
}
