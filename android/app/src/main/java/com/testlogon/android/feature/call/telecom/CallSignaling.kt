package com.testlogon.android.feature.call.telecom

import com.testlogon.android.data.call.CallRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-304 — thin signaling abstraction the (android) Telecom [TestLogonConnection] callbacks route to.
 *
 * The OS delivers answer/reject/disconnect on the main thread synchronously, but the control-plane POSTs
 * ([CallRepository.accept] / [decline] / [end]) are suspend; this interface lets the Connection fire them
 * without itself being coroutine-aware (and keeps the Connection JVM-shaped). The real binding launches each
 * op on the app-scoped call coroutine scope. Kept as an interface so it could be faked in a future seam test.
 */
interface CallSignaling {
    /** The user answered the OS call -> accept on the backend. */
    fun accept(callId: String)

    /** The user rejected the OS call -> decline on the backend. */
    fun decline(callId: String)

    /** The user/OS ended the OS call -> end on the backend. */
    fun hangup(callId: String)
}

/**
 * Backs [CallSignaling] with [CallRepository], launching each fire-and-forget op on the injected app-scoped
 * [CoroutineScope] (the same supervised scope the call orchestrators use). Every op is wrapped so a backend
 * failure can never propagate back into an OS Telecom callback and crash the call.
 */
@Singleton
class RepositoryCallSignaling @Inject constructor(
    private val callRepository: CallRepository,
    private val scope: CoroutineScope,
) : CallSignaling {

    override fun accept(callId: String) {
        scope.launch { runCatching { callRepository.accept(callId) } }
    }

    override fun decline(callId: String) {
        scope.launch { runCatching { callRepository.decline(callId) } }
    }

    override fun hangup(callId: String) {
        scope.launch { runCatching { callRepository.end(callId) } }
    }
}
