package com.testlogon.android.data.push

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.PushLogoutHandler
import com.testlogon.android.push.PushLog
import kotlinx.coroutines.withTimeoutOrNull
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-109 — the real [PushLogoutHandler] inserted at the front of the AND-032 logout flow.
 *
 * Order is mandatory (AND-109 §4.5): deregister runs while session cookies + CSRF are still live, so
 * the `POST /ui/push/revoke` call is authenticated. It is best-effort with a short timeout (FR-5): on
 * timeout/failure logout still proceeds, a deregister-retry worker is enqueued, and local push state
 * is cleared regardless so a different user on the same device does not inherit this registration.
 */
@Singleton
class PushLogoutHandlerImpl @Inject constructor(
    private val repository: PushRepository,
    private val workScheduler: PushWorkScheduler,
) : PushLogoutHandler {

    override suspend fun onLogout() {
        val result = withTimeoutOrNull(DEREGISTER_TIMEOUT_MS) {
            repository.deregisterCurrentToken()
        }
        if (result !is ApiResult.Success) {
            PushLog.d("deregister deferred to worker")
            workScheduler.enqueueDeregister()
        }
        // Clear local push state regardless of the network outcome (AND-109 FR-4).
        repository.clearLocalPushState()
    }

    companion object {
        // Shorter than the ~20s app default so logout stays snappy; the worker covers slow/offline.
        const val DEREGISTER_TIMEOUT_MS = 5_000L
    }
}
