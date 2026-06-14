package com.testlogon.android.data.push

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.AppScope
import com.testlogon.android.push.PushLog
import com.testlogon.android.push.PushTokenSink
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.launch
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-106/109 — drives push-token registration off two triggers and bridges the FCM token sink.
 *
 *  1. The auth `false -> true` edge (collected from [com.testlogon.android.data.auth.AuthStateStore]
 *     in an application-scoped coroutine): after login the current token is registered.
 *  2. [com.google.firebase.messaging.FirebaseMessagingService.onNewToken] -> [onTokenRefreshed]:
 *     a rotated token is registered immediately when authenticated, or cached for next login.
 *
 * This is the real [PushTokenSink] binding (replacing AND-105's logging default). It is started
 * once from [TestLogonApp.onCreate] via [start]. All work runs on [AppScope] (SupervisorJob + IO) so
 * registration is a non-blocking background side effect of login and never touches the login UiState
 * (AND-106 FR-5). Transient failures fall back to the WorkManager job (FR-6).
 */
@Singleton
class FcmTokenRegistrar @Inject constructor(
    private val repository: PushRepository,
    private val authState: com.testlogon.android.data.auth.AuthStateStore,
    private val workScheduler: PushWorkScheduler,
    @AppScope private val scope: CoroutineScope,
) : PushTokenSink {

    @Volatile
    private var started = false

    /** Starts the auth-edge collector. Idempotent; safe to call from Application.onCreate. */
    fun start() {
        if (started) return
        started = true
        scope.launch {
            authState.isAuthenticated
                // StateFlow is already conflated/distinct, so no distinctUntilChanged needed.
                // drop(1): ignore the initial replayed value; we only act on real transitions and
                // the genuine post-login edge. (A cold-start "already authenticated" is registered
                // idempotently anyway — the tuple comparison no-ops if nothing changed.)
                .drop(1)
                .collect { authed ->
                    if (authed) registerWithFallback(forceToken = null)
                }
        }
    }

    /** AND-109 — onNewToken: register the rotated token (authed) or cache it (unauthed). */
    override fun onTokenRefreshed(token: String) {
        PushLog.d("new_token_received ${PushLog.redactToken(token)}")
        scope.launch { registerWithFallback(forceToken = token) }
    }

    /** AND-109 — clears local state on logout (called from the logout flow). */
    suspend fun onLogout() {
        repository.clearLocalPushState()
    }

    private suspend fun registerWithFallback(forceToken: String?) {
        when (repository.registerCurrentToken(forceToken)) {
            is ApiResult.Success -> Unit
            is ApiResult.NetworkError -> workScheduler.enqueueRegister()
            is ApiResult.Failure -> workScheduler.enqueueRegister()
        }
    }
}
