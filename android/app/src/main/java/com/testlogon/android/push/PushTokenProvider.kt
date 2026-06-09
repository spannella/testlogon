package com.testlogon.android.push

import com.google.firebase.messaging.FirebaseMessaging
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import kotlinx.coroutines.suspendCancellableCoroutine
import javax.inject.Inject
import kotlin.coroutines.resume

/**
 * AND-105 (FR-6) / AND-106 — read path for the current FCM registration token.
 *
 * Interface seam so the repository can be unit-tested with a fake provider (no live Firebase). The
 * default [FirebaseMessagingTokenProvider] wraps `FirebaseMessaging.getToken()`.
 */
interface PushTokenProvider {
    suspend fun currentToken(): ApiResult<String>
}

/**
 * Wraps the `FirebaseMessaging.getToken()` [com.google.android.gms.tasks.Task] as a suspending call,
 * folding success/failure into [ApiResult]. Token fetch fails on devices without Google Play services
 * / offline / SERVICE_NOT_AVAILABLE — those surface as [ApiResult.Failure] (never thrown), so callers
 * can defer registration rather than crash.
 *
 * The Task->coroutine bridge is implemented locally (suspendCancellableCoroutine) so we do not add
 * the kotlinx-coroutines-play-services dependency; behavior matches Task.await().
 */
class FirebaseMessagingTokenProvider @Inject constructor(
    private val messaging: FirebaseMessaging,
) : PushTokenProvider {

    override suspend fun currentToken(): ApiResult<String> = try {
        val token = suspendCancellableCoroutine { cont ->
            messaging.token
                .addOnSuccessListener { t -> if (cont.isActive) cont.resume(t) }
                .addOnFailureListener { e -> if (cont.isActive) cont.resumeWith(Result.failure(e)) }
                .addOnCanceledListener { if (cont.isActive) cont.cancel() }
        }
        if (token.isNullOrBlank()) {
            ApiResult.Failure(ApiError(ApiError.STATUS_NETWORK, "FCM token unavailable"))
        } else {
            ApiResult.Success(token)
        }
    } catch (e: Exception) {
        PushLog.d("fcm_token_fetch_failed ${e.javaClass.simpleName}")
        ApiResult.Failure(
            ApiError(ApiError.STATUS_NETWORK, "FCM token unavailable: ${e.javaClass.simpleName}"),
        )
    }
}
