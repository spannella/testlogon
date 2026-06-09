package com.testlogon.android.data.push

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.push.PushLog
import com.testlogon.android.push.PushTokenProvider
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-106 (register) + AND-109 (rotation re-register + logout deregister) — push device data layer.
 *
 * Registration is a best-effort background side effect of login (FR-5): it never blocks or fails the
 * login flow, and a failure leaves the user fully authenticated. Idempotency is enforced locally by
 * comparing the persisted `(user_sub, token, contractVersion)` tuple against the current one (FR-3),
 * so a repeat login with an unchanged token issues no network call.
 *
 * Real contract used (verified): POST /ui/push/register {token, platform} -> PushDevice;
 * POST /ui/push/revoke {device_id} -> OkResp. (See PushDtos / PushApi.)
 */
interface PushRepository {

    /**
     * Register the current FCM token if authenticated and the tuple changed.
     * @param forceToken use this token instead of fetching from Firebase (onNewToken path).
     * Returns Success (incl. authenticated-no-op / unauthenticated-cache no-op) or a mapped error.
     */
    suspend fun registerCurrentToken(forceToken: String? = null): ApiResult<Unit>

    /** Deregister this device server-side (revoke by device_id). Local no-op success if none stored. */
    suspend fun deregisterCurrentToken(): ApiResult<Unit>

    /** Clear all local push state (tuple, device_id, pending token). Called on logout. */
    suspend fun clearLocalPushState()
}

@Singleton
class PushRepositoryImpl @Inject constructor(
    private val api: PushApi,
    private val tokenProvider: PushTokenProvider,
    private val store: PushRegistrationStore,
    private val authState: AuthStateStore,
    private val errorParser: ApiErrorParser,
) : PushRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun registerCurrentToken(forceToken: String?): ApiResult<Unit> = withContext(io) {
        val userSub = authState.userSub.first()
        if (userSub.isNullOrBlank()) {
            // Unauthenticated: cache the rotated token (if any) and register at next login (FR-2/3).
            forceToken?.let { store.cachePendingToken(it) }
            PushLog.d("register_skip_unauth")
            return@withContext ApiResult.Success(Unit)
        }

        // Resolve token: explicit (rotation) > pending (cached while logged out) > Firebase fetch.
        val token = when {
            !forceToken.isNullOrBlank() -> forceToken
            else -> store.pendingToken()?.takeIf { it.isNotBlank() }
                ?: when (val t = tokenProvider.currentToken()) {
                    is ApiResult.Success -> t.data
                    is ApiResult.Failure -> return@withContext ApiResult.Failure(t.error)
                    is ApiResult.NetworkError -> return@withContext t
                }
        }

        val current = RegisteredTuple(userSub, token, PUSH_CONTRACT_VERSION)
        if (store.lastRegistered() == current) {
            PushLog.d("register_skip_noop ${PushLog.redactToken(token)}")
            return@withContext ApiResult.Success(Unit)
        }

        PushLog.d("register_attempt ${PushLog.redactToken(token)}")
        when (val result = apiCall { api.register(PushRegisterRequest(token = token)) }) {
            is ApiResult.Success -> {
                store.setDeviceId(result.data.deviceId)
                store.setLastRegistered(current)
                store.cachePendingToken(null)
                PushLog.d("register_success deviceId=${result.data.deviceId}")
                ApiResult.Success(Unit)
            }
            is ApiResult.Failure -> {
                PushLog.d("register_error http=${result.error.status}")
                result
            }
            is ApiResult.NetworkError -> {
                PushLog.d("register_error network")
                result
            }
        }
    }

    override suspend fun deregisterCurrentToken(): ApiResult<Unit> = withContext(io) {
        val deviceId = store.deviceId()
        if (deviceId.isNullOrBlank()) {
            // Nothing deliverable server-side; treat as a local no-op success (AND-109 §4.2).
            PushLog.d("deregister_skip_no_device_id")
            return@withContext ApiResult.Success(Unit)
        }
        when (val result = apiCall { api.revoke(PushRevokeRequest(deviceId)) }) {
            is ApiResult.Success -> {
                PushLog.d("deregister_success")
                ApiResult.Success(Unit)
            }
            is ApiResult.Failure -> {
                PushLog.d("deregister_error http=${result.error.status}")
                result
            }
            is ApiResult.NetworkError -> {
                PushLog.d("deregister_error network")
                result
            }
        }
    }

    override suspend fun clearLocalPushState() {
        store.clear()
        PushLog.d("local_push_state_cleared")
    }

    private suspend fun <T> apiCall(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
