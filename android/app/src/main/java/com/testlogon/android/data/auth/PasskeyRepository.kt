package com.testlogon.android.data.auth

import android.content.Context
import com.squareup.moshi.Moshi
import com.squareup.moshi.Types
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/** Domain result of registering a platform passkey (AND-062). Label is held client-side. */
data class RegisteredPasskey(
    val credentialId: String?,
    val label: String?,
)

/** Domain result of a passkey assertion (AND-062). [Authenticated] means getMe succeeded. */
sealed interface PasskeyAuthResult {
    data class Authenticated(val user: User) : PasskeyAuthResult
    data object Cancelled : PasskeyAuthResult
}

/**
 * AND-062 — passkey (WebAuthn) repository. Orchestrates begin → Credential Manager → finish:
 *  1. call the begin endpoint (register is authenticated, authenticate is public) → opaque `options`;
 *  2. hand the verbatim options JSON to [PasskeyManager] (NOT an HTTP call; never OkHttp-retried);
 *  3. map the [PasskeyOutcome] (cancel/no-credential/provider/dom) to a typed result/error;
 *  4. post the response JSON to the finish endpoint.
 *
 * Cancellation never calls `finish`. Challenges are single-use, so begin/finish are never auto-retried
 * (only the shared 401-refresh interceptor may retry register once). No challenge / credential JSON /
 * user identifier is ever logged.
 */
interface PasskeyRepository {

    /** True only when the device can mint/return platform passkeys (API 28+, provider present). */
    suspend fun isSupported(): Boolean

    /** Register a platform passkey from an authenticated context; [label] is held client-side. */
    suspend fun registerPasskey(activity: Context, label: String?): ApiResult<RegisteredPasskey>

    /** Authenticate with a passkey. [username] is REQUIRED by the contract. */
    suspend fun authenticateWithPasskey(activity: Context, username: String): ApiResult<PasskeyAuthResult>
}

@Singleton
class PasskeyRepositoryImpl @Inject constructor(
    private val api: AuthApi,
    private val passkeyManager: PasskeyManager,
    private val authRepository: AuthRepository,
    private val errorParser: ApiErrorParser,
    moshi: Moshi,
) : PasskeyRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    private val mapAdapter = moshi.adapter<Map<String, Any?>>(
        Types.newParameterizedType(Map::class.java, String::class.java, Any::class.java),
    )

    override suspend fun isSupported(): Boolean = passkeyManager.isPasskeySupported()

    override suspend fun registerPasskey(activity: Context, label: String?): ApiResult<RegisteredPasskey> {
        val begin = apiCall { api.webauthnRegisterBegin(WebAuthnRegisterBeginReq(label = label)) }
        val options = when (begin) {
            is ApiResult.Failure -> return begin
            is ApiResult.NetworkError -> return begin
            is ApiResult.Success -> begin.data.options
        }

        // Credential Manager step — not an HTTP call; cancellation must NOT reach finish.
        val outcome = passkeyManager.createCredential(activity, mapAdapter.toJson(options))
        val responseJson = when (val mapped = outcome.toCredentialResult()) {
            is ApiResult.Failure -> return mapped
            is ApiResult.NetworkError -> return mapped
            is ApiResult.Success -> mapped.data ?: return cancelledRegister()
        }

        val credential = mapAdapter.fromJson(responseJson).orEmpty()
        return when (val finish = apiCall {
            api.webauthnRegisterFinish(WebAuthnRegisterFinishReq(credential = credential, label = label))
        }) {
            is ApiResult.Success ->
                ApiResult.Success(RegisteredPasskey(credentialId = finish.data.credentialId, label = label))
            is ApiResult.Failure -> finish
            is ApiResult.NetworkError -> finish
        }
    }

    override suspend fun authenticateWithPasskey(
        activity: Context,
        username: String,
    ): ApiResult<PasskeyAuthResult> {
        val trimmed = username.trim()
        if (trimmed.isEmpty()) {
            return ApiResult.Failure(ApiError(status = 0, message = "Enter your username.", code = "missing_username"))
        }

        val begin = apiCall { api.webauthnAuthenticateBegin(WebAuthnAuthBeginReq(username = trimmed)) }
        val options = when (begin) {
            is ApiResult.Failure -> return begin
            is ApiResult.NetworkError -> return begin
            is ApiResult.Success -> begin.data.options
        }

        val outcome = passkeyManager.getCredential(activity, mapAdapter.toJson(options))
        val responseJson = when (val mapped = outcome.toCredentialResult()) {
            is ApiResult.Failure -> return mapped
            is ApiResult.NetworkError -> return mapped
            is ApiResult.Success -> mapped.data ?: return ApiResult.Success(PasskeyAuthResult.Cancelled)
        }

        val credential = mapAdapter.fromJson(responseJson).orEmpty()
        val finish = apiCall {
            api.webauthnAuthenticateFinish(WebAuthnAuthFinishReq(username = trimmed, credential = credential))
        }
        return when (finish) {
            is ApiResult.Failure -> finish
            is ApiResult.NetworkError -> finish
            is ApiResult.Success -> {
                val resp = finish.data
                if (resp.status == "ok" && !resp.sessionId.isNullOrBlank()) {
                    // Session established by the finish response; confirm + hydrate via getMe so the
                    // nav gate swaps graphs.
                    when (val me = authRepository.getMe()) {
                        is ApiResult.Success -> ApiResult.Success(PasskeyAuthResult.Authenticated(me.data))
                        is ApiResult.Failure -> me
                        is ApiResult.NetworkError -> me
                    }
                } else {
                    ApiResult.Failure(
                        ApiError(status = 200, message = "Passkey sign-in failed. Try again.", code = "webauthn_failed"),
                    )
                }
            }
        }
    }

    /**
     * Maps a [PasskeyOutcome] to a transport-shaped result: [ApiResult.Success] with a non-null JSON
     * to continue to finish, [ApiResult.Success] with null to signal a clean cancellation (caller
     * returns its own Cancelled value WITHOUT calling finish), or a typed [ApiResult.Failure].
     */
    private fun PasskeyOutcome.toCredentialResult(): ApiResult<String?> = when (this) {
        is PasskeyOutcome.Success -> ApiResult.Success(responseJson)
        PasskeyOutcome.Cancelled -> ApiResult.Success(null)
        PasskeyOutcome.NoCredential ->
            ApiResult.Failure(
                ApiError(0, "No passkey found for this account on this device.", "no_credential"),
            )
        is PasskeyOutcome.Failure -> ApiResult.Failure(type.toApiError())
    }

    private fun PasskeyErrorType.toApiError(): ApiError = when (this) {
        PasskeyErrorType.UNSUPPORTED ->
            ApiError(0, "Passkeys aren't available on this device.", "passkey_unsupported")
        PasskeyErrorType.PROVIDER ->
            ApiError(0, "Passkey service unavailable. Try again.", "passkey_provider")
        PasskeyErrorType.DOM_EXCEPTION ->
            ApiError(0, "Passkeys aren't set up for this app yet.", "passkey_dom")
        PasskeyErrorType.INTERRUPTED ->
            ApiError(0, "Passkey request was interrupted. Try again.", "passkey_interrupted")
        PasskeyErrorType.UNKNOWN ->
            ApiError(0, "Couldn't complete the passkey request. Try again.", "passkey_unknown")
    }

    private fun cancelledRegister(): ApiResult<RegisteredPasskey> =
        ApiResult.Failure(ApiError(0, "Passkey registration was cancelled.", "cancelled"))

    private suspend fun <T> apiCall(block: suspend () -> T): ApiResult<T> = withContext(io) {
        try {
            ApiResult.Success(block())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Failure(errorParser.from(e))
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is java.net.SocketTimeoutException)
        }
    }
}
