package com.testlogon.android.data.auth

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.SettingsStore
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/** AND-063 — tenant SSO discovery result mapped from `GET /ui/sso/info`. */
data class SsoInfo(
    val ssoAvailable: Boolean,
    val ssoOnly: Boolean,
    val ssoLoginUrl: String?,
    val providerDisplayName: String?,
    val providerProtocol: String?,
)

/** Outcome of finalizing an SSO browser round-trip (AND-063). */
sealed interface SsoFinalizeResult {
    data class Authenticated(val user: User) : SsoFinalizeResult
}

/**
 * AND-063 — SSO / SAML repository. Provides tenant discovery, builds the browser authorization URL,
 * and finalizes the post-callback session via `GET /ui/me` (cookies are set by the ACS redirect into
 * the shared persistent cookie jar). The authorization endpoint itself is opened in a Custom Tab —
 * it is NOT a Retrofit call.
 */
interface SsoRepository {
    /** Tenant-scoped discovery (idempotent GET). [tenant] defaults to "default". */
    suspend fun getSsoInfo(tenant: String = "default"): ApiResult<SsoInfo>

    /**
     * Authorization URL to open in the browser: `sso_login_url` verbatim when present, else
     * `{baseUrl}/saml/login?tenant=<tenant>`. The backend accepts ONLY a `tenant` query param — no
     * `state`/`return_url` is ever appended.
     */
    fun authorizeUrl(info: SsoInfo?, tenant: String): String

    /** Confirm the post-callback session via getMe; populates the durable auth state on success. */
    suspend fun finalizeAfterCallback(): ApiResult<SsoFinalizeResult>
}

@Singleton
class SsoRepositoryImpl @Inject constructor(
    private val api: AuthApi,
    private val authRepository: AuthRepository,
    private val settingsStore: SettingsStore,
    private val errorParser: ApiErrorParser,
) : SsoRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun getSsoInfo(tenant: String): ApiResult<SsoInfo> =
        apiCall { api.getSsoInfo(tenant) }.let { r ->
            when (r) {
                is ApiResult.Success -> ApiResult.Success(r.data.toDomain())
                is ApiResult.Failure -> r
                is ApiResult.NetworkError -> r
            }
        }

    override fun authorizeUrl(info: SsoInfo?, tenant: String): String {
        // Use sso_login_url verbatim when present and parseable; the web client does exactly this.
        val verbatim = info?.ssoLoginUrl
        if (!verbatim.isNullOrBlank() && verbatim.toHttpUrlOrNull() != null) return verbatim

        // Fallback: {baseUrl}/saml/login?tenant=<tenant>. ONLY the tenant param is appended.
        val base = settingsStore.baseUrl.trimEnd('/')
        val builder = "$base/saml/login".toHttpUrlOrNull()?.newBuilder()
        return builder?.addQueryParameter("tenant", tenant)?.build()?.toString()
            ?: "$base/saml/login?tenant=$tenant"
    }

    override suspend fun finalizeAfterCallback(): ApiResult<SsoFinalizeResult> =
        when (val me = authRepository.getMe()) {
            is ApiResult.Success -> ApiResult.Success(SsoFinalizeResult.Authenticated(me.data))
            is ApiResult.Failure -> me
            is ApiResult.NetworkError -> me
        }

    private fun SsoInfoDto.toDomain() = SsoInfo(
        ssoAvailable = ssoAvailable,
        ssoOnly = ssoOnly,
        ssoLoginUrl = ssoLoginUrl,
        providerDisplayName = providerDisplayName,
        providerProtocol = providerProtocol,
    )

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
