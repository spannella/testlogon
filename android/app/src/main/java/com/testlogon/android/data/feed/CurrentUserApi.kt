package com.testlogon.android.data.feed

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.http.GET
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * FD1 — the current user's identity (`user_sub`), read from `GET /ui/me`. Needed to scope the feed to
 * the signed-in author ("Your posts"). The endpoint returns `{ user_sub, session_id, ip }`.
 */
@JsonClass(generateAdapter = true)
data class CurrentUserDto(
    @Json(name = "user_sub") val userSub: String? = null,
    // B-SUP (batch 7): /ui/me now also carries the caller's support/admin role signal.
    @Json(name = "role") val role: String? = null,
    @Json(name = "is_admin") val isAdmin: Boolean? = null,
)

interface CurrentUserApi {
    @GET("ui/me")
    suspend fun me(): CurrentUserDto
}

@Singleton
class CurrentUserRepository @Inject constructor(
    private val api: CurrentUserApi,
    private val errorParser: ApiErrorParser,
) {
    @Volatile
    private var cached: String? = null

    @Volatile
    private var cachedAdmin: Boolean? = null

    /** The signed-in user's `user_sub`, cached after the first successful lookup. */
    suspend fun currentUserSub(): ApiResult<String> = withContext(Dispatchers.IO) {
        cached?.let { return@withContext ApiResult.Success(it) }
        try {
            val sub = api.me().userSub?.takeIf { it.isNotBlank() }
            if (sub != null) {
                cached = sub
                ApiResult.Success(sub)
            } else {
                ApiResult.Failure(
                    com.testlogon.android.core.model.ApiError(status = 0, message = "Couldn't resolve your account."),
                )
            }
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Failure(errorParser.from(e))
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }

    /**
     * B-SUP (batch 7): the caller's admin status, resolved from `GET /ui/me.is_admin` (with a `role`
     * fallback of `admin`/`root`). Cached after the first successful lookup. Used by the Support surface to
     * branch the USER help experience vs the ADMIN helpdesk/moderation queue. On any failure this returns a
     * Failure so the caller can degrade to the (safe) USER view.
     */
    suspend fun isAdmin(): ApiResult<Boolean> = withContext(Dispatchers.IO) {
        cachedAdmin?.let { return@withContext ApiResult.Success(it) }
        try {
            val me = api.me()
            val admin = me.isAdmin ?: (me.role?.lowercase() in setOf("admin", "root"))
            cachedAdmin = admin
            ApiResult.Success(admin)
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Failure(errorParser.from(e))
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }
}
