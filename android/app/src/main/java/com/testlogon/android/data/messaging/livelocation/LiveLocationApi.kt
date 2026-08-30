package com.testlogon.android.data.messaging.livelocation

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import retrofit2.http.Body
import retrofit2.http.POST
import retrofit2.http.Path
import javax.inject.Inject
import javax.inject.Singleton

/**
 * FE-131 (EPIC D, <- BE-131) - LIVE location relay: start a share, post periodic position updates,
 * and stop it. Matches the assumed BE-131 wire contract:
 *   POST messaging/conversations/{id}/live-location/start  { duration_sec }        -> { share_id, started_at, expires_at }
 *   POST messaging/live-location/{share_id}/update         { lat, lng }            -> 200
 *   POST messaging/live-location/{share_id}/stop                                    -> 200
 *
 * DEGRADE-ON-404: the moving-pin relay requires BE-131. When the endpoint is missing (404) or the
 * call fails, [LiveLocationRepository] returns null / false and the caller falls back to the local
 * TLLIVE1 optimistic card (last-known pin + LIVE badge + countdown + auto-expiry). Paths are relative
 * (no leading slash) so they resolve against the shared Retrofit base URL.
 */
interface LiveLocationApi {
    @POST("messaging/conversations/{conversation_id}/live-location/start")
    suspend fun start(
        @Path("conversation_id") conversationId: String,
        @Body body: StartLiveLocationRequestDto,
    ): StartLiveLocationResponseDto

    @POST("messaging/live-location/{share_id}/update")
    suspend fun update(
        @Path("share_id") shareId: String,
        @Body body: LiveLocationUpdateRequestDto,
    )

    @POST("messaging/live-location/{share_id}/stop")
    suspend fun stop(
        @Path("share_id") shareId: String,
    )
}

@JsonClass(generateAdapter = true)
data class StartLiveLocationRequestDto(
    @Json(name = "duration_sec") val durationSec: Long,
)

@JsonClass(generateAdapter = true)
data class StartLiveLocationResponseDto(
    @Json(name = "share_id") val shareId: String,
    @Json(name = "started_at") val startedAt: Long,
    @Json(name = "expires_at") val expiresAt: Long,
)

@JsonClass(generateAdapter = true)
data class LiveLocationUpdateRequestDto(
    @Json(name = "lat") val lat: Double,
    @Json(name = "lng") val lng: Double,
)

/** A started live share as resolved by the backend (server-authoritative share_id + window). */
data class StartedLiveShare(
    val shareId: String,
    val startedAtSec: Long,
    val expiresAtSec: Long,
)

/**
 * Degrade-safe wrapper over [LiveLocationApi]. Every method swallows failures (incl. a 404 when
 * BE-131 is undeployed) and returns null/false so the UI never crashes and can fall back to the
 * local optimistic TLLIVE1 card.
 */
interface LiveLocationRepository {
    /** Returns the server share window, or null when the relay is unavailable (degrade to local). */
    suspend fun start(conversationId: String, durationSec: Long): StartedLiveShare?

    /** Best-effort position relay; true when the update was accepted. */
    suspend fun update(shareId: String, lat: Double, lng: Double): Boolean

    /** Best-effort stop; true when the stop was accepted. */
    suspend fun stop(shareId: String): Boolean
}

@Singleton
class DefaultLiveLocationRepository @Inject constructor(
    private val api: LiveLocationApi,
) : LiveLocationRepository {

    override suspend fun start(conversationId: String, durationSec: Long): StartedLiveShare? =
        runCatching {
            val dto = api.start(conversationId, StartLiveLocationRequestDto(durationSec))
            StartedLiveShare(dto.shareId, dto.startedAt, dto.expiresAt)
        }.getOrNull()

    override suspend fun update(shareId: String, lat: Double, lng: Double): Boolean =
        runCatching { api.update(shareId, LiveLocationUpdateRequestDto(lat, lng)) }.isSuccess

    override suspend fun stop(shareId: String): Boolean =
        runCatching { api.stop(shareId) }.isSuccess
}

@Module
@InstallIn(SingletonComponent::class)
object LiveLocationApiModule {
    @Provides
    @Singleton
    fun provideLiveLocationApi(retrofit: Retrofit): LiveLocationApi =
        retrofit.create(LiveLocationApi::class.java)

    @Provides
    @Singleton
    fun provideLiveLocationRepository(impl: DefaultLiveLocationRepository): LiveLocationRepository = impl
}
