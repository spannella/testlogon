package com.testlogon.android.data.messaging.geocode

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import retrofit2.http.GET
import retrofit2.http.Query
import javax.inject.Inject
import javax.inject.Singleton

/**
 * FE-130 (EPIC D, <- BE-133) - reverse-geocode read: resolve a lat/lng to a human place name.
 *
 * Matches the WEB contract (frontend/src/api/endpoints/messaging.ts reverseGeocode):
 *   GET messaging/geocode/reverse?lat=&lng=  -> { place_name?, display_name? }
 *
 * Best-effort: the composer NEVER blocks a send on this. If the endpoint is missing (404), the backend
 * has no key configured, or the call fails for any reason, [GeocodeRepository.reverse] returns null and
 * the location card simply ships coords-only (degrade, no crash).
 */
interface GeocodeApi {
    @GET("messaging/geocode/reverse")
    suspend fun reverse(
        @Query("lat") lat: Double,
        @Query("lng") lng: Double,
    ): ReverseGeocodeDto
}

/** BE-133 reverse-geocode response; either field may carry the place name. */
@JsonClass(generateAdapter = true)
data class ReverseGeocodeDto(
    @Json(name = "place_name") val placeName: String? = null,
    @Json(name = "display_name") val displayName: String? = null,
)

/** Best-effort reverse-geocode wrapper; returns null on any failure so a send is never blocked. */
interface GeocodeRepository {
    suspend fun reverse(lat: Double, lng: Double): String?
}

@Singleton
class DefaultGeocodeRepository @Inject constructor(
    private val api: GeocodeApi,
) : GeocodeRepository {
    override suspend fun reverse(lat: Double, lng: Double): String? =
        runCatching {
            val dto = api.reverse(lat, lng)
            (dto.placeName ?: dto.displayName)?.trim()?.takeIf { it.isNotBlank() }
        }.getOrNull()
}

@Module
@InstallIn(SingletonComponent::class)
object GeocodeApiModule {
    @Provides
    @Singleton
    fun provideGeocodeApi(retrofit: Retrofit): GeocodeApi = retrofit.create(GeocodeApi::class.java)

    @Provides
    @Singleton
    fun provideGeocodeRepository(impl: DefaultGeocodeRepository): GeocodeRepository = impl
}
