package com.testlogon.android.core.network.health

import retrofit2.Response
import retrofit2.http.GET

/** Lightweight, unauthenticated backend liveness endpoints (any 2xx == healthy). */
interface HealthApi {
    @GET("health")
    suspend fun health(): Response<Unit>

    @GET("api/ping")
    suspend fun ping(): Response<Unit>
}
