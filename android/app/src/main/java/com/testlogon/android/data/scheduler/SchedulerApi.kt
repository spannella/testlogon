package com.testlogon.android.data.scheduler

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-275 — Retrofit interface for the scheduler-actions endpoints.
 *
 * Verified against openapi.index.txt lines 1834-1838 and src/api/endpoints/scheduler.ts. Paths are
 * relative (no leading slash); cookies / CSRF (on mutations) / auth are attached by the shared
 * interceptor chain. create responds 201; reschedule (PATCH) and cancel (DELETE) respond 200. The list
 * read takes optional `types`/`status` query params (no from/to). The single-action GET is idempotent.
 */
interface SchedulerApi {

    @GET("ui/scheduler/actions")
    suspend fun listActions(
        @Query("types") types: String? = null,
        @Query("status") status: String? = null,
    ): ScheduledActionListOutDto

    @GET("ui/scheduler/actions/{actionId}")
    suspend fun getAction(@Path("actionId") actionId: String): ScheduledActionOutDto

    @Headers("Content-Type: application/json")
    @POST("ui/scheduler/actions")
    suspend fun createAction(@Body body: ScheduledActionCreateInDto): ScheduledActionOutDto

    @Headers("Content-Type: application/json")
    @PATCH("ui/scheduler/actions/{actionId}")
    suspend fun updateAction(
        @Path("actionId") actionId: String,
        @Body body: ScheduledActionUpdateInDto,
    ): ScheduledActionOutDto

    @DELETE("ui/scheduler/actions/{actionId}")
    suspend fun cancelAction(@Path("actionId") actionId: String): ScheduledActionDeleteOutDto
}
