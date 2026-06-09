package com.testlogon.android.data.push

import retrofit2.http.Body
import retrofit2.http.Headers
import retrofit2.http.POST

/**
 * AND-106/109 — Retrofit interface for the push device endpoints.
 *
 * Paths are relative (no leading slash) so they resolve against the shared Retrofit base URL;
 * session cookies, Authorization: Bearer, and X-CSRF-Token are attached by the core-network
 * interceptor chain (so no auth headers are declared per-method). All methods are suspend and
 * return the typed DTO body; non-2xx surfaces as retrofit2.HttpException.
 *
 * Contract verified against reference/openapi.index.txt + reference/src/api/endpoints/push.ts:
 *  - register -> POST ui/push/register (req PushRegisterReq {token, platform}; resp PushDevice)
 *  - revoke   -> POST ui/push/revoke   (req PushRevokeReq {device_id};         resp OkResp)
 */
interface PushApi {

    @Headers("Content-Type: application/json")
    @POST("ui/push/register")
    suspend fun register(@Body body: PushRegisterRequest): PushDeviceDto

    @Headers("Content-Type: application/json")
    @POST("ui/push/revoke")
    suspend fun revoke(@Body body: PushRevokeRequest): OkRespDto
}
