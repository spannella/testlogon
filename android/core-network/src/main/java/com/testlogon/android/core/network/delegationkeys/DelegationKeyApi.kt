package com.testlogon.android.core.network.delegationkeys

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * Retrofit interface for the delegation-API keys surface (web parity: /delegation-api). Transport only; the
 * :app repository folds these RAW DTO returns into ApiResult. Paths are relative (no leading slash); the
 * shared authenticated client attaches the session cookie + X-CSRF-Token + Bearer globally.
 *
 * Two key groups under /ui/delegation-api:
 *  - MY keys: keys the caller (a delegate) issued for creators they manage.
 *  - CREATOR keys: keys other delegates issued that are scoped to the caller's OWN account.
 */
interface DelegationKeyApi {

    /** GET the caller's own delegation API keys (as a delegate). Bare array. Idempotent. */
    @GET("ui/delegation-api/keys")
    suspend fun listMyKeys(): List<DelegationApiKeyDto>

    /** POST a new delegation API key. Returns the created key WITH the one-time key_secret. */
    @Headers("Content-Type: application/json")
    @POST("ui/delegation-api/keys")
    suspend fun createKey(@Body body: DelegationApiKeyCreateRequest): DelegationApiKeyDto

    /** DELETE (revoke) one of the caller's own delegation API keys. Returns {"ok":true}. */
    @DELETE("ui/delegation-api/keys/{keyId}")
    suspend fun revokeMyKey(@Path("keyId") keyId: String)

    /** GET the delegation API keys other delegates issued that are scoped to the caller's account. */
    @GET("ui/delegation-api/creator-keys")
    suspend fun listCreatorKeys(): List<DelegationApiKeyDto>

    /** DELETE (revoke) a delegation API key scoped to the caller's account. Returns {"ok":true}. */
    @DELETE("ui/delegation-api/creator-keys/{keyId}")
    suspend fun revokeCreatorKey(@Path("keyId") keyId: String)

    /** GET the creators the caller delegates for (populates the create dialog). Bare array. */
    @GET("ui/delegates/managed")
    suspend fun listManagedCreators(): List<ManagedCreatorDto>
}
