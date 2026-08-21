package com.testlogon.android.feature.apikeys.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.apikeys.ApiKeysApi
import com.testlogon.android.core.network.apikeys.CreateApiKeyRequest
import com.testlogon.android.core.network.apikeys.RevokeApiKeyRequest
import com.testlogon.android.core.network.apikeys.SetIpRulesRequest
import com.testlogon.android.core.network.apikeys.SetScopesRequest
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * B-APIKEY (batch 7) - data layer for the developer API-keys management surface, over the [ApiKeysApi].
 *
 * [list] maps the {keys:[...]} envelope to domain and folds into [ApiResult] via [call]; on a non-401 failure
 * with a populated in-memory snapshot it returns the cached list (the VM flips an isStale flag) - the same
 * IN-MEMORY (NOT Room) fallback pattern as the AND-398 webhooks repository (no migration / no Pixel smoke).
 * [create] and [revoke] are NON-idempotent mutations that are NEVER auto-retried here. After a successful create
 * the new key is write-through-merged (secret-less) at the head of the snapshot; after a revoke the key is
 * removed from the snapshot so a subsequent [list] reflects it immediately even before the next network read.
 *
 * The one-time [com.testlogon.android.feature.apikeys.data.CreatedApiKey.secret] from [create] is passed straight
 * through to the caller for one-time in-session display; it is NEVER written into the cache, persisted, or logged.
 */
interface ApiKeysRepository {

    /** GET the caller's API keys, mapped to domain. Falls back to the in-memory snapshot on a non-401 failure. */
    suspend fun list(): ApiResult<List<ApiKey>>

    /** POST a new API key (label + capabilities + optional expiry). On success returns the one-time secret. */
    suspend fun create(
        label: String,
        capabilities: List<String>,
        expiresInDays: Int?,
        protocols: List<String> = emptyList(),
    ): ApiResult<CreatedApiKey>

    /** POST a revoke for the given key id. On success the key is dropped from the in-memory snapshot. */
    suspend fun revoke(keyId: String): ApiResult<Unit>

    /** Returns the cached key (from the last [list]) by id, or null. No network call. */
    fun cached(keyId: String): ApiKey?

    /**
     * Batch 8 (#17): PATCH a key's full capability set. On success the cached row's capabilities are updated
     * (the server may expand implied capabilities, so the authoritative returned list is written through).
     */
    suspend fun setCapabilities(keyId: String, capabilities: List<String>): ApiResult<List<String>>

    /**
     * Batch 8 (#18): POST a key's full IP allow/deny CIDR lists (SET/replace). On success the cached row's
     * allow/deny lists are updated to the server-normalised values.
     */
    suspend fun setIpRules(
        keyId: String,
        allowCidrs: List<String>,
        denyCidrs: List<String>,
    ): ApiResult<Pair<List<String>, List<String>>>

    /**
     * MULTI-PROTOCOL: GET the unified exchange gateway per-protocol availability. NEW endpoint -> DEGRADES ON
     * 404 to `ApiResult.Success(null)` (an honest "not available yet" state; existing keys are unaffected).
     */
    suspend fun gatewayEndpoints(): ApiResult<GatewayEndpoints?>

    /**
     * MULTI-PROTOCOL: GET a key's per-protocol connection credentials. NEW endpoint -> DEGRADES ON 404 to
     * `ApiResult.Success(null)`. Secrets are never returned here (only token_set/key_set flags).
     */
    suspend fun keyProtocols(keyId: String): ApiResult<KeyProtocols?>

    /**
     * MULTI-PROTOCOL: POST a rotate of one protocol's secret. Returns the ONE-TIME new secret (show-once).
     * A mutation -> errors clearly (does NOT degrade on 404).
     */
    suspend fun rotateProtocolSecret(keyId: String, protocol: String): ApiResult<String>
}

@Singleton
class DefaultApiKeysRepository @Inject constructor(
    private val api: ApiKeysApi,
    private val errorParser: ApiErrorParser,
) : ApiKeysRepository {

    /** IN-MEMORY last-good snapshot. Null = never loaded; non-null = last good list. */
    @Volatile
    private var cache: List<ApiKey>? = null

    override suspend fun list(): ApiResult<List<ApiKey>> =
        withContext(Dispatchers.IO) {
            when (val result = call { api.list().keys.map { it.toDomain() } }) {
                is ApiResult.Success -> {
                    cache = result.data
                    result
                }
                is ApiResult.Failure -> {
                    val cached = cache
                    if (result.error.status != HTTP_UNAUTHORIZED && cached != null) {
                        ApiResult.Success(cached)
                    } else {
                        result
                    }
                }
                is ApiResult.NetworkError -> {
                    val cached = cache
                    if (cached != null) ApiResult.Success(cached) else result
                }
            }
        }

    override suspend fun create(
        label: String,
        capabilities: List<String>,
        expiresInDays: Int?,
        protocols: List<String>,
    ): ApiResult<CreatedApiKey> =
        withContext(Dispatchers.IO) {
            val result = call {
                api.create(
                    CreateApiKeyRequest(
                        label = label,
                        capabilities = capabilities,
                        expiresInDays = expiresInDays,
                        // Absent (null) for a content-only key so the wire body stays unchanged from before.
                        protocols = protocols.takeIf { it.isNotEmpty() },
                    ),
                ).toDomain()
            }
            if (result is ApiResult.Success) {
                val created = result.data
                // Write-through a SECRET-LESS row at the head (the secret stays only in the returned value).
                val row = ApiKey(
                    id = created.id,
                    label = created.label,
                    capabilities = created.capabilities,
                    createdAt = created.createdAt,
                    lastUsedAt = null,
                    expiresAt = created.expiresAt,
                    prefix = "ak_${created.id.take(8)}",
                )
                val prior = cache.orEmpty().filterNot { it.id == created.id }
                cache = listOf(row) + prior
            }
            result
        }

    override suspend fun revoke(keyId: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) {
            val result = call { api.revoke(RevokeApiKeyRequest(keyId = keyId)) }
            if (result is ApiResult.Success) {
                cache = cache?.filterNot { it.id == keyId }
            }
            result
        }

    override fun cached(keyId: String): ApiKey? = cache?.firstOrNull { it.id == keyId }

    override suspend fun setCapabilities(
        keyId: String,
        capabilities: List<String>,
    ): ApiResult<List<String>> =
        withContext(Dispatchers.IO) {
            val result = call {
                api.setScopes(keyId, SetScopesRequest(keyId = keyId, capabilities = capabilities)).capabilities
            }
            if (result is ApiResult.Success) {
                updateCached(keyId) { it.copy(capabilities = result.data) }
            }
            result
        }

    override suspend fun setIpRules(
        keyId: String,
        allowCidrs: List<String>,
        denyCidrs: List<String>,
    ): ApiResult<Pair<List<String>, List<String>>> =
        withContext(Dispatchers.IO) {
            val result = call {
                val out = api.setIpRules(
                    SetIpRulesRequest(keyId = keyId, allowCidrs = allowCidrs, denyCidrs = denyCidrs),
                )
                out.allowCidrs to out.denyCidrs
            }
            if (result is ApiResult.Success) {
                updateCached(keyId) {
                    it.copy(allowCidrs = result.data.first, denyCidrs = result.data.second)
                }
            }
            result
        }

    override suspend fun gatewayEndpoints(): ApiResult<GatewayEndpoints?> =
        withContext(Dispatchers.IO) {
            degradeOn404 { api.gatewayEndpoints().toDomain() }
        }

    override suspend fun keyProtocols(keyId: String): ApiResult<KeyProtocols?> =
        withContext(Dispatchers.IO) {
            degradeOn404 { api.keyProtocols(keyId).toDomain() }
        }

    override suspend fun rotateProtocolSecret(keyId: String, protocol: String): ApiResult<String> =
        withContext(Dispatchers.IO) {
            call { api.rotateProtocolSecret(keyId, protocol).secret }
        }

    /**
     * Folds a NEW-endpoint READ into ApiResult, mapping a 404 to `Success(null)` (the endpoint is "not available
     * yet"). Any other HTTP/transport failure surfaces normally so a real error is not masked as absence.
     */
    private suspend fun <T> degradeOn404(block: suspend () -> T): ApiResult<T?> =
        when (val r = call { block() }) {
            is ApiResult.Success -> r
            is ApiResult.Failure -> if (r.error.status == HTTP_NOT_FOUND) ApiResult.Success(null) else r
            is ApiResult.NetworkError -> r
        }

    /** Patches the cached row for [keyId] (if present) so detail/list reflect a mutation without a re-fetch. */
    private fun updateCached(keyId: String, transform: (ApiKey) -> ApiKey) {
        cache = cache?.map { if (it.id == keyId) transform(it) else it }
    }

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (preserving the status so 401 surfaces for the VM's
     * re-auth handoff); malformed JSON -> Failure; transport failures -> NetworkError. Cancellation is re-thrown.
     * Mirrors AND-398.
     */
    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    private companion object {
        const val HTTP_UNAUTHORIZED = 401
        const val HTTP_NOT_FOUND = 404
    }
}
