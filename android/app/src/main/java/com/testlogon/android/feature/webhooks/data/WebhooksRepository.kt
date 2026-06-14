package com.testlogon.android.feature.webhooks.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.webhooks.Webhook
import com.testlogon.android.core.model.webhooks.WebhookEventType
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.webhooks.CreateWebhookRequest
import com.testlogon.android.core.network.webhooks.WebhooksApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-398 - data layer for the WEBHOOKS config (light) surface, over the AND-398 [WebhooksApi].
 *
 * READS ([list], [get], [eventTypes]) map the RAW DTO (a BARE ARRAY for list - NO envelope; a bare object for
 * get; the NAMED {event_types} envelope for the metadata call) to the core-model domain and fold into
 * [ApiResult] via [call] (mirrors AND-372 TicketsRepository). [create] is the only mutation - a NON-idempotent
 * POST that is NEVER auto-retried here (the caller decides whether to re-send).
 *
 * CACHE (IN-MEMORY, write-through): per the established AND-372 pattern this feature keeps the last-good
 * endpoint list IN MEMORY (a @Volatile snapshot), NOT in Room - so there is NO Room migration and NO Pixel
 * smoke this wave (the spec's draft Room cache is intentionally avoided in favour of the in-memory stale
 * pattern used elsewhere; cross-process persistence is DEFERRED). [list] returns the network result on success
 * (refreshing the snapshot) and FALLS BACK to the cached snapshot on a non-401 failure (offline / flaky host -
 * §7 / AC-6). [create] performs a write-through merge (the created endpoint is inserted at the head of the
 * snapshot) so a subsequent [list] / [get] sees it immediately even before the next network refresh. [get]
 * prefers the cached entry and falls back to the network.
 *
 * The signing [Webhook.secret], if returned on [create], is passed straight through to the caller for one-time
 * in-session display; it is NEVER written into the cached snapshot (the cache stores the secret-less endpoint),
 * never persisted, and never logged (AC-7 / §8).
 */
interface WebhooksRepository {

    /**
     * GET the caller's webhook endpoints, mapped to domain. On a non-401 failure with a populated in-memory
     * cache, returns the cached snapshot (the caller flips an isStale flag); with an empty cache, the failure
     * surfaces as Failure / NetworkError. [forceRefresh] is accepted for API parity but the read is always a
     * network read (the cache is a fallback, not a short-circuit).
     */
    suspend fun list(forceRefresh: Boolean = false): ApiResult<List<Webhook>>

    /** GET one endpoint - prefers the cached snapshot entry, else a network GET ui/webhooks/{endpointId}. */
    suspend fun get(id: String): ApiResult<Webhook>

    /**
     * POST a LIGHT create (url + event_types). On 201 the created endpoint (which may carry the one-time secret)
     * is returned AND write-through-merged into the cache (secret stripped from the cached copy). NON-idempotent
     * -> NO auto-retry inside the repo.
     */
    suspend fun create(targetUrl: String, events: List<String>): ApiResult<Webhook>

    /** GET the enumerable subscribable event types for the create multi-select (NAMED envelope unwrap). */
    suspend fun eventTypes(): ApiResult<List<WebhookEventType>>
}

@Singleton
class DefaultWebhooksRepository @Inject constructor(
    private val api: WebhooksApi,
    private val errorParser: ApiErrorParser,
) : WebhooksRepository {

    /** AND-398 - the IN-MEMORY last-good snapshot (secret-less). Null = never loaded; non-null = last good list. */
    @Volatile
    private var cache: List<Webhook>? = null

    override suspend fun list(forceRefresh: Boolean): ApiResult<List<Webhook>> =
        withContext(Dispatchers.IO) {
            when (val result = call { api.list().map { it.toDomain() } }) {
                is ApiResult.Success -> {
                    cache = result.data.map { it.copy(secret = null) }
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

    override suspend fun get(id: String): ApiResult<Webhook> =
        withContext(Dispatchers.IO) {
            cache?.firstOrNull { it.id == id }?.let { return@withContext ApiResult.Success(it) }
            call { api.get(id).toDomain() }
        }

    override suspend fun create(targetUrl: String, events: List<String>): ApiResult<Webhook> =
        withContext(Dispatchers.IO) {
            val result = call {
                api.create(CreateWebhookRequest(url = targetUrl, eventTypes = events)).toDomain()
            }
            if (result is ApiResult.Success) {
                // Write-through: store the SECRET-LESS endpoint at the head; the secret stays only in the
                // returned value for one-time in-session display (never cached / persisted / logged).
                val created = result.data
                val secretLess = created.copy(secret = null)
                val prior = cache.orEmpty().filterNot { it.id == created.id }
                cache = listOf(secretLess) + prior
            }
            result
        }

    override suspend fun eventTypes(): ApiResult<List<WebhookEventType>> =
        withContext(Dispatchers.IO) {
            call { api.eventTypes().eventTypes.map { it.toDomain() } }
        }

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser], preserving the status so a
     * 401 surfaces as Failure(status=401) for the VM's re-auth handoff); malformed JSON -> Failure; transport
     * failures -> NetworkError. JsonEncodingException precedes IOException (it is a subtype). Cancellation is
     * re-thrown. Mirrors AND-372.
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
    }
}
