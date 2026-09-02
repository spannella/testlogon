package com.testlogon.android.data.alerts

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/** Resolved webhook alert-channel state: subscribed [urls] + the [eventTypes] they fire on. */
data class WebhookPrefs(
    val urls: List<String> = emptyList(),
    val eventTypes: List<String> = emptyList(),
)

/**
 * Webhook alert-target data layer over [WebhookAlertApi].
 *
 * get() reads the current webhook_prefs; save()/addUrl()/removeUrl() POST the full desired list
 * (the endpoint is a whole-list PUT-style upsert) and return the server-echoed state. URL/event-type
 * normalization is delegated to [AlertsPrefsMath] so it stays pure + tested. All calls fold into
 * [ApiResult] and never throw (CancellationException re-thrown).
 */
interface WebhookAlertRepository {
    suspend fun get(): ApiResult<WebhookPrefs>
    suspend fun save(prefs: WebhookPrefs): ApiResult<WebhookPrefs>
    suspend fun addUrl(current: WebhookPrefs, rawUrl: String): ApiResult<WebhookPrefs>
    suspend fun removeUrl(current: WebhookPrefs, url: String): ApiResult<WebhookPrefs>
}

@Singleton
class WebhookAlertRepositoryImpl @Inject constructor(
    private val api: WebhookAlertApi,
    private val errorParser: ApiErrorParser,
) : WebhookAlertRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun get(): ApiResult<WebhookPrefs> = withContext(io) {
        apiCall { api.getWebhookPrefs() }.map { it.toDomain() }
    }

    override suspend fun save(prefs: WebhookPrefs): ApiResult<WebhookPrefs> = withContext(io) {
        val urls = AlertsPrefsMath.normalizeUrls(prefs.urls)
        val events = AlertsPrefsMath.normalizeEventTypes(prefs.eventTypes)
        apiCall { api.setWebhookPrefs(WebhookPrefsUpdateDto(urls, events)) }.map { it.toDomain() }
    }

    override suspend fun addUrl(current: WebhookPrefs, rawUrl: String): ApiResult<WebhookPrefs> =
        save(current.copy(urls = AlertsPrefsMath.addUrl(current.urls, rawUrl)))

    override suspend fun removeUrl(current: WebhookPrefs, url: String): ApiResult<WebhookPrefs> =
        save(current.copy(urls = AlertsPrefsMath.removeUrl(current.urls, url)))

    private fun WebhookPrefsDto.toDomain(): WebhookPrefs = WebhookPrefs(
        urls = AlertsPrefsMath.normalizeUrls(webhookUrls),
        eventTypes = AlertsPrefsMath.normalizeEventTypes(events()),
    )

    private suspend fun <T> apiCall(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: com.squareup.moshi.JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
