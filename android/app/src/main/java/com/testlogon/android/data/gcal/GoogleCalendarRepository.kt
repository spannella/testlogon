package com.testlogon.android.data.gcal

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
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

/**
 * AND-273 — data layer over [GoogleCalendarApi] + [GoogleCalendarStore].
 *
 * Backend-mediated OAuth (no Google SDK): [startConnect] persists the returned state/nonce before the
 * Custom Tab opens; on return, [refreshStatus] reads `connection_active`. [completeConnect] is only used
 * when a custom-scheme deep link drives the GET callback; it validates the echoed state against the
 * persisted value and caches the account email from the callback (status omits it). Idempotent GETs map
 * to ApiResult; mutations are never auto-retried here. CancellationException is re-thrown.
 */
interface GoogleCalendarRepository {

    suspend fun startConnect(): ApiResult<ConnectStart>

    /** Drives the GET callback (custom-scheme deep-link path). Validates state; caches account email. */
    suspend fun completeConnect(code: String, state: String): ApiResult<GoogleCalendarStatus>

    suspend fun refreshStatus(): ApiResult<GoogleCalendarStatus>

    /** The DataStore-cached projection (active flag + account email), for instant first render. */
    suspend fun cachedStatus(): GoogleCalendarStatus?

    /** The persisted in-flight OAuth state/nonce (for deep-link validation), or null. */
    suspend fun pendingOauthState(): String?

    suspend fun clearPendingOauth()

    suspend fun listProviderCalendars(): ApiResult<List<ProviderCalendar>>

    suspend fun createMapping(
        internalCalendarId: String,
        googleCalendarId: String,
    ): ApiResult<ProviderCalendar>

    suspend fun runSync(mode: String = "incremental"): ApiResult<Unit>

    suspend fun disconnect(connectionId: String? = null): ApiResult<Unit>
}

@Singleton
class GoogleCalendarRepositoryImpl @Inject constructor(
    private val api: GoogleCalendarApi,
    private val store: GoogleCalendarStore,
    private val errorParser: ApiErrorParser,
) : GoogleCalendarRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun startConnect(): ApiResult<ConnectStart> = withContext(io) {
        when (val r = call { api.connectStart() }) {
            is ApiResult.Success -> {
                val domain = r.data.toDomain()
                store.savePendingOauth(domain.state, domain.nonce)
                ApiResult.Success(domain)
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

    override suspend fun completeConnect(code: String, state: String): ApiResult<GoogleCalendarStatus> =
        withContext(io) {
            val pending = store.pendingOauth()
            // Validate the echoed state against the persisted value; mismatch aborts (never finalizes).
            if (pending != null && pending.state != state) {
                return@withContext ApiResult.Failure(
                    com.testlogon.android.core.model.ApiError(
                        status = 400,
                        message = STATE_MISMATCH,
                    ),
                )
            }
            when (val cb = call { api.connectCallback(code = code, state = state) }) {
                is ApiResult.Success -> {
                    store.saveConnection(active = cb.data.linked, accountEmail = cb.data.accountEmail)
                    store.clearPendingOauth()
                    refreshStatus(cachedEmail = cb.data.accountEmail)
                }
                is ApiResult.Failure -> cb
                is ApiResult.NetworkError -> cb
            }
        }

    override suspend fun refreshStatus(): ApiResult<GoogleCalendarStatus> = withContext(io) {
        refreshStatus(cachedEmail = store.cachedConnection()?.accountEmail)
    }

    private suspend fun refreshStatus(cachedEmail: String?): ApiResult<GoogleCalendarStatus> =
        when (val r = call { api.status() }) {
            is ApiResult.Success -> {
                val status = r.data.toDomain(cachedAccountEmail = cachedEmail)
                store.saveConnection(active = status.connectionActive, accountEmail = cachedEmail)
                ApiResult.Success(status)
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }

    override suspend fun cachedStatus(): GoogleCalendarStatus? = withContext(io) {
        store.cachedConnection()?.let { cached ->
            GoogleCalendarStatus(
                connectionActive = cached.connectionActive,
                syncEnabled = false,
                writebackEnabled = false,
                reauthRequired = false,
                syncHealth = "unknown",
                lastSyncStatus = "never_synced",
                lastSyncAtUtc = "",
                rolloutMode = "off",
                rolloutPercent = 0,
                inRolloutCohort = false,
                accountEmail = cached.accountEmail,
            )
        }
    }

    override suspend fun pendingOauthState(): String? = withContext(io) { store.pendingOauth()?.state }

    override suspend fun clearPendingOauth() = withContext(io) { store.clearPendingOauth() }

    override suspend fun listProviderCalendars(): ApiResult<List<ProviderCalendar>> = withContext(io) {
        call { api.listProviderCalendars() }.map { dto -> dto.calendars.map { it.toDomain() } }
    }

    override suspend fun createMapping(
        internalCalendarId: String,
        googleCalendarId: String,
    ): ApiResult<ProviderCalendar> = withContext(io) {
        call {
            api.createMapping(
                MappingCreateDto(
                    internalCalendarId = internalCalendarId,
                    googleCalendarId = googleCalendarId,
                ),
            )
        }.map { it.toProviderCalendar() }
    }

    override suspend fun runSync(mode: String): ApiResult<Unit> = withContext(io) {
        call { api.runSync(mode) }.map { }
    }

    override suspend fun disconnect(connectionId: String?): ApiResult<Unit> = withContext(io) {
        when (val r = call { api.disconnect(connectionId) }) {
            is ApiResult.Success -> {
                store.clearConnection()
                ApiResult.Success(Unit)
            }
            is ApiResult.Failure -> r
            is ApiResult.NetworkError -> r
        }
    }

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
        const val STATE_MISMATCH = "Connection failed, please try again"
    }
}
