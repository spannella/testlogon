package com.testlogon.android.data.locale

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.locale.LocalePreference
import com.testlogon.android.core.model.locale.LocaleSource
import com.testlogon.android.core.model.locale.LocaleTag
import com.testlogon.android.core.model.locale.SupportedLocales
import com.testlogon.android.core.network.LocalePreferencesStore
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-113/AND-114 — single source of truth for the user's effective locale, reconciling the device
 * default, a locally cached value, an explicit in-app override, and the server preference
 * (GET/PUT /ui/i18n/locale).
 *
 * The persisted state lives in [LocalePreferencesStore]; this repository layers the precedence
 * ladder (FR-1), the server reconciliation (FR-3), the optimistic device->server write + pending
 * retry queue (FR-4/FR-6), and FR-5 supported-locale gating on top. All resolved tags are passed
 * through [SupportedLocales.normalize] so an unsupported value downgrades to its base language then
 * the default, never crashes the UI.
 */
interface LocaleRepository {
    /** Cold flow of the resolved preference; recomputes whenever the persisted state changes. */
    val preference: Flow<LocalePreference>

    /** Synchronous snapshot of the resolved preference (for the launch-time bootstrap). */
    fun currentPreference(): LocalePreference

    /** Reconcile against a freshly fetched server value (post-login / on resume). */
    suspend fun syncFromServer(serverLocale: LocaleTag?): ApiResult<LocalePreference>

    /**
     * Fetch the server locale then reconcile. Convenience used by the app bootstrap so callers don't
     * touch [LocaleApi] directly. Network/HTTP failures are swallowed into [ApiResult] (never thrown).
     */
    suspend fun refreshFromServer(): ApiResult<LocalePreference>

    /** User-initiated change (picker): persist locally immediately, then PUT to the server (FR-4). */
    suspend fun setUserLocale(tag: LocaleTag?): ApiResult<LocalePreference>

    /** Retry a previously failed device->server write (FR-6). No-op when nothing is pending. */
    suspend fun flushPendingSync(): ApiResult<Unit>

    /** Clears the in-app override so the server value can win again. */
    fun clearOverride()
}

@Singleton
class LocaleRepositoryImpl @Inject constructor(
    private val api: LocaleApi,
    private val store: LocalePreferencesStore,
    private val deviceLocaleProvider: DeviceLocaleProvider,
    private val errorParser: ApiErrorParser,
) : LocaleRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override val preference: Flow<LocalePreference> = store.state.map { resolve() }

    override fun currentPreference(): LocalePreference = resolve()

    override suspend fun syncFromServer(serverLocale: LocaleTag?): ApiResult<LocalePreference> {
        val state = store.current()
        // An explicit in-app override is never clobbered by the server.
        if (state.override) return ApiResult.Success(resolve())

        val normalized = SupportedLocales.normalize(serverLocale)
        if (normalized != null && normalized.value != state.tag) {
            store.setServerValue(normalized.value)
        }
        return ApiResult.Success(resolve())
    }

    override suspend fun refreshFromServer(): ApiResult<LocalePreference> = withContext(io) {
        when (val fetched = apiCall { api.getUserLocale() }) {
            is ApiResult.Success -> syncFromServer(LocaleTag(fetched.data.locale))
            is ApiResult.Failure -> fetched
            is ApiResult.NetworkError -> fetched
        }
    }

    override suspend fun setUserLocale(tag: LocaleTag?): ApiResult<LocalePreference> =
        withContext(io) {
            // "System default" == null tag: clear the override and follow the device locale.
            if (tag == null) {
                store.setUserChoice(tag = null, pendingSync = false)
                return@withContext ApiResult.Success(resolve())
            }
            val normalized = SupportedLocales.normalize(tag) ?: SupportedLocales.DEFAULT
            // Optimistic local write first (override + pending), so the UI switches instantly.
            store.setUserChoice(tag = normalized.value, pendingSync = true)
            val result = apiCall { api.saveUserLocale(SaveLocaleRequest(normalized.value)) }
            if (result is ApiResult.Success) store.clearPendingSync()
            // On failure the optimistic value + pending flag are kept for a later flush (FR-6).
            when (result) {
                is ApiResult.Success -> ApiResult.Success(resolve())
                is ApiResult.Failure -> result
                is ApiResult.NetworkError -> result
            }
        }

    override suspend fun flushPendingSync(): ApiResult<Unit> = withContext(io) {
        val state = store.current()
        val tag = state.tag
        if (!state.pendingSync || tag.isNullOrBlank()) return@withContext ApiResult.Success(Unit)
        when (val result = apiCall { api.saveUserLocale(SaveLocaleRequest(tag)) }) {
            is ApiResult.Success -> {
                store.clearPendingSync()
                ApiResult.Success(Unit)
            }
            is ApiResult.Failure -> result
            is ApiResult.NetworkError -> result
        }
    }

    override fun clearOverride() = store.clearOverride()

    /**
     * The FR-1 precedence ladder: in-app override -> cached value -> device default -> app default.
     * (The server value, once adopted, is stored as the cached tag, so it participates as CACHE.)
     */
    private fun resolve(): LocalePreference {
        val state = store.current()
        val cachedTag = state.tag?.let { SupportedLocales.normalize(LocaleTag(it)) }

        return when {
            state.override && cachedTag != null ->
                LocalePreference(cachedTag, LocaleSource.IN_APP_OVERRIDE, state.pendingSync)

            cachedTag != null ->
                LocalePreference(cachedTag, LocaleSource.CACHE, state.pendingSync)

            else -> {
                val device = SupportedLocales.normalize(deviceLocaleProvider.deviceLocaleTag())
                if (device != null) {
                    LocalePreference(device, LocaleSource.DEVICE, state.pendingSync)
                } else {
                    LocalePreference(SupportedLocales.DEFAULT, LocaleSource.DEFAULT, state.pendingSync)
                }
            }
        }
    }

    private suspend fun <T> apiCall(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
