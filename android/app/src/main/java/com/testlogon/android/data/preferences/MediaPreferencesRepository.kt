package com.testlogon.android.data.preferences

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.MediaPreferences
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
 * AND-079 — call media preferences data layer over [MediaPreferencesApi], with a local
 * [MediaPreferencesStore] mirror for offline read / survive-relaunch (FR-7).
 *
 * `refresh` GETs server truth and mirrors it locally; `update` PUTs the full desired state and on
 * success mirrors the server echo. `cached` is the last-known-good for stale rendering.
 */
interface MediaPreferencesRepository {
    suspend fun refresh(): ApiResult<MediaPreferences>
    suspend fun update(prefs: MediaPreferences): ApiResult<MediaPreferences>
    fun cached(): MediaPreferences?
}

@Singleton
class MediaPreferencesRepositoryImpl @Inject constructor(
    private val api: MediaPreferencesApi,
    private val store: MediaPreferencesMirror,
    private val errorParser: ApiErrorParser,
) : MediaPreferencesRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun refresh(): ApiResult<MediaPreferences> = withContext(io) {
        apiCall { api.getMediaPreferences().toDomain() }.also { result ->
            if (result is ApiResult.Success) store.write(result.data)
        }
    }

    override suspend fun update(prefs: MediaPreferences): ApiResult<MediaPreferences> =
        withContext(io) {
            apiCall { api.saveMediaPreferences(prefs.toRequestDto()).toDomain() }.also { result ->
                if (result is ApiResult.Success) store.write(result.data)
            }
        }

    override fun cached(): MediaPreferences? = store.read()

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
