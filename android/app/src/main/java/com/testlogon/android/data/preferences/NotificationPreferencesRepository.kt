package com.testlogon.android.data.preferences

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.NotificationTypePreference
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
 * AND-080 — notification (alert-type) preferences data layer over [NotificationPreferencesApi].
 *
 * `getTypePreferences` decodes the untyped GET tolerantly into domain types. `updateTypePreference`
 * POSTs one `AlertTypePreferenceUpdate`; the POST response is untyped (`200: {}`), so on success it
 * re-GETs for authoritative server state (reconcile-by-re-GET).
 */
interface NotificationPreferencesRepository {
    suspend fun getTypePreferences(): ApiResult<List<NotificationTypePreference>>
    suspend fun updateTypePreference(
        pref: NotificationTypePreference,
    ): ApiResult<List<NotificationTypePreference>>
}

@Singleton
class NotificationPreferencesRepositoryImpl @Inject constructor(
    private val api: NotificationPreferencesApi,
    private val errorParser: ApiErrorParser,
) : NotificationPreferencesRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun getTypePreferences(): ApiResult<List<NotificationTypePreference>> =
        withContext(io) {
            apiCall { api.getTypePreferences().entries().mapNotNull { it.toDomainOrNull() } }
        }

    override suspend fun updateTypePreference(
        pref: NotificationTypePreference,
    ): ApiResult<List<NotificationTypePreference>> = withContext(io) {
        when (val save = apiCall { api.updateTypePreference(pref.toUpdateDto()) }) {
            is ApiResult.Success ->
                apiCall { api.getTypePreferences().entries().mapNotNull { it.toDomainOrNull() } }
            is ApiResult.Failure -> save
            is ApiResult.NetworkError -> save
        }
    }

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
