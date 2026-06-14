package com.testlogon.android.data.preferences

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.PreferencesPatch
import com.testlogon.android.core.model.UserPreferences
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
 * AND-078 — preferences data layer over [PreferencesApi].
 *
 * `getPreferences` unwraps the `{"preferences":{...}}` envelope and applies domain defaults for
 * absent keys. `updatePreferences` PATCHes the partial body (nulls omitted) — the backend answers
 * `{"ok":true}` without echoing prefs, so on success it re-GETs for authoritative server state.
 */
interface PreferencesRepository {
    suspend fun getPreferences(): ApiResult<UserPreferences>
    suspend fun updatePreferences(patch: PreferencesPatch): ApiResult<UserPreferences>
}

@Singleton
class PreferencesRepositoryImpl @Inject constructor(
    private val api: PreferencesApi,
    private val errorParser: ApiErrorParser,
) : PreferencesRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun getPreferences(): ApiResult<UserPreferences> = withContext(io) {
        apiCall { api.getPreferences().toDomain() }
    }

    override suspend fun updatePreferences(patch: PreferencesPatch): ApiResult<UserPreferences> =
        withContext(io) {
            when (val save = apiCall { api.updatePreferences(patch.toRequestDto()) }) {
                is ApiResult.Success -> apiCall { api.getPreferences().toDomain() }
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
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
