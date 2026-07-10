package com.testlogon.android.data.preferences

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Retrofit
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * D2 - resolved per-event PUSH preference state. [defaults] is the server's default-ON transactional
 * set; [optOut] is which of those the user turned OFF; [explicitOptIn] is opt-in for non-default events.
 */
data class PushEventPrefs(
    val explicitOptIn: Set<String>,
    val optOut: Set<String>,
    val defaults: Set<String>,
) {
    /** Push on iff (default-ON and not opted-out) OR (explicitly opted-in). */
    fun isPushEnabled(event: String): Boolean =
        if (event in defaults) event !in optOut else event in explicitOptIn

    fun isDefaultOn(event: String): Boolean = event in defaults

    /** Returns the new state after toggling [event] to [enabled], preserving the opt-in/opt-out model. */
    fun withToggle(event: String, enabled: Boolean): PushEventPrefs = when {
        event in defaults ->
            copy(optOut = if (enabled) optOut - event else optOut + event)
        else ->
            copy(explicitOptIn = if (enabled) explicitOptIn + event else explicitOptIn - event)
    }
}

interface PushEventPrefsRepository {
    suspend fun get(): ApiResult<PushEventPrefs>
    suspend fun save(prefs: PushEventPrefs): ApiResult<PushEventPrefs>
}

@Singleton
class PushEventPrefsRepositoryImpl @Inject constructor(
    private val api: PushEventPrefsApi,
    private val errorParser: ApiErrorParser,
) : PushEventPrefsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun get(): ApiResult<PushEventPrefs> = withContext(io) {
        apiCall { api.getPushPrefs().toDomain() }
    }

    override suspend fun save(prefs: PushEventPrefs): ApiResult<PushEventPrefs> = withContext(io) {
        apiCall {
            api.setPushPrefs(
                PushPrefsUpdateDto(
                    pushEventTypes = prefs.explicitOptIn.toList(),
                    pushOptOutEventTypes = prefs.optOut.toList(),
                ),
            ).toDomain(defaultsFallback = prefs.defaults)
        }
    }

    private fun PushPrefsDto.toDomain(defaultsFallback: Set<String> = emptySet()): PushEventPrefs =
        PushEventPrefs(
            explicitOptIn = pushEventTypes.toSet(),
            optOut = pushOptOutEventTypes.toSet(),
            // The POST response echoes the alert-prefs dict (no default list); carry the known defaults.
            defaults = defaultPushEventTypes.toSet().ifEmpty { defaultsFallback },
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

/** D2 - provides [PushEventPrefsApi] on the shared Retrofit and binds the repository. */
@Module
@InstallIn(SingletonComponent::class)
object PushEventPrefsApiModule {
    @Provides
    @Singleton
    fun providePushEventPrefsApi(retrofit: Retrofit): PushEventPrefsApi =
        retrofit.create(PushEventPrefsApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class PushEventPrefsDataModule {
    @Binds
    @Singleton
    abstract fun bindPushEventPrefsRepository(impl: PushEventPrefsRepositoryImpl): PushEventPrefsRepository
}
