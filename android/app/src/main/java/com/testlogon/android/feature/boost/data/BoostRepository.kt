package com.testlogon.android.feature.boost.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.ads.BoostCancelResult
import com.testlogon.android.core.model.ads.BoostSpend
import com.testlogon.android.core.model.ads.ContentBoost
import com.testlogon.android.core.network.ads.ContentBoostApi
import com.testlogon.android.core.network.ads.ContentBoostCreateIn
import com.testlogon.android.core.network.error.ApiErrorParser
import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-364 - data layer for the content-boost surface.
 *
 * REUSE: every call REUSES the AND-364 [ContentBoostApi] (RAW DTOs); this repository wraps each call in
 * [call] and maps the DTO to the core-model domain BEFORE the typed [ApiResult] (mirrors AND-353
 * OrgsRepository). There is NO Room / disk persistence here and NO poll loop (the bounded poll lives in
 * the ViewModel; the small status cache is a separate DataStore seam, [BoostStatusCache]).
 *
 * NO payment-method / ads-account selection is involved: create sends EXACTLY
 * {content_type, content_id, budget_cents, duration_seconds} and the server charges the wallet up-front.
 */
interface BoostRepository {

    /**
     * POST a new boost. Body is {content_type, content_id, budget_cents, duration_seconds}; the server
     * charges the wallet up-front and returns the created [ContentBoost].
     */
    suspend fun createBoost(
        contentType: String,
        contentId: String,
        budgetCents: Long,
        durationSeconds: Long,
    ): ApiResult<ContentBoost>

    /** GET one boost's current state (mapped). Idempotent GET. */
    suspend fun getBoost(boostId: String): ApiResult<ContentBoost>

    /** GET a boost's spend snapshot (mapped). Idempotent GET. */
    suspend fun getSpend(boostId: String): ApiResult<BoostSpend>

    /** POST a cancel of an ACTIVE boost; returns the refund result (mapped). */
    suspend fun cancelBoost(boostId: String): ApiResult<BoostCancelResult>

    /** GET the caller's boosts (mapped). Idempotent GET. Used by the boost list/detail screens. */
    suspend fun listBoosts(): ApiResult<List<ContentBoost>>
}

@Singleton
class BoostRepositoryImpl @Inject constructor(
    private val api: ContentBoostApi,
    private val errorParser: ApiErrorParser,
) : BoostRepository {

    override suspend fun createBoost(
        contentType: String,
        contentId: String,
        budgetCents: Long,
        durationSeconds: Long,
    ): ApiResult<ContentBoost> = withContext(Dispatchers.IO) {
        call {
            api.createBoost(
                ContentBoostCreateIn(
                    contentType = contentType,
                    contentId = contentId,
                    budgetCents = budgetCents,
                    durationSeconds = durationSeconds,
                ),
            ).toDomain()
        }
    }

    override suspend fun getBoost(boostId: String): ApiResult<ContentBoost> =
        withContext(Dispatchers.IO) {
            call { api.getBoost(boostId).toDomain() }
        }

    override suspend fun getSpend(boostId: String): ApiResult<BoostSpend> =
        withContext(Dispatchers.IO) {
            call { api.getBoostSpend(boostId).toDomain() }
        }

    override suspend fun cancelBoost(boostId: String): ApiResult<BoostCancelResult> =
        withContext(Dispatchers.IO) {
            call { api.cancelBoost(boostId).toDomain() }
        }

    override suspend fun listBoosts(): ApiResult<List<ContentBoost>> =
        withContext(Dispatchers.IO) {
            call { api.listBoosts().all.map { it.toDomain() } }
        }

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser], preserving the
     * status); malformed JSON -> Failure(parse); transport failures -> NetworkError. The
     * JsonEncodingException catch precedes the IOException catch (it is an IOException subtype).
     * Cancellation is re-thrown. Mirrors AND-353 OrgsRepository.
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
}

/**
 * AND-364 - Hilt wiring for the boost feature. Binds the repository seam to its default impl (which
 * consumes the AND-364 [ContentBoostApi] + the shared [ApiErrorParser]). The [BoostStatusCache] binding
 * lives next to the store. NO new endpoint module, migration, or dependency is added here.
 */
@Module
@InstallIn(SingletonComponent::class)
abstract class BoostDataModule {

    @Binds
    @Singleton
    abstract fun bindBoostRepository(impl: BoostRepositoryImpl): BoostRepository
}
