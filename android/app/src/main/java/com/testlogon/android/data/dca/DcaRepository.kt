package com.testlogon.android.data.dca

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
 * Data layer for the DCA / RECURRING-BUYS surface over [DcaApi].
 *
 * READS ([plans], [history]) DEGRADE on a 404 / HTTP error to an honest EMPTY value so the screen shows a
 * truthful "no plans yet / pending backend runner" state rather than an error; a real transport failure
 * surfaces as [ApiResult.NetworkError] so the UI can offer retry. MUTATIONS ([createPlan], [pause],
 * [resume], [cancel], [runNow]) pass failures through as [ApiResult.Failure]/[ApiResult.NetworkError] — a
 * rejection (or undeployed 404) surfaces as a clear error and NEVER a silent success. CancellationException
 * is always re-thrown.
 */
interface DcaRepository {
    suspend fun plans(): ApiResult<List<DcaPlan>>
    suspend fun createPlan(request: CreateDcaPlanRequestDto): ApiResult<DcaPlan>
    suspend fun pause(planId: String): ApiResult<DcaPlan>
    suspend fun resume(planId: String): ApiResult<DcaPlan>
    suspend fun cancel(planId: String): ApiResult<DcaPlan>
    suspend fun history(planId: String): ApiResult<List<DcaRun>>
    suspend fun runNow(planId: String): ApiResult<Unit>
}

@Singleton
class DcaRepositoryImpl @Inject constructor(
    private val api: DcaApi,
    private val errorParser: ApiErrorParser,
) : DcaRepository {
    private val io: CoroutineDispatcher = Dispatchers.IO

    /** All plans. A 404 (undeployed runner) degrades to an empty list; network errors surface. */
    override suspend fun plans(): ApiResult<List<DcaPlan>> = withContext(io) {
        try {
            ApiResult.Success((api.plans().plans ?: emptyList()).mapNotNull { it.toDomain() })
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Success(emptyList())
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }

    /** History for a plan. A 404 degrades to an empty list; network errors surface. */
    override suspend fun history(planId: String): ApiResult<List<DcaRun>> = withContext(io) {
        try {
            ApiResult.Success((api.history(planId).runs ?: emptyList()).mapNotNull { it.toDomain() })
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Success(emptyList())
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }

    override suspend fun createPlan(request: CreateDcaPlanRequestDto): ApiResult<DcaPlan> = call {
        api.createPlan(request).toDomain() ?: error("Malformed plan in response")
    }

    override suspend fun pause(planId: String): ApiResult<DcaPlan> = call {
        api.pause(planId).toDomain() ?: error("Malformed plan in response")
    }

    override suspend fun resume(planId: String): ApiResult<DcaPlan> = call {
        api.resume(planId).toDomain() ?: error("Malformed plan in response")
    }

    override suspend fun cancel(planId: String): ApiResult<DcaPlan> = call {
        api.cancel(planId).toDomain() ?: error("Malformed plan in response")
    }

    override suspend fun runNow(planId: String): ApiResult<Unit> = call {
        api.runNow(planId)
        Unit
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = withContext(io) {
        try {
            ApiResult.Success(block())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Failure(errorParser.from(e))
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }
}

// ---- DTO -> domain mappers ----

/** Wire timestamps are epoch SECONDS (matching the other money surfaces); the app works in millis. */
private const val SEC_TO_MS: Long = 1_000L
private fun secToMs(sec: Long?): Long? = sec?.let { it * SEC_TO_MS }

private fun DcaTargetDto.toDomain(): DcaTarget? {
    val tid = id?.trim()?.takeIf { it.isNotBlank() } ?: return null
    val kind = DcaTargetKind.fromWire(kind)
    val lbl = label?.trim()?.takeIf { it.isNotBlank() } ?: tid
    return DcaTarget(kind = kind, id = tid, label = lbl)
}

private fun DcaPlanDto.toDomain(): DcaPlan? {
    val pid = planId?.trim()?.takeIf { it.isNotBlank() } ?: return null
    val tgt = target?.toDomain() ?: return null
    return DcaPlan(
        planId = pid,
        target = tgt,
        amountCents = amountCents ?: 0L,
        frequency = DcaFrequency.fromWire(frequency),
        dayOfWeek = dayOfWeek,
        dayOfMonth = dayOfMonth,
        startTs = secToMs(startTs) ?: 0L,
        endTs = secToMs(endTs),
        totalBudgetCents = totalBudgetCents,
        funding = funding?.trim()?.takeIf { it.isNotBlank() } ?: "usd_wallet",
        status = DcaStatus.fromWire(status),
        nextRunTs = secToMs(nextRunTs),
        spentCents = spentCents ?: 0L,
        buysCount = buysCount ?: 0,
        createdTs = secToMs(createdTs) ?: 0L,
    )
}

private fun DcaRunDto.toDomain(): DcaRun? {
    val t = secToMs(ts) ?: return null
    return DcaRun(
        ts = t,
        amountCents = amountCents ?: 0L,
        filledQty = filledQty,
        priceCents = price,
        status = status?.trim()?.takeIf { it.isNotBlank() } ?: "unknown",
        note = note?.trim()?.takeIf { it.isNotBlank() },
    )
}

/** Provides [DcaApi] on the shared authenticated Retrofit + binds the repository impl. */
@Module
@InstallIn(SingletonComponent::class)
object DcaApiModule {
    @Provides
    @Singleton
    fun provideDcaApi(retrofit: Retrofit): DcaApi = retrofit.create(DcaApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class DcaDataModule {
    @Binds
    @Singleton
    abstract fun bindDcaRepository(impl: DcaRepositoryImpl): DcaRepository
}
