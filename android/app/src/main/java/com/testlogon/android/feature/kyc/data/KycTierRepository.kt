package com.testlogon.android.feature.kyc.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.kyc.KycApi
import com.testlogon.android.feature.kyc.model.MAX_TIER
import com.testlogon.android.feature.kyc.model.TierEvaluation
import com.testlogon.android.feature.kyc.model.TierStatus
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import okhttp3.ResponseBody
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import java.time.Instant
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-320 — THIN data layer for the KYC Tier Status surface.
 *
 * Consumes AND-319's [KycApi] tier endpoints, which return [okhttp3.ResponseBody] (the bodies are
 * undocumented on the backend, so AND-319 deliberately leaves them untyped). THIS feature owns parsing:
 * the injected shared [Moshi] (the core-network NetworkModule singleton) parses each body string into the
 * feature-local DTOs ([TierDetailsDto] / [TierRequirementsDto]) via reflective adapters built with
 * moshi.adapter(...). DTOs map to the domain BEFORE the typed [ApiResult] (mirrors LayoutRepositoryImpl).
 *
 * There is NO @IoDispatcher qualifier in this project, so IO work runs under Dispatchers.IO directly.
 *
 * The last snapshot is cached in [KycTierStore] (DataStore) for an instant offline-friendly render;
 * [observeTierStatus] exposes that cache as a Flow.
 */
interface KycTierRepository {

    /** Observe the last cached [TierStatus] (DataStore-backed; emits null until first persist). */
    fun observeTierStatus(): Flow<TierStatus?>

    /** GET tiers/me (+ requirements for the next target) -> persist -> typed result. */
    suspend fun refreshTierStatus(): ApiResult<TierStatus>

    /** POST evaluate -> re-fetch requirements for the new target -> persist -> typed result + promoted flag. */
    suspend fun evaluate(): ApiResult<TierEvaluation>
}

@Singleton
class KycTierRepositoryImpl @Inject constructor(
    private val api: KycApi,
    moshi: Moshi,
    private val store: KycTierStore,
    private val errorParser: ApiErrorParser,
) : KycTierRepository {

    private val detailsAdapter = moshi.adapter(TierDetailsDto::class.java)
    private val requirementsAdapter = moshi.adapter(TierRequirementsDto::class.java)

    /** Clock seam (overridable in tests). Stamps [TierStatus.asOf]. */
    internal var now: () -> Instant = Instant::now

    override fun observeTierStatus(): Flow<TierStatus?> = store.observe()

    override suspend fun refreshTierStatus(): ApiResult<TierStatus> = withContext(Dispatchers.IO) {
        call {
            val details = parseDetails(api.tierMe())
            val requirements = fetchRequirementsFor(details.current_tier)
            details.toTierStatus(requirements, asOf = now())
        }.also { persistOnSuccess(it) }
    }

    override suspend fun evaluate(): ApiResult<TierEvaluation> = withContext(Dispatchers.IO) {
        val prev = store.read()?.current?.level
        val result = call {
            val details = parseDetails(api.evaluateTier())
            val requirements = fetchRequirementsFor(details.current_tier)
            val status = details.toTierStatus(requirements, asOf = now())
            // Promotion is DERIVED: the new current tier exceeds the previously-known one.
            val promoted = prev != null && details.current_tier > prev
            TierEvaluation(tierStatus = status, promoted = promoted)
        }
        if (result is ApiResult.Success) store.write(result.data.tierStatus)
        result
    }

    /**
     * Fetches + parses the requirements for the tier ABOVE [currentTier]. The path segment is the target
     * tier as an INTEGER string (min(current + 1, [MAX_TIER])). At [MAX_TIER] there is no target, so the
     * requirements call is SKIPPED and null is returned.
     */
    private suspend fun fetchRequirementsFor(currentTier: Int): TierRequirementsDto? {
        if (currentTier >= MAX_TIER) return null
        val target = (currentTier + 1).coerceAtMost(MAX_TIER)
        return parseRequirements(api.tierRequirements(target.toString()))
    }

    private fun parseDetails(body: ResponseBody): TierDetailsDto =
        detailsAdapter.fromJson(body.string()) ?: throw JsonDataException("empty tier details body")

    private fun parseRequirements(body: ResponseBody): TierRequirementsDto =
        requirementsAdapter.fromJson(body.string()) ?: throw JsonDataException("empty requirements body")

    private suspend fun persistOnSuccess(result: ApiResult<TierStatus>) {
        if (result is ApiResult.Success) store.write(result.data)
    }

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser]); malformed JSON ->
     * Failure(parse); transport failures -> NetworkError. The JsonEncodingException catch precedes the
     * IOException catch (it is an IOException subtype). Cancellation is re-thrown. Mirrors
     * LayoutRepositoryImpl.call.
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
