package com.testlogon.android.feature.kyc.eidv.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.kyc.KycCaseCreateRequest
import com.testlogon.android.core.model.kyc.StartEidVerificationInDto
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.kyc.KycApi
import com.testlogon.android.core.network.kyc.KycEidvApi
import com.testlogon.android.feature.kyc.eidv.model.EidStatusResult
import com.testlogon.android.feature.kyc.eidv.model.SchemeInfo
import com.testlogon.android.feature.kyc.eidv.model.StartEidSession
import com.testlogon.android.feature.kyc.eidv.model.toDomain
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-325 - data layer for the KYC electronic ID verification (eIDV) redirect flow.
 *
 * Wraps AND-325's [KycEidvApi] AND REUSES AND-319's [KycApi] (both provided by core-network's
 * KycNetworkModule). DTOs are mapped to the feature domain BEFORE the typed [ApiResult] (mirrors AND-320 /
 * AND-321 / AND-322 / AND-323 / AND-324).
 *
 * This is a REAL REST redirect-based eIDV control plane: [listSchemes] lists the available government eID
 * schemes; [ensureDraftCase] REUSES KycApi.createCase to obtain a draft case_id (case.kyc_case_id);
 * [start] opens a provider session for the chosen scheme (NON-IDEMPOTENT POST, NOT auto-retried, debounced
 * by the VM); [status] polls until an assertion appears. The screen opens the returned redirect_url
 * EXTERNALLY (ACTION_VIEW). NO PII is submitted by the app (only {scheme}); NO vendor / ML / CameraX SDK.
 */
interface EidvRepository {

    /** Lists the available government eID schemes, optionally filtered by [country]. */
    suspend fun listSchemes(country: String? = null): ApiResult<List<SchemeInfo>>

    /** Ensures a draft KYC case exists, returning its case_id. REUSES AND-319 KycApi.createCase. */
    suspend fun ensureDraftCase(): ApiResult<String>

    /** Starts an eID session for [caseId] + [scheme] (the start-request wire token). */
    suspend fun start(caseId: String, scheme: String): ApiResult<StartEidSession>

    /** Reads the current eID verification status for [caseId] (idempotent poll). */
    suspend fun status(caseId: String): ApiResult<EidStatusResult>
}

@Singleton
class EidvRepositoryImpl @Inject constructor(
    private val eidvApi: KycEidvApi,
    private val kycApi: KycApi,
    private val errorParser: ApiErrorParser,
) : EidvRepository {

    override suspend fun listSchemes(country: String?): ApiResult<List<SchemeInfo>> =
        withContext(Dispatchers.IO) {
            call { eidvApi.listSchemes(country).schemes.map { it.toDomain() } }
        }

    override suspend fun ensureDraftCase(): ApiResult<String> = withContext(Dispatchers.IO) {
        call { kycApi.createCase(KycCaseCreateRequest()).case.kyc_case_id }
    }

    override suspend fun start(caseId: String, scheme: String): ApiResult<StartEidSession> =
        withContext(Dispatchers.IO) {
            call { eidvApi.startEid(caseId, StartEidVerificationInDto(scheme = scheme)).toDomain() }
        }

    override suspend fun status(caseId: String): ApiResult<EidStatusResult> =
        withContext(Dispatchers.IO) {
            call { eidvApi.eidStatus(caseId).toDomain() }
        }

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser], preserving the status);
     * malformed JSON -> Failure(parse); transport failures -> NetworkError. The JsonEncodingException catch
     * precedes the IOException catch (it is an IOException subtype). Cancellation is re-thrown. Mirrors
     * AND-321 / AND-322 / AND-323 / AND-324.
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
