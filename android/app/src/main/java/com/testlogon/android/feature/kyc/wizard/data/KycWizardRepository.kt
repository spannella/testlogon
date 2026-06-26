package com.testlogon.android.feature.kyc.wizard.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.kyc.KycCaseCreateRequest
import com.testlogon.android.core.model.kyc.KycVerifyConfirmRequestDto
import com.testlogon.android.core.model.kyc.KycVerifyEmailStartRequestDto
import com.testlogon.android.core.model.kyc.KycVerifyPhoneStartRequestDto
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.kyc.KycApi
import com.testlogon.android.core.network.kyc.KycVerifyApi
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/** Result of a verify START call: where the code went + the dev code (dev_mode only) to prefill. */
data class VerifyStarted(
    val sentTo: String?,
    val devCode: String?,
)

/**
 * Batch-9 (#18) - data layer for the guided KYC verification wizard.
 *
 * Wraps the new [KycVerifyApi] (email/phone start+confirm) and REUSES [KycApi.createCase] to mint the draft
 * case the ID-scanner step needs. DTOs are folded into the typed [ApiResult]: HTTP errors -> Failure (via
 * [ApiErrorParser]); transport failures -> NetworkError; cancellation is re-thrown. No poll loops.
 */
interface KycWizardRepository {

    suspend fun startEmail(email: String?): ApiResult<VerifyStarted>
    suspend fun confirmEmail(code: String): ApiResult<Boolean>
    suspend fun startPhone(phone: String): ApiResult<VerifyStarted>
    suspend fun confirmPhone(code: String): ApiResult<Boolean>

    /** Creates a fresh draft KYC case and returns its id (for the ID-scanner step). */
    suspend fun createCase(): ApiResult<String>
}

@Singleton
class KycWizardRepositoryImpl @Inject constructor(
    private val verifyApi: KycVerifyApi,
    private val kycApi: KycApi,
    private val errorParser: ApiErrorParser,
) : KycWizardRepository {

    override suspend fun startEmail(email: String?): ApiResult<VerifyStarted> = io {
        val out = verifyApi.startEmail(KycVerifyEmailStartRequestDto(email = email?.takeIf { it.isNotBlank() }))
        VerifyStarted(sentTo = out.target, devCode = out.dev_code)
    }

    override suspend fun confirmEmail(code: String): ApiResult<Boolean> = io {
        verifyApi.confirmEmail(KycVerifyConfirmRequestDto(code = code)).email_verified ?: true
    }

    override suspend fun startPhone(phone: String): ApiResult<VerifyStarted> = io {
        val out = verifyApi.startPhone(KycVerifyPhoneStartRequestDto(phone = phone))
        VerifyStarted(sentTo = out.target, devCode = out.dev_code)
    }

    override suspend fun confirmPhone(code: String): ApiResult<Boolean> = io {
        verifyApi.confirmPhone(KycVerifyConfirmRequestDto(code = code)).phone_verified ?: true
    }

    override suspend fun createCase(): ApiResult<String> = io {
        kycApi.createCase(KycCaseCreateRequest()).case.kyc_case_id
    }

    private suspend fun <T> io(block: suspend () -> T): ApiResult<T> = withContext(Dispatchers.IO) {
        try {
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
}
