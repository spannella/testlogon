package com.testlogon.android.data.auth

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

/** AND-064 — MFA factor type, assigned client-side by which list endpoint returned the element. */
enum class MfaFactorType(val wire: String) {
    TOTP("totp"),
    SMS("sms"),
    EMAIL("email"),
}

/** A merged, typed enrolled MFA factor (AND-064). Destinations are masked at the UI layer. */
data class MfaDevice(
    val deviceId: String,
    val type: MfaFactorType,
    val label: String?,
    val destination: String?, // phone_e164 / email for sms/email; null for totp
    val enabled: Boolean,
    val pending: Boolean,
    val createdAtEpochSeconds: Long,
)

/** TOTP enrollment material shown once during enrollment (AND-064). Sensitive, transient. */
data class TotpEnrollment(
    val deviceId: String,
    val qrCodeUri: String,
    val secret: String,
)

/** sms/email begin AND remove/begin result (AND-064). Confirm keys on [challengeId]. */
data class DeviceChallenge(
    val challengeId: String,
    val sentTo: List<String>,
    val deviceId: String? = null,
)

/** totp/sms/email confirm result (AND-064). Recovery codes shown once if non-empty. */
data class EnrollResult(
    val ok: Boolean,
    val deviceId: String?,
    val recoveryCodes: List<String>,
)

/**
 * AND-064 — manages enrolled MFA devices on top of [AuthApi]. Lists fan out to the three per-type
 * endpoints (merged + tagged client-side); enroll/remove are non-idempotent POSTs that are never
 * auto-retried. All failures fold into [ApiResult] via [ApiErrorParser]; no secrets/codes leak.
 */
interface MfaDeviceRepository {
    /** Fan-out to the three per-type list endpoints; merge + tag type + sort (TOTP first, then newest). */
    suspend fun list(): ApiResult<List<MfaDevice>>

    suspend fun beginTotp(label: String? = null): ApiResult<TotpEnrollment>
    suspend fun confirmTotp(deviceId: String, totpCode: String, totpCode2: String): ApiResult<EnrollResult>

    /** sms/email enroll begin; [destination] is a phone_e164 (sms) or email (email). */
    suspend fun beginCode(type: MfaFactorType, destination: String, label: String? = null): ApiResult<DeviceChallenge>
    suspend fun confirmCode(type: MfaFactorType, challengeId: String, code: String): ApiResult<EnrollResult>

    /** TOTP remove — single-step with a re-auth [totpCode]. */
    suspend fun removeTotp(deviceId: String, totpCode: String): ApiResult<Unit>

    /** sms/email remove begin — delivers a remove-challenge code. */
    suspend fun beginRemoveCode(type: MfaFactorType, deviceId: String): ApiResult<DeviceChallenge>
    suspend fun confirmRemoveCode(type: MfaFactorType, challengeId: String, code: String): ApiResult<Unit>
}

@Singleton
class MfaDeviceRepositoryImpl @Inject constructor(
    private val api: AuthApi,
    private val errorParser: ApiErrorParser,
) : MfaDeviceRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun list(): ApiResult<List<MfaDevice>> = withContext(io) {
        coroutineScope {
            val totp = async { apiCall { api.listTotpDevices() } }
            val sms = async { apiCall { api.listSmsDevices() } }
            val email = async { apiCall { api.listEmailDevices() } }

            val totpRes = totp.await()
            val smsRes = sms.await()
            val emailRes = email.await()

            // Surface a hard failure only if every list failed; otherwise return a merged (possibly
            // partial) list so one flaky endpoint doesn't blank the screen.
            val merged = buildList {
                (totpRes as? ApiResult.Success)?.data?.devices?.forEach { add(it.toDomain()) }
                (smsRes as? ApiResult.Success)?.data?.devices?.forEach { add(it.toDomain()) }
                (emailRes as? ApiResult.Success)?.data?.devices?.forEach { add(it.toDomain()) }
            }.sortedWith(compareBy({ it.type.ordinal }, { -it.createdAtEpochSeconds }))

            val anySuccess = totpRes is ApiResult.Success ||
                smsRes is ApiResult.Success ||
                emailRes is ApiResult.Success
            if (anySuccess) {
                ApiResult.Success(merged)
            } else {
                // All three failed; propagate the first failure verbatim.
                totpRes.asFailureOf() ?: smsRes.asFailureOf() ?: emailRes.asFailureOf()
                    ?: ApiResult.Success(emptyList())
            }
        }
    }

    override suspend fun beginTotp(label: String?): ApiResult<TotpEnrollment> =
        apiCall { api.beginTotpDevice(TotpDeviceBeginReq(label = label)) }
            .mapResult { TotpEnrollment(deviceId = it.deviceId, qrCodeUri = it.qrCodeUri, secret = it.secret) }

    override suspend fun confirmTotp(
        deviceId: String,
        totpCode: String,
        totpCode2: String,
    ): ApiResult<EnrollResult> =
        apiCall {
            api.confirmTotpDevice(
                TotpDeviceConfirmReq(deviceId = deviceId, totpCode = totpCode.trim(), totpCode2 = totpCode2.trim()),
            )
        }.mapResult { it.toDomain() }

    override suspend fun beginCode(
        type: MfaFactorType,
        destination: String,
        label: String?,
    ): ApiResult<DeviceChallenge> = when (type) {
        MfaFactorType.SMS ->
            apiCall { api.beginSmsDevice(SmsDeviceBeginReq(phoneE164 = destination.trim(), label = label)) }
                .mapResult { it.toDomain() }
        MfaFactorType.EMAIL ->
            apiCall { api.beginEmailDevice(EmailDeviceBeginReq(email = destination.trim(), label = label)) }
                .mapResult { it.toDomain() }
        MfaFactorType.TOTP ->
            ApiResult.Failure(
                com.testlogon.android.core.model.ApiError(0, "TOTP uses a different enroll flow.", "wrong_type"),
            )
    }

    override suspend fun confirmCode(
        type: MfaFactorType,
        challengeId: String,
        code: String,
    ): ApiResult<EnrollResult> =
        apiCall {
            api.confirmCodeDevice(type.wire, DeviceConfirmReq(challengeId = challengeId, code = code.trim()))
        }.mapResult { it.toDomain() }

    override suspend fun removeTotp(deviceId: String, totpCode: String): ApiResult<Unit> =
        apiCall { api.removeTotpDevice(deviceId, TotpDeviceRemoveReq(totpCode = totpCode.trim())) }
            .mapResult { }

    override suspend fun beginRemoveCode(type: MfaFactorType, deviceId: String): ApiResult<DeviceChallenge> =
        apiCall { api.beginRemoveCodeDevice(type.wire, deviceId) }.mapResult { it.toDomain() }

    override suspend fun confirmRemoveCode(
        type: MfaFactorType,
        challengeId: String,
        code: String,
    ): ApiResult<Unit> =
        apiCall {
            api.confirmRemoveCodeDevice(type.wire, DeviceConfirmReq(challengeId = challengeId, code = code.trim()))
        }.mapResult { }

    // ── mappers ──

    private fun TotpDeviceDto.toDomain() = MfaDevice(
        deviceId = deviceId,
        type = MfaFactorType.TOTP,
        label = label,
        destination = null,
        enabled = enabled,
        pending = false,
        createdAtEpochSeconds = createdAt,
    )

    private fun SmsDeviceDto.toDomain() = MfaDevice(
        deviceId = deviceId,
        type = MfaFactorType.SMS,
        label = label,
        destination = phoneE164,
        enabled = enabled,
        pending = pending,
        createdAtEpochSeconds = createdAt,
    )

    private fun EmailDeviceDto.toDomain() = MfaDevice(
        deviceId = deviceId,
        type = MfaFactorType.EMAIL,
        label = label,
        destination = email,
        enabled = enabled,
        pending = pending,
        createdAtEpochSeconds = createdAt,
    )

    private fun DeviceChallengeDto.toDomain() = DeviceChallenge(
        challengeId = challengeId,
        sentTo = sentTo,
        deviceId = smsDeviceId ?: emailDeviceId,
    )

    private fun EnrollResultDto.toDomain() = EnrollResult(
        ok = ok,
        deviceId = smsDeviceId ?: emailDeviceId,
        recoveryCodes = recoveryCodes,
    )

    private fun <T> ApiResult<T>.asFailureOf(): ApiResult<List<MfaDevice>>? = when (this) {
        is ApiResult.Failure -> this
        is ApiResult.NetworkError -> this
        is ApiResult.Success -> null
    }

    private fun <T, R> ApiResult<T>.mapResult(transform: (T) -> R): ApiResult<R> = when (this) {
        is ApiResult.Success -> ApiResult.Success(transform(data))
        is ApiResult.Failure -> this
        is ApiResult.NetworkError -> this
    }

    private suspend fun <T> apiCall(block: suspend () -> T): ApiResult<T> =
        try {
            ApiResult.Success(block())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Failure(errorParser.from(e))
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is java.net.SocketTimeoutException)
        }
}
