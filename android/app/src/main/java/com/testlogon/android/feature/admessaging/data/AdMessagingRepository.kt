package com.testlogon.android.feature.admessaging.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.admessaging.AdMassDmCreateReq
import com.testlogon.android.core.network.admessaging.AdMessageApproveReq
import com.testlogon.android.core.network.admessaging.AdMessagingApi
import com.testlogon.android.core.network.admessaging.AdMessageOfferReq
import com.testlogon.android.core.network.admessaging.AdMessagePrefsReq
import com.testlogon.android.core.network.admessaging.AdMessageRejectReq
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ADV2-E5 (F5+F6) — data layer for the ad-messaging surface.
 *
 * F5 WRITE: advertiser [createOffer]; creator [approve] / [reject] from the review queue. F5 READ: [inbox]
 * (creators pending queue) + [outbox] (advertisers own). F6: [audiencePreview] (reachable count) +
 * [sendMassDm] (compose+send AS the advertiser). SHARED recipient engagement: [reportOpen] / [reportClick]
 * (best-effort, idempotent server-side) + the per-user opt-out [getAdPreferences] / [setAdPreferences].
 *
 * All folded into [ApiResult] via [call]; the mutations are NON-idempotent (the VM owns confirm-then-POST,
 * in-flight gating and the NO-auto-retry policy). The open/click reporters are best-effort / swallow every
 * failure — a billing beacon must never disturb the messaging experience.
 */
interface AdMessagingRepository {

    suspend fun createOffer(req: AdMessageOfferReq): ApiResult<AdMessageOffer>

    suspend fun inbox(): ApiResult<List<AdMessageOffer>>

    suspend fun outbox(): ApiResult<List<AdMessageOffer>>

    suspend fun approve(offerId: String, bodyOverride: String = ""): ApiResult<AdMessageSend>

    suspend fun reject(offerId: String, reason: String = ""): ApiResult<Unit>

    suspend fun audiencePreview(): ApiResult<AdDmAudience>

    suspend fun sendMassDm(req: AdMassDmCreateReq): ApiResult<AdMessageSend>

    suspend fun getAdPreferences(): ApiResult<Boolean>

    suspend fun setAdPreferences(allowAdMessages: Boolean): ApiResult<Boolean>

    /** Best-effort: report the recipient OPENED an ad message (+5c open surcharge, once). */
    suspend fun reportOpen(adClickId: String)

    /** Best-effort: report the recipient tapped the CTA (+10c click surcharge, once). */
    suspend fun reportClick(adClickId: String)
}

@Singleton
class AdMessagingRepositoryImpl @Inject constructor(
    private val api: AdMessagingApi,
    private val errorParser: ApiErrorParser,
) : AdMessagingRepository {

    override suspend fun createOffer(req: AdMessageOfferReq): ApiResult<AdMessageOffer> =
        withContext(Dispatchers.IO) { call { api.createOffer(req).toDomain() } }

    override suspend fun inbox(): ApiResult<List<AdMessageOffer>> =
        withContext(Dispatchers.IO) { call { api.inbox().offers.map { it.toDomain() } } }

    override suspend fun outbox(): ApiResult<List<AdMessageOffer>> =
        withContext(Dispatchers.IO) { call { api.outbox().offers.map { it.toDomain() } } }

    override suspend fun approve(offerId: String, bodyOverride: String): ApiResult<AdMessageSend> =
        withContext(Dispatchers.IO) { call { api.approve(offerId, AdMessageApproveReq(body = bodyOverride)).toDomain() } }

    override suspend fun reject(offerId: String, reason: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) { call { api.reject(offerId, AdMessageRejectReq(reason = reason)); Unit } }

    override suspend fun audiencePreview(): ApiResult<AdDmAudience> =
        withContext(Dispatchers.IO) { call { api.audiencePreview().toDomain() } }

    override suspend fun sendMassDm(req: AdMassDmCreateReq): ApiResult<AdMessageSend> =
        withContext(Dispatchers.IO) { call { api.createMassDm(req).toDomain() } }

    override suspend fun getAdPreferences(): ApiResult<Boolean> =
        withContext(Dispatchers.IO) { call { api.getAdPreferences().allowAdMessages } }

    override suspend fun setAdPreferences(allowAdMessages: Boolean): ApiResult<Boolean> =
        withContext(Dispatchers.IO) { call { api.setAdPreferences(AdMessagePrefsReq(allowAdMessages = allowAdMessages)).allowAdMessages } }

    override suspend fun reportOpen(adClickId: String) = fire { api.reportOpen(adClickId) }

    override suspend fun reportClick(adClickId: String) = fire { api.reportClick(adClickId) }

    /** Fire-and-forget engagement beacon: swallow every failure (never surface to the reader). */
    private suspend fun fire(block: suspend () -> Any?) {
        try {
            withContext(Dispatchers.IO) { block() }
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            // best-effort beacon: the money path settles server-side regardless.
        }
    }

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
