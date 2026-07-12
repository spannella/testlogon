package com.testlogon.android.feature.settings.msgprivacy

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.msgprivacy.MessagePrivacyAllowlistEntryDto
import com.testlogon.android.core.network.msgprivacy.MessagePrivacyApi
import com.testlogon.android.core.network.msgprivacy.MessagePrivacyDto
import com.testlogon.android.core.network.msgprivacy.MessagePrivacyUpdateDto
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * TIP-B4 (TIP-404) — data layer for the caller's message-privacy (pay-to-message) settings over
 * [MessagePrivacyApi]. Read the caller's own gate, set require/min, and add/remove allowlist users.
 * Every mutation returns the fresh [MessagePrivacy] the server echoes back.
 */
interface MessagePrivacyRepository {

    /** GET the caller's own message-privacy settings. */
    suspend fun get(): ApiResult<MessagePrivacy>

    /** PUT (partial) require_tip_to_message + min_tip_cents. */
    suspend fun update(requireTipToMessage: Boolean, minTipCents: Int): ApiResult<MessagePrivacy>

    /** POST add one user_sub to the tip-free allowlist. */
    suspend fun addAllowlist(userId: String): ApiResult<MessagePrivacy>

    /** DELETE one user_sub from the tip-free allowlist. */
    suspend fun removeAllowlist(userId: String): ApiResult<MessagePrivacy>
}

@Singleton
class DefaultMessagePrivacyRepository @Inject constructor(
    private val api: MessagePrivacyApi,
    private val errorParser: ApiErrorParser,
) : MessagePrivacyRepository {

    override suspend fun get(): ApiResult<MessagePrivacy> =
        withContext(Dispatchers.IO) { call { api.get().toDomain() } }

    override suspend fun update(requireTipToMessage: Boolean, minTipCents: Int): ApiResult<MessagePrivacy> =
        withContext(Dispatchers.IO) {
            call {
                api.update(
                    MessagePrivacyUpdateDto(
                        requireTipToMessage = requireTipToMessage,
                        minTipCents = minTipCents,
                    ),
                ).toDomain()
            }
        }

    override suspend fun addAllowlist(userId: String): ApiResult<MessagePrivacy> =
        withContext(Dispatchers.IO) {
            call { api.addAllowlist(MessagePrivacyAllowlistEntryDto(userId = userId)).toDomain() }
        }

    override suspend fun removeAllowlist(userId: String): ApiResult<MessagePrivacy> =
        withContext(Dispatchers.IO) { call { api.removeAllowlist(userId).toDomain() } }

    private fun MessagePrivacyDto.toDomain(): MessagePrivacy = MessagePrivacy(
        requireTipToMessage = requireTipToMessage,
        minTipCents = minTipCents,
        tipFreeAllowlist = tipFreeAllowlist,
    )

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
