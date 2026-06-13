package com.testlogon.android.feature.signing.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.signing.CreateSignaturePacketRequest
import com.testlogon.android.core.network.signing.SigningApi
import com.testlogon.android.feature.signing.model.PacketEvent
import com.testlogon.android.feature.signing.model.SignaturePacket
import com.testlogon.android.feature.signing.model.toDomain
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-340 - data layer for the e-signature packet DETAIL surface.
 *
 * REUSE: every call REUSES AND-339's [SigningApi], which returns RAW DTOs; this repository wraps each
 * call in [call] and maps the DTO to the feature domain BEFORE the typed [ApiResult] (mirrors AND-329).
 *
 * NO LIST: there is no backend packet-list endpoint, so this repository deliberately exposes NO list /
 * browse method - the entry is load-by-id ([getPacket]) or create-a-draft ([createDraft]).
 *
 * There is NO Room / disk persistence (no migration) and NO poll loop here - refresh is driven by the
 * ViewModel.
 */
interface SignatureRepository {

    /** Reads one packet's full detail (mapped). REUSES AND-339 SigningApi.getPacket. Idempotent GET. */
    suspend fun getPacket(packetId: String): ApiResult<SignaturePacket>

    /** Reads one packet's audit events (mapped). REUSES AND-339 SigningApi.getEvents. Idempotent GET. */
    suspend fun getEvents(packetId: String): ApiResult<List<PacketEvent>>

    /**
     * Creates a draft packet from a [sourcePath] (e.g. a Files-feature file path) and returns the new
     * packet id. REUSES AND-339 SigningApi.createPacket. [originChannel] is "share" or "message".
     */
    suspend fun createDraft(
        sourcePath: String,
        originChannel: String,
        originRef: String? = null,
    ): ApiResult<String>

    /**
     * Sends a draft packet to its signers (the status-driven action for a draft SENDER). REUSES AND-339
     * SigningApi.sendPacket. NOT idempotent (a mutating POST).
     */
    suspend fun send(packetId: String): ApiResult<Unit>
}

@Singleton
class SignatureRepositoryImpl @Inject constructor(
    private val signingApi: SigningApi,
    private val errorParser: ApiErrorParser,
) : SignatureRepository {

    override suspend fun getPacket(packetId: String): ApiResult<SignaturePacket> =
        withContext(Dispatchers.IO) {
            call { signingApi.getPacket(packetId).toDomain() }
        }

    override suspend fun getEvents(packetId: String): ApiResult<List<PacketEvent>> =
        withContext(Dispatchers.IO) {
            call { signingApi.getEvents(packetId).events.map { it.toDomain() } }
        }

    override suspend fun createDraft(
        sourcePath: String,
        originChannel: String,
        originRef: String?,
    ): ApiResult<String> = withContext(Dispatchers.IO) {
        call {
            val body = CreateSignaturePacketRequest(
                sourcePath = sourcePath,
                originChannel = originChannel,
                originRef = originRef,
            )
            // The create response is lenient (packet_id may be absent); empty-string is a safe default
            // that the ViewModel treats as a no-navigate.
            signingApi.createPacket(body).packetId.orEmpty()
        }
    }

    override suspend fun send(packetId: String): ApiResult<Unit> = withContext(Dispatchers.IO) {
        call { signingApi.sendPacket(packetId) }
            .let { result ->
                when (result) {
                    is ApiResult.Success -> ApiResult.Success(Unit)
                    is ApiResult.Failure -> result
                    is ApiResult.NetworkError -> result
                }
            }
    }

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser], preserving the
     * status); malformed JSON -> Failure(parse); transport failures -> NetworkError. The
     * JsonEncodingException catch precedes the IOException catch (it is an IOException subtype).
     * Cancellation is re-thrown. Mirrors AND-329.
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
