package com.testlogon.android.feature.signing.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.signing.CreateSignaturePacketRequest
import com.testlogon.android.core.network.signing.RevokeSigningLinkRequest
import com.testlogon.android.core.network.signing.SigningApi
import com.testlogon.android.feature.signing.capture.model.FieldPlacement
import com.testlogon.android.feature.signing.capture.model.SignedPacketDraft
import com.testlogon.android.feature.signing.model.PacketEvent
import com.testlogon.android.feature.signing.model.SignaturePacket
import com.testlogon.android.feature.signing.model.toDomain
import com.testlogon.android.feature.signing.submit.model.AssetBytesReader
import com.testlogon.android.feature.signing.submit.model.MarkDoneResult
import com.testlogon.android.feature.signing.submit.model.buildFillRequest
import com.testlogon.android.feature.signing.submit.model.toMarkDoneResult
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
/**
 * SUX-005 - the outcome of revoking a signer's public signing link: the [jti] that was revoked and
 * whether the server actually revoked a live token (false when it was already gone / never minted).
 */
data class RevokeLinkResult(
    val jti: String,
    val revoked: Boolean,
)

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

    /**
     * AND-343 - fills ONE field individually (there is NO bulk submit). REUSES AND-339
     * SigningApi.fillField with a request built from [placement] (typed/date -> value+TYPED; drawn ->
     * capture_mode DRAWN + base64 render_payload). NOT idempotent (a mutating POST).
     */
    suspend fun fillField(packetId: String, placement: FieldPlacement): ApiResult<Unit>

    /**
     * AND-343 - flushes every placement in [draft] by calling [fillField] in order; short-circuits and
     * returns the FIRST failure (no auto-retry). This performs AND-342's deferred network fills. Returns
     * Success(Unit) when (and only when) every placement filled.
     */
    suspend fun flushDraft(draft: SignedPacketDraft): ApiResult<Unit>

    /**
     * AND-343 - acknowledges the packet's inline legal notice (POST acknowledge-legal-notice, EMPTY
     * body). REUSES AND-339 SigningApi.acknowledgeLegalNotice. The CALLER reloads getPacket afterwards
     * to observe the updated accepted flag. NOT idempotent.
     */
    suspend fun acknowledgeLegalNotice(packetId: String): ApiResult<Unit>

    /**
     * AND-343 - the TERMINAL e-sign action: POST mark-done (EMPTY body). REUSES AND-339
     * SigningApi.markDone. Because that response is lenient ({ok,status}), the impl follows up with a
     * getPacket to populate completed_at / signer_status in the returned [MarkDoneResult]. NOT
     * idempotent; the ViewModel blocks duplicate taps.
     */
    suspend fun markDone(packetId: String): ApiResult<MarkDoneResult>

    /**
     * SUX-005 - the packet OWNER revokes a signer's public signing link by its [jti]. REUSES
     * SigningApi.revokeSigningLink. Returns the revoke outcome ([RevokeLinkResult]); a 404 (public-link
     * feature off) degrades to an [ApiResult.Failure] the caller can surface calmly. NOT idempotent.
     */
    suspend fun revokeSigningLink(
        packetId: String,
        signerId: String,
        jti: String,
    ): ApiResult<RevokeLinkResult>
}

@Singleton
class SignatureRepositoryImpl @Inject constructor(
    private val signingApi: SigningApi,
    private val errorParser: ApiErrorParser,
    private val assetBytesReader: AssetBytesReader,
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

    override suspend fun fillField(
        packetId: String,
        placement: FieldPlacement,
    ): ApiResult<Unit> = withContext(Dispatchers.IO) {
        call {
            val body = buildFillRequest(placement, assetBytesReader)
            signingApi.fillField(packetId, placement.fieldId, body)
            Unit
        }
    }

    override suspend fun flushDraft(draft: SignedPacketDraft): ApiResult<Unit> =
        withContext(Dispatchers.IO) {
            // Fill each placement individually (NO bulk submit); short-circuit on the first failure.
            for (placement in draft.placements) {
                when (val result = fillField(draft.packetId, placement)) {
                    is ApiResult.Success -> Unit
                    is ApiResult.Failure -> return@withContext result
                    is ApiResult.NetworkError -> return@withContext result
                }
            }
            ApiResult.Success(Unit)
        }

    override suspend fun acknowledgeLegalNotice(packetId: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) {
            call {
                // EMPTY body; the lenient ack DTO already tolerates a sparse / empty 200 response.
                signingApi.acknowledgeLegalNotice(packetId)
                Unit
            }
        }

    override suspend fun markDone(packetId: String): ApiResult<MarkDoneResult> =
        withContext(Dispatchers.IO) {
            // Terminal action: POST mark-done (EMPTY body). The response is lenient, so reload the
            // packet to source completed_at / signer_status. A failed reload degrades to a null packet
            // (the mark-done itself still succeeded), never overriding the mark-done outcome.
            call {
                val response = signingApi.markDone(packetId)
                val reloaded = runCatching { signingApi.getPacket(packetId).toDomain() }.getOrNull()
                response.toMarkDoneResult(reloaded)
            }
        }

    override suspend fun revokeSigningLink(
        packetId: String,
        signerId: String,
        jti: String,
    ): ApiResult<RevokeLinkResult> = withContext(Dispatchers.IO) {
        call {
            val response = signingApi.revokeSigningLink(
                packetId,
                signerId,
                RevokeSigningLinkRequest(jti = jti),
            )
            RevokeLinkResult(jti = response.jti ?: jti, revoked = response.revoked)
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
