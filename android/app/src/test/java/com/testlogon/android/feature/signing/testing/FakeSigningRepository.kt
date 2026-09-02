package com.testlogon.android.feature.signing.testing

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.signing.capture.model.FieldPlacement
import com.testlogon.android.feature.signing.capture.model.SignedPacketDraft
import com.testlogon.android.feature.signing.data.SignatureRepository
import com.testlogon.android.feature.signing.data.RevokeLinkResult
import com.testlogon.android.feature.signing.model.PacketEvent
import com.testlogon.android.feature.signing.model.SignaturePacket
import com.testlogon.android.feature.signing.model.toDomain
import com.testlogon.android.feature.signing.submit.model.MarkDoneResult

/**
 * AND-345 - a shared, in-memory fake of the :app [SignatureRepository] (FR-7).
 *
 * PLACEMENT (dependency direction): [SignatureRepository] is a :app-level interface, and :app depends
 * on :core-testing (not the reverse), so :core-testing cannot see this interface. A shared fake of it
 * therefore MUST live under :app test rather than in :core-testing (per the ticket's documented
 * fallback). It pairs with [SigningFixtures], which lives next to it for the same reason.
 *
 * Each method returns a configurable [ApiResult] (default Success). The mutating calls (fillField /
 * flushDraft / markDone / acknowledgeLegalNotice / send / createDraft) RECORD their arguments BEFORE
 * honouring a configured failure, so a test can assert the call happened even on the failure path.
 * Helper / recording names are distinct and never shadow an interface method.
 */
class FakeSigningRepository(
    var getPacketResult: ApiResult<SignaturePacket> =
        ApiResult.Success(SigningFixtures.packetDetailDto().toDomain()),
    var getEventsResult: ApiResult<List<PacketEvent>> = ApiResult.Success(emptyList()),
    var createDraftResult: ApiResult<String> = ApiResult.Success("pkt_new"),
    var sendResult: ApiResult<Unit> = ApiResult.Success(Unit),
    var fillFieldResult: ApiResult<Unit> = ApiResult.Success(Unit),
    var flushDraftResult: ApiResult<Unit> = ApiResult.Success(Unit),
    var acknowledgeResult: ApiResult<Unit> = ApiResult.Success(Unit),
    var markDoneResult: ApiResult<MarkDoneResult> =
        ApiResult.Success(MarkDoneResult(packetStatus = SigningFixtures.packetDetailDto().status)),
    var revokeSigningLinkResult: ApiResult<RevokeLinkResult> =
        ApiResult.Success(RevokeLinkResult(jti = "jti_1", revoked = true)),
) : SignatureRepository {

    /** Recorded arguments, in call order (BEFORE any configured failure is returned). */
    val getPacketIds = mutableListOf<String>()
    val getEventsIds = mutableListOf<String>()
    val createDraftCalls = mutableListOf<CreateDraftCall>()
    val sentPacketIds = mutableListOf<String>()
    val filledFields = mutableListOf<Pair<String, FieldPlacement>>()
    val flushedDrafts = mutableListOf<SignedPacketDraft>()
    val acknowledgedPacketIds = mutableListOf<String>()
    val markDonePacketIds = mutableListOf<String>()
    val revokedLinks = mutableListOf<Triple<String, String, String>>()

    /** Records the args of a createDraft call. */
    data class CreateDraftCall(
        val sourcePath: String,
        val originChannel: String,
        val originRef: String?,
    )

    override suspend fun getPacket(packetId: String): ApiResult<SignaturePacket> {
        getPacketIds += packetId
        return getPacketResult
    }

    override suspend fun getEvents(packetId: String): ApiResult<List<PacketEvent>> {
        getEventsIds += packetId
        return getEventsResult
    }

    override suspend fun createDraft(
        sourcePath: String,
        originChannel: String,
        originRef: String?,
    ): ApiResult<String> {
        createDraftCalls += CreateDraftCall(sourcePath, originChannel, originRef)
        return createDraftResult
    }

    override suspend fun send(packetId: String): ApiResult<Unit> {
        sentPacketIds += packetId
        return sendResult
    }

    override suspend fun fillField(
        packetId: String,
        placement: FieldPlacement,
    ): ApiResult<Unit> {
        filledFields += packetId to placement
        return fillFieldResult
    }

    override suspend fun flushDraft(draft: SignedPacketDraft): ApiResult<Unit> {
        flushedDrafts += draft
        return flushDraftResult
    }

    override suspend fun acknowledgeLegalNotice(packetId: String): ApiResult<Unit> {
        acknowledgedPacketIds += packetId
        return acknowledgeResult
    }

    override suspend fun markDone(packetId: String): ApiResult<MarkDoneResult> {
        markDonePacketIds += packetId
        return markDoneResult
    }

    override suspend fun revokeSigningLink(
        packetId: String,
        signerId: String,
        jti: String,
    ): ApiResult<RevokeLinkResult> {
        revokedLinks += Triple(packetId, signerId, jti)
        return revokeSigningLinkResult
    }

    companion object {
        /** A convenience 422 failure for wiring a method's *Result to an error path. */
        fun failure422(message: String = "unprocessable"): ApiResult.Failure =
            ApiResult.Failure(ApiError(status = 422, message = message))
    }
}
