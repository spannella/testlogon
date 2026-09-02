package com.testlogon.android.feature.signing

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.signing.CreateSignaturePacketRequest
import com.testlogon.android.core.network.signing.SigningInboxListDto
import com.testlogon.android.core.network.signing.CreateSignaturePacketResponse
import com.testlogon.android.core.network.signing.LegalNoticeDto
import com.testlogon.android.core.network.signing.PacketRole
import com.testlogon.android.core.network.signing.PacketStatus
import com.testlogon.android.core.network.signing.SendSignaturePacketResponse
import com.testlogon.android.core.network.signing.SignatureFieldDto
import com.testlogon.android.core.network.signing.SignatureFieldType
import com.testlogon.android.core.network.signing.SignaturePacketDetailDto
import com.testlogon.android.core.network.signing.SignaturePacketEventDto
import com.testlogon.android.core.network.signing.SignaturePacketEventsDto
import com.testlogon.android.core.network.signing.SignaturePacketFieldFillRequest
import com.testlogon.android.core.network.signing.SignaturePacketFieldFillResponse
import com.testlogon.android.core.network.signing.SignaturePacketFieldMutationRequest
import com.testlogon.android.core.network.signing.SignaturePacketFieldMutationResponse
import com.testlogon.android.core.network.signing.SignaturePacketLegalNoticeAckResponse
import com.testlogon.android.core.network.signing.SignaturePacketMarkDoneResponse
import com.testlogon.android.core.network.signing.SignaturePacketSignerDto
import com.testlogon.android.core.network.signing.SignatureTemplateListDto
import com.testlogon.android.core.network.signing.SignatureTemplateMigrationCheckRequest
import com.testlogon.android.core.network.signing.SignatureTemplateMigrationListDto
import com.testlogon.android.core.network.signing.SignatureTemplateVersionDto
import com.testlogon.android.core.network.signing.SignatureTemplateVersionsDto
import com.testlogon.android.core.network.signing.CreateSignatureTemplateVersionRequest
import com.testlogon.android.core.network.signing.SigningApi
import com.testlogon.android.core.network.signing.RevokeSigningLinkRequest
import com.testlogon.android.core.network.signing.RevokeSigningLinkResponse
import com.testlogon.android.feature.signing.data.SignatureRepositoryImpl
import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException
import java.time.Instant

/**
 * AND-340 - unit tests for [SignatureRepositoryImpl].
 *
 * The fake [SigningApi] (distinct helper name [StubSigningApi]) serves AND-339 RAW DTOs / throws; the
 * repository maps them to the feature domain BEFORE the typed ApiResult. Covers: getPacket DTO->domain
 * (status / role enum reuse, signers, fields, Instant from ISO), getEvents mapping, createDraft returning
 * the packet_id, send mapping to Unit, and the HttpException->Failure / IOException->NetworkError folding.
 */
class SignatureRepositoryTest {

    private val parser = ApiErrorParser(Moshi.Builder().build())

    private fun repo(api: SigningApi) = SignatureRepositoryImpl(
        signingApi = api,
        errorParser = parser,
        assetBytesReader = { null },
    )

    @Test
    fun getPacket_mapsDtoToDomain_includingEnumsSignersFieldsAndInstant() = runTest {
        val api = StubSigningApi(packet = samplePacketDto())
        val result = repo(api).getPacket("pkt_1")

        assertTrue(result is ApiResult.Success)
        val packet = (result as ApiResult.Success).data
        assertEquals("pkt_1", packet.packetId)
        assertEquals(PacketStatus.SENT, packet.status)
        assertEquals(PacketRole.SENDER, packet.role)
        assertEquals(Instant.parse("2026-06-01T10:00:00Z"), packet.createdAt)
        assertEquals(Instant.parse("2026-06-02T10:00:00Z"), packet.sentAt)
        assertEquals(1, packet.signers.size)
        assertEquals("sgn_1" to "pending", packet.signers[0].signerId to packet.signers[0].status)
        assertEquals(1, packet.fields.size)
        assertEquals(SignatureFieldType.SIGNATURE, packet.fields[0].fieldType)
        assertEquals(true, packet.fields[0].isAssignedToViewer)
    }

    @Test
    fun getPacket_badIsoTimestamp_degradesToNull() = runTest {
        val api = StubSigningApi(packet = samplePacketDto().copy(createdAt = "not-a-date"))
        val packet = (repo(api).getPacket("pkt_1") as ApiResult.Success).data
        assertNull(packet.createdAt)
    }

    @Test
    fun getEvents_mapsEachEvent_withInstant() = runTest {
        val api = StubSigningApi(
            events = SignaturePacketEventsDto(
                packetId = "pkt_1",
                events = listOf(
                    SignaturePacketEventDto(
                        eventId = "ev_1",
                        packetId = "pkt_1",
                        actorUserId = "usr_1",
                        eventType = "created",
                        createdAt = "2026-06-01T10:00:00Z",
                    ),
                ),
            ),
        )
        val result = repo(api).getEvents("pkt_1")

        assertTrue(result is ApiResult.Success)
        val events = (result as ApiResult.Success).data
        assertEquals(1, events.size)
        assertEquals("created", events[0].eventType)
        assertEquals(Instant.parse("2026-06-01T10:00:00Z"), events[0].createdAt)
    }

    @Test
    fun createDraft_sendsBody_andReturnsPacketId() = runTest {
        val api = StubSigningApi(createResponse = CreateSignaturePacketResponse(packetId = "pkt_new"))
        val result = repo(api).createDraft(sourcePath = "files/doc.pdf", originChannel = "share")

        assertTrue(result is ApiResult.Success)
        assertEquals("pkt_new", (result as ApiResult.Success).data)
        assertEquals("files/doc.pdf", api.createBodies.single().sourcePath)
        assertEquals("share", api.createBodies.single().originChannel)
    }

    @Test
    fun send_mapsTo_unitSuccess() = runTest {
        val api = StubSigningApi(sendResponse = SendSignaturePacketResponse(ok = true))
        val result = repo(api).send("pkt_1")

        assertTrue(result is ApiResult.Success)
        assertEquals(listOf("pkt_1"), api.sentPacketIds)
    }

    @Test
    fun fillField_buildsTypedRequest_andMapsToUnit() = runTest {
        val api = StubSigningApi(packet = samplePacketDto())
        val placement = com.testlogon.android.feature.signing.capture.model.FieldPlacement(
            fieldId = "fld_date",
            page = 0,
            rect = com.testlogon.android.feature.signing.capture.model.NormalizedRect(0f, 0f, 1f, 1f),
            textValue = "2026-06-13",
            satisfied = true,
        )
        val result = repo(api).fillField("pkt_1", placement)

        assertTrue(result is ApiResult.Success)
        assertEquals(1, api.fillCalls.size)
        assertEquals("fld_date", api.fillCalls.single().first)
        assertEquals("2026-06-13", api.fillCalls.single().second.value)
    }

    @Test
    fun flushDraft_fillsEachPlacement_inOrder() = runTest {
        val api = StubSigningApi(packet = samplePacketDto())
        val draft = com.testlogon.android.feature.signing.capture.model.SignedPacketDraft(
            packetId = "pkt_1",
            documentId = "pkt_1",
            placements = listOf(
                fillPlacement("fld_a"),
                fillPlacement("fld_b"),
            ),
        )
        val result = repo(api).flushDraft(draft)

        assertTrue(result is ApiResult.Success)
        assertEquals(listOf("fld_a", "fld_b"), api.fillCalls.map { it.first })
    }

    @Test
    fun flushDraft_shortCircuits_onFirstFailure() = runTest {
        val api = StubSigningApi(packet = samplePacketDto(), fillError = { httpException(422) })
        val draft = com.testlogon.android.feature.signing.capture.model.SignedPacketDraft(
            packetId = "pkt_1",
            documentId = "pkt_1",
            placements = listOf(fillPlacement("fld_a"), fillPlacement("fld_b")),
        )
        val result = repo(api).flushDraft(draft)

        assertTrue(result is ApiResult.Failure)
        assertEquals(1, api.fillCalls.size) // stopped after the first failure.
    }

    @Test
    fun markDone_reloadsPacket_forCompletedAt() = runTest {
        val api = StubSigningApi(
            packet = samplePacketDto().copy(
                status = PacketStatus.COMPLETED,
                completedAt = "2026-06-13T12:00:00Z",
            ),
            markDoneResponse = SignaturePacketMarkDoneResponse(ok = true, status = PacketStatus.COMPLETED),
        )
        val result = repo(api).markDone("pkt_1")

        assertTrue(result is ApiResult.Success)
        val done = (result as ApiResult.Success).data
        assertEquals(PacketStatus.COMPLETED, done.packetStatus)
        assertEquals(Instant.parse("2026-06-13T12:00:00Z"), done.completedAt)
        assertEquals(listOf("pkt_1"), api.markDonePacketIds)
    }

    @Test
    fun acknowledgeLegalNotice_mapsToUnit() = runTest {
        val api = StubSigningApi(packet = samplePacketDto())
        val result = repo(api).acknowledgeLegalNotice("pkt_1")

        assertTrue(result is ApiResult.Success)
        assertEquals(listOf("pkt_1"), api.ackPacketIds)
    }

    @Test
    fun httpError_foldsToFailure_preservingStatus() = runTest {
        val api = StubSigningApi(packetError = { httpException(422) })
        val result = repo(api).getPacket("pkt_1")

        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun ioError_foldsToNetworkError() = runTest {
        val api = StubSigningApi(packetError = { IOException("offline") })
        val result = repo(api).getPacket("pkt_1")

        assertTrue(result is ApiResult.NetworkError)
    }

    // ---- helpers (distinct names; never shadow a repo method) ----

    private fun httpException(code: Int): HttpException =
        HttpException(Response.error<Any>(code, "bad".toResponseBody("text/plain".toMediaType())))

    private fun fillPlacement(fieldId: String) =
        com.testlogon.android.feature.signing.capture.model.FieldPlacement(
            fieldId = fieldId,
            page = 0,
            rect = com.testlogon.android.feature.signing.capture.model.NormalizedRect(0f, 0f, 1f, 1f),
            textValue = "v",
            satisfied = true,
        )

    private fun samplePacketDto() = SignaturePacketDetailDto(
        packetId = "pkt_1",
        status = PacketStatus.SENT,
        ownerUserId = "usr_owner",
        sourcePath = "files/doc.pdf",
        role = PacketRole.SENDER,
        createdAt = "2026-06-01T10:00:00Z",
        sentAt = "2026-06-02T10:00:00Z",
        signers = listOf(SignaturePacketSignerDto(signerId = "sgn_1", status = "pending")),
        fields = listOf(
            SignatureFieldDto(
                fieldId = "fld_1",
                fieldType = SignatureFieldType.SIGNATURE,
                page = 0,
                x = 1f,
                y = 2f,
                width = 3f,
                height = 4f,
                required = true,
                assignedSignerId = "sgn_1",
                isAssignedToViewer = true,
            ),
        ),
        legalNotice = LegalNoticeDto(required = true, accepted = false, version = "v1", text = "notice"),
    )

    @Test
    fun revokeSigningLink_sendsJti_andMapsResult() = runTest {
        val api = StubSigningApi(revokeResponse = RevokeSigningLinkResponse(jti = "jti_9", revoked = true))
        val result = repo(api).revokeSigningLink("pkt_1", "sgn_1", "jti_9")

        assertTrue(result is ApiResult.Success)
        val data = (result as ApiResult.Success).data
        assertEquals("jti_9", data.jti)
        assertTrue(data.revoked)
        assertEquals(Triple("pkt_1", "sgn_1", "jti_9"), api.revokeCalls.single())
    }

    /**
     * AND-340 - hand-rolled fake [SigningApi]. The three methods this repo uses (getPacket / getEvents /
     * createPacket / sendPacket) serve configured DTOs or throw the configured error and record their args;
     * every other method throws (unused by AND-340).
     */
    private class StubSigningApi(
        private val packet: SignaturePacketDetailDto? = null,
        private val events: SignaturePacketEventsDto = SignaturePacketEventsDto(packetId = "pkt_1"),
        private val createResponse: CreateSignaturePacketResponse = CreateSignaturePacketResponse(),
        private val sendResponse: SendSignaturePacketResponse = SendSignaturePacketResponse(),
        private val packetError: (() -> Throwable)? = null,
        private val fillError: (() -> Throwable)? = null,
        private val markDoneResponse: SignaturePacketMarkDoneResponse = SignaturePacketMarkDoneResponse(),
        private val revokeResponse: RevokeSigningLinkResponse = RevokeSigningLinkResponse(revoked = true),
        private val revokeError: (() -> Throwable)? = null,
    ) : SigningApi {

        val createBodies = mutableListOf<CreateSignaturePacketRequest>()
        val sentPacketIds = mutableListOf<String>()
        val fillCalls = mutableListOf<Pair<String, SignaturePacketFieldFillRequest>>()
        val markDonePacketIds = mutableListOf<String>()
        val ackPacketIds = mutableListOf<String>()
        val revokeCalls = mutableListOf<Triple<String, String, String>>()

        override suspend fun createPacket(body: CreateSignaturePacketRequest): CreateSignaturePacketResponse {
            createBodies += body
            return createResponse
        }

        override suspend fun getPacket(packetId: String): SignaturePacketDetailDto {
            packetError?.let { throw it() }
            return packet ?: error("no packet configured")
        }

        override suspend fun getEvents(packetId: String): SignaturePacketEventsDto = events

        override suspend fun sendPacket(packetId: String): SendSignaturePacketResponse {
            sentPacketIds += packetId
            return sendResponse
        }

        override suspend fun mutateField(
            packetId: String,
            body: SignaturePacketFieldMutationRequest,
        ): SignaturePacketFieldMutationResponse = unused()

        override suspend fun fillField(
            packetId: String,
            fieldId: String,
            body: SignaturePacketFieldFillRequest,
        ): SignaturePacketFieldFillResponse {
            fillCalls += fieldId to body
            fillError?.let { throw it() }
            return SignaturePacketFieldFillResponse(ok = true)
        }

        override suspend fun markDone(packetId: String): SignaturePacketMarkDoneResponse {
            markDonePacketIds += packetId
            return markDoneResponse
        }

        override suspend fun acknowledgeLegalNotice(
            packetId: String,
        ): SignaturePacketLegalNoticeAckResponse {
            ackPacketIds += packetId
            return SignaturePacketLegalNoticeAckResponse(ok = true, accepted = true)
        }

        override suspend fun downloadFinalPdf(packetId: String): Response<ResponseBody> = unused()

        override suspend fun listAwaiting(limit: Int): SigningInboxListDto = unused()

        override suspend fun listSent(limit: Int): SigningInboxListDto = unused()

        override suspend fun listCompletedForMe(limit: Int): SigningInboxListDto = unused()

        override suspend fun listDrafts(limit: Int): SigningInboxListDto = unused()

        override suspend fun listTemplates(): SignatureTemplateListDto = unused()

        override suspend fun createTemplateVersion(
            body: CreateSignatureTemplateVersionRequest,
        ): SignatureTemplateVersionDto = unused()

        override suspend fun getTemplateVersions(templateKey: String): SignatureTemplateVersionsDto = unused()

        override suspend fun getTemplateVersion(
            templateKey: String,
            version: Int,
        ): SignatureTemplateVersionDto = unused()

        override suspend fun migrationCheck(
            body: SignatureTemplateMigrationCheckRequest,
        ): SignatureTemplateMigrationListDto = unused()

        override suspend fun revokeSigningLink(
            packetId: String,
            signerId: String,
            body: RevokeSigningLinkRequest,
        ): RevokeSigningLinkResponse {
            revokeCalls += Triple(packetId, signerId, body.jti)
            revokeError?.let { throw it() }
            return revokeResponse
        }

        private fun unused(): Nothing = throw UnsupportedOperationException("not used in AND-340 tests")
    }
}
