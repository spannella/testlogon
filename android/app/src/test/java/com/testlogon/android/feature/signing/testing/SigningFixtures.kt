package com.testlogon.android.feature.signing.testing

import com.testlogon.android.core.network.signing.LegalNoticeDto
import com.testlogon.android.core.network.signing.PacketRole
import com.testlogon.android.core.network.signing.PacketStatus
import com.testlogon.android.core.network.signing.SignatureFieldDto
import com.testlogon.android.core.network.signing.SignatureFieldType
import com.testlogon.android.core.network.signing.SignatureInputMode
import com.testlogon.android.core.network.signing.SignaturePacketDetailDto
import com.testlogon.android.core.network.signing.SignaturePacketEventDto
import com.testlogon.android.core.network.signing.SignaturePacketEventsDto
import com.testlogon.android.core.network.signing.SignaturePacketSignerDto

/**
 * AND-345 - reusable, hermetic fixtures for the signing suite (FR-7).
 *
 * PLACEMENT (dependency direction): these fixtures reference core-network signing DTOs/enums AND the
 * :app feature domain, so they CANNOT live in :core-testing without a new module dependency
 * (:core-testing depends on :core-model only, not on :core-network, and never on :app). Adding such a
 * dependency is forbidden by this ticket, so the shared fixtures live under :app test instead. The
 * core-network DTO/API tests are deliberately self-contained (their own inline JSON + their own Moshi
 * built like NetworkModule.provideMoshi) because core-network has NO testImplementation on core-testing
 * either.
 *
 * Everything here is PURE JVM (no android.* types): raw JSON Strings, a hand-built 2-page PDF byte
 * array, and DTO / domain object builders. KDoc avoids the comment-terminator character pair.
 */
object SigningFixtures {

    // ---- Raw JSON bodies (mirror the AND-339 wire contract) ----

    /**
     * A SENT packet detail for a SIGNER: signers[], a flat fields[] covering every field type
     * (signature/initials/date/text/notary_stamp), a legal_notice {required,accepted,version,text},
     * and capabilities{can_fill_fields:true}. The signature field carries capture_mode drawn +
     * render_payload; the others use the typed/default shapes.
     */
    val PACKET_DETAIL_SENT_JSON: String = """
        {
          "packet_id": "pkt_1",
          "status": "sent",
          "owner_user_id": "usr_owner",
          "source_path": "/docs/contract.pdf",
          "role": "signer",
          "signer_status": "pending",
          "origin_channel": "share",
          "created_at": "2026-05-01T10:00:00Z",
          "sent_at": "2026-05-02T10:00:00Z",
          "signers": [
            { "signer_id": "sgn_1", "status": "pending" },
            { "signer_id": "sgn_2", "status": "completed" }
          ],
          "fields": [
            {
              "field_id": "fld_sig", "field_type": "signature", "page": 1,
              "x": 0.1, "y": 0.2, "width": 0.3, "height": 0.1,
              "required": true, "assigned_signer_id": "sgn_1", "is_assigned_to_viewer": true,
              "capture_mode": "drawn", "render_payload": { "color": "blue" }
            },
            {
              "field_id": "fld_init", "field_type": "initials", "page": 1,
              "x": 0.5, "y": 0.2, "width": 0.1, "height": 0.05,
              "required": true, "is_assigned_to_viewer": true
            },
            {
              "field_id": "fld_date", "field_type": "date", "page": 1,
              "x": 0.1, "y": 0.4, "width": 0.2, "height": 0.05,
              "required": true, "is_assigned_to_viewer": true, "capture_mode": "typed"
            },
            {
              "field_id": "fld_text", "field_type": "text", "page": 2,
              "x": 0.1, "y": 0.1, "width": 0.4, "height": 0.05,
              "required": false, "is_assigned_to_viewer": true
            },
            {
              "field_id": "fld_notary", "field_type": "notary_stamp", "page": 2,
              "x": 0.6, "y": 0.6, "width": 0.2, "height": 0.1,
              "required": false
            }
          ],
          "capabilities": { "can_fill_fields": true, "can_send": false },
          "legal_notice": {
            "required": true, "accepted": false, "version": "v2", "text": "You agree to sign electronically."
          }
        }
    """.trimIndent()

    /** A COMPLETED packet detail (terminal): completed_at present, legal notice accepted. */
    val PACKET_DETAIL_COMPLETED_JSON: String = """
        {
          "packet_id": "pkt_1",
          "status": "completed",
          "owner_user_id": "usr_owner",
          "source_path": "/docs/contract.pdf",
          "role": "signer",
          "signer_status": "completed",
          "created_at": "2026-05-01T10:00:00Z",
          "sent_at": "2026-05-02T10:00:00Z",
          "completed_at": "2026-05-03T10:00:00Z",
          "signers": [ { "signer_id": "sgn_1", "status": "completed" } ],
          "fields": [],
          "capabilities": { "can_fill_fields": false },
          "legal_notice": { "required": true, "accepted": true, "version": "v2", "text": "Notice" }
        }
    """.trimIndent()

    /**
     * A deliberately SPARSE packet body (only the required, no-default fields present). Every optional
     * field is absent so the reflective adapter must fall back to the DTO defaults.
     */
    val PACKET_DETAIL_SPARSE_JSON: String = """
        {
          "packet_id": "pkt_sparse",
          "status": "draft",
          "owner_user_id": "usr_owner",
          "source_path": "/docs/x.pdf",
          "role": "sender"
        }
    """.trimIndent()

    /** A field-fill success response body ({ok, field}). */
    val FIELD_FILL_OK_JSON: String = """
        {
          "ok": true,
          "field": {
            "field_id": "fld_sig", "field_type": "signature", "page": 1,
            "x": 0.1, "y": 0.2, "width": 0.3, "height": 0.1,
            "filled_at": "2026-05-02T11:00:00Z", "value": "John Doe", "capture_mode": "typed"
          }
        }
    """.trimIndent()

    /** A mark-done success response body ({ok, status}). */
    val MARK_DONE_OK_JSON: String = """{"ok":true,"status":"completed"}"""

    /** A legal-notice acknowledge success body ({ok, accepted}). */
    val LEGAL_NOTICE_ACK_OK_JSON: String = """{"ok":true,"accepted":true}"""

    /** A packet events body with one audit event. */
    val EVENTS_JSON: String = """
        {
          "packet_id": "pkt_1",
          "events": [
            {
              "event_id": "evt_1",
              "packet_id": "pkt_1",
              "actor_user_id": "usr_owner",
              "event_type": "packet.sent",
              "event_payload": { "signer_id": "sgn_1" },
              "created_at": "2026-05-02T10:00:00Z"
            }
          ]
        }
    """.trimIndent()

    /**
     * A FastAPI-style 422 error body (the {detail:[...]} validation shape) for the API error path. The
     * raw String form lets a test enqueue it on a 422 MockResponse.
     */
    val ERROR_422_DETAIL_JSON: String = """
        {"detail":[{"loc":["body","value"],"msg":"field required","type":"value_error.missing"}]}
    """.trimIndent()

    // ---- A minimal, VALID 2-page PDF (pure bytes) ----

    /**
     * A tiny, hand-built PDF-1.4 document with two Page objects, terminated by the end-of-file marker.
     * It starts with the 5-byte PDF signature that AND-341's PdfSource.hasPdfMagic verifies, so it is a
     * drop-in for the streamed-download / magic-header fixtures. Built as a String then encoded to bytes
     * (ISO-8859-1 keeps it one-byte-per-char so the literal bytes round-trip exactly).
     */
    val TWO_PAGE_PDF_BYTES: ByteArray by lazy { buildTwoPagePdf() }

    private fun buildTwoPagePdf(): ByteArray {
        // Catalog -> Pages -> two Page kids -> one shared content stream. Object offsets are not
        // byte-accurate (no real xref table is needed for the magic-header + parse-shape fixtures), but
        // the structure is well-formed and starts with the PDF signature + ends with the EOF marker.
        val eof = "%" + "%EOF"
        val pdf = buildString {
            append("%PDF-1.4\n")
            append("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
            append("2 0 obj\n<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>\nendobj\n")
            append("3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 5 0 R >>\nendobj\n")
            append("4 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 5 0 R >>\nendobj\n")
            append("5 0 obj\n<< /Length 8 >>\nstream\nBT ET\nendstream\nendobj\n")
            append("trailer\n<< /Root 1 0 R /Size 6 >>\n")
            append(eof)
            append("\n")
        }
        return pdf.toByteArray(Charsets.ISO_8859_1)
    }

    // ---- DTO builders (reuse the AND-339 DTOs; sensible defaults, override per test) ----

    /** A signer DTO builder. */
    fun signerDto(
        signerId: String = "sgn_1",
        status: String = "pending",
    ): SignaturePacketSignerDto = SignaturePacketSignerDto(signerId = signerId, status = status)

    /** A field DTO builder (defaults to an assigned signature field on page 1). */
    fun fieldDto(
        fieldId: String = "fld_sig",
        fieldType: SignatureFieldType = SignatureFieldType.SIGNATURE,
        page: Int = 1,
        x: Float = 0.1f,
        y: Float = 0.2f,
        width: Float = 0.3f,
        height: Float = 0.1f,
        required: Boolean = true,
        assignedSignerId: String? = "sgn_1",
        isAssignedToViewer: Boolean? = true,
        captureMode: SignatureInputMode? = null,
    ): SignatureFieldDto = SignatureFieldDto(
        fieldId = fieldId,
        fieldType = fieldType,
        page = page,
        x = x,
        y = y,
        width = width,
        height = height,
        required = required,
        assignedSignerId = assignedSignerId,
        isAssignedToViewer = isAssignedToViewer,
        captureMode = captureMode,
    )

    /** A legal-notice DTO builder. */
    fun legalNoticeDto(
        required: Boolean = true,
        accepted: Boolean = false,
        version: String = "v2",
        text: String = "You agree to sign electronically.",
    ): LegalNoticeDto = LegalNoticeDto(
        required = required,
        accepted = accepted,
        version = version,
        text = text,
    )

    /** A full packet-detail DTO builder (a SENT signer packet with the five typed fields). */
    fun packetDetailDto(
        packetId: String = "pkt_1",
        status: PacketStatus = PacketStatus.SENT,
        role: PacketRole = PacketRole.SIGNER,
        signerStatus: String? = "pending",
        createdAt: String? = "2026-05-01T10:00:00Z",
        sentAt: String? = "2026-05-02T10:00:00Z",
        completedAt: String? = null,
        signers: List<SignaturePacketSignerDto> = listOf(signerDto()),
        fields: List<SignatureFieldDto> = listOf(
            fieldDto(fieldId = "fld_sig", fieldType = SignatureFieldType.SIGNATURE),
            fieldDto(fieldId = "fld_init", fieldType = SignatureFieldType.INITIALS),
            fieldDto(fieldId = "fld_date", fieldType = SignatureFieldType.DATE),
        ),
        capabilities: Map<String, Boolean> = mapOf("can_fill_fields" to true),
        legalNotice: LegalNoticeDto? = legalNoticeDto(),
    ): SignaturePacketDetailDto = SignaturePacketDetailDto(
        packetId = packetId,
        status = status,
        ownerUserId = "usr_owner",
        sourcePath = "/docs/contract.pdf",
        role = role,
        signerStatus = signerStatus,
        createdAt = createdAt,
        sentAt = sentAt,
        completedAt = completedAt,
        signers = signers,
        fields = fields,
        capabilities = capabilities,
        legalNotice = legalNotice,
    )

    /** A single packet-event DTO builder. */
    fun eventDto(
        eventId: String = "evt_1",
        eventType: String = "packet.sent",
        actorUserId: String = "usr_owner",
        createdAt: String = "2026-05-02T10:00:00Z",
    ): SignaturePacketEventDto = SignaturePacketEventDto(
        eventId = eventId,
        packetId = "pkt_1",
        actorUserId = actorUserId,
        eventType = eventType,
        createdAt = createdAt,
    )

    /** A packet-events wrapper builder. */
    fun eventsDto(
        packetId: String = "pkt_1",
        events: List<SignaturePacketEventDto> = listOf(eventDto()),
    ): SignaturePacketEventsDto = SignaturePacketEventsDto(packetId = packetId, events = events)
}
