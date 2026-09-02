package com.testlogon.android.core.network.signing

import okhttp3.ResponseBody
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query
import retrofit2.http.Streaming

/**
 * AND-339 - Retrofit interface for the signing endpoint surface (signature packets + templates).
 * Transport only; no repo / VM / UI.
 *
 * Paths have NO leading slash (relative to the shared Retrofit base URL, matching the rest of the
 * codebase). All calls are suspend. Mutating verbs that send a JSON body carry an explicit JSON
 * Content-Type; the empty-body POSTs (send / mark-done / acknowledge-legal-notice) send no body.
 * Session cookies, Authorization Bearer and X-CSRF-Token are attached globally by the core-network
 * interceptors.
 *
 * RECONCILIATION (return types): the ticket text writes ApiResult of T, but this project has NO
 * ApiResult Retrofit call adapter (KycApi / FilesApi return the RAW DTO / Response, and repositories
 * wrap the call). So every method here returns the raw DTO directly; the future repository (AND-344)
 * wraps these. downloadFinalPdf is a @Streaming raw-bytes Response of ResponseBody (the endpoint
 * returns the assembled PDF, not JSON).
 */
interface SigningApi {

    // ---- Signature packets ----

    @Headers("Content-Type: application/json")
    @POST("v1/signature-packets")
    suspend fun createPacket(
        @Body body: CreateSignaturePacketRequest,
    ): CreateSignaturePacketResponse

    @GET("v1/signature-packets/{packetId}")
    suspend fun getPacket(@Path("packetId") packetId: String): SignaturePacketDetailDto

    @Headers("Content-Type: application/json")
    @POST("v1/signature-packets/{packetId}/fields")
    suspend fun mutateField(
        @Path("packetId") packetId: String,
        @Body body: SignaturePacketFieldMutationRequest,
    ): SignaturePacketFieldMutationResponse

    @Headers("Content-Type: application/json")
    @POST("v1/signature-packets/{packetId}/fields/{fieldId}/fill")
    suspend fun fillField(
        @Path("packetId") packetId: String,
        @Path("fieldId") fieldId: String,
        @Body body: SignaturePacketFieldFillRequest,
    ): SignaturePacketFieldFillResponse

    @POST("v1/signature-packets/{packetId}/send")
    suspend fun sendPacket(@Path("packetId") packetId: String): SendSignaturePacketResponse

    @POST("v1/signature-packets/{packetId}/mark-done")
    suspend fun markDone(@Path("packetId") packetId: String): SignaturePacketMarkDoneResponse

    @POST("v1/signature-packets/{packetId}/acknowledge-legal-notice")
    suspend fun acknowledgeLegalNotice(
        @Path("packetId") packetId: String,
    ): SignaturePacketLegalNoticeAckResponse

    /**
     * SUX-005 - owner revokes a signer's public signing link by its [jti]. The link/create counterpart
     * is not surfaced in this Android client; only revoke is wired here. NOT idempotent (mutating POST).
     */
    @Headers("Content-Type: application/json")
    @POST("v1/signature-packets/{packetId}/signers/{signerId}/link/revoke")
    suspend fun revokeSigningLink(
        @Path("packetId") packetId: String,
        @Path("signerId") signerId: String,
        @Body body: RevokeSigningLinkRequest,
    ): RevokeSigningLinkResponse

    @GET("v1/signature-packets/{packetId}/events")
    suspend fun getEvents(@Path("packetId") packetId: String): SignaturePacketEventsDto

    /**
     * Streamed download of the assembled final PDF. @Streaming means Retrofit does NOT buffer the whole
     * body into memory; the caller copies the byte stream to disk on an IO dispatcher. The body is
     * opaque PDF bytes (NOT JSON), so it is returned as a raw Response of ResponseBody.
     */
    @Streaming
    @GET("v1/signature-packets/{packetId}/final-pdf")
    suspend fun downloadFinalPdf(@Path("packetId") packetId: String): Response<ResponseBody>

    // ---- Signing inbox (SUX-008 browse lists) ----
    //
    // The four browse endpoints that did not exist when AND-339 shipped the load-by-id-only API. All
    // return the same {items, count} envelope ([SigningInboxListDto]); the repository maps it to domain
    // and the SigningInboxViewModel groups the four buckets. `limit` mirrors the web default of 100.

    @GET("v1/signature-packets/awaiting")
    suspend fun listAwaiting(@Query("limit") limit: Int = 100): SigningInboxListDto

    @GET("v1/signature-packets/sent")
    suspend fun listSent(@Query("limit") limit: Int = 100): SigningInboxListDto

    @GET("v1/signature-packets/completed-for-me")
    suspend fun listCompletedForMe(@Query("limit") limit: Int = 100): SigningInboxListDto

    @GET("v1/signature-packets/drafts")
    suspend fun listDrafts(@Query("limit") limit: Int = 100): SigningInboxListDto

    // ---- Templates ----

    @GET("ui/signing/templates")
    suspend fun listTemplates(): SignatureTemplateListDto

    @Headers("Content-Type: application/json")
    @POST("ui/signing/templates")
    suspend fun createTemplateVersion(
        @Body body: CreateSignatureTemplateVersionRequest,
    ): SignatureTemplateVersionDto

    @GET("ui/signing/templates/{templateKey}/versions")
    suspend fun getTemplateVersions(
        @Path("templateKey") templateKey: String,
    ): SignatureTemplateVersionsDto

    @GET("ui/signing/templates/{templateKey}/versions/{version}")
    suspend fun getTemplateVersion(
        @Path("templateKey") templateKey: String,
        @Path("version") version: Int,
    ): SignatureTemplateVersionDto

    @Headers("Content-Type: application/json")
    @POST("ui/signing/templates/migration-check")
    suspend fun migrationCheck(
        @Body body: SignatureTemplateMigrationCheckRequest,
    ): SignatureTemplateMigrationListDto
}
