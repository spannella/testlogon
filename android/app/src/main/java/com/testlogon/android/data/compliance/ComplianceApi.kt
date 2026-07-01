package com.testlogon.android.data.compliance

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * Retrofit interface + Moshi DTOs for the Compliance / Security agent (web /agents/compliance AND
 * /agents/security — the web reuses ComplianceAgentConfigPage for both). Mirrors
 * frontend/src/api/endpoints/complianceAgent.ts (BASE /ui/agents/compliance): security findings list +
 * status PATCH, audit history + trigger, framework compliance status, and finding trends. All endpoints
 * are backend `require_ui_session` (agent_compliance.py) -> usable by any authenticated user (no operator
 * gate). Finding / audit / trend timestamps are epoch-SECONDS (Long). Session cookies / Bearer /
 * X-CSRF-Token attached by interceptors; paths relative (base URL carries the trailing slash).
 */
interface ComplianceApi {

    @GET("ui/agents/compliance/findings")
    suspend fun listFindings(
        @Query("severity") severity: String? = null,
        @Query("status") status: String? = null,
        @Query("source_ref") sourceRef: String? = null,
        @Query("limit") limit: Int? = null,
    ): SecurityFindingsListDto

    @GET("ui/agents/compliance/findings/{findingId}")
    suspend fun getFinding(@Path("findingId") findingId: String): SecurityFindingDto

    @PATCH("ui/agents/compliance/findings/{findingId}/status")
    suspend fun updateFindingStatus(
        @Path("findingId") findingId: String,
        @Body body: UpdateFindingStatusReqDto,
    ): SecurityFindingDto

    @GET("ui/agents/compliance/audits")
    suspend fun listAudits(@Query("limit") limit: Int = 20): SecurityAuditsListDto

    @POST("ui/agents/compliance/audits/trigger")
    suspend fun triggerAudit(@Body body: Map<String, String> = emptyMap()): SecurityAuditDto

    @GET("ui/agents/compliance/trends")
    suspend fun getTrends(@Query("days") days: Int = 90): SecurityTrendsDto

    @GET("ui/agents/compliance/compliance")
    suspend fun getComplianceStatus(): ComplianceStatusDto
}

// ---- DTOs ----

@JsonClass(generateAdapter = true)
data class SecurityFindingDto(
    @Json(name = "finding_id") val findingId: String = "",
    @Json(name = "agent_id") val agentId: String = "",
    val source: String = "",
    @Json(name = "source_ref") val sourceRef: String = "",
    val severity: String = "",
    val category: String = "",
    val title: String = "",
    val description: String = "",
    @Json(name = "file_path") val filePath: String? = null,
    @Json(name = "line_range") val lineRange: String? = null,
    @Json(name = "code_snippet") val codeSnippet: String? = null,
    val remediation: String? = null,
    val status: String = "",
    @Json(name = "remediation_ticket_id") val remediationTicketId: String? = null,
    val note: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class SecurityFindingsListDto(
    val findings: List<SecurityFindingDto> = emptyList(),
    val count: Int = 0,
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class UpdateFindingStatusReqDto(
    val status: String,
    val note: String? = null,
)

@JsonClass(generateAdapter = true)
data class SecurityAuditDto(
    @Json(name = "audit_id") val auditId: String = "",
    @Json(name = "agent_id") val agentId: String = "",
    val status: String = "",
    @Json(name = "started_at") val startedAt: Long = 0,
    @Json(name = "completed_at") val completedAt: Long? = null,
    @Json(name = "finding_counts") val findingCounts: Map<String, Int> = emptyMap(),
    @Json(name = "files_scanned") val filesScanned: Int = 0,
)

@JsonClass(generateAdapter = true)
data class SecurityAuditsListDto(
    val audits: List<SecurityAuditDto> = emptyList(),
    val count: Int = 0,
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class SecurityTrendWeekDto(
    @Json(name = "week_start") val weekStart: Long = 0,
    @Json(name = "by_severity") val bySeverity: Map<String, Int> = emptyMap(),
    val total: Int = 0,
)

@JsonClass(generateAdapter = true)
data class SecurityTrendsDto(
    val weeks: List<SecurityTrendWeekDto> = emptyList(),
    val days: Int = 0,
    val total: Int = 0,
)

@JsonClass(generateAdapter = true)
data class ComplianceFrameworkStatusDto(
    val name: String = "",
    val passed: Int = 0,
    val failed: Int = 0,
    @Json(name = "open_findings") val openFindings: Int = 0,
    val status: String = "",
)

@JsonClass(generateAdapter = true)
data class ComplianceStatusDto(
    val frameworks: Map<String, ComplianceFrameworkStatusDto> = emptyMap(),
)
