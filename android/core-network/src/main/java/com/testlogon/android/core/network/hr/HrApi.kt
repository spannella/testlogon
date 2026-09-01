package com.testlogon.android.core.network.hr

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * HRM-009 (Android) — Retrofit interface + Moshi DTOs for the OFBiz HR / Payroll surface.
 *
 * Prefix `/ui/hr`; admin/root only. Feature-flag guarded server-side (hr_enabled / hr_payroll_enabled):
 * when off the backend answers 404 {code:"hr_disabled"|"hr_payroll_disabled"} — the repository/ViewModel
 * degrade that to an empty/unavailable surface rather than an error.
 *
 * VERIFIED against the web contract (frontend/src/api/endpoints/hr.ts) + backend app/routers/hr.py.
 * Money is uniformly integer cents (`*_cents`); dates/timestamps are epoch-SECONDS Longs. Session cookie +
 * Authorization Bearer + X-CSRF-Token are attached by the shared core-network interceptors.
 *
 * Scope here is the READ surface (list/detail/view). The mutating routes (create/patch/terminate/
 * approve/post) exist on the backend but are intentionally NOT surfaced on Android in this pass.
 *
 * Endpoint citations (app/routers/hr.py / hr.ts):
 *  - GET ui/hr/positions                       -> {items:[Position], next_cursor}
 *  - GET ui/hr/positions/{position_id}         -> Position
 *  - GET ui/hr/employments                     -> {items:[Employment], next_cursor}
 *  - GET ui/hr/employments/{employment_id}     -> Employment
 *  - GET ui/hr/payroll                         -> {items:[PayrollRun], next_cursor}
 *  - GET ui/hr/payroll/{payroll_run_id}        -> PayrollRun
 *  - GET ui/hr/payroll/{payroll_run_id}/lines  -> {lines:[PayrollLine]}
 */
interface HrApi {

    /** Paged positions list. `status` filter is optional (OPEN|FILLED|CLOSED). Idempotent GET. */
    @GET("ui/hr/positions")
    suspend fun listPositions(
        @Query("status") status: String? = null,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = DEFAULT_LIMIT,
    ): PositionPageDto

    /** A single position's detail. Idempotent GET. */
    @GET("ui/hr/positions/{position_id}")
    suspend fun getPosition(@Path("position_id") positionId: String): PositionDto

    /** Paged employments list. `party_id`/`status` filters optional. Idempotent GET. */
    @GET("ui/hr/employments")
    suspend fun listEmployments(
        @Query("party_id") partyId: String? = null,
        @Query("status") status: String? = null,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = DEFAULT_LIMIT,
    ): EmploymentPageDto

    /** A single employment's detail. Idempotent GET. */
    @GET("ui/hr/employments/{employment_id}")
    suspend fun getEmployment(@Path("employment_id") employmentId: String): EmploymentDto

    /** Paged payroll-run list. `status` filter optional (DRAFT|APPROVED|POSTED). Idempotent GET. */
    @GET("ui/hr/payroll")
    suspend fun listPayrollRuns(
        @Query("status") status: String? = null,
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int = DEFAULT_LIMIT,
    ): PayrollRunPageDto

    /** A single payroll run (header + embedded lines). Idempotent GET. */
    @GET("ui/hr/payroll/{payroll_run_id}")
    suspend fun getPayrollRun(@Path("payroll_run_id") payrollRunId: String): PayrollRunDto

    /** The payroll run's line breakdown ({lines:[...]}). Idempotent GET. */
    @GET("ui/hr/payroll/{payroll_run_id}/lines")
    suspend fun getPayrollRunLines(@Path("payroll_run_id") payrollRunId: String): PayrollLinesDto

    companion object {
        const val DEFAULT_LIMIT = 50
    }
}

// ---- Position DTOs ----

/** Position (PositionOut). Verified: hr.ts Position. `department` is nullable upstream. */
@JsonClass(generateAdapter = true)
data class PositionDto(
    @Json(name = "position_id") val positionId: String,
    @Json(name = "title") val title: String = "",
    @Json(name = "department") val department: String? = null,
    @Json(name = "status") val status: String = "OPEN",
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class PositionPageDto(
    @Json(name = "items") val items: List<PositionDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

// ---- Employment DTOs ----

/** Employment (EmploymentOut). Verified: hr.ts Employment. `end_date` nullable (null = still active). */
@JsonClass(generateAdapter = true)
data class EmploymentDto(
    @Json(name = "employment_id") val employmentId: String,
    @Json(name = "party_id") val partyId: String = "",
    @Json(name = "position_id") val positionId: String = "",
    @Json(name = "org_party_id") val orgPartyId: String = "",
    @Json(name = "status") val status: String = "ACTIVE",
    @Json(name = "start_date") val startDate: Long = 0,
    @Json(name = "end_date") val endDate: Long? = null,
    @Json(name = "pay_rate_cents") val payRateCents: Long = 0,
    @Json(name = "pay_period") val payPeriod: String = "MONTHLY",
    @Json(name = "currency") val currency: String = "USD",
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
)

@JsonClass(generateAdapter = true)
data class EmploymentPageDto(
    @Json(name = "items") val items: List<EmploymentDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

// ---- Payroll DTOs ----

/** A single payroll line (gross pay for one employment). Verified: hr.ts PayrollLine. */
@JsonClass(generateAdapter = true)
data class PayrollLineDto(
    @Json(name = "employment_id") val employmentId: String = "",
    @Json(name = "party_id") val partyId: String = "",
    @Json(name = "gross_cents") val grossCents: Long = 0,
    @Json(name = "currency") val currency: String = "USD",
)

/** PayrollRun (PayrollRunOut). Verified: hr.ts PayrollRun. `lines` embedded; period_* epoch-seconds. */
@JsonClass(generateAdapter = true)
data class PayrollRunDto(
    @Json(name = "payroll_run_id") val payrollRunId: String,
    @Json(name = "period_start") val periodStart: Long = 0,
    @Json(name = "period_end") val periodEnd: Long = 0,
    @Json(name = "status") val status: String = "DRAFT",
    @Json(name = "lines") val lines: List<PayrollLineDto> = emptyList(),
    @Json(name = "created_at") val createdAt: Long = 0,
    @Json(name = "updated_at") val updatedAt: Long = 0,
    @Json(name = "approved_by") val approvedBy: String? = null,
    @Json(name = "posted_at") val postedAt: Long? = null,
)

@JsonClass(generateAdapter = true)
data class PayrollRunPageDto(
    @Json(name = "items") val items: List<PayrollRunDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

/** PayrollLinesResp. Verified: hr.ts PayrollLinesResp — the flat {lines:[...]} envelope. */
@JsonClass(generateAdapter = true)
data class PayrollLinesDto(
    @Json(name = "lines") val lines: List<PayrollLineDto> = emptyList(),
)
