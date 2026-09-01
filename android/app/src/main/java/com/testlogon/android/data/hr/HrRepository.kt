package com.testlogon.android.data.hr

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.model.hr.Employment
import com.testlogon.android.core.model.hr.EmploymentStatus
import com.testlogon.android.core.model.hr.HrMoney
import com.testlogon.android.core.model.hr.HrPage
import com.testlogon.android.core.model.hr.PayPeriod
import com.testlogon.android.core.model.hr.PayrollLine
import com.testlogon.android.core.model.hr.PayrollRun
import com.testlogon.android.core.model.hr.PayrollRunStatus
import com.testlogon.android.core.model.hr.Position
import com.testlogon.android.core.model.hr.PositionStatus
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.hr.EmploymentDto
import com.testlogon.android.core.network.hr.HrApi
import com.testlogon.android.core.network.hr.PayrollLineDto
import com.testlogon.android.core.network.hr.PayrollRunDto
import com.testlogon.android.core.network.hr.PositionDto
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * HRM-009 (Android) — HR / Payroll read data layer over [HrApi].
 *
 * Wraps every call in [ApiResult] (matching the invoices/billing repositories): CancellationException is
 * re-thrown; HTTP errors fold to Failure (via [ApiErrorParser]) — a 404 there is the feature-flag-off
 * signal the ViewModel degrades to "unavailable"; transport failures to NetworkError. DTOs are mapped to
 * core-model domain before returning (no raw DTOs leak out).
 *
 * All reads are idempotent GETs (the core-network RetryInterceptor handles bounded retry on network
 * errors). No mutating routes are surfaced in this pass.
 */
interface HrRepository {

    suspend fun listPositions(status: String?, cursor: String?, limit: Int): ApiResult<HrPage<Position>>
    suspend fun getPosition(positionId: String): ApiResult<Position>

    suspend fun listEmployments(
        partyId: String?,
        status: String?,
        cursor: String?,
        limit: Int,
    ): ApiResult<HrPage<Employment>>

    suspend fun getEmployment(employmentId: String): ApiResult<Employment>

    suspend fun listPayrollRuns(status: String?, cursor: String?, limit: Int): ApiResult<HrPage<PayrollRun>>
    suspend fun getPayrollRun(payrollRunId: String): ApiResult<PayrollRun>
    suspend fun getPayrollRunLines(payrollRunId: String): ApiResult<List<PayrollLine>>
}

@Singleton
class HrRepositoryImpl @Inject constructor(
    private val api: HrApi,
    private val errorParser: ApiErrorParser,
) : HrRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun listPositions(
        status: String?,
        cursor: String?,
        limit: Int,
    ): ApiResult<HrPage<Position>> = withContext(io) {
        call { api.listPositions(status = status, cursor = cursor, limit = limit) }
            .map { dto -> HrPage(dto.items.map { it.toDomain() }, dto.nextCursor?.takeIf { it.isNotBlank() }) }
    }

    override suspend fun getPosition(positionId: String): ApiResult<Position> = withContext(io) {
        call { api.getPosition(positionId) }.map { it.toDomain() }
    }

    override suspend fun listEmployments(
        partyId: String?,
        status: String?,
        cursor: String?,
        limit: Int,
    ): ApiResult<HrPage<Employment>> = withContext(io) {
        call { api.listEmployments(partyId = partyId, status = status, cursor = cursor, limit = limit) }
            .map { dto -> HrPage(dto.items.map { it.toDomain() }, dto.nextCursor?.takeIf { it.isNotBlank() }) }
    }

    override suspend fun getEmployment(employmentId: String): ApiResult<Employment> = withContext(io) {
        call { api.getEmployment(employmentId) }.map { it.toDomain() }
    }

    override suspend fun listPayrollRuns(
        status: String?,
        cursor: String?,
        limit: Int,
    ): ApiResult<HrPage<PayrollRun>> = withContext(io) {
        call { api.listPayrollRuns(status = status, cursor = cursor, limit = limit) }
            .map { dto -> HrPage(dto.items.map { it.toDomain() }, dto.nextCursor?.takeIf { it.isNotBlank() }) }
    }

    override suspend fun getPayrollRun(payrollRunId: String): ApiResult<PayrollRun> = withContext(io) {
        call { api.getPayrollRun(payrollRunId) }.map { it.toDomain() }
    }

    override suspend fun getPayrollRunLines(payrollRunId: String): ApiResult<List<PayrollLine>> =
        withContext(io) {
            call { api.getPayrollRunLines(payrollRunId) }.map { dto -> dto.lines.map { it.toDomain() } }
        }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}

// ---- Mappers (DTO -> core-model domain). TOTAL: unknown enums -> UNKNOWN, 0 timestamps -> null. ----

private fun Long.epochSecondsOrNull(): Long? = takeIf { it > 0 }
private fun Long?.epochSecondsOrNull(): Long? = this?.takeIf { it > 0 }

internal fun PositionDto.toDomain(): Position = Position(
    positionId = positionId,
    title = title,
    department = department?.takeIf { it.isNotBlank() },
    status = PositionStatus.fromWire(status),
    createdAtEpochSeconds = createdAt.epochSecondsOrNull(),
    updatedAtEpochSeconds = updatedAt.epochSecondsOrNull(),
)

internal fun EmploymentDto.toDomain(): Employment = Employment(
    employmentId = employmentId,
    partyId = partyId,
    positionId = positionId,
    orgPartyId = orgPartyId,
    status = EmploymentStatus.fromWire(status),
    startDateEpochSeconds = startDate.epochSecondsOrNull(),
    endDateEpochSeconds = endDate.epochSecondsOrNull(),
    payRate = HrMoney(payRateCents, currency),
    payPeriod = PayPeriod.fromWire(payPeriod),
    createdAtEpochSeconds = createdAt.epochSecondsOrNull(),
    updatedAtEpochSeconds = updatedAt.epochSecondsOrNull(),
)

internal fun PayrollLineDto.toDomain(): PayrollLine = PayrollLine(
    employmentId = employmentId,
    partyId = partyId,
    gross = HrMoney(grossCents, currency),
)

internal fun PayrollRunDto.toDomain(): PayrollRun = PayrollRun(
    payrollRunId = payrollRunId,
    periodStartEpochSeconds = periodStart.epochSecondsOrNull(),
    periodEndEpochSeconds = periodEnd.epochSecondsOrNull(),
    status = PayrollRunStatus.fromWire(status),
    lines = lines.map { it.toDomain() },
    approvedBy = approvedBy?.takeIf { it.isNotBlank() },
    postedAtEpochSeconds = postedAt.epochSecondsOrNull(),
    createdAtEpochSeconds = createdAt.epochSecondsOrNull(),
    updatedAtEpochSeconds = updatedAt.epochSecondsOrNull(),
)
