package com.testlogon.android.feature.disputes

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.disputes.Dispute
import com.testlogon.android.data.disputes.DisputeMoney
import com.testlogon.android.data.disputes.DisputeStatus
import com.testlogon.android.data.disputes.DisputesRepository
import com.testlogon.android.data.disputes.FileDisputeInput
import kotlinx.coroutines.CompletableDeferred

/**
 * AND-245 — a configurable [DisputesRepository] test double. Sample builders are NOT named like an
 * interface member (per the test-helper gotcha): [sampleDispute].
 */
class FakeDisputesRepository : DisputesRepository {

    var listResult: ApiResult<List<Dispute>> = ApiResult.Success(emptyList())
    var detailResult: ApiResult<Dispute> = ApiResult.Success(sampleDispute())
    var fileResult: ApiResult<Dispute> = ApiResult.Success(sampleDispute())

    var fileGate: CompletableDeferred<Unit>? = null
    var fileCalls = 0
        private set

    override suspend fun listDisputes(limit: Int): ApiResult<List<Dispute>> = listResult

    override suspend fun getDispute(id: String): ApiResult<Dispute> = detailResult

    override suspend fun fileDispute(input: FileDisputeInput): ApiResult<Dispute> {
        fileCalls++
        fileGate?.await()
        return fileResult
    }
}

fun sampleDispute(id: String = "dp_1", status: DisputeStatus = DisputeStatus.OPEN): Dispute = Dispute(
    id = id,
    provider = "stripe",
    providerDisputeId = "du_1",
    status = status,
    reason = "Cardholder reports an unauthorized charge.",
    amount = DisputeMoney(4900, "usd"),
    evidenceSubmitted = false,
    evidenceText = null,
    resolution = null,
    transactionEntryId = "le_88a",
    createdAtEpochSeconds = 1_747_749_780L,
    updatedAtEpochSeconds = null,
    deadlineAtEpochSeconds = 1_749_599_999L,
)

internal fun disputeFailure(status: Int): ApiResult<Nothing> =
    ApiResult.Failure(ApiError(status = status, message = "boom"))
