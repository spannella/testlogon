package com.testlogon.android.feature.refunds

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.refunds.RefundMoney
import com.testlogon.android.data.refunds.RefundRequest
import com.testlogon.android.data.refunds.RefundStatus
import com.testlogon.android.data.refunds.RefundsRepository
import com.testlogon.android.data.refunds.SubmitRefundInput
import kotlinx.coroutines.CompletableDeferred

/**
 * AND-244 — a configurable [RefundsRepository] test double. Sample builders are NOT named like an
 * interface member (per the test-helper gotcha): [sampleRefund].
 */
class FakeRefundsRepository : RefundsRepository {

    var listResult: ApiResult<List<RefundRequest>> = ApiResult.Success(emptyList())
    var detailResult: ApiResult<RefundRequest> = ApiResult.Success(sampleRefund())
    var submitResult: ApiResult<RefundRequest> = ApiResult.Success(sampleRefund())

    /** When set, submit suspends on this gate so a double-submit test can run while in flight. */
    var submitGate: CompletableDeferred<Unit>? = null

    var submitCalls = 0
        private set

    override suspend fun listRefunds(limit: Int): ApiResult<List<RefundRequest>> = listResult

    override suspend fun getRefund(id: String): ApiResult<RefundRequest> = detailResult

    override suspend fun submitRefund(input: SubmitRefundInput): ApiResult<RefundRequest> {
        submitCalls++
        submitGate?.await()
        return submitResult
    }
}

fun sampleRefund(id: String = "rfnd_1", status: RefundStatus = RefundStatus.PENDING): RefundRequest =
    RefundRequest(
        id = id,
        transactionEntryId = "entry_1",
        status = status,
        reason = "Charged twice for the same item",
        amount = RefundMoney(1299, "usd"),
        transactionType = "charge",
        adminNotes = null,
        createdAtEpochSeconds = 1_749_124_800L,
        completedAtEpochSeconds = null,
    )

internal fun failure(status: Int): ApiResult<Nothing> = ApiResult.Failure(ApiError(status = status, message = "boom"))
