package com.testlogon.android.feature.privacy.deletion

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.privacy.AccountDeletionRepository
import com.testlogon.android.data.privacy.DeletionStatus

/**
 * AND-386 - a controllable [AccountDeletionRepository] fake for ViewModel tests. Network calls return preset
 * results and record their invocations; helper names are distinct so none shadows an interface method. A
 * recording call records BEFORE returning. The status results are settable; [lastKnown] backs the offline
 * stale view.
 */
class FakeAccountDeletionRepository(
    var statusResult: ApiResult<DeletionStatus> = ApiResult.Success(DeletionStatus.Active),
) : AccountDeletionRepository {

    var requestResult: ApiResult<DeletionStatus.Pending> = ApiResult.Success(
        DeletionStatus.Pending(
            requestId = "del_x",
            createdAtEpochMs = 1_000L,
            scheduledForEpochMs = 2_000L,
            graceDaysRemaining = 14,
            canCancel = true,
        ),
    )
    var cancelResult: ApiResult<DeletionStatus> = ApiResult.Success(DeletionStatus.Active)
    var lastKnown: DeletionStatus? = null

    var statusCount = 0
    var requestCount = 0
    val cancelCalls = mutableListOf<String>()

    // Captured args of the last requestDeletion call.
    var lastPassword: String? = null
    var lastConfirmText: String? = null
    var lastReason: String? = null

    override suspend fun getStatus(): ApiResult<DeletionStatus> {
        statusCount++
        return statusResult
    }

    override suspend fun requestDeletion(
        password: String,
        confirmText: String,
        reason: String?,
    ): ApiResult<DeletionStatus.Pending> {
        requestCount++
        lastPassword = password
        lastConfirmText = confirmText
        lastReason = reason
        return requestResult
    }

    override suspend fun cancelDeletion(requestId: String): ApiResult<DeletionStatus> {
        cancelCalls += requestId
        return cancelResult
    }

    override suspend fun lastKnownStatus(): DeletionStatus? = lastKnown

    override suspend fun clearCache() {
        lastKnown = null
    }
}
