package com.testlogon.android.feature.account.closure

import com.testlogon.android.core.model.AccountState
import com.testlogon.android.core.model.AccountStatus
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.account.AccountLifecycleRepository
import com.testlogon.android.data.account.ClosureStartResult

/**
 * AND-387 - a controllable [AccountLifecycleRepository] fake for ViewModel tests. Each call returns a preset
 * result and records its invocation BEFORE returning; helper/counter names are distinct so none shadows an
 * interface method. The teardown / getMe side effects of the real impl are not relevant to the VM tests
 * (the VM only observes the [ApiResult]); they are verified separately in the contract test.
 */
class FakeAccountLifecycleRepository : AccountLifecycleRepository {

    var statusResult: ApiResult<AccountStatus> = ApiResult.Success(active())
    var startClosureResult: ApiResult<ClosureStartResult> =
        ApiResult.Success(ClosureStartResult(authRequired = true, challengeId = "ch_re_19", requiredFactors = listOf("password")))
    var finalizeResult: ApiResult<AccountStatus> = ApiResult.Success(closed())
    var suspendResult: ApiResult<AccountStatus> = ApiResult.Success(suspended())
    var reactivateResult: ApiResult<AccountStatus> = ApiResult.Success(active())

    var statusCount = 0
    var startClosureCount = 0
    var finalizeCount = 0
    var suspendCount = 0
    var reactivateCount = 0

    var lastFinalizeChallenge: String? = null
    var lastSuspendReason: String? = null
    var lastReactivateReason: String? = null

    override suspend fun status(): ApiResult<AccountStatus> {
        statusCount++
        return statusResult
    }

    override suspend fun startClosure(): ApiResult<ClosureStartResult> {
        startClosureCount++
        return startClosureResult
    }

    override suspend fun finalizeClosure(challengeId: String): ApiResult<AccountStatus> {
        finalizeCount++
        lastFinalizeChallenge = challengeId
        return finalizeResult
    }

    override suspend fun suspend(reason: String?): ApiResult<AccountStatus> {
        suspendCount++
        lastSuspendReason = reason
        return suspendResult
    }

    override suspend fun reactivate(reason: String?): ApiResult<AccountStatus> {
        reactivateCount++
        lastReactivateReason = reason
        return reactivateResult
    }

    companion object {
        fun active() = AccountStatus(state = AccountState.ACTIVE, rawState = "active")
        fun suspended() = AccountStatus(state = AccountState.SUSPENDED, rawState = "suspended")
        fun closed() = AccountStatus(state = AccountState.CLOSED, rawState = "closed")
        fun closurePending() = AccountStatus(state = AccountState.CLOSURE_PENDING, rawState = "closure_pending")
    }
}
