package com.testlogon.android.feature.calendar.scheduler

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.scheduler.ScheduledAction
import com.testlogon.android.data.scheduler.ScheduledActionCreateInDto
import com.testlogon.android.data.scheduler.ScheduledActionUpdateInDto
import com.testlogon.android.data.scheduler.SchedulerRepository
import kotlinx.coroutines.CompletableDeferred
import java.time.Instant

/** AND-275 — pure-JVM fake [SchedulerRepository] for ViewModel tests. */
class FakeSchedulerRepository : SchedulerRepository {

    var loadResult: ApiResult<ScheduledAction> = ApiResult.Success(sampleScheduled())
    var createResult: ApiResult<ScheduledAction> = ApiResult.Success(sampleScheduled())
    var rescheduleResult: ApiResult<ScheduledAction> = ApiResult.Success(sampleScheduled())
    var cancelResult: ApiResult<Unit> = ApiResult.Success(Unit)
    var listResult: ApiResult<List<ScheduledAction>> = ApiResult.Success(emptyList())

    var lastCreate: ScheduledActionCreateInDto? = null
    var lastUpdate: ScheduledActionUpdateInDto? = null
    var createCalls = 0
    var cancelCalls = 0

    /** When set, create suspends until completed — for the double-submit guard test. */
    var createGate: CompletableDeferred<Unit>? = null

    override suspend fun listActions(types: String?, status: String?): ApiResult<List<ScheduledAction>> =
        listResult

    override suspend fun loadAction(actionId: String): ApiResult<ScheduledAction> = loadResult

    override suspend fun create(request: ScheduledActionCreateInDto): ApiResult<ScheduledAction> {
        createCalls++
        lastCreate = request
        createGate?.await()
        return createResult
    }

    override suspend fun reschedule(
        actionId: String,
        request: ScheduledActionUpdateInDto,
    ): ApiResult<ScheduledAction> {
        lastUpdate = request
        return rescheduleResult
    }

    override suspend fun cancel(actionId: String): ApiResult<Unit> {
        cancelCalls++
        return cancelResult
    }

    companion object {
        fun sampleScheduled(
            actionId: String = "act_1",
            actionType: String = "post",
            scheduledSeconds: Long = 1_900_000_000L,
        ) = ScheduledAction(
            actionId = actionId,
            actionType = actionType,
            status = "pending",
            scheduledAt = Instant.ofEpochSecond(scheduledSeconds),
            createdAt = Instant.ofEpochSecond(1_700_000_000L),
            title = "Launch",
            maxRetries = 3,
        )
    }
}
