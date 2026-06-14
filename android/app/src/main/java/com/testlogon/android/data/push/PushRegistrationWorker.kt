package com.testlogon.android.data.push

import android.content.Context
import androidx.work.BackoffPolicy
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.ListenableWorker
import androidx.work.NetworkType
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.push.PushLog
import dagger.hilt.EntryPoint
import dagger.hilt.InstallIn
import dagger.hilt.android.EntryPointAccessors
import dagger.hilt.components.SingletonComponent
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-106 (FR-6) / AND-109 — deferred push (de)registration via WorkManager.
 *
 * When an in-call attempt fails transiently (network / 5xx), the registrar/logout flow enqueues this
 * worker (network-constrained, exponential backoff) so registration survives process death and
 * connectivity loss. The dependency is obtained through a Hilt [EntryPoint] rather than @HiltWorker
 * so no custom WorkerFactory wiring is required (keeps the build/DI graph simple and green).
 *
 *  - Success / no-op  -> Result.success()
 *  - Transient error  -> Result.retry()
 *  - Permanent error (unauthenticated / 4xx) -> Result.failure() (don't spin)
 */
class PushRegistrationWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {

    @EntryPoint
    @InstallIn(SingletonComponent::class)
    interface WorkerEntryPoint {
        fun pushRepository(): PushRepository
    }

    override suspend fun doWork(): Result {
        val repo = EntryPointAccessors
            .fromApplication(applicationContext, WorkerEntryPoint::class.java)
            .pushRepository()
        val action = inputData.getString(KEY_ACTION) ?: ACTION_REGISTER
        val result = when (action) {
            ACTION_DEREGISTER -> repo.deregisterCurrentToken()
            else -> repo.registerCurrentToken()
        }
        return resultFor(result)
    }

    companion object {
        const val KEY_ACTION = "action"
        const val ACTION_REGISTER = "register"
        const val ACTION_DEREGISTER = "deregister"
        const val WORK_REGISTER = "push_register"
        const val WORK_DEREGISTER = "push_deregister"

        /**
         * Pure mapping from an [ApiResult] to a WorkManager [Result] (testable without a worker):
         *  - Success      -> success() (incl. no-op success)
         *  - NetworkError -> retry()
         *  - 5xx Failure  -> retry() (transient)
         *  - other Failure (e.g. 4xx / unauthenticated) -> failure() (don't spin)
         */
        fun resultFor(result: ApiResult<Unit>): ListenableWorker.Result = when (result) {
            is ApiResult.Success -> ListenableWorker.Result.success()
            is ApiResult.NetworkError -> ListenableWorker.Result.retry()
            is ApiResult.Failure ->
                if (result.error.status >= 500) {
                    ListenableWorker.Result.retry()
                } else {
                    ListenableWorker.Result.failure()
                }
        }
    }
}

/** AND-106/109 — schedules the deferred push (de)registration work. */
interface PushWorkScheduler {
    fun enqueueRegister()
    fun enqueueDeregister()
}

@Singleton
class WorkManagerPushScheduler @Inject constructor(
    private val workManager: WorkManager,
) : PushWorkScheduler {

    override fun enqueueRegister() = enqueue(
        PushRegistrationWorker.WORK_REGISTER,
        PushRegistrationWorker.ACTION_REGISTER,
    )

    override fun enqueueDeregister() = enqueue(
        PushRegistrationWorker.WORK_DEREGISTER,
        PushRegistrationWorker.ACTION_DEREGISTER,
    )

    private fun enqueue(uniqueName: String, action: String) {
        val request = OneTimeWorkRequestBuilder<PushRegistrationWorker>()
            .setConstraints(
                Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build(),
            )
            .setInputData(
                androidx.work.workDataOf(PushRegistrationWorker.KEY_ACTION to action),
            )
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
            .build()
        runCatching {
            workManager.enqueueUniqueWork(uniqueName, ExistingWorkPolicy.REPLACE, request)
        }.onFailure { PushLog.d("enqueue $uniqueName failed: ${it.javaClass.simpleName}") }
    }
}
