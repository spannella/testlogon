package com.testlogon.android.data.vod.download

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
import androidx.work.workDataOf
import com.testlogon.android.core.model.ApiResult
import dagger.hilt.EntryPoint
import dagger.hilt.InstallIn
import dagger.hilt.android.EntryPointAccessors
import dagger.hilt.components.SingletonComponent
import java.util.concurrent.TimeUnit
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-195 — durable watermarked-download work via WorkManager.
 *
 * Uses the same Hilt [EntryPoint] pattern as AND-106's push worker (no custom WorkerFactory wiring).
 * Runs the entitlement-gated, fail-closed pipeline in [WatermarkDownloadRepository.runDownload]; the
 * download survives process death and resumes on connectivity per the work constraints. A transient
 * (network) failure retries; a permanent failure (NOT_ENTITLED / WATERMARK_FAILED) does not spin.
 */
class WatermarkDownloadWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {

    @EntryPoint
    @InstallIn(SingletonComponent::class)
    interface WorkerEntryPoint {
        fun watermarkDownloadRepository(): WatermarkDownloadRepository
    }

    override suspend fun doWork(): ListenableWorker.Result {
        val videoId = inputData.getString(KEY_VIDEO_ID) ?: return ListenableWorker.Result.failure()
        val repo = EntryPointAccessors
            .fromApplication(applicationContext, WorkerEntryPoint::class.java)
            .watermarkDownloadRepository()
        return resultFor(repo.runDownload(videoId))
    }

    companion object {
        const val KEY_VIDEO_ID = "video_id"
        fun workName(videoId: String): String = "wm-download:$videoId"

        /**
         * Pure mapping (testable without a worker):
         *  - Success            -> success()
         *  - NetworkError       -> retry()
         *  - NETWORK token error -> retry(); other Failure (NOT_ENTITLED / WATERMARK_FAILED) -> failure()
         */
        fun resultFor(result: ApiResult<DownloadedItem>): ListenableWorker.Result = when (result) {
            is ApiResult.Success -> ListenableWorker.Result.success()
            is ApiResult.NetworkError -> ListenableWorker.Result.retry()
            is ApiResult.Failure ->
                if (result.error.code == DownloadError.NETWORK.name ||
                    result.error.code == DownloadError.TOKEN_EXPIRED.name
                ) {
                    ListenableWorker.Result.retry()
                } else {
                    ListenableWorker.Result.failure(workDataOf(KEY_ERR to result.error.code))
                }
        }

        const val KEY_ERR = "error"
    }
}

/** AND-195 — schedules the durable watermarked-download work (unique per video). */
interface WatermarkDownloadScheduler {
    fun enqueue(videoId: String)
}

@Singleton
class WorkManagerWatermarkDownloadScheduler @Inject constructor(
    private val workManager: WorkManager,
) : WatermarkDownloadScheduler {

    override fun enqueue(videoId: String) {
        val request = OneTimeWorkRequestBuilder<WatermarkDownloadWorker>()
            .setConstraints(
                Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build(),
            )
            .setInputData(workDataOf(WatermarkDownloadWorker.KEY_VIDEO_ID to videoId))
            .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
            .build()
        runCatching {
            // KEEP so a re-tap does not double-enqueue an in-flight unique download.
            workManager.enqueueUniqueWork(
                WatermarkDownloadWorker.workName(videoId),
                ExistingWorkPolicy.KEEP,
                request,
            )
        }
    }
}
