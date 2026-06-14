package com.testlogon.android.data.vod.download

import com.testlogon.android.core.data.download.DownloadDao
import com.testlogon.android.core.data.download.DownloadEntity
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map

/** In-memory fake [DownloadDao] for JVM unit tests. */
class FakeDownloadDao : DownloadDao {
    private val rows = MutableStateFlow<List<DownloadEntity>>(emptyList())

    override fun observe(videoId: String): Flow<DownloadEntity?> =
        rows.map { list -> list.firstOrNull { it.videoId == videoId } }

    override suspend fun get(videoId: String): DownloadEntity? =
        rows.value.firstOrNull { it.videoId == videoId }

    override fun completed(): Flow<List<DownloadEntity>> =
        rows.map { list -> list.filter { it.status == "COMPLETED" } }

    override suspend fun upsert(entity: DownloadEntity) {
        rows.value = rows.value.filterNot { it.videoId == entity.videoId } + entity
    }

    override suspend fun delete(videoId: String) {
        rows.value = rows.value.filterNot { it.videoId == videoId }
    }

    fun snapshot(): List<DownloadEntity> = rows.value
}
