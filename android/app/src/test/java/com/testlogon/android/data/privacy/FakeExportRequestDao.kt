package com.testlogon.android.data.privacy

import com.testlogon.android.core.data.privacy.ExportRequestDao
import com.testlogon.android.core.data.privacy.ExportRequestEntity
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.map

/**
 * AND-385 - an in-memory [ExportRequestDao] for JVM tests (no Room/Robolectric). Mirrors the real DAO's
 * newest-first ordering and the transactional [replaceAll]. Distinct helper names so nothing shadows the
 * interface methods.
 */
class FakeExportRequestDao(seed: List<ExportRequestEntity> = emptyList()) : ExportRequestDao {

    private val state = MutableStateFlow(seed.sortedByDescending { it.requestedAt })

    override fun observeAll(): Flow<List<ExportRequestEntity>> =
        state.map { it.sortedByDescending { e -> e.requestedAt } }

    override suspend fun getAll(): List<ExportRequestEntity> =
        state.value.sortedByDescending { it.requestedAt }

    override suspend fun upsert(entity: ExportRequestEntity) {
        state.value = (state.value.filterNot { it.id == entity.id } + entity)
    }

    override suspend fun upsertAll(entities: List<ExportRequestEntity>) {
        val ids = entities.map { it.id }.toSet()
        state.value = state.value.filterNot { it.id in ids } + entities
    }

    override suspend fun clearAll() {
        state.value = emptyList()
    }

    /** Snapshot helper for assertions. */
    fun snapshot(): List<ExportRequestEntity> = state.value.sortedByDescending { it.requestedAt }
}
