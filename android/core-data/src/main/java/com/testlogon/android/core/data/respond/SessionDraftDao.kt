package com.testlogon.android.core.data.respond

import androidx.room.Dao
import androidx.room.Query
import androidx.room.Upsert
import kotlinx.coroutines.flow.Flow

/**
 * AND-348 - read/write surface for the [SessionDraftEntity] local respondent-session draft.
 *
 * [observe] lets the ViewModel re-render on any local draft change; [getBySlug] is the one-shot resume
 * read. [setDirty] flips the FR-5 offline flag without rewriting the answers (used to clear dirty after a
 * successful server save, or to re-mark dirty on a failed sync). All writes are suspend (off-main).
 */
@Dao
interface SessionDraftDao {

    @Upsert
    suspend fun upsert(entity: SessionDraftEntity)

    @Query("SELECT * FROM session_draft WHERE slug = :slug LIMIT 1")
    suspend fun getBySlug(slug: String): SessionDraftEntity?

    @Query("SELECT * FROM session_draft WHERE slug = :slug LIMIT 1")
    fun observe(slug: String): Flow<SessionDraftEntity?>

    @Query("UPDATE session_draft SET dirty = :dirty, updated_at = :updatedAt WHERE slug = :slug")
    suspend fun setDirty(slug: String, dirty: Boolean, updatedAt: Long)

    @Query("DELETE FROM session_draft WHERE slug = :slug")
    suspend fun deleteBySlug(slug: String)
}
