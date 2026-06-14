package com.testlogon.android.core.data.respond

import androidx.room.ColumnInfo
import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * AND-348 - the durable on-device draft of a respondent's in-progress questionnaire session.
 *
 * KEYED BY [slug] (the published-questionnaire nav arg): FR-7 mandates a SINGLE active session per slug
 * per device, so the slug is the primary key (a new start-over replaces the row in place).
 *
 * Unlike the AND-115 cache tables this is NOT a [com.testlogon.android.core.data.db.CacheEntity]: it is
 * authoritative-until-synced local state (the user's typed answers), not a refetchable cache row, so it
 * deliberately carries no TTL/LRU metadata and is never swept by the cache maintenance DAO. It mirrors
 * the AND-302 pending_recording standalone-entity shape.
 *
 * [answersJson] holds the answers map serialized to JSON via the INJECTED Moshi (AnswerValue has a
 * registered custom adapter from AND-346); no new dependency and no hand-rolled JSON. [dirty] is the
 * FR-5 offline flag: set true on every local write, cleared only after a successful server save.
 */
@Entity(tableName = "session_draft")
data class SessionDraftEntity(
    @PrimaryKey @ColumnInfo(name = "slug") val slug: String,
    @ColumnInfo(name = "session_id") val sessionId: String,
    @ColumnInfo(name = "questionnaire_id") val questionnaireId: String,
    @ColumnInfo(name = "version_id") val versionId: String,
    @ColumnInfo(name = "answers_json") val answersJson: String,
    @ColumnInfo(name = "current_section_index") val currentSectionIndex: Int? = null,
    @ColumnInfo(name = "current_question_id") val currentQuestionId: String? = null,
    @ColumnInfo(name = "dirty", defaultValue = "0") val dirty: Boolean = false,
    @ColumnInfo(name = "updated_at", defaultValue = "0") val updatedAt: Long = 0L,
)
