package com.testlogon.android.feature.questionnaire.respond.data

import com.testlogon.android.core.data.respond.SessionDraftEntity
import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.RespondentSession
import com.testlogon.android.core.model.questionnaire.SessionState
import com.testlogon.android.core.model.questionnaire.SessionStateEnvelope
import com.testlogon.android.core.model.questionnaire.SessionStatus

/**
 * AND-348 - mappers between AND-346's wire DTOs / the Room draft and the [RespondentSession] domain.
 *
 * The wire session object does NOT carry the published slug (it is a nav arg), so every mapper takes
 * the [slug] explicitly. Unknown wire status -> [SessionStatus.IN_PROGRESS] (never throws).
 */

/** Maps a [SessionStateEnvelope] (GET / PUT response) + the nav [slug] to a [RespondentSession]. */
fun SessionStateEnvelope.toDomain(slug: String): RespondentSession =
    session.toDomain(slug, answers_by_question_id)

/** Maps a typed [SessionState] + an answers map to a [RespondentSession]. */
fun SessionState.toDomain(
    slug: String,
    answers: Map<String, AnswerValue>,
): RespondentSession = RespondentSession(
    sessionId = response_session_id,
    slug = slug,
    questionnaireId = questionnaire_id,
    versionId = version_id,
    answers = answers,
    status = SessionStatus.fromWire(status),
    currentSectionIndex = current_section_index,
    currentQuestionId = current_question_id,
)

/**
 * Maps the local Room draft to a [RespondentSession] using [decodeAnswers] to inflate the answers JSON.
 * Status is always [SessionStatus.IN_PROGRESS] (a submitted session has no editable draft).
 */
fun SessionDraftEntity.toDomain(
    decodeAnswers: (String?) -> Map<String, AnswerValue>,
): RespondentSession = RespondentSession(
    sessionId = sessionId,
    slug = slug,
    questionnaireId = questionnaireId,
    versionId = versionId,
    answers = decodeAnswers(answersJson),
    status = SessionStatus.IN_PROGRESS,
    currentSectionIndex = currentSectionIndex,
    currentQuestionId = currentQuestionId,
)

/**
 * Builds the Room draft row for [session] with the given [dirty] flag and [encodeAnswers] serializer.
 * [updatedAt] is the caller's clock (epoch ms) so writes are testable.
 */
fun RespondentSession.toDraftEntity(
    dirty: Boolean,
    updatedAt: Long,
    encodeAnswers: (Map<String, AnswerValue>) -> String,
): SessionDraftEntity = SessionDraftEntity(
    slug = slug,
    sessionId = sessionId,
    questionnaireId = questionnaireId,
    versionId = versionId,
    answersJson = encodeAnswers(answers),
    currentSectionIndex = currentSectionIndex,
    currentQuestionId = currentQuestionId,
    dirty = dirty,
    updatedAt = updatedAt,
)
