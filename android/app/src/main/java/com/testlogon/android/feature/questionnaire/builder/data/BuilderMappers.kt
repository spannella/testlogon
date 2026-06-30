package com.testlogon.android.feature.questionnaire.builder.data

import com.testlogon.android.core.network.questionnaire.QnrDraftDto
import com.testlogon.android.core.network.questionnaire.QnrQuestionDto
import com.testlogon.android.core.network.questionnaire.QnrSectionDto
import com.testlogon.android.core.network.questionnaire.QnrVersionDto

/**
 * DTO -> domain mappers for the questionnaire builder. They live in :app (NOT core-model) because
 * core-model cannot depend on core-network; mirrors the apikeys ApiKeyMappers pattern. Missing optional
 * strings default to "".
 */

fun QnrDraftDto.toDomain(): QnrDraft = QnrDraft(
    questionnaireId = questionnaireId,
    title = title.orEmpty(),
    description = description.orEmpty(),
    status = status.orEmpty().ifBlank { "draft" },
    visibility = visibility.orEmpty().ifBlank { "private" },
    publishedVersionId = publishedVersionId,
    updatedAt = updatedAt,
)

fun QnrSectionDto.toDomain(): QnrSection = QnrSection(
    sectionId = sectionId,
    title = title.orEmpty(),
    description = description.orEmpty(),
    position = position,
)

fun QnrQuestionDto.toDomain(): QnrQuestion = QnrQuestion(
    questionId = questionId,
    sectionId = sectionId,
    type = QnrQuestionType.fromWire(type),
    label = label.orEmpty(),
    required = required,
    hint = hint.orEmpty(),
    configJson = configJson,
    position = position,
)

fun QnrVersionDto.toDomain(): QnrPublishedVersion = QnrPublishedVersion(
    versionId = versionId,
    publishedSlug = publishedSlug,
    publishedAt = publishedAt,
)
