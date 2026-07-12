package com.testlogon.android.feature.questionnaire.builder.ui

import com.testlogon.android.feature.questionnaire.builder.data.QnrDraft
import com.testlogon.android.feature.questionnaire.builder.data.QnrQuestion
import com.testlogon.android.feature.questionnaire.builder.data.QnrSection

/**
 * Exhaustive UI state + effects + stable testTags for the questionnaire-BUILDER feature (drafts list,
 * create-draft form, and the per-draft builder editor). Mirrors the apikeys UiState shape (sealed
 * Loading/Content/Empty/Error for lists; a flat form state for create; a one-shot effect Channel).
 */

// ---- Drafts list ----

sealed interface DraftsListUiState {
    data object Loading : DraftsListUiState
    data class Content(
        val items: List<QnrDraft>,
        val isRefreshing: Boolean = false,
    ) : DraftsListUiState
    data object Empty : DraftsListUiState
    data class Error(val message: String) : DraftsListUiState
}

// ---- Create draft form ----

data class CreateDraftForm(
    val title: String = "",
    val description: String = "",
    val visibility: String = "private",
    val submitting: Boolean = false,
    val titleError: String? = null,
    val submitError: String? = null,
) {
    val canSubmit: Boolean get() = title.isNotBlank() && !submitting
}

// ---- Builder editor ----

/** One section with its loaded questions, for the builder editor tree. */
data class BuilderSection(
    val section: QnrSection,
    val questions: List<QnrQuestion>,
)

sealed interface BuilderUiState {
    data object Loading : BuilderUiState
    data class Content(
        val questionnaireId: String,
        val title: String,
        val description: String,
        val visibility: String,
        val status: String,
        val publishedVersionId: String?,
        val sections: List<BuilderSection>,
        /** True while any create/update/delete/publish round-trip is in flight (disables actions). */
        val busy: Boolean = false,
        /** Transient inline action error (e.g. a failed save), cleared on the next edit. */
        val actionError: String? = null,
        /** The publish readiness checklist + outcome (null = dialog not open). */
        val publish: PublishState? = null,
    ) : BuilderUiState
    data class Error(val message: String) : BuilderUiState
}

/** Publish dialog state: the readiness items + (after a successful publish) the new version id. */
data class PublishState(
    val checks: List<String>,
    val ready: Boolean,
    val publishing: Boolean = false,
    val publishedVersionId: String? = null,
    val publishedSlug: String? = null,
)

// ---- Effects (one-shot) ----

sealed interface BuilderEffect {
    data object NavigateToLogin : BuilderEffect
    /** Emitted after a successful create so the create screen pops back to the (refreshing) list. */
    data class DraftCreated(val questionnaireId: String) : BuilderEffect
}

object QuestionnaireBuilderTestTags {
    const val LIST_SCREEN = "qnr_builder_list_screen"
    const val LIST_EMPTY = "qnr_builder_list_empty"
    const val LIST_ERROR_RETRY = "qnr_builder_list_retry"
    const val CREATE_FAB = "qnr_builder_create_fab"

    const val CREATE_SCREEN = "qnr_builder_create_screen"
    const val CREATE_TITLE = "qnr_builder_create_title"
    const val CREATE_DESCRIPTION = "qnr_builder_create_description"
    const val CREATE_SUBMIT = "qnr_builder_create_submit"

    const val BUILDER_SCREEN = "qnr_builder_screen"
    const val BUILDER_TITLE = "qnr_builder_title"
    const val BUILDER_DESCRIPTION = "qnr_builder_description"
    const val ADD_SECTION = "qnr_builder_add_section"
    const val PUBLISH = "qnr_builder_publish"
    const val PUBLISH_CONFIRM = "qnr_builder_publish_confirm"
    const val PUBLISH_DIALOG = "qnr_builder_publish_dialog"

    fun draftRow(id: String) = "qnr_draft_row_$id"
    fun addQuestion(sectionId: String) = "qnr_add_question_$sectionId"
    fun questionCard(id: String) = "qnr_question_$id"
}
