package com.testlogon.android.feature.adminemail

import androidx.annotation.StringRes
import com.testlogon.android.data.admin.email.AdminEmailMath
import com.testlogon.android.data.admin.email.CampaignTemplate
import com.testlogon.android.data.admin.email.EmailStats
import com.testlogon.android.data.admin.email.SuppressedEmail

/** Top-level tabs of the admin-email hub (templates / suppressed). Stats render as a header on both. */
enum class AdminEmailTab(val label: String) {
    TEMPLATES("Templates"),
    SUPPRESSED("Suppressed"),
}

/** Render-ready state for the admin-email management hub. */
data class AdminEmailUiState(
    val phase: Phase = Phase.Loading,
    val tab: AdminEmailTab = AdminEmailTab.TEMPLATES,
    val stats: EmailStats? = null,
    val templates: List<CampaignTemplate> = emptyList(),
    val suppressed: List<SuppressedEmail> = emptyList(),
    val isRefreshing: Boolean = false,
    val busyId: String? = null,
    val createTemplate: CreateTemplateFormState = CreateTemplateFormState(),
) {
    enum class Phase { Loading, Content, Forbidden, SessionExpired, Error, Offline }

    val isEmptyForTab: Boolean
        get() = when (tab) {
            AdminEmailTab.TEMPLATES -> templates.isEmpty()
            AdminEmailTab.SUPPRESSED -> suppressed.isEmpty()
        }
}

/** Create-campaign-template form. Mirrors the backend field bounds via [AdminEmailMath]. */
data class CreateTemplateFormState(
    val isOpen: Boolean = false,
    val name: String = "",
    val subject: String = "",
    val body: String = "",
    val mergeFields: String = "",
    val isSubmitting: Boolean = false,
) {
    val validationErrors: List<String>
        get() = AdminEmailMath.templateFormErrors(name, subject, body, mergeFields)
    val canSubmit: Boolean
        get() = !isSubmitting && validationErrors.isEmpty()
}

/** One-shot side effects. */
sealed interface AdminEmailEffect {
    data class ShowMessage(@StringRes val resId: Int) : AdminEmailEffect
    data class ShowText(val text: String) : AdminEmailEffect
}
