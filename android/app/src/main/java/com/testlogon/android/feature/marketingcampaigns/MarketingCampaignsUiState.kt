package com.testlogon.android.feature.marketingcampaigns

import androidx.annotation.StringRes
import com.testlogon.android.data.marketing.campaigns.ContactList
import com.testlogon.android.data.marketing.campaigns.MarketingCampaign
import com.testlogon.android.data.marketing.campaigns.MarketingMath
import com.testlogon.android.data.marketing.campaigns.PartySegment

/** Top-level tabs of the Marketing-campaigns hub (web MKT: campaigns / lists / segments). */
enum class MarketingCampaignsTab(val label: String) {
    CAMPAIGNS("Campaigns"),
    LISTS("Lists"),
    SEGMENTS("Segments"),
}

/** Render-ready state for the Marketing-campaigns hub. */
data class MarketingCampaignsUiState(
    val phase: Phase = Phase.Loading,
    val tab: MarketingCampaignsTab = MarketingCampaignsTab.CAMPAIGNS,
    val campaigns: List<MarketingCampaign> = emptyList(),
    val lists: List<ContactList> = emptyList(),
    val segments: List<PartySegment> = emptyList(),
    val isRefreshing: Boolean = false,
    val errorMessage: String? = null,
    val busyCampaignId: String? = null,
    val createCampaign: CreateCampaignFormState = CreateCampaignFormState(),
    val createList: CreateListFormState = CreateListFormState(),
) {
    enum class Phase { Loading, Content, SessionExpired, Error, Offline }

    val isEmptyForTab: Boolean
        get() = when (tab) {
            MarketingCampaignsTab.CAMPAIGNS -> campaigns.isEmpty()
            MarketingCampaignsTab.LISTS -> lists.isEmpty()
            MarketingCampaignsTab.SEGMENTS -> segments.isEmpty()
        }
}

/** Create-campaign form. Mirrors the web validation: name + objective + non-negative budget. */
data class CreateCampaignFormState(
    val isOpen: Boolean = false,
    val name: String = "",
    val objective: MarketingMath.CampaignObjective = MarketingMath.CampaignObjective.AWARENESS,
    val budget: String = "",
    val isSubmitting: Boolean = false,
) {
    val budgetCents: Long? get() = MarketingMath.parseBudgetToCents(budget.ifBlank { "0" })
    val canSubmit: Boolean
        get() = !isSubmitting && name.trim().isNotEmpty() && budgetCents != null
}

/** Create contact-list form. Name required; description optional. */
data class CreateListFormState(
    val isOpen: Boolean = false,
    val name: String = "",
    val description: String = "",
    val isSubmitting: Boolean = false,
) {
    val canSubmit: Boolean get() = !isSubmitting && name.trim().isNotEmpty()
}

/** One-shot side effects. */
sealed interface MarketingCampaignsEffect {
    data class ShowMessage(@StringRes val resId: Int) : MarketingCampaignsEffect
    data class ShowText(val text: String) : MarketingCampaignsEffect
}
