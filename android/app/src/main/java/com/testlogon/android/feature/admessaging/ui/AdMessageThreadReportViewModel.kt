package com.testlogon.android.feature.admessaging.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.feature.admessaging.data.AdMessagingRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.launch
import java.util.Collections
import javax.inject.Inject

/**
 * ADV2-504/605/610 — the recipient-side ad-message engagement reporter for the conversation thread.
 *
 * Hosted at the thread route via hiltViewModel so it stays entirely OUT of the giant ThreadViewModel.
 * [reportOpen] fires when a received ad message is shown (the recipient opened/read it -> +5c open
 * surcharge); [reportClick] fires when the recipient taps the CTA (+10c click surcharge). Both are
 * idempotent server-side (bill ONCE per message+recipient); this VM ALSO dedupes per ad_click_id in-
 * process so the beacon fires at most once per session even as the thread recomposes. Every call is best-
 * effort (the repo swallows failures) — a billing beacon never disturbs messaging.
 */
@HiltViewModel
class AdMessageThreadReportViewModel @Inject constructor(
    private val repository: AdMessagingRepository,
) : ViewModel() {

    private val openedReported = Collections.synchronizedSet(mutableSetOf<String>())
    private val clickReported = Collections.synchronizedSet(mutableSetOf<String>())

    /** Report that a received ad message was opened/read. Deduped per ad_click_id per session. */
    fun reportOpen(adClickId: String?) {
        val id = adClickId?.takeIf { it.isNotBlank() } ?: return
        if (!openedReported.add(id)) return
        viewModelScope.launch { repository.reportOpen(id) }
    }

    /** Report a CTA tap on a received ad message. Deduped per ad_click_id per session. */
    fun reportClick(adClickId: String?) {
        val id = adClickId?.takeIf { it.isNotBlank() } ?: return
        if (!clickReported.add(id)) return
        viewModelScope.launch { repository.reportClick(id) }
    }
}
