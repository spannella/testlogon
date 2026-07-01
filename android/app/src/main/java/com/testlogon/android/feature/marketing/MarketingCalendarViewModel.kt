package com.testlogon.android.feature.marketing

import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.marketing.MarketingRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import java.util.Calendar
import javax.inject.Inject

/**
 * Drives [MarketingCalendarUiState] for the content calendar (web MarketingContentCalendarPage). Loads
 * scheduled/published entries for a YYYY-MM month; Prev/Next/Today shift the month and reload. Month
 * arithmetic uses java.util.Calendar (java.time unavailable) and is unit-testable via [shiftMonth].
 */
@HiltViewModel
class MarketingCalendarViewModel @Inject constructor(
    private val repository: MarketingRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(MarketingCalendarUiState(month = currentMonth()))
    val uiState: StateFlow<MarketingCalendarUiState> = _uiState.asStateFlow()

    init {
        load()
    }

    fun onRetry() = load()
    fun onPrevMonth() = setMonth(shiftMonth(_uiState.value.month, -1))
    fun onNextMonth() = setMonth(shiftMonth(_uiState.value.month, 1))
    fun onToday() = setMonth(currentMonth())

    private fun setMonth(month: String) {
        if (month == _uiState.value.month) return
        _uiState.update { it.copy(month = month, phase = MarketingCalendarUiState.Phase.Loading) }
        load()
    }

    private fun load() {
        val month = _uiState.value.month
        _uiState.update {
            it.copy(phase = if (it.entries.isEmpty()) MarketingCalendarUiState.Phase.Loading else it.phase)
        }
        viewModelScope.launch {
            when (val result = repository.loadCalendar(month)) {
                is ApiResult.Success ->
                    _uiState.update {
                        it.copy(
                            phase = if (result.data.isEmpty()) MarketingCalendarUiState.Phase.Empty else MarketingCalendarUiState.Phase.Content,
                            entries = result.data,
                            errorMessage = null,
                        )
                    }
                is ApiResult.Failure ->
                    if (result.error.status == HTTP_UNAUTHORIZED) {
                        _uiState.update { it.copy(phase = MarketingCalendarUiState.Phase.SessionExpired) }
                    } else {
                        _uiState.update {
                            it.copy(phase = MarketingCalendarUiState.Phase.Error, errorMessage = result.error.message)
                        }
                    }
                is ApiResult.NetworkError ->
                    _uiState.update {
                        it.copy(phase = MarketingCalendarUiState.Phase.Offline, errorMessage = OFFLINE_FALLBACK)
                    }
            }
        }
    }

    companion object {
        private const val HTTP_UNAUTHORIZED = 401
        private const val OFFLINE_FALLBACK = "Could not reach the server. Retry."

        fun currentMonth(): String {
            val c = Calendar.getInstance()
            return format(c.get(Calendar.YEAR), c.get(Calendar.MONTH) + 1)
        }

        /** Shift a YYYY-MM string by [delta] months. Pure + unit-testable. */
        fun shiftMonth(month: String, delta: Int): String {
            val parts = month.split("-")
            val y = parts.getOrNull(0)?.toIntOrNull() ?: Calendar.getInstance().get(Calendar.YEAR)
            val m = parts.getOrNull(1)?.toIntOrNull() ?: 1
            val c = Calendar.getInstance()
            c.clear()
            c.set(y, m - 1, 1)
            c.add(Calendar.MONTH, delta)
            return format(c.get(Calendar.YEAR), c.get(Calendar.MONTH) + 1)
        }

        private fun format(year: Int, month: Int): String =
            "%04d-%02d".format(year, month)
    }
}
