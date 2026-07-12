package com.testlogon.android.core.network.ads

import com.squareup.moshi.Json

/**
 * Ad SCHEDULING (dayparting + flights) transport DTOs (web parity: /ads/scheduling -> ad_dayparting.py,
 * prefix /ui/ads/scheduling).
 *
 * Mirrors the backend shapes: schedule templates (named day->hours maps), the per-campaign schedule
 * (dayparting {timezone, schedule:{day:[hours]}} + flights[] + campaign_timezone), the PATCH update body,
 * the eligibility debug result, and the pacing result. Reflective Moshi (no codegen): explicit @Json on
 * every wire key. The dayparting `schedule` is a Map<day, List<hour>>; templates are the same shape.
 */

/** Response from GET /templates: { templates: { name: { day: [hours] } } }. */
data class ScheduleTemplatesDto(
    @Json(name = "templates") val templates: Map<String, Map<String, List<Int>>> = emptyMap(),
)

/** The dayparting block: a timezone + day-of-week -> active hours (0-23). */
data class DaypartingDto(
    @Json(name = "timezone") val timezone: String = "UTC",
    @Json(name = "schedule") val schedule: Map<String, List<Int>> = emptyMap(),
)

/** One flight (campaign phase). */
data class CampaignFlightDto(
    @Json(name = "flight_id") val flightId: String? = null,
    @Json(name = "name") val name: String = "Flight",
    @Json(name = "start_date") val startDate: String,
    @Json(name = "end_date") val endDate: String,
    @Json(name = "daily_budget_cents") val dailyBudgetCents: Long,
    @Json(name = "creative_ids") val creativeIds: List<String> = emptyList(),
    @Json(name = "status") val status: String? = null,
)

/** GET .../schedule result (the schedule view of a campaign record). */
data class CampaignScheduleDto(
    @Json(name = "campaign_id") val campaignId: String? = null,
    @Json(name = "campaign_timezone") val campaignTimezone: String = "UTC",
    @Json(name = "dayparting") val dayparting: DaypartingDto? = null,
    @Json(name = "flights") val flights: List<CampaignFlightDto>? = null,
    @Json(name = "start_date") val startDate: String? = null,
    @Json(name = "end_date") val endDate: String? = null,
)

/** PATCH .../schedule body. Only set fields are sent (nulls omitted by the shared Moshi). */
data class CampaignScheduleUpdateIn(
    @Json(name = "dayparting") val dayparting: DaypartingDto? = null,
    @Json(name = "flights") val flights: List<CampaignFlightDto>? = null,
    @Json(name = "campaign_timezone") val campaignTimezone: String? = null,
)

/** GET .../schedule/eligibility result (debug map + eligible flag + active flight). */
data class ScheduleEligibilityDto(
    @Json(name = "eligible") val eligible: Boolean = true,
    @Json(name = "reason") val reason: String? = null,
    @Json(name = "timezone") val timezone: String? = null,
    @Json(name = "local_time") val localTime: String? = null,
    @Json(name = "day") val day: String? = null,
    @Json(name = "hour") val hour: Int? = null,
    @Json(name = "active_hours") val activeHours: List<Int>? = null,
    @Json(name = "active_flight") val activeFlight: CampaignFlightDto? = null,
)

/** GET .../schedule/pacing result. */
data class BudgetPacingDto(
    @Json(name = "active_hours_today") val activeHoursToday: Int = 0,
    @Json(name = "hours_remaining") val hoursRemaining: Int = 0,
    @Json(name = "hourly_budget_cents") val hourlyBudgetCents: Long = 0L,
    @Json(name = "remaining_budget_cents") val remainingBudgetCents: Long = 0L,
)
