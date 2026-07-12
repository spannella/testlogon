package com.testlogon.android.feature.settings.geo

/** Framework-free domain models for the geo-blocking settings screen (mirrors the web GeoRulesPage). */

data class GeoCountry(
    val code: String,
    val name: String,
)

data class MyCountry(
    val country: String?,
    val ip: String,
    val source: String,
)

data class GeoCheckOutcome(
    val allowed: Boolean,
    val country: String?,
    val matchedRule: String?,
)
