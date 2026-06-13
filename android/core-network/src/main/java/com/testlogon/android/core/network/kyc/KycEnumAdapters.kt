package com.testlogon.android.core.network.kyc

import com.squareup.moshi.FromJson
import com.squareup.moshi.ToJson
import com.testlogon.android.core.model.kyc.KycCaseStatus
import com.testlogon.android.core.model.kyc.KycFileType

/**
 * AND-319 - Moshi adapter for [KycCaseStatus]. The wire value is the snake_case token string; an
 * unrecognized token decodes to [KycCaseStatus.UNKNOWN] (never throws) and serializes back to its
 * token. Registered on the production Moshi in core-network's NetworkModule (direct Moshi.Builder().add()).
 */
object KycCaseStatusAdapter {

    @FromJson
    fun fromJson(token: String?): KycCaseStatus = KycCaseStatus.fromToken(token)

    @ToJson
    fun toJson(value: KycCaseStatus): String = value.token
}

/**
 * AND-319 - Moshi adapter for [KycFileType]. Mirrors [KycCaseStatusAdapter]: token string in/out,
 * unrecognized token -> [KycFileType.UNKNOWN].
 */
object KycFileTypeAdapter {

    @FromJson
    fun fromJson(token: String?): KycFileType = KycFileType.fromToken(token)

    @ToJson
    fun toJson(value: KycFileType): String = value.token
}
