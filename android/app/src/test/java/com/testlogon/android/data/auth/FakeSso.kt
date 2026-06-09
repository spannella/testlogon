package com.testlogon.android.data.auth

import android.content.Context
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.auth.sso.SsoTabLauncher

/** Scriptable [SsoRepository] for LoginViewModel SSO tests. */
class FakeSsoRepository : SsoRepository {
    var infoResult: ApiResult<SsoInfo> = ApiResult.Failure(ApiError(0, "unset"))
    var finalizeResult: ApiResult<SsoFinalizeResult> =
        ApiResult.Success(SsoFinalizeResult.Authenticated(User("usr_1", "sess_1", "1.2.3.4")))
    var authorizeUrlValue = "http://host/saml/login?tenant=default"

    var getInfoCalls = 0
    var finalizeCalls = 0

    override suspend fun getSsoInfo(tenant: String): ApiResult<SsoInfo> {
        getInfoCalls++
        return infoResult
    }

    override fun authorizeUrl(info: SsoInfo?, tenant: String): String = authorizeUrlValue

    override suspend fun finalizeAfterCallback(): ApiResult<SsoFinalizeResult> {
        finalizeCalls++
        return finalizeResult
    }
}

/** In-memory [SsoStateStore]. */
class FakeSsoStateStore : SsoStateStore {
    private var pending: PendingSso? = null
    override suspend fun save(state: String, ttlMillis: Long) {
        pending = PendingSso(state, System.currentTimeMillis() + ttlMillis)
    }
    override suspend fun peek(): PendingSso? = pending
    override suspend fun clear() { pending = null }
}

/** Records SSO tab launches; [available] controls whether a browser was found. */
class FakeSsoTabLauncher(var available: Boolean = true) : SsoTabLauncher {
    var launchCalls = 0
    var lastUrl: String? = null
    override fun launch(context: Context, authorizeUrl: String): Boolean {
        launchCalls++
        lastUrl = authorizeUrl
        return available
    }
}
