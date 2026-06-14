package com.testlogon.android.data.auth

import android.content.Context

/** Scriptable [PasskeyManager] for PasskeyRepository tests. Captures the forwarded options JSON. */
class FakePasskeyManager : PasskeyManager {

    var supported = true
    var createOutcome: PasskeyOutcome = PasskeyOutcome.Success("""{"registration":true}""")
    var getOutcome: PasskeyOutcome = PasskeyOutcome.Success("""{"assertion":true}""")

    var lastCreateRequestJson: String? = null
    var lastGetRequestJson: String? = null
    var createCalls = 0
    var getCalls = 0

    override suspend fun isPasskeySupported(): Boolean = supported

    override suspend fun createCredential(activity: Context, requestJson: String): PasskeyOutcome {
        createCalls++
        lastCreateRequestJson = requestJson
        return createOutcome
    }

    override suspend fun getCredential(activity: Context, requestJson: String): PasskeyOutcome {
        getCalls++
        lastGetRequestJson = requestJson
        return getOutcome
    }
}
