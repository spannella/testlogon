package com.testlogon.android.data.auth

import android.content.Context
import android.os.Build
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.CredentialManager
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.PublicKeyCredential
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialProviderConfigurationException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.GetCredentialProviderConfigurationException
import androidx.credentials.exceptions.NoCredentialException
import androidx.credentials.exceptions.domerrors.DomError
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import androidx.credentials.exceptions.publickeycredential.GetPublicKeyCredentialDomException
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.CancellationException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-062 — thin, injectable wrapper around AndroidX Credential Manager so the WebAuthn ceremony is
 * testable without the framework. The repository hands the raw begin-`options` JSON to
 * [createCredential]/[getCredential] and receives the registration/assertion response JSON back.
 *
 * The framework renders system UI, so both calls must be invoked with an Activity [Context]; the
 * caller passes the Activity through from a Compose `LocalContext`, never holding a long-lived ref.
 *
 * Capability is gated on API >= 28 (platform passkeys via Play services); on unsupported devices
 * [isPasskeySupported] returns false and the affordances are hidden / degrade silently.
 */
interface PasskeyManager {
    suspend fun isPasskeySupported(): Boolean

    /** @param requestJson the raw creation-options JSON from register/begin. */
    suspend fun createCredential(activity: Context, requestJson: String): PasskeyOutcome

    /** @param requestJson the raw request-options JSON from authenticate/begin. */
    suspend fun getCredential(activity: Context, requestJson: String): PasskeyOutcome
}

/** Result of a Credential Manager ceremony. [responseJson] is the registration/assertion JSON. */
sealed interface PasskeyOutcome {
    data class Success(val responseJson: String) : PasskeyOutcome
    data object Cancelled : PasskeyOutcome
    data object NoCredential : PasskeyOutcome
    data class Failure(val type: PasskeyErrorType, val cause: Throwable) : PasskeyOutcome
}

enum class PasskeyErrorType { UNSUPPORTED, INTERRUPTED, PROVIDER, DOM_EXCEPTION, UNKNOWN }

@Singleton
class CredentialManagerPasskeyManager @Inject constructor(
    @ApplicationContext private val appContext: Context,
) : PasskeyManager {

    private val credentialManager: CredentialManager by lazy { CredentialManager.create(appContext) }

    /** Platform passkeys require API 28+ and a Credential Manager provider (GMS). */
    override suspend fun isPasskeySupported(): Boolean = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P

    override suspend fun createCredential(activity: Context, requestJson: String): PasskeyOutcome {
        if (!isPasskeySupported()) {
            return PasskeyOutcome.Failure(PasskeyErrorType.UNSUPPORTED, UnsupportedOperationException())
        }
        return try {
            val request = CreatePublicKeyCredentialRequest(requestJson = requestJson)
            val response = credentialManager.createCredential(activity, request)
            val pk = response as? CreatePublicKeyCredentialResponse
                ?: return PasskeyOutcome.Failure(PasskeyErrorType.UNKNOWN, IllegalStateException("type"))
            PasskeyOutcome.Success(pk.registrationResponseJson)
        } catch (e: CancellationException) {
            throw e
        } catch (e: CreateCredentialException) {
            e.toCreateOutcome()
        }
    }

    override suspend fun getCredential(activity: Context, requestJson: String): PasskeyOutcome {
        if (!isPasskeySupported()) {
            return PasskeyOutcome.Failure(PasskeyErrorType.UNSUPPORTED, UnsupportedOperationException())
        }
        return try {
            val option = GetPublicKeyCredentialOption(requestJson = requestJson)
            val request = GetCredentialRequest(listOf(option))
            val response = credentialManager.getCredential(activity, request)
            val pk = response.credential as? PublicKeyCredential
                ?: return PasskeyOutcome.Failure(PasskeyErrorType.UNKNOWN, IllegalStateException("type"))
            PasskeyOutcome.Success(pk.authenticationResponseJson)
        } catch (e: CancellationException) {
            throw e
        } catch (e: GetCredentialException) {
            e.toGetOutcome()
        }
    }

    private fun CreateCredentialException.toCreateOutcome(): PasskeyOutcome = when (this) {
        is CreateCredentialCancellationException -> PasskeyOutcome.Cancelled
        is CreatePublicKeyCredentialDomException ->
            PasskeyOutcome.Failure(this.domError.toErrorType(), this)
        is CreateCredentialProviderConfigurationException ->
            PasskeyOutcome.Failure(PasskeyErrorType.PROVIDER, this)
        else -> PasskeyOutcome.Failure(PasskeyErrorType.UNKNOWN, this)
    }

    private fun GetCredentialException.toGetOutcome(): PasskeyOutcome = when (this) {
        is GetCredentialCancellationException -> PasskeyOutcome.Cancelled
        is NoCredentialException -> PasskeyOutcome.NoCredential
        is GetPublicKeyCredentialDomException ->
            PasskeyOutcome.Failure(this.domError.toErrorType(), this)
        is GetCredentialProviderConfigurationException ->
            PasskeyOutcome.Failure(PasskeyErrorType.PROVIDER, this)
        else -> PasskeyOutcome.Failure(PasskeyErrorType.UNKNOWN, this)
    }

    @Suppress("UnusedReceiverParameter")
    private fun DomError.toErrorType(): PasskeyErrorType = PasskeyErrorType.DOM_EXCEPTION
}
