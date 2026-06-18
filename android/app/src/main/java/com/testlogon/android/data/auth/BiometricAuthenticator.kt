package com.testlogon.android.data.auth

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_WEAK
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import dagger.hilt.android.qualifiers.ApplicationContext
import kotlinx.coroutines.suspendCancellableCoroutine
import javax.inject.Inject
import javax.inject.Singleton
import kotlin.coroutines.resume

/** Outcome of one BiometricPrompt ceremony. */
sealed interface BiometricOutcome {
    data object Succeeded : BiometricOutcome

    /** User cancelled / dismissed — not an error, render nothing. */
    data object Cancelled : BiometricOutcome
    data class Failed(val message: String) : BiometricOutcome
}

/** Thin wrapper over androidx.biometric so ViewModels stay testable (fakeable in unit tests). */
interface BiometricAuthenticator {
    /** True when the device has usable, enrolled biometrics (strong or weak). */
    fun canAuthenticate(): Boolean

    suspend fun authenticate(
        activity: FragmentActivity,
        title: String,
        subtitle: String,
    ): BiometricOutcome
}

@Singleton
class AndroidBiometricAuthenticator @Inject constructor(
    @ApplicationContext private val context: Context,
) : BiometricAuthenticator {

    private val allowed = BIOMETRIC_STRONG or BIOMETRIC_WEAK

    override fun canAuthenticate(): Boolean =
        BiometricManager.from(context).canAuthenticate(allowed) == BiometricManager.BIOMETRIC_SUCCESS

    override suspend fun authenticate(
        activity: FragmentActivity,
        title: String,
        subtitle: String,
    ): BiometricOutcome = suspendCancellableCoroutine { cont ->
        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(context),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    if (cont.isActive) cont.resume(BiometricOutcome.Succeeded)
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    val outcome = when (errorCode) {
                        BiometricPrompt.ERROR_USER_CANCELED,
                        BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                        BiometricPrompt.ERROR_CANCELED,
                        -> BiometricOutcome.Cancelled
                        else -> BiometricOutcome.Failed(errString.toString())
                    }
                    if (cont.isActive) cont.resume(outcome)
                }
                // onAuthenticationFailed = one non-matching attempt; the prompt stays up. No resume.
            },
        )
        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setNegativeButtonText("Cancel")
            .setAllowedAuthenticators(allowed)
            .build()
        prompt.authenticate(info)
        cont.invokeOnCancellation { /* prompt is torn down with the activity */ }
    }
}
