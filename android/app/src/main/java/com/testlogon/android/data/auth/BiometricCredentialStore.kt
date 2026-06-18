package com.testlogon.android.data.auth

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

/** The credential a biometric unlock re-plays into [AuthRepository.login]. */
data class StoredCredential(val email: String, val password: String)

/**
 * Persists the credential that a successful biometric unlock re-plays into login.
 *
 * Stored in a Keystore-backed [EncryptedSharedPreferences] file (AES-256). NOTE (demo
 * simplification): the cipher key is not bound to the BiometricPrompt CryptoObject — the app gates
 * reads behind a successful [BiometricAuthenticator.authenticate] call instead. A production build
 * SHOULD bind the key to the prompt so the OS, not the app, enforces the gate.
 */
interface BiometricCredentialStore {
    fun hasCredential(): Boolean
    fun save(email: String, password: String)
    fun read(): StoredCredential?
    fun clear()
}

@Singleton
class EncryptedBiometricCredentialStore @Inject constructor(
    @ApplicationContext private val context: Context,
) : BiometricCredentialStore {

    // Lazily built so a Keystore/Tink hiccup degrades to "no saved credential" instead of crashing.
    private val prefs: SharedPreferences? by lazy {
        runCatching {
            val key = MasterKey.Builder(context)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            EncryptedSharedPreferences.create(
                context,
                FILE_NAME,
                key,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
            )
        }.getOrNull()
    }

    override fun hasCredential(): Boolean =
        prefs?.let { it.contains(KEY_EMAIL) && it.contains(KEY_PASSWORD) } == true

    override fun save(email: String, password: String) {
        prefs?.edit()?.putString(KEY_EMAIL, email)?.putString(KEY_PASSWORD, password)?.apply()
    }

    override fun read(): StoredCredential? {
        val p = prefs ?: return null
        val email = p.getString(KEY_EMAIL, null) ?: return null
        val password = p.getString(KEY_PASSWORD, null) ?: return null
        return StoredCredential(email, password)
    }

    override fun clear() {
        prefs?.edit()?.remove(KEY_EMAIL)?.remove(KEY_PASSWORD)?.apply()
    }

    private companion object {
        const val FILE_NAME = "biometric_credential"
        const val KEY_EMAIL = "email"
        const val KEY_PASSWORD = "password"
    }
}
