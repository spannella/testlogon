package com.testlogon.android.data.auth

import javax.inject.Inject
import javax.inject.Singleton

/**
 * In-memory hand-off of the just-entered credential from the registration form (where the password
 * is known) to the confirm step (where the biometric-enroll offer is shown). Never persisted;
 * dropped on process death; cleared once consumed.
 */
@Singleton
class BiometricEnrollmentBuffer @Inject constructor() {
    @Volatile
    private var pending: StoredCredential? = null

    fun stash(email: String, password: String) {
        pending = StoredCredential(email, password)
    }

    fun peek(): StoredCredential? = pending

    fun clear() {
        pending = null
    }
}
