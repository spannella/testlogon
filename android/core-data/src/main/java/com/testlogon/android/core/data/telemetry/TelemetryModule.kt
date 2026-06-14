package com.testlogon.android.core.data.telemetry

import com.testlogon.android.core.data.BuildConfig
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import java.security.SecureRandom
import javax.inject.Singleton

/**
 * AND-052 — Hilt bindings for the redacted auth telemetry layer.
 *
 * The redaction salt is a per-process random value (held only in memory) so `cref` correlation
 * hashes are stable within a session but never persisted or reversible across runs.
 */
@Module
@InstallIn(SingletonComponent::class)
object TelemetryModule {

    @Provides
    @Singleton
    fun provideRedactor(): Redactor {
        val salt = ByteArray(SALT_BYTES).also { SecureRandom().nextBytes(it) }
        return Redactor(salt)
    }

    @Provides
    @Singleton
    fun provideRemoteTelemetrySink(): RemoteTelemetrySink = NoopRemoteTelemetrySink

    @Provides
    @Singleton
    fun provideAuthTelemetry(redactor: Redactor): AuthTelemetry =
        DefaultAuthTelemetry(redactor = redactor, debug = BuildConfig.DEBUG)

    private const val SALT_BYTES = 16
}
