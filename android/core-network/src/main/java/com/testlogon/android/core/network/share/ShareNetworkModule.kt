package com.testlogon.android.core.network.share

import com.squareup.moshi.Moshi
import com.testlogon.android.core.network.BuildConfig
import com.testlogon.android.core.network.SettingsStore
import com.testlogon.android.core.network.host.HostSelectionInterceptor
import com.testlogon.android.core.network.retry.RetryInterceptor
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import okhttp3.OkHttpClient
import okhttp3.logging.HttpLoggingInterceptor
import retrofit2.Retrofit
import retrofit2.converter.moshi.MoshiConverterFactory
import java.util.concurrent.TimeUnit
import javax.inject.Qualifier
import javax.inject.Singleton

/** Qualifies the COOKIELESS OkHttp / Retrofit used only for the session-free public share surface. */
@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class PublicShareClient

/**
 * AND-335 - Hilt wiring for the share-link transport layer.
 *
 * OWNER ([FileShareLinksApi]) is created from the SHARED authenticated singleton [Retrofit] (cookie jar +
 * CSRF + Bearer + 401-refresh all apply), mirroring the AND-331 FilesNetworkModule pattern.
 *
 * PUBLIC ([PublicShareApi]) MUST be session-free, so it gets a SEPARATE [PublicShareClient]-qualified
 * OkHttp + Retrofit built here with NO cookie jar, NO CsrfInterceptor and NO SessionAuthenticator. No
 * @StorageOkHttp client exists in this codebase (verified by grep), so this module builds a minimal plain
 * OkHttpClient with the same timeouts as NetworkModule, reusing only the host-selection (so the runtime
 * base URL still applies), retry and debug-logging interceptors. The existing authed interceptors are NOT
 * modified. The reflective Moshi (shared singleton) decodes the public DTOs with no custom adapters.
 */
@Module
@InstallIn(SingletonComponent::class)
object ShareNetworkModule {

    private const val TIMEOUT_SECONDS = 20L

    // ---- Owner (authenticated, shared Retrofit) ----

    @Provides
    @Singleton
    fun provideFileShareLinksApi(retrofit: Retrofit): FileShareLinksApi =
        retrofit.create(FileShareLinksApi::class.java)

    // ---- Public (session-free, cookieless Retrofit) ----

    /**
     * A cookieless OkHttp client for the public share endpoints: NO cookie jar, NO CSRF interceptor, NO
     * authenticator. Host selection is kept so the runtime base URL still targets the right server; retry
     * + debug logging are kept for parity. This client never attaches Cookie / X-CSRF-Token /
     * Authorization headers.
     */
    @Provides
    @Singleton
    @PublicShareClient
    fun providePublicShareClient(
        hostSelectionInterceptor: HostSelectionInterceptor,
        retryInterceptor: RetryInterceptor,
        loggingInterceptor: HttpLoggingInterceptor,
    ): OkHttpClient = OkHttpClient.Builder()
        .connectTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .readTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .writeTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        // NO cookieJar, NO CsrfInterceptor, NO authenticator - the public surface is session-free.
        .addInterceptor(hostSelectionInterceptor)
        .addInterceptor(retryInterceptor)
        .apply { if (BuildConfig.DEBUG) addInterceptor(loggingInterceptor) }
        .build()

    @Provides
    @Singleton
    @PublicShareClient
    fun providePublicShareRetrofit(
        @PublicShareClient client: OkHttpClient,
        moshi: Moshi,
        settingsStore: SettingsStore,
    ): Retrofit = Retrofit.Builder()
        // Placeholder base URL; HostSelectionInterceptor rewrites scheme/host/port at request time.
        .baseUrl(settingsStore.baseUrl)
        .callFactory(client)
        .addConverterFactory(MoshiConverterFactory.create(moshi))
        .build()

    @Provides
    @Singleton
    fun providePublicShareApi(@PublicShareClient retrofit: Retrofit): PublicShareApi =
        retrofit.create(PublicShareApi::class.java)
}
