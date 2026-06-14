package com.testlogon.android.core.network.donation

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

/** Qualifies the COOKIELESS OkHttp / Retrofit used only for the session-free public donation surface. */
@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class PublicDonationClient

/**
 * AND-393 - Hilt wiring for the PUBLIC donation transport layer.
 *
 * The public fundraiser/donation endpoints MUST be callable anonymously (a donor may be signed out), so
 * [DonationApi] gets a SEPARATE [PublicDonationClient]-qualified OkHttp + Retrofit built here with NO
 * cookie jar, NO CsrfInterceptor and NO SessionAuthenticator - mirroring the AND-335 ShareNetworkModule
 * public client. Only the host-selection (so the runtime base URL still applies), retry and debug-logging
 * interceptors are reused. The existing authed interceptors are NOT modified. The shared reflective Moshi
 * decodes the public DTOs with no custom adapters.
 *
 * A separate qualifier (not @PublicShareClient) keeps this module decoupled from the share surface; the
 * two cookieless clients are independent singletons with identical config.
 */
@Module
@InstallIn(SingletonComponent::class)
object DonationNetworkModule {

    private const val TIMEOUT_SECONDS = 20L

    /**
     * A cookieless OkHttp client for the public donation endpoints: NO cookie jar, NO CSRF interceptor, NO
     * authenticator. Host selection is kept so the runtime base URL still targets the right server; retry
     * + debug logging are kept for parity. This client never attaches Cookie / X-CSRF-Token /
     * Authorization headers.
     */
    @Provides
    @Singleton
    @PublicDonationClient
    fun providePublicDonationClient(
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
    @PublicDonationClient
    fun providePublicDonationRetrofit(
        @PublicDonationClient client: OkHttpClient,
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
    fun provideDonationApi(@PublicDonationClient retrofit: Retrofit): DonationApi =
        retrofit.create(DonationApi::class.java)
}
