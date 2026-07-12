package com.testlogon.android.core.network.di

import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.network.BuildConfig
import com.testlogon.android.core.network.ads.AdAccountStatusAdapter
import com.testlogon.android.core.network.ads.AdCampaignStatusAdapter
import com.testlogon.android.core.network.json.BigDecimalAdapter
import com.testlogon.android.core.network.json.LenientNumberAdapters
import com.testlogon.android.core.network.kyc.KycCaseStatusAdapter
import com.testlogon.android.core.network.kyc.KycFileTypeAdapter
import com.testlogon.android.core.network.signing.PacketRoleAdapter
import com.testlogon.android.core.network.signing.PacketStatusAdapter
import com.testlogon.android.core.network.signing.SignatureFieldTypeAdapter
import com.testlogon.android.core.network.signing.SignatureInputModeAdapter
import com.testlogon.android.core.network.questionnaire.AnswerValueAdapter
import com.testlogon.android.core.network.questionnaire.QuestionTypeAdapter
import com.testlogon.android.core.network.questionnaire.QuestionnaireFieldFactory
import com.testlogon.android.core.network.SettingsStore
import com.testlogon.android.core.network.auth.AuthEventSink
import com.testlogon.android.core.network.auth.SessionAuthenticator
import com.testlogon.android.core.network.cookie.PersistentCookieJar
import com.testlogon.android.core.network.csrf.CsrfInterceptor
import com.testlogon.android.core.network.delegates.DelegateRoutingInterceptor
import com.testlogon.android.core.network.health.HealthApi
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
import javax.inject.Provider
import javax.inject.Qualifier
import javax.inject.Singleton

/** Qualifies the loop-safe client (no authenticator) used to perform the session refresh call. */
@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class RefreshClient

@Module
@InstallIn(SingletonComponent::class)
object NetworkModule {

    private const val TIMEOUT_SECONDS = 20L

    @Provides
    @Singleton
    fun provideMoshi(): Moshi = Moshi.Builder()
        // AND-218: BigDecimal mapping for the purchases transaction `amount` (no built-in adapter).
        // Registered before the reflective factory so it wins for BigDecimal-typed fields.
        .add(BigDecimalAdapter)
        // Helpdesk FAIL #3/#4 (B-HELP-SHAPE): lenient Long?/Int? for the support-ticket media
        // numeric fields (size_bytes/width/height) so a stringified number never throws and empties
        // the whole ticket list / breaks the close-ticket envelope. Registered before the reflective factory.
        .add(LenientNumberAdapters)
        // AND-319: KYC enum token mapping (lenient -> UNKNOWN). Registered before the reflective
        // factory so they resolve for KycCaseStatus / KycFileType fields on the KYC DTOs.
        .add(KycCaseStatusAdapter)
        .add(KycFileTypeAdapter)
        // AND-339: signing enum token mapping (lenient -> UNKNOWN). The dependency-free stand-in for
        // EnumJsonAdapter.withUnknownFallback (moshi-adapters is not a project dependency). Registered
        // before the reflective factory so they resolve for the signing DTO enum fields.
        .add(PacketStatusAdapter)
        .add(SignatureFieldTypeAdapter)
        .add(PacketRoleAdapter)
        .add(SignatureInputModeAdapter)
        // AND-346: questionnaire custom adapters - the dependency-free polymorphic field schema
        // (QuestionnaireFieldFactory), the answer union (AnswerValueAdapter) and the question-type
        // enum (QuestionTypeAdapter, lenient -> UNKNOWN). Registered BEFORE the reflective factory so
        // they win for QuestionnaireField / AnswerValue / QuestionType. No new dependency is added
        // (NO PolymorphicJsonAdapterFactory, NO moshi-adapters).
        .add(QuestionnaireFieldFactory)
        .add(QuestionTypeAdapter)
        .add(AnswerValueAdapter)
        // AND-363: ads accounts enum token mapping (lenient -> UNKNOWN). The dependency-free stand-in for
        // EnumJsonAdapter.withUnknownFallback. Registered before the reflective factory so they resolve
        // for AdAccountStatus / AdCampaignStatus on the ads DTOs.
        .add(AdAccountStatusAdapter)
        .add(AdCampaignStatusAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    @Provides
    @Singleton
    fun provideRetryInterceptor(): RetryInterceptor = RetryInterceptor()

    @Provides
    @Singleton
    fun provideHttpLoggingInterceptor(): HttpLoggingInterceptor =
        HttpLoggingInterceptor().apply {
            level = HttpLoggingInterceptor.Level.BODY
            redactHeader("Authorization")
            redactHeader("Cookie")
            redactHeader("Set-Cookie")
            redactHeader("X-CSRF-Token")
            redactHeader("Proxy-Authorization")
        }

    /**
     * Builds the base [OkHttpClient] (timeouts, cookie jar, host-selection + CSRF + retry
     * interceptors, debug-only logging). The 401-refresh authenticator is added separately so the
     * refresh call can reuse this exact configuration without recursing.
     */
    private fun baseClientBuilder(
        cookieJar: PersistentCookieJar,
        hostSelectionInterceptor: HostSelectionInterceptor,
        csrfInterceptor: CsrfInterceptor,
        retryInterceptor: RetryInterceptor,
        delegateRoutingInterceptor: DelegateRoutingInterceptor,
        loggingInterceptor: HttpLoggingInterceptor,
    ): OkHttpClient.Builder = OkHttpClient.Builder()
        .connectTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .readTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .writeTimeout(TIMEOUT_SECONDS, TimeUnit.SECONDS)
        .retryOnConnectionFailure(true)
        .cookieJar(cookieJar)
        // Host selection first (so downstream sees the effective URL), then delegate re-routing (so the
        // rewritten messaging path is the one CSRF/retry/logging observe), then CSRF, then retry, and
        // logging last so it observes/redacts the final headers.
        .addInterceptor(hostSelectionInterceptor)
        .addInterceptor(delegateRoutingInterceptor)
        .addInterceptor(csrfInterceptor)
        .addInterceptor(retryInterceptor)
        .apply { if (BuildConfig.DEBUG) addInterceptor(loggingInterceptor) }

    /** Loop-safe client (no authenticator) used only to perform the refresh request. */
    @Provides
    @Singleton
    @RefreshClient
    fun provideRefreshClient(
        cookieJar: PersistentCookieJar,
        hostSelectionInterceptor: HostSelectionInterceptor,
        csrfInterceptor: CsrfInterceptor,
        retryInterceptor: RetryInterceptor,
        delegateRoutingInterceptor: DelegateRoutingInterceptor,
        loggingInterceptor: HttpLoggingInterceptor,
    ): OkHttpClient = baseClientBuilder(
        cookieJar, hostSelectionInterceptor, csrfInterceptor, retryInterceptor,
        delegateRoutingInterceptor, loggingInterceptor,
    ).build()

    @Provides
    @Singleton
    fun provideOkHttpClient(
        cookieJar: PersistentCookieJar,
        hostSelectionInterceptor: HostSelectionInterceptor,
        csrfInterceptor: CsrfInterceptor,
        retryInterceptor: RetryInterceptor,
        delegateRoutingInterceptor: DelegateRoutingInterceptor,
        loggingInterceptor: HttpLoggingInterceptor,
        authenticator: SessionAuthenticator,
    ): OkHttpClient = baseClientBuilder(
        cookieJar, hostSelectionInterceptor, csrfInterceptor, retryInterceptor,
        delegateRoutingInterceptor, loggingInterceptor,
    ).authenticator(authenticator).build()

    @Provides
    @Singleton
    fun provideSessionAuthenticator(
        @RefreshClient refreshClient: Provider<OkHttpClient>,
        cookieJar: PersistentCookieJar,
        settingsStore: SettingsStore,
        authEventSink: AuthEventSink,
    ): SessionAuthenticator = SessionAuthenticator(
        refreshClient = refreshClient,
        cookieJar = cookieJar,
        settingsStore = settingsStore,
        authEventSink = authEventSink,
    )

    @Provides
    @Singleton
    fun provideRetrofit(
        client: OkHttpClient,
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
    fun provideHealthApi(retrofit: Retrofit): HealthApi = retrofit.create(HealthApi::class.java)
}
