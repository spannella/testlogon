package com.testlogon.android.core.network.kyc

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-319 - Hilt wiring for the KYC transport layer.
 *
 * Provides [KycApi] from the shared singleton [Retrofit] (reusing the production OkHttp/Moshi/
 * converter config; no new Retrofit/OkHttp/Moshi is built). The two KYC enum adapters are NOT
 * registered here: this codebase has no @IntoSet/@AppMoshiAdapter multibinding for Moshi adapters,
 * so they are added directly to the shared Moshi builder in NetworkModule.provideMoshi, alongside
 * the existing BigDecimalAdapter. No new dependency is introduced.
 *
 * AND-321 - also provides [KycDocumentsApi] (the `ui/kyc/documents` upload endpoint) from the SAME
 * shared Retrofit, alongside KycApi for consistency.
 *
 * AND-322 - also provides [KycIdScannerApi] (the `ui/kyc/id-scanner/cases/{caseId}/...` validate +
 * per-side scan control plane) from the same shared Retrofit.
 *
 * AND-323 - also provides [FaceComparisonApi] (the `v1/kyc/cases/{caseId}/compare-face` +
 * `face-comparisons` server-side facial-comparison control plane) from the same shared Retrofit.
 *
 * AND-324 - also provides [KycLivenessCallApi] (the `ui/kyc/liveness-call` scheduled video-verification
 * control plane) from the same shared Retrofit.
 *
 * AND-325 - also provides [KycEidvApi] (the `v1/kyc/eid` electronic ID verification redirect control plane)
 * from the same shared Retrofit.
 */
@Module
@InstallIn(SingletonComponent::class)
object KycNetworkModule {

    @Provides
    @Singleton
    fun provideKycApi(retrofit: Retrofit): KycApi = retrofit.create(KycApi::class.java)

    @Provides
    @Singleton
    fun provideKycDocumentsApi(retrofit: Retrofit): KycDocumentsApi =
        retrofit.create(KycDocumentsApi::class.java)

    @Provides
    @Singleton
    fun provideKycIdScannerApi(retrofit: Retrofit): KycIdScannerApi =
        retrofit.create(KycIdScannerApi::class.java)

    @Provides
    @Singleton
    fun provideFaceComparisonApi(retrofit: Retrofit): FaceComparisonApi =
        retrofit.create(FaceComparisonApi::class.java)

    @Provides
    @Singleton
    fun provideKycLivenessCallApi(retrofit: Retrofit): KycLivenessCallApi =
        retrofit.create(KycLivenessCallApi::class.java)

    @Provides
    @Singleton
    fun provideKycEidvApi(retrofit: Retrofit): KycEidvApi =
        retrofit.create(KycEidvApi::class.java)
}
