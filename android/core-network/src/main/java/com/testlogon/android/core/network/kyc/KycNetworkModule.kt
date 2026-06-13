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
 */
@Module
@InstallIn(SingletonComponent::class)
object KycNetworkModule {

    @Provides
    @Singleton
    fun provideKycApi(retrofit: Retrofit): KycApi = retrofit.create(KycApi::class.java)
}
