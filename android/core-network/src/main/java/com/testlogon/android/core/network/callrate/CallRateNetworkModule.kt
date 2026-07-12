package com.testlogon.android.core.network.callrate

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * Hilt wiring for the call-rate settings transport. Provides [CallRateApi] from the shared singleton [Retrofit]
 * (no new Retrofit/OkHttp/Moshi). Mirrors ApiKeysNetworkModule.
 */
@Module
@InstallIn(SingletonComponent::class)
object CallRateNetworkModule {

    @Provides
    @Singleton
    fun provideCallRateApi(retrofit: Retrofit): CallRateApi = retrofit.create(CallRateApi::class.java)
}
