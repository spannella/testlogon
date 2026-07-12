package com.testlogon.android.core.network.delegationkeys

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * Hilt wiring for the delegation-API keys transport layer. Provides [DelegationKeyApi] from the shared
 * singleton [Retrofit] (reusing the production OkHttp / Moshi config; no new Retrofit/OkHttp/Moshi is built
 * and no new dependency is introduced). Mirrors ApiKeysNetworkModule.
 */
@Module
@InstallIn(SingletonComponent::class)
object DelegationKeyNetworkModule {

    @Provides
    @Singleton
    fun provideDelegationKeyApi(retrofit: Retrofit): DelegationKeyApi =
        retrofit.create(DelegationKeyApi::class.java)
}
