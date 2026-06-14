package com.testlogon.android.core.network.collaborations

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-358 - Hilt wiring for the collaborations transport layer.
 *
 * Provides [CollaborationsApi] from the shared singleton [Retrofit] (reusing the production OkHttp / Moshi /
 * converter config; no new Retrofit, OkHttp or Moshi is built, and NO new dependency is introduced). The
 * collaboration DTOs decode with the reflective KotlinJsonAdapterFactory already on the shared Moshi. Mirrors
 * the AND-356 SyndicateNetworkModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
object CollaborationsNetworkModule {

    @Provides
    @Singleton
    fun provideCollaborationsApi(retrofit: Retrofit): CollaborationsApi =
        retrofit.create(CollaborationsApi::class.java)
}
