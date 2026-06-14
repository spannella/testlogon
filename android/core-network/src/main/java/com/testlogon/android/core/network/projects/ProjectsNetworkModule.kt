package com.testlogon.android.core.network.projects

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-374 - Hilt wiring for the projects transport layer.
 *
 * Provides [ProjectsApi] from the shared singleton [Retrofit] (reusing the AND-027 OkHttp cookie-jar / CSRF /
 * 401-refresh + the shared Moshi / converter config; no new Retrofit, OkHttp, Moshi, or dependency is added).
 * The project DTOs decode with the reflective KotlinJsonAdapterFactory already on the shared Moshi (the
 * provider key is a plain String - no enum adapter is needed). Mirrors the AND-371 TicketsNetworkModule.
 */
@Module
@InstallIn(SingletonComponent::class)
object ProjectsNetworkModule {

    @Provides
    @Singleton
    fun provideProjectsApi(retrofit: Retrofit): ProjectsApi =
        retrofit.create(ProjectsApi::class.java)
}
