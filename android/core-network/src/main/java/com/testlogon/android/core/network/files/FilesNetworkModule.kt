package com.testlogon.android.core.network.files

import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-331 - Hilt wiring for the file-manager transport layer.
 *
 * Provides [FilesApi] from the shared singleton [Retrofit] (reusing the production OkHttp / Moshi /
 * converter config; no new Retrofit, OkHttp or Moshi is built, and no new dependency is introduced).
 * The file DTOs need no custom Moshi adapters: they decode via the reflective KotlinJsonAdapterFactory
 * already registered in NetworkModule.provideMoshi, and timestamp parsing happens in FileDtoMappers (not
 * in Moshi). Mirrors the AND-319 KycNetworkModule pattern.
 */
@Module
@InstallIn(SingletonComponent::class)
object FilesNetworkModule {

    @Provides
    @Singleton
    fun provideFilesApi(retrofit: Retrofit): FilesApi = retrofit.create(FilesApi::class.java)
}
