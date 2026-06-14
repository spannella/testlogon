package com.testlogon.android.feature.seo.data

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-400 - provides the public SEO API on the shared (authenticated-pipeline) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object SeoApiModule {

    @Provides
    @Singleton
    fun provideSeoApi(retrofit: Retrofit): SeoApi = retrofit.create(SeoApi::class.java)
}

/** AND-400 - binds the SEO repository implementation. The mapper is constructor-injected. */
@Module
@InstallIn(SingletonComponent::class)
abstract class SeoDataModule {

    @Binds
    @Singleton
    abstract fun bindSeoRepository(impl: SeoRepositoryImpl): SeoRepository
}
