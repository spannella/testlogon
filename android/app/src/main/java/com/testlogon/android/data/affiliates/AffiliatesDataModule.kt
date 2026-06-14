package com.testlogon.android.data.affiliates

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-265 — provides [AffiliatesApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object AffiliatesApiModule {

    @Provides
    @Singleton
    fun provideAffiliatesApi(retrofit: Retrofit): AffiliatesApi =
        retrofit.create(AffiliatesApi::class.java)
}

/** AND-265 — binds the affiliates data-layer implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class AffiliatesDataModule {

    @Binds
    @Singleton
    abstract fun bindAffiliatesRepository(impl: AffiliatesRepositoryImpl): AffiliatesRepository
}
