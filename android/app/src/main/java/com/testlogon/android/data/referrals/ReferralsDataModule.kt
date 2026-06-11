package com.testlogon.android.data.referrals

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-264 — provides [ReferralsApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object ReferralsApiModule {

    @Provides
    @Singleton
    fun provideReferralsApi(retrofit: Retrofit): ReferralsApi =
        retrofit.create(ReferralsApi::class.java)
}

/** AND-264 — binds the referrals data-layer implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class ReferralsDataModule {

    @Binds
    @Singleton
    abstract fun bindReferralsRepository(impl: ReferralsRepositoryImpl): ReferralsRepository
}
