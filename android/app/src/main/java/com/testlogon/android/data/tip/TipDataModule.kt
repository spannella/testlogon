package com.testlogon.android.data.tip

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-178 — provides the [TipApi] on the shared Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object TipApiModule {

    @Provides
    @Singleton
    fun provideTipApi(retrofit: Retrofit): TipApi =
        retrofit.create(TipApi::class.java)

    // TIPX-C2 - the standalone profile (creator) direct-tip API on the shared Retrofit.
    @Provides
    @Singleton
    fun provideProfileTipApi(retrofit: Retrofit): ProfileTipApi =
        retrofit.create(ProfileTipApi::class.java)
}

/** AND-178 — binds the tip repository to its implementation. */
@Module
@InstallIn(SingletonComponent::class)
abstract class TipDataModule {

    @Binds
    @Singleton
    abstract fun bindTipRepository(impl: TipRepositoryImpl): TipRepository

    // TIPX-C2 - the profile (creator) direct-tip repository.
    @Binds
    @Singleton
    abstract fun bindProfileTipRepository(impl: ProfileTipRepositoryImpl): ProfileTipRepository
}
