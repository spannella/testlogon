package com.testlogon.android.data.refunds

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** AND-244 — provides the [RefundsApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object RefundsApiModule {

    @Provides
    @Singleton
    fun provideRefundsApi(retrofit: Retrofit): RefundsApi =
        retrofit.create(RefundsApi::class.java)
}

/** AND-244 — binds the refund-requests repository over [RefundsApi]. */
@Module
@InstallIn(SingletonComponent::class)
abstract class RefundsDataModule {

    @Binds
    @Singleton
    abstract fun bindRefundsRepository(impl: RefundsRepositoryImpl): RefundsRepository
}
