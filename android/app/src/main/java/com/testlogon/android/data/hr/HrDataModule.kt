package com.testlogon.android.data.hr

import com.testlogon.android.core.network.hr.HrApi
import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** HRM-009 — provides the [HrApi] on the shared (authenticated) Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object HrApiModule {

    @Provides
    @Singleton
    fun provideHrApi(retrofit: Retrofit): HrApi = retrofit.create(HrApi::class.java)
}

/** HRM-009 — binds the HR read repository over [HrApi]. */
@Module
@InstallIn(SingletonComponent::class)
abstract class HrDataModule {

    @Binds
    @Singleton
    abstract fun bindHrRepository(impl: HrRepositoryImpl): HrRepository
}
