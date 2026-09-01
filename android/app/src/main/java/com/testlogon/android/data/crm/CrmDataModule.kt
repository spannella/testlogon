package com.testlogon.android.data.crm

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/** CRM-AND-1 — provides the [LeadsApi] + [SalesApi] on the shared Retrofit. */
@Module
@InstallIn(SingletonComponent::class)
object CrmApiModule {

    @Provides
    @Singleton
    fun provideLeadsApi(retrofit: Retrofit): LeadsApi = retrofit.create(LeadsApi::class.java)

    @Provides
    @Singleton
    fun provideSalesApi(retrofit: Retrofit): SalesApi = retrofit.create(SalesApi::class.java)
}

/** CRM-AND-1 — binds the CRM repositories to their implementations. */
@Module
@InstallIn(SingletonComponent::class)
abstract class CrmDataModule {

    @Binds
    @Singleton
    abstract fun bindLeadsRepository(impl: LeadsRepositoryImpl): LeadsRepository

    @Binds
    @Singleton
    abstract fun bindSalesRepository(impl: SalesRepositoryImpl): SalesRepository
}
