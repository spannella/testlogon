package com.testlogon.android.data.calendar

import dagger.Binds
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import retrofit2.Retrofit
import javax.inject.Singleton

/**
 * AND-270 — provides the dedicated [CalendarApi] + [PublicEventApi] on the shared Retrofit (no new
 * OkHttp/Retrofit) and binds [CalendarRepository]. Kept separate from other feature wiring.
 */
@Module
@InstallIn(SingletonComponent::class)
object CalendarApiModule {

    @Provides
    @Singleton
    fun provideCalendarApi(retrofit: Retrofit): CalendarApi =
        retrofit.create(CalendarApi::class.java)

    @Provides
    @Singleton
    fun providePublicEventApi(retrofit: Retrofit): PublicEventApi =
        retrofit.create(PublicEventApi::class.java)
}

@Module
@InstallIn(SingletonComponent::class)
abstract class CalendarDataModule {

    @Binds
    @Singleton
    abstract fun bindCalendarRepository(impl: CalendarRepositoryImpl): CalendarRepository
}
