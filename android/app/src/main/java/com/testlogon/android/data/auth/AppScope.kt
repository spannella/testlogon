package com.testlogon.android.data.auth

import javax.inject.Qualifier

/** Qualifies the application-lifetime [kotlinx.coroutines.CoroutineScope] backing hot stores. */
@Qualifier
@Retention(AnnotationRetention.BINARY)
annotation class AppScope
