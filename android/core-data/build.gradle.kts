plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.hilt)
    alias(libs.plugins.ksp)
}

android {
    namespace = "com.testlogon.android.core.data"
    compileSdk = 35

    defaultConfig {
        minSdk = 24
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }

    buildFeatures {
        // AND-052 — BuildConfig.DEBUG gates Logcat output in the telemetry layer.
        // AND-115 — BuildConfig.DEBUG gates fallbackToDestructiveMigration in DatabaseModule.
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    jvmToolchain(17)
}

// AND-115 — export Room schemas for migration diffing & CI (KSP top-level extension).
ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
}

dependencies {
    implementation(project(":core-model"))
    implementation(project(":core-network"))

    // Coroutines (telemetry scope seam; SWR Flow builder)
    implementation(libs.coroutines.core)

    // AND-115 — Room cache store (room-runtime + room-ktx Flow/suspend), KSP processor.
    implementation(libs.room.runtime)
    implementation(libs.room.ktx)
    ksp(libs.room.compiler)

    // DI
    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)

    // Test (JVM unit — SWR policy + TTL/eviction pure logic)
    testImplementation(libs.junit)
    testImplementation(libs.coroutines.test)

    // AND-115/AND-119 — instrumented Room DAO round-trip + migration tests (need an Android runtime).
    androidTestImplementation(project(":core-testing"))
    androidTestImplementation(libs.androidx.test.ext)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.room.testing)
    androidTestImplementation(libs.coroutines.test)
}
