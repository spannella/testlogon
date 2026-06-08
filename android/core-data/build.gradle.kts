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
    }

    buildFeatures {
        // AND-052 — BuildConfig.DEBUG gates Logcat output in the telemetry layer.
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

dependencies {
    implementation(project(":core-model"))
    implementation(project(":core-network"))

    // Coroutines (telemetry scope seam)
    implementation(libs.coroutines.core)

    // DI
    implementation(libs.hilt.android)
    ksp(libs.hilt.compiler)

    // Test
    testImplementation(libs.junit)
    testImplementation(libs.coroutines.test)
}
