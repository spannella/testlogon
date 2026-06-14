import com.diffplug.gradle.spotless.SpotlessExtension
import io.gitlab.arturbosch.detekt.Detekt
import io.gitlab.arturbosch.detekt.extensions.DetektExtension
import org.gradle.api.artifacts.VersionCatalogsExtension
import org.gradle.kotlin.dsl.getByType

plugins {
    alias(libs.plugins.android.application) apply false
    alias(libs.plugins.android.library) apply false
    alias(libs.plugins.kotlin.android) apply false
    alias(libs.plugins.kotlin.compose) apply false
    alias(libs.plugins.ksp) apply false
    alias(libs.plugins.hilt) apply false
    // AND-005: formatting (Spotless/ktlint) + static analysis (detekt).
    // Applied to subprojects below; deliberately NOT wired into assembleDebug.
    alias(libs.plugins.spotless) apply false
    alias(libs.plugins.detekt) apply false
}

// Version catalog accessor usable inside the `subprojects {}` block (the typed `libs` accessor
// is only available in this root script's own dependencies block, not inside subprojects).
val catalog = extensions.getByType<VersionCatalogsExtension>().named("libs")
val ktlintVersion = catalog.findVersion("ktlint").get().requiredVersion
val detektFormatting = catalog.findLibrary("detekt-formatting").get()
val detektComposeRules = catalog.findLibrary("detekt-compose-rules").get()

// AND-005 — uniform code-quality gate across every Kotlin module.
// `./gradlew spotlessCheck detekt` runs these; they are standalone lifecycle tasks and are
// intentionally NOT hooked into `assembleDebug`/`testDebugUnitTest`.
subprojects {
    apply(plugin = "com.diffplug.spotless")
    apply(plugin = "io.gitlab.arturbosch.detekt")

    extensions.configure<SpotlessExtension> {
        kotlin {
            target("src/**/*.kt")
            targetExclude("**/build/**", "**/generated/**")
            ktlint(ktlintVersion)
                .editorConfigOverride(
                    mapOf(
                        // Compose @Composable functions are PascalCase; do not flag them.
                        "ktlint_function_naming_ignore_when_annotated_with" to "Composable,Test",
                        // Leniency: filename rule is noisy for multi-declaration files.
                        "ktlint_standard_filename" to "disabled",
                    ),
                )
            trimTrailingWhitespace()
            endWithNewline()
        }
        kotlinGradle {
            target("*.gradle.kts")
            ktlint(ktlintVersion)
        }
    }

    extensions.configure<DetektExtension> {
        config.setFrom(rootProject.file("config/detekt/detekt.yml"))
        baseline = rootProject.file("config/detekt/baseline.xml")
        parallel = true
        buildUponDefaultConfig = true
        autoCorrect = false
    }

    dependencies {
        add("detektPlugins", detektFormatting)
        add("detektPlugins", detektComposeRules)
    }

    tasks.withType<Detekt>().configureEach {
        jvmTarget = "17"
        // Never analyze generated (KSP/Hilt/Moshi) or build output.
        exclude("**/build/**", "**/generated/**")
        reports {
            html.required.set(true)
            sarif.required.set(true) // consumed by CI (AND-008/AND-050)
            xml.required.set(false)
            txt.required.set(false)
        }
    }
}
