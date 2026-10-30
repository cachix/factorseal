import org.jetbrains.kotlin.gradle.targets.native.tasks.KotlinNativeSimulatorTest

plugins {
    alias(libs.plugins.kotlin.multiplatform)
    alias(libs.plugins.android.kotlin.multiplatform.library)
    alias(libs.plugins.compose.multiplatform)
    alias(libs.plugins.compose.compiler)
    alias(libs.plugins.kotlin.serialization)
}

kotlin {
    jvmToolchain(21)

    android {
        namespace = "com.cachix.factorseal.shared"
        compileSdk {
            version =
                release(
                    libs.versions.android.compile.sdk.major
                        .get()
                        .toInt(),
                ) {
                    minorApiLevel =
                        libs.versions.android.compile.sdk.minor
                            .get()
                            .toInt()
                }
        }
        minSdk =
            libs.versions.android.min.sdk
                .get()
                .toInt()
        androidResources.enable = true
        withHostTest {}
    }

    listOf(iosArm64(), iosSimulatorArm64()).forEach { target ->
        target.binaries.framework {
            baseName = "FactorSealKit"
            isStatic = true
        }
    }

    sourceSets {
        commonMain.dependencies {
            implementation(libs.compose.runtime)
            implementation(libs.compose.foundation)
            implementation(libs.compose.ui)
            implementation(libs.compose.components.resources)
            implementation(libs.jetbrains.lifecycle.runtime.compose)
            implementation(libs.jetbrains.navigationevent.compose)
            implementation(libs.kotlinx.coroutines.core)
            implementation(libs.kotlinx.datetime)
            implementation(libs.kotlinx.serialization.json)
        }
        commonTest.dependencies {
            implementation(libs.kotlin.test)
            implementation(libs.kotlinx.coroutines.test)
        }
        androidMain.dependencies {
            implementation(libs.androidx.activity.compose)
            implementation(libs.androidx.camera.camera2)
            implementation(libs.androidx.camera.lifecycle)
            implementation(libs.androidx.camera.view)
            implementation(libs.androidx.core)
        }
    }
}

compose.resources {
    publicResClass = false
    packageOfResClass = "com.cachix.factorseal.resources"
    generateResClass = always
}

tasks.withType<Test>().configureEach {
    inputs.file(rootProject.file("protocol/messages.json"))
}

tasks.withType<KotlinNativeSimulatorTest>().configureEach {
    providers.gradleProperty("factorseal.simulator").orNull?.let(device::set)
}
