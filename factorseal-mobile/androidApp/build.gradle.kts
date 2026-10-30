import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.FileSystemOperations
import org.gradle.api.provider.ListProperty
import org.gradle.api.provider.Property
import org.gradle.process.ExecOperations
import javax.inject.Inject

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.compose.compiler)
}

val upload =
    listOf("KEYSTORE", "KEYSTORE_PASSWORD", "KEY_ALIAS", "KEY_PASSWORD")
        .map { providers.environmentVariable("FACTORSEAL_UPLOAD_$it").orNull }

val version =
    providers
        .fileContents(rootProject.layout.projectDirectory.file("../Cargo.toml"))
        .asText
        .map { manifest ->
            requireNotNull(Regex("""^version = "(\d+)\.(\d+)\.(\d+)"$""", RegexOption.MULTILINE).find(manifest))
                .groupValues
                .drop(1)
                .map(String::toInt)
        }

android {
    namespace = "com.cachix.factorseal"
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

    ndkVersion =
        libs.versions.android.ndk
            .get()

    defaultConfig {
        applicationId = "com.cachix.factorseal"
        minSdk =
            libs.versions.android.min.sdk
                .get()
                .toInt()
        targetSdk =
            libs.versions.android.target.sdk
                .get()
                .toInt()
        versionName = version.get().joinToString(".")
        versionCode = version.get().let { (major, minor, patch) -> major * 1_000_000 + minor * 1_000 + patch }
    }

    signingConfigs {
        val (keystore, storePassword, alias, keyPassword) = upload
        if (keystore != null && storePassword != null && alias != null && keyPassword != null) {
            create("upload") {
                storeFile = file(keystore)
                this.storePassword = storePassword
                keyAlias = alias
                this.keyPassword = keyPassword
            }
        }
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.findByName("upload")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    buildFeatures {
        compose = true
    }

    packaging {
        jniLibs.useLegacyPackaging = false
    }

    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    lint {
        abortOnError = true
        warningsAsErrors = true
        checkDependencies = true
        disable += "NewerVersionAvailable"
        disable += "GradleDependency"
        disable += "AndroidGradlePluginVersion"
    }
}

kotlin {
    jvmToolchain(21)
}

dependencies {
    implementation(project(":shared"))
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.core)
    implementation(libs.androidx.lifecycle.process)
}

abstract class CargoNdk : DefaultTask() {
    @get:Inject
    abstract val exec: ExecOperations

    @get:Inject
    abstract val files: FileSystemOperations

    @get:Input
    abstract val abis: ListProperty<String>

    @get:Input
    abstract val platform: Property<String>

    @get:Input
    abstract val profile: Property<String>

    @get:Internal
    abstract val crate: DirectoryProperty

    @get:Internal
    abstract val staging: DirectoryProperty

    @get:OutputDirectory
    abstract val output: DirectoryProperty

    @TaskAction
    fun build() {
        val targets = abis.get().flatMap { listOf("--target", it) }
        exec.exec {
            workingDir(crate.get().asFile)
            commandLine(
                listOf("cargo", "ndk") + targets +
                    listOf(
                        "--platform",
                        platform.get(),
                        "--output-dir",
                        staging.get().asFile.absolutePath,
                        "build",
                        "--profile",
                        profile.get(),
                        "--locked",
                        "--package",
                        "factorseal-mobile",
                    ),
            )
        }
        files.sync {
            from(staging)
            include(abis.get().map { "$it/libfactorseal_mobile.so" })
            into(output)
        }
    }
}

val rustAbis =
    providers
        .gradleProperty("factorseal.abis")
        .orElse("arm64-v8a,armeabi-v7a,x86_64")
        .map { value -> value.split(',').map(String::trim).filter(String::isNotEmpty) }

androidComponents {
    onVariants { variant ->
        val name = variant.name.replaceFirstChar(Char::uppercase)
        val rust =
            tasks.register<CargoNdk>("buildRust$name") {
                abis.set(rustAbis)
                platform.set(libs.versions.android.min.sdk)
                profile.set(if (variant.buildType == "release") "mobile" else "release")
                crate.set(rootProject.layout.projectDirectory.dir("core"))
                staging.set(layout.buildDirectory.dir("rust/staging/${variant.name}"))
                output.set(layout.buildDirectory.dir("rust/${variant.name}"))
                outputs.upToDateWhen { false }
            }
        variant.sources.jniLibs?.addGeneratedSourceDirectory(rust, CargoNdk::output)
    }
}
