import org.gradle.api.tasks.testing.Test
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.solar23040.bitaudio.security.harness"
    compileSdk = 35

    defaultConfig {
        minSdk = 26
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

val contractVector = rootProject.file("security/contract-vectors.json")

tasks.withType<Test>().configureEach {
    systemProperty("security.contractVector", contractVector.absolutePath)
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    testImplementation(project(":mesh"))
    testImplementation(project(":crypto"))
    testImplementation(project(":transport"))
    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.coroutines.test)
}
