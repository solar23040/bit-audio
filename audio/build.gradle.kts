import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
}

android {
    namespace = "com.meshvoice.audio"
    compileSdk = 35
    ndkVersion = "27.0.12077973"

    defaultConfig {
        minSdk = 26
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")

        externalNativeBuild {
            cmake {
                // NDK r27 still needs this flag to produce 16 KB aligned libraries.
                arguments += "-DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON"
            }
        }
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        buildConfig = false
    }

    testOptions {
        unitTests.all {
            it.maxHeapSize = "1g"
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    implementation(libs.androidx.annotation)

    testImplementation(libs.junit)

    // Real libopus on the JVM, used only as a test oracle. Production code uses the JNI bridge.
    testImplementation(libs.lwjgl)
    testImplementation(libs.lwjgl.opus)
    testRuntimeOnly(variantOf(libs.lwjgl) { classifier("natives-linux") })
    testRuntimeOnly(variantOf(libs.lwjgl) { classifier("natives-linux-arm64") })
    testRuntimeOnly(variantOf(libs.lwjgl.opus) { classifier("natives-linux") })
    testRuntimeOnly(variantOf(libs.lwjgl.opus) { classifier("natives-linux-arm64") })

    androidTestImplementation(libs.androidx.test.junit)
    androidTestImplementation(libs.androidx.test.runner)
}
