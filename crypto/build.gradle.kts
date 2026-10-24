// Agent E — :crypto module.
//
// This file is written to stand alone until Agent A lands the Phase 0 root
// project. If the root build uses a version catalog / different AGP+Kotlin
// versions, merge the `dependencies` block into that setup and drop this file.
plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.bitaudio.crypto"
    compileSdk = 35

    defaultConfig {
        minSdk = 26
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    testOptions {
        unitTests.isReturnDefaultValues = true
    }

    packaging {
        resources {
            excludes += "META-INF/versions/9/OSGI-INF/MANIFEST.MF"
        }
    }
}

dependencies {
    // Ed25519, Argon2id and ChaCha20-Poly1305 primitives. Used directly (low-level
    // API), never registered as a JCA provider, so it cannot clash with Android's
    // built-in "BC" provider.
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")

    testImplementation("junit:junit:4.13.2")
}
