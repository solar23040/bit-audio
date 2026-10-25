import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.kotlin.android)
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

    packaging {
        // BouncyCastle ships a Java 9 module descriptor that Android builds ignore.
        resources.excludes += "META-INF/versions/9/OSGI-INF/MANIFEST.MF"
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    // Ed25519, Argon2id and ChaCha20-Poly1305 primitives. Used through the
    // low-level API only, never registered as a JCA provider, so it cannot
    // clash with Android's built-in "BC" provider.
    implementation(libs.bouncycastle)

    testImplementation(libs.junit)
}
