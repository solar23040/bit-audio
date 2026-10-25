// CI-only Gradle init script. It registers the Agent H security harness as a
// project without touching settings.gradle.kts (owned by Agent A).
//
//   ./gradlew -I security/ci/harness.init.gradle.kts :security-harness:testDebugUnitTest
settingsEvaluated { settings ->
    settings.include(":security-harness")
    settings.project(":security-harness").projectDir =
        settings.rootDir.resolve("security/harness")
}
