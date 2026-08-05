import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import org.jetbrains.kotlin.gradle.plugin.getKotlinPluginVersion

group = "com.workos"
version = "0.1.0" // x-release-please-version

if (!project.hasProperty("release")) {
  version = "$version-SNAPSHOT"
}

plugins {
  // Currently the JVM plugin, not `com.android.library`. Nothing in the generated
  // SDK touches an Android API — it is OkHttp + kotlinx only — so a plain JVM
  // library is consumable from Android and buildable without the Android SDK.
  // Switching to `com.android.library` to publish an AAR is a build-file change,
  // not a source change. See the "Android target" section of README.md.
  id("org.jetbrains.kotlin.jvm") version "2.4.0"

  id("org.jetbrains.kotlin.plugin.serialization") version "2.4.0"

  id("org.jlleitschuh.gradle.ktlint") version "14.2.0"

  // Dokka generates the HTML API reference published to GitHub Pages by
  // .github/workflows/docs.yml via ./script/docs. Only the `html` publication
  // is used; it runs solely through script/docs, never on the CI build path.
  id("org.jetbrains.dokka") version "2.2.0"

  // Maven Central publishing (com.vanniktech.maven.publish). The split
  // release process: release-please.yml tags + creates the GitHub Release;
  // .github/workflows/release.yml consumes `release: published` and runs
  // `publishAndReleaseToMavenCentral -Prelease`. Signing key + Maven Central
  // credentials are injected via ORG_GRADLE_PROJECT_* env vars in release.yml.
  id("com.vanniktech.maven.publish") version "0.36.0"

  `java-library`
}

repositories {
  mavenCentral()
  mavenLocal()
}

val kotlinVersion = getKotlinPluginVersion()

dependencies {
  implementation(platform("org.jetbrains.kotlin:kotlin-bom:$kotlinVersion"))

  implementation("org.jetbrains.kotlin:kotlin-stdlib:$kotlinVersion")

  // kotlinx.serialization rather than Jackson: compile-time serializers, no
  // reflection, no R8/ProGuard keep rules. This is the decisive difference from
  // workos-kotlin and the reason `android` is a separate emitter.
  implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")

  // kotlinx-datetime rather than java.time: java.time needs desugaring below API 26.
  implementation("org.jetbrains.kotlinx:kotlinx-datetime:0.6.1")

  implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")

  implementation("com.squareup.okhttp3:okhttp:4.12.0")

  // JWT verification + JWKS handling for the session helpers (hand-maintained).
  // Matches workos-kotlin so session behavior is identical across the two Kotlin SDKs.
  // Note for Android consumers: this is a JVM-sized dependency; R8 shrinking is
  // effective on it, but if APK size becomes a concern the alternative is a
  // hand-rolled RS256 verifier, which trades size for hand-audited crypto.
  implementation("com.nimbusds:nimbus-jose-jwt:10.9.1")

  testImplementation(kotlin("test"))

  testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")

  testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")

  testImplementation(platform("org.junit:junit-bom:5.10.2"))

  testImplementation("org.junit.jupiter:junit-jupiter")

  testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

kotlin {
  compilerOptions {
    // minSdk 24 consumers run on JVM 17 toolchains via AGP desugaring.
    jvmTarget.set(JvmTarget.JVM_17)

    // Fail the build on any compiler warning. The redundant-.toString()
    // warnings that Kotlin 2.4.0 introduced in generated query-param code
    // were fixed at the emitter (workos/oagen-emitters#206) and the SDK
    // regenerated, so this passes cleanly today; it stays in to prevent
    // future regressions.
    allWarningsAsErrors.set(true)
  }
  jvmToolchain(17)
}

tasks.test {
  useJUnitPlatform()
  testLogging { events("failed") }
}

mavenPublishing {
  publishToMavenCentral(automaticRelease = true)
  signAllPublications()

  coordinates("com.workos", "workos-android", version.toString())

  pom {
    name.set("WorkOS Android SDK")
    description.set(
      "The WorkOS Android (Kotlin) library provides convenient access to the WorkOS API " +
        "from applications written in Kotlin for Android.",
    )
    url.set("https://github.com/workos/workos-android")
    licenses {
      license {
        name.set("MIT License")
        url.set("https://github.com/workos/workos-android/blob/main/LICENSE")
      }
    }
    developers {
      developer {
        id.set("workos")
        name.set("WorkOS")
        email.set("sdk@workos.com")
        organization.set("WorkOS")
        organizationUrl.set("https://workos.com")
      }
    }
    scm {
      connection.set("scm:git:git://github.com/workos/workos-android.git")
      developerConnection.set("scm:git:git@github.com:workos/workos-android.git")
      url.set("https://github.com/workos/workos-android")
    }
  }
}
