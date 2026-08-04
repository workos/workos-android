// build.gradle.kts pins `jvmToolchain(17)`, which requires a JDK 17 specifically —
// a newer JDK does not satisfy it. Without a toolchain download repository Gradle
// can only use an already-installed 17 and otherwise hard-fails with
// "Cannot find a Java installation on your machine ... matching {languageVersion=17}".
// That made `script/ci` unrunnable on any machine whose only JDK was not 17, and
// left CI silently dependent on whatever JDK the runner image happens to preinstall.
// This resolver lets Gradle provision the toolchain itself, so the pinned version
// is honored rather than merely hoped for.
plugins {
  id("org.gradle.toolchains.foojay-resolver-convention") version "0.10.0"
}

rootProject.name = "workos-android"
