import com.diffplug.gradle.spotless.SpotlessExtension
import org.gradle.api.tasks.testing.logging.TestLogEvent

plugins {
  kotlin("jvm")
  id("com.diffplug.spotless")
  id("ru.vyarus.animalsniffer")
}

kotlin { explicitApi() }

tasks.withType<org.jetbrains.kotlin.gradle.tasks.KotlinCompile> {
  kotlinOptions { moduleName = "kage" }
}

configure<SpotlessExtension> {
  kotlin {
    ktfmt().googleStyle()
    target("**/*.kt")
    targetExclude("**/build/")
  }
  kotlinGradle {
    ktfmt().googleStyle()
    target("**/*.kts")
  }
}

sourceSets { named("main") { java.srcDirs("src/kotlin") } }

dependencies {
  signature("net.sf.androidscents.signature:android-api-level-23:6.0_r3")
  implementation("at.favre.lib:hkdf:1.1.0")
  testImplementation(libs.kotlintest.junit)
}

tasks.withType<Test>().configureEach {
  maxParallelForks = Runtime.getRuntime().availableProcessors() * 2
  testLogging { events(TestLogEvent.PASSED, TestLogEvent.SKIPPED, TestLogEvent.FAILED) }
  outputs.upToDateWhen { false }
}
