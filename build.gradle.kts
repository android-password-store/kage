import com.diffplug.gradle.spotless.SpotlessExtension

plugins {
  kotlin("jvm")
  id("com.diffplug.spotless")
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

sourceSets {
  named("main") { java.srcDirs("src/kotlin") }
  named("test") { java.srcDirs("test/kotlin") }
}

dependencies { testImplementation(libs.kotlintest.junit) }
