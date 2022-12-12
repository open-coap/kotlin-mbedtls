import com.github.benmanes.gradle.versions.updates.DependencyUpdatesTask

plugins {
    id("com.github.mfarsikov.kewt-versioning") version "1.0.0"
    id("se.patrikerdes.use-latest-versions") version "0.2.18"
    id("com.github.ben-manes.versions") version "0.44.0"
}

allprojects {
    apply {
        plugin("com.github.mfarsikov.kewt-versioning")
        plugin("se.patrikerdes.use-latest-versions")
        plugin("com.github.ben-manes.versions")
    }

    repositories {
        mavenCentral()
    }

    kewtVersioning.configuration {
        separator = ""
    }
    version = kewtVersioning.version

    tasks.withType<DependencyUpdatesTask> {
        rejectVersionIf {
            val stableKeyword = listOf("RELEASE", "FINAL", "GA").any { candidate.version.toUpperCase().contains(it) }
            val regex = "^[0-9,.v-]+(-r)?$".toRegex()
            val isNonStable = !(stableKeyword || regex.matches(candidate.version))

            // newer version of logback-classic is not java8 compatible
            isNonStable || candidate.module == "logback-classic"
        }
    }

}
