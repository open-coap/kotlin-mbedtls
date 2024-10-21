import com.github.benmanes.gradle.versions.updates.DependencyUpdatesTask
import io.gitlab.arturbosch.detekt.Detekt
import io.gitlab.arturbosch.detekt.DetektCreateBaselineTask
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("org.jetbrains.kotlin.jvm") version "2.0.21"
    id("com.github.mfarsikov.kewt-versioning") version "1.0.0"
    id("se.patrikerdes.use-latest-versions") version "0.2.18"
    id("com.github.ben-manes.versions") version "0.51.0"
    id("java-library")
    id("maven-publish")
    id("org.gradle.signing")
    id("io.github.gradle-nexus.publish-plugin") version "2.0.0"
    id("org.jlleitschuh.gradle.ktlint") version "12.1.1"
    id("com.adarshr.test-logger") version "4.0.0"
    id("io.gitlab.arturbosch.detekt") version "1.23.7"
}

allprojects {
    apply {
        plugin("com.github.mfarsikov.kewt-versioning")
        plugin("se.patrikerdes.use-latest-versions")
        plugin("com.github.ben-manes.versions")
        plugin("java-library")
        plugin("maven-publish")
        plugin("org.gradle.signing")
        plugin("org.jetbrains.kotlin.jvm")
        plugin("org.jlleitschuh.gradle.ktlint")
        plugin("com.adarshr.test-logger")
        plugin("io.gitlab.arturbosch.detekt")
    }

    repositories {
        mavenCentral()
    }

    kewtVersioning.configuration {
        separator = ""
    }
    version = kewtVersioning.version
    group = "io.github.open-coap"

    java {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }

    kotlin {
        compilerOptions {
            jvmTarget.set(JvmTarget.JVM_1_8)
            freeCompilerArgs.add("-Werror")
        }
    }

    tasks {
        withType<Detekt>().configureEach {
            jvmTarget = "1.8"
        }
        withType<DetektCreateBaselineTask>().configureEach {
            jvmTarget = "1.8"
        }

        withType<DependencyUpdatesTask> {
            rejectVersionIf {
                val stableKeyword = listOf("RELEASE", "FINAL", "GA").any { candidate.version.uppercase().contains(it) }
                val regex = "^[0-9,.v-]+(-r)?$".toRegex()
                val isNonStable = !(stableKeyword || regex.matches(candidate.version))

                // newer version of logback-classic is not java8 compatible
                // newer version of kewt-versioning plugin requires java 21
                isNonStable || listOf("logback-classic", "com.github.mfarsikov.kewt-versioning.gradle.plugin").contains(candidate.module)
            }
        }

        create<Jar>("sourceJar") {
            archiveClassifier.set("sources")
            from(sourceSets["main"].allSource)
        }

        create<Jar>("javadocJar") {
            archiveClassifier.set("javadoc")
            from(javadoc)
        }
    }

    detekt {
        source.setFrom("$projectDir/src/main/kotlin")
        config.setFrom("$rootDir/detekt.yml")
        buildUponDefaultConfig = true
    }

    publishing {
        publications {
            create<MavenPublication>("OSSRH") {
                from(components["java"])
                groupId = "io.github.open-coap"
                artifact(tasks["javadocJar"])
                artifact(tasks["sourceJar"])

                pom {
                    name.set("Kotlin mbedtls")
                    description.set("Bridge of mbedtls and jvm (kotlin)")
                    url.set("https://github.com/open-coap/kotlin-mbedtls")
                    scm {
                        url.set("https://github.com/open-coap/kotlin-mbedtls")
                    }
                    licenses {
                        license {
                            name.set("Apache License, Version 2.0")
                            url.set("https://www.apache.org/licenses/LICENSE-2.0.txt")
                        }
                    }
                    developers {
                        developer {
                            name.set("Szymon Sasin")
                            email.set("szymon.sasin@gmail.com")
                        }
                    }
                }
            }
        }
    }

    signing {
        val signingKeyId: String? by project
        val signingKey: String? by project
        val signingPassword: String? by project

        if (signingKey != null) {
            useInMemoryPgpKeys(signingKeyId, signingKey, signingPassword)
            sign(publishing.publications["OSSRH"])
        }
    }
}

nexusPublishing {
    repositories {
        sonatype {
            val ossrhUserName: String? by project
            val ossrhPassword: String? by project

            nexusUrl.set(uri("https://s01.oss.sonatype.org/service/local/"))
            snapshotRepositoryUrl.set(uri("https://s01.oss.sonatype.org/content/repositories/snapshots/"))
            username.set(ossrhUserName)
            password.set(ossrhPassword)
        }
    }
}
