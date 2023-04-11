import org.jetbrains.kotlin.gradle.tasks.KotlinCompile
import org.jlleitschuh.gradle.ktlint.KtlintExtension

plugins {
    id("org.jetbrains.kotlin.jvm")
    id("org.jlleitschuh.gradle.ktlint") version "11.3.1"
    id("com.adarshr.test-logger") version "3.2.0"
    id("io.gitlab.arturbosch.detekt") version "1.22.0"
    id("me.champeau.jmh") version "0.7.0"
}

dependencies {
    api(project(":mbedtls-lib"))

    api(platform("org.jetbrains.kotlin:kotlin-bom"))
    api("org.jetbrains.kotlin:kotlin-stdlib-jdk8")

    api("org.slf4j:slf4j-api:2.0.7")
    api("net.java.dev.jna:jna:5.13.0")

    // TESTS
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.9.2")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine:5.9.2")
    testImplementation("org.awaitility:awaitility-kotlin:4.2.0")
    testImplementation("ch.qos.logback:logback-classic:1.3.0")
    testImplementation("org.bouncycastle:bcpkix-jdk15on:1.70")
    testImplementation("io.mockk:mockk:1.13.4")
}

java {
    sourceCompatibility = JavaVersion.VERSION_1_8
    targetCompatibility = JavaVersion.VERSION_1_8
}

tasks.withType<KotlinCompile> {
    kotlinOptions.jvmTarget = "1.8"
}

tasks.test {
    useJUnitPlatform()
}

detekt {
    source = files("src/main/kotlin")
    config = files("../detekt.yml")
    buildUponDefaultConfig = true
}

configure<KtlintExtension> {
    disabledRules.set(setOf("trailing-comma-on-call-site", "trailing-comma-on-declaration-site"))
}
